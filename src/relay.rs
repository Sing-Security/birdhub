// ============================================================================
// RELAY MODULE: the bytes a conversation carries, and the pump that carries
// ============================================================================
//
// A session between two nodes carries many conversations — one per local
// connection on a client, one per inbound request on a serving node — as
// streams multiplexed by `mux.rs`. This module owns the wire vocabulary
// (`RelayMessage`) and the copy loop that moves bytes between a plaintext
// connection and a stream.
//
// There is no framing of our own: every message here is postcard-encoded and
// sealed as one AEAD record by `temper::transport`. Each message names its
// stream, so `Data` from two conversations interleave freely and a stalled
// one does not reorder the others.
//
// The hub speaks a second shape of stream: a *pair*. When a node asks for a
// carrier to a peer (`@peer/<subject>`), the hub opens one stream on each
// session and splices them, byte for byte, in both directions. The two peers
// then run their own Temper session inside that splice, so what the hub
// relays is a record stream it holds no keys for — the hub is a meeting point
// and a fallback path, never a party to the conversation.
//
// Authorization lives in the hub's accept loop. The session already proved
// *who* the client is; the grant table — consulted per `Open`, before the
// dial — decides *what* that identity may ask for. A client naming anything
// else is refused with the target, and nothing about the hub's network is
// learned by trying: a refused target is never dialed, so a client cannot
// even use timing to probe what the hub can see.

use crate::error::{Error, Result};
use crate::events::{EventLog, Kind};
use crate::hub::{HubShared, SessionInfo};
use crate::mux::{IncomingStream, MuxSession, Substream};
use crate::registry::PeerRegistry;
use crate::target::{self, Target};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use temper::transport::{Session, SessionRx, SessionTx};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes moved per message. Small enough that a slow reader on one side does
/// not have to buffer a whole file to make progress on the other, large enough
/// that the per-record AEAD cost disappears into the copy.
const CHUNK: usize = 64 * 1024;

// region:    --- Messages

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayMessage {
    /// Dialing side → serving side: open a stream to `target`.
    Open { stream: u32, target: String },
    /// Serving side → dialing side: the target is connected; `Data` may flow.
    Opened { stream: u32 },
    /// Serving side → dialing side: the target could not be connected.
    Refused { stream: u32, reason: String },
    /// Either direction: opaque bytes for one conversation.
    Data { stream: u32, bytes: Vec<u8> },
    /// Either direction: this side has no more to send on this stream.
    Close { stream: u32 },
    /// Either direction: drop this stream now, without half-closing.
    Reset { stream: u32 },
}

// endregion: --- Messages

// region:    --- Message channel

/// What the mux driver needs from the session's send half.
///
/// The driver is written against these two traits rather than the concrete
/// `SessionTx`/`SessionRx` so the multiplexing can be tested over an
/// in-memory channel: exercising it through a real session costs two
/// post-quantum handshakes per test, and a mux bug lives entirely in the
/// bookkeeping, not in the crypto.
pub(crate) trait MessageTx {
    /// `Send` is part of the contract, spelled out rather than implied: the
    /// mux driver lives in a spawned task, so a half whose future is not
    /// `Send` is not a half this relay can use.
    fn send_msg(
        &mut self,
        message: &RelayMessage,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// The receive half. `Ok(None)` is the session's own "closed cleanly", kept
/// distinct from a `Close` message for the same reason the transport keeps
/// them distinct.
pub(crate) trait MessageRx {
    fn recv_msg(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<RelayMessage>>> + Send;
}

impl<S> MessageTx for SessionTx<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send_msg(&mut self, message: &RelayMessage) -> Result<()> {
        Ok(SessionTx::send(self, message).await?)
    }
}

impl<S> MessageRx for SessionRx<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn recv_msg(&mut self) -> Result<Option<RelayMessage>> {
        Ok(SessionRx::recv(self).await?)
    }
}

// endregion: --- Message channel

// region:    --- Hub side

/// Drive the hub half of a session until it ends.
///
/// One accept loop, one task per stream: a client that opens a second
/// conversation while the first is still moving bytes gets service without
/// waiting for the first to finish — the thing the single-stream build could
/// not do, because the session *was* the conversation.
///
/// `granted` is the exact list of targets the *authenticated* client may ask
/// for — the caller read the client's certificate subject out of the session
/// and looked that subject up in the hub's grant table before calling this.
/// An empty list is a client that may do nothing, which is the correct answer
/// for every client the operator has not written down.
///
/// The session is registered in `registry` for exactly as long as this
/// function serves it, so pairing (`@peer/<subject>`) and certificate lookups
/// (`@cert/<subject>`) can find it — presence is the session being here, and
/// the session id guards the reconnect race (registry.rs). Its entry in the
/// hub's session board lives exactly as long, and its stream counter is what
/// "busy" means in the fleet view.
pub async fn run_hub<S>(
    session: Session<S>,
    info: Arc<SessionInfo>,
    granted: Vec<String>,
    shared: Arc<HubShared>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session_id = session.session_id();
    let (tx, rx) = session.split();
    let mut mux = MuxSession::responder(tx, rx);
    info.set_mux(mux.handle());
    shared.registry.insert(
        &info.subject,
        session_id,
        info.since_unix,
        info.certificate.clone(),
        mux.handle(),
    );
    let granted = Arc::new(granted);

    while let Some(incoming) = mux.accept().await {
        let granted = granted.clone();
        let registry = shared.registry.clone();
        let subject = info.subject.clone();
        let events = shared.events.clone();
        let info = info.clone();
        tokio::spawn(async move {
            // Counted for as long as the conversation runs, however it ends.
            let _counted = StreamCount::new(info);
            if let Err(e) = serve_stream(
                incoming,
                &subject,
                &granted,
                &registry,
                &events,
                |target: String| tokio::net::TcpStream::connect(target),
            )
            .await
            {
                events.warn(Kind::Refusal, format!("Hub: {}", e.message()));
            }
        });
    }

    shared.registry.remove_if(&info.subject, session_id);
    // The board entry goes when the session it describes does. The registry
    // needs the id guard because a reconnect may have replaced the entry; the
    // board is keyed by the id itself, so a removal here can only ever hit a
    // session that has already ended.
    shared.sessions.remove(session_id);
    Ok(())
}

/// Keeps one session's open-stream count honest for exactly the lifetime of
/// the conversation it was made for — including an early return, which a bare
/// increment/decrement pair around the call would leak on.
struct StreamCount(Arc<SessionInfo>);

impl StreamCount {
    fn new(info: Arc<SessionInfo>) -> Self {
        info.streams_open.fetch_add(1, Ordering::Relaxed);
        Self(info)
    }
}

impl Drop for StreamCount {
    fn drop(&mut self) {
        self.0.streams_open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Answer one inbound stream.
///
/// Which of four answers it gets is decided by the target's grammar
/// (`target.rs`), and every branch checks authorization before it does the
/// thing:
///
///   - `host:port` — exact-string grant, then dial, then pump. Unchanged.
///   - `@peer/<subject>` — exact-string grant, then pair: open a carrier on
///     the peer's session and splice the two streams. The hub moves bytes it
///     cannot read; the peers' own Temper session is the payload, so nothing
///     carried is visible here.
///   - `@cert/<subject>` — the `@peer/<subject>` grant (one grant entry means
///     "may reach this peer", and both requests are that reach), then hand
///     back the certificate the peer presented at its handshake. The
///     requester verifies it against the CA; the hub vouches for nothing.
///   - `subject/service` — refused. Service names are between peers, inside
///     their session; a client that opens one at the hub is confused, and
///     saying so beats dialing a host called "subject".
///
/// Split out from `run_hub` for one reason: the refusal path must be
/// provably dial-free, and a real `TcpStream::connect` cannot prove that — a
/// test that points it at a closed port cannot distinguish "not dialed" from
/// "dialed and failed". The `dial` closure makes the difference observable:
/// the refusal tests hand it a function that panics, so a refusal that dials
/// is a test failure, not a slower refusal.
async fn serve_stream<U, F, Fut>(
    incoming: IncomingStream,
    requester: &str,
    granted: &[String],
    registry: &PeerRegistry,
    events: &EventLog,
    dial: F,
) -> Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(String) -> Fut + Send,
    Fut: std::future::Future<Output = std::io::Result<U>> + Send,
{
    let target = incoming.target().to_string();
    let parsed = match target::parse(&target) {
        Ok(parsed) => parsed,
        Err(reason) => {
            incoming.refuse(&reason);
            return Err(Error::custom(reason));
        }
    };

    // Exact string match, deliberately: a prefix match here would let
    // "internal:8080" grant "internal:80808", and a parsed-host match would
    // make the operator's mental model of the line depend on DNS at check
    // time. The grant is the string; the string must be equal. The directory's
    // request string differs from its grant string (`@cert/x` vs `@peer/x`),
    // so that one comparison is spelled as what each side means.
    let permitted = match &parsed {
        Target::Dial { target } => granted.iter().any(|allowed| allowed == target),
        Target::Carrier { .. } => granted.iter().any(|allowed| allowed == &target),
        Target::Directory { subject } => granted
            .iter()
            .any(|allowed| allowed == &target::peer_grant(subject)),
        Target::Peer { .. } => false,
    };
    if !permitted {
        let reason = match &parsed {
            // The hint names the fix: this is the message an operator sees
            // the first time they reach for a peer they never wrote down.
            Target::Directory { subject } => format!(
                "no grant names peer '{}' (reaching it is granted as \"{}\")",
                subject,
                target::peer_grant(subject)
            ),
            Target::Peer { .. } => {
                "service targets travel between peers, not to the hub; open '@peer/<subject>' \
                 for a carrier"
                    .to_string()
            }
            _ => format!("{} is not granted to this client", target),
        };
        incoming.refuse(&reason);
        return Err(Error::custom(reason));
    }

    match parsed {
        Target::Dial { target } => match dial(target.clone()).await {
            Ok(upstream) => {
                let (_target, stream) = incoming.accept();
                run_pump(upstream, stream).await
            }
            Err(e) => {
                let reason = e.to_string();
                incoming.refuse(&reason);
                Err(Error::custom(format!(
                    "cannot connect to {}: {}",
                    target, reason
                )))
            }
        },

        Target::Carrier { subject } => {
            let Some((peer_mux, _cert)) = registry.get(&subject) else {
                let reason = format!("peer '{}' is not connected", subject);
                incoming.refuse(&reason);
                return Err(Error::custom(reason));
            };
            let peer_stream = match peer_mux.open(target::CARRIER_TARGET).await {
                Ok(stream) => stream,
                Err(e) => {
                    // The peer refused the carrier, or its session died
                    // between the registry lookup and this open. Either way
                    // its reason is the best one to pass on.
                    let reason = e.message();
                    incoming.refuse(&reason);
                    return Err(Error::custom(reason));
                }
            };
            events.info(
                Kind::Pairing,
                format!("Hub: pairing '{}' with '{}'", requester, subject),
            );
            let (_target, stream) = incoming.accept();
            run_pair(stream, peer_stream).await
        }

        Target::Directory { subject } => {
            let Some((_mux, certificate)) = registry.get(&subject) else {
                let reason = format!("peer '{}' is not connected", subject);
                incoming.refuse(&reason);
                return Err(Error::custom(reason));
            };
            let bytes = postcard::to_allocvec(&certificate)
                .map_err(|e| Error::custom(format!("cannot encode certificate: {}", e)))?;
            let (_target, mut stream) = incoming.accept();
            stream.write_all(&bytes).await?;
            // A half-close, so the requester's read-to-end terminates on EOF
            // rather than on a reset.
            stream.shutdown().await?;
            Ok(())
        }

        Target::Peer { .. } => unreachable!("refused above"),
    }
}

// endregion: --- Hub side

// region:    --- The pump

/// Copy in both directions until both sides are done.
///
/// One `select!` over a read from the plaintext connection and a read from
/// the stream. Bytes move in whatever chunk size the plaintext side produces;
/// the mux carries each chunk as one `Data` message.
///
/// A read of zero is a *half*-close in TCP's vocabulary, and the two branches
/// mirror each other: the plaintext side's EOF becomes `shutdown` on the
/// stream (a `Close` on the wire), which the peer mirrors back as a shutdown
/// of the plaintext side there. The first version of the single-stream pump
/// broke out of the loop on the received `Close` instead, which tears down
/// exactly the bytes the peer is waiting for in the shape every `nc -N` and
/// HTTP/1.0 client produces: shut the write half after the request, then read
/// the response. Only once both sides have half-closed is there nothing left
/// to wait on.
pub async fn run_pump<L>(mut local: L, mut stream: Substream) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let result = pump(&mut local, &mut stream).await;
    if result.is_err() {
        // Giving up mid-transfer is an abort, not a half-close: the peer
        // should stop sending now instead of discovering the failure one
        // write later. A clean end never reaches this — `pump` returns only
        // after both directions have closed.
        stream.reset();
    }
    result
}

/// Splice two streams — the hub pairing a carrier: the dialing node's stream
/// and the peer's are two halves of one pipe, and the hub copies between them
/// without interpreting a byte. On error both ends are aborted, because a
/// splice has no "one side is fine" state: the peers' session spans the pair.
pub async fn run_pair(mut a: Substream, mut b: Substream) -> Result<()> {
    let result = pump(&mut a, &mut b).await;
    if result.is_err() {
        a.reset();
        b.reset();
    }
    result
}

async fn pump<L>(local: &mut L, stream: &mut Substream) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    // One buffer per direction: `select!` holds both read futures at once,
    // so they cannot share a buffer.
    let mut local_buf = vec![0u8; CHUNK];
    let mut peer_buf = vec![0u8; CHUNK];
    let mut local_open = true;
    let mut peer_open = true;

    loop {
        tokio::select! {
            read = local.read(&mut local_buf), if local_open => {
                let n = read?;
                if n == 0 {
                    // Half-close: tell the peer, and keep receiving. The
                    // peer may still have everything it was asked for.
                    stream.shutdown().await?;
                    local_open = false;
                    if !peer_open {
                        break;
                    }
                    continue;
                }
                stream.write_all(&local_buf[..n]).await?;
            }

            read = stream.read(&mut peer_buf), if peer_open => {
                let n = read?;
                if n == 0 {
                    // Mirror the peer's half-close as a shutdown of the
                    // plaintext side — that is a FIN the local program may be
                    // waiting for — and keep sending. "Nothing more from me"
                    // is not "nothing more from you".
                    local.shutdown().await?;
                    peer_open = false;
                    if !local_open {
                        break;
                    }
                    continue;
                }
                local.write_all(&peer_buf[..n]).await?;
            }
        }
    }

    Ok(())
}

// endregion: --- The pump

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::enroll;
    use tokio::sync::mpsc;

    /// Sessions over in-memory channels — the same shape `mux.rs` uses for
    /// its own tests, duplicated here so the pump tests can drive the far end
    /// of a stream directly.
    struct ChanTx(mpsc::UnboundedSender<RelayMessage>);
    struct ChanRx(mpsc::UnboundedReceiver<RelayMessage>);

    impl MessageTx for ChanTx {
        async fn send_msg(&mut self, message: &RelayMessage) -> Result<()> {
            self.0
                .send(message.clone())
                .map_err(|_| Error::custom("test channel closed"))
        }
    }

    impl MessageRx for ChanRx {
        async fn recv_msg(&mut self) -> Result<Option<RelayMessage>> {
            Ok(self.0.recv().await)
        }
    }

    fn pair() -> (MuxSession, MuxSession) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        // Crossed: what A sends is what B receives, and the other way round.
        (
            MuxSession::initiator(ChanTx(a_tx), ChanRx(b_rx)),
            MuxSession::responder(ChanTx(b_tx), ChanRx(a_rx)),
        )
    }

    /// The shape `transport.rs` builds per local connection: a plaintext
    /// `DuplexStream` standing in for the accepted TCP connection, pumped
    /// through `run_pump` into a stream on the session.
    ///
    /// Returns the test's end of the plaintext pipe, the remote (serving)
    /// session endpoint, and the pump task.
    fn pump_rig() -> (
        tokio::io::DuplexStream,
        MuxSession,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (a, b) = pair();
        let mux = a.handle();
        let (plaintext, pump_side) = tokio::io::duplex(CHUNK);
        let pump = tokio::spawn(async move {
            let stream = mux.open("svc").await?;
            run_pump(pump_side, stream).await
        });
        (plaintext, b, pump)
    }

    /// A peer's half-close must not cut off bytes the local side is still
    /// producing — the shape `nc -N` and HTTP/1.0 clients produce when they
    /// shut down their write half after their request and then read the
    /// response. The single-stream pump broke out of its loop on the received
    /// `Close`, so the response it was waiting for was truncated.
    #[tokio::test]
    async fn peer_close_keeps_local_data_flowing() {
        let (mut plaintext, mut remote, pump) = pump_rig();

        let incoming = remote.accept().await.expect("inbound stream");
        let (_target, mut stream) = incoming.accept();

        plaintext.write_all(b"request").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        // The peer half-closes its *send* direction. The local side must see
        // the mirrored shutdown — a FIN — and still be able to send.
        stream.shutdown().await.unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(plaintext.read(&mut eof).await.unwrap(), 0);

        plaintext.write_all(b"body").await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"body");

        // Local finishes: EOF → Close → both sides closed → the pump ends.
        plaintext.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
        pump.await.unwrap().unwrap();
    }

    /// The other half of the symmetry, pinned so it cannot regress: after the
    /// local side half-closes, the pump keeps receiving, and the peer's reply
    /// still reaches the local program.
    #[tokio::test]
    async fn local_close_still_receives_peer_reply() {
        let (mut plaintext, mut remote, pump) = pump_rig();

        let incoming = remote.accept().await.expect("inbound stream");
        let (_target, mut stream) = incoming.accept();

        plaintext.write_all(b"request").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        plaintext.shutdown().await.unwrap();
        assert_eq!(
            stream.read(&mut buf).await.unwrap(),
            0,
            "half-close arrives"
        );

        stream.write_all(b"response").await.unwrap();
        let mut response = [0u8; 8];
        plaintext.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");

        stream.shutdown().await.unwrap();
        pump.await.unwrap().unwrap();
    }

    // region: --- Grants

    /// A dialer that must never run. Passing it to `serve_stream` is how the
    /// refusal tests prove "not dialed" rather than "dialed and failed".
    async fn never_dial(_target: String) -> std::io::Result<tokio::io::DuplexStream> {
        unreachable!("a refused target must never reach the dialer")
    }

    /// The empty registry — the presence state of a hub nobody has connected
    /// to, which is what the dial-path tests run against.
    fn no_peers() -> PeerRegistry {
        PeerRegistry::new()
    }

    /// A registry with one peer online. The mux is only spoken on by the
    /// pairing test; the directory branch hands the certificate back without
    /// touching it.
    fn peers_with(
        subject: &str,
        certificate: temper::ca::TemperCertificate,
        mux: crate::mux::Mux,
    ) -> PeerRegistry {
        let registry = PeerRegistry::new();
        registry.insert(subject, 1, 0, certificate, mux);
        registry
    }

    /// A target outside the client's grants is refused, and — the point of
    /// the test — never dialed: the dialer below panics, so a refusal that
    /// connects first is a test failure rather than a slower refusal. The
    /// refusal also reaches the dialing side intact.
    #[tokio::test]
    async fn ungranted_target_is_refused_without_dialing() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let opened = tokio::spawn(async move { a_mux.open("evil.internal:22").await });
        let incoming = b.accept().await.expect("inbound stream");

        let granted = ["origin.internal:80".to_string()];
        let err = serve_stream(
            incoming,
            "a.example",
            &granted,
            &no_peers(),
            EventLog::silent(),
            never_dial,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("evil.internal:22"), "error was: {}", err);
        assert!(err.contains("not granted"), "error was: {}", err);

        let refused = opened.await.unwrap().err().expect("refused").to_string();
        assert!(
            refused.contains("evil.internal:22"),
            "error was: {}",
            refused
        );
        assert!(refused.contains("not granted"), "error was: {}", refused);
    }

    /// The grant is the exact string. A prefix or a stripped port must not
    /// match, in either direction — this is the check that keeps
    /// "internal:8080" from granting "internal:80808".
    #[tokio::test]
    async fn grant_matching_is_exact() {
        let cases = [
            ("origin.internal:80", "origin.internal"),
            ("origin.internal", "origin.internal:80"),
        ];
        for (granted, target) in cases {
            let (a, mut b) = pair();
            let a_mux = a.handle();

            let opened = {
                let a_mux = a_mux.clone();
                let target = target.to_string();
                tokio::spawn(async move { a_mux.open(&target).await })
            };
            let incoming = b.accept().await.expect("inbound stream");

            let granted = [granted.to_string()];
            let err = serve_stream(
                incoming,
                "a.example",
                &granted,
                &no_peers(),
                EventLog::silent(),
                never_dial,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("not granted"),
                "grant {:?} matched target {:?}",
                granted,
                target
            );
            assert!(opened.await.unwrap().is_err());
        }
    }

    /// A granted target is dialed exactly once, with the client's string, and
    /// the stream that comes back carries the dialed connection's bytes.
    #[tokio::test]
    async fn granted_target_is_dialed_and_answered() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let opened = tokio::spawn(async move { a_mux.open("origin.internal:80").await });
        let incoming = b.accept().await.expect("inbound stream");

        let (dialed, mut upstream) = tokio::io::duplex(CHUNK);
        let served = tokio::spawn(async move {
            let granted = ["origin.internal:80".to_string()];
            serve_stream(
                incoming,
                "a.example",
                &granted,
                &no_peers(),
                EventLog::silent(),
                move |target: String| {
                    assert_eq!(target, "origin.internal:80");
                    async move { Ok::<_, std::io::Error>(dialed) }
                },
            )
            .await
        });

        let mut stream = opened.await.unwrap().expect("granted open succeeds");

        // The bytes come from the dialed connection, not a fresh one.
        upstream.write_all(b"reply").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"reply");

        // And the plaintext side's close ends the stream and the pump. The
        // pump still waits for the *stream* to close, which is this side's
        // `Substream`; dropping it turns the read-to-EOF into the half-close
        // the pump is waiting for.
        upstream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        drop(stream);
        served.await.unwrap().unwrap();
    }

    // endregion: --- Grants

    // region: --- Peers

    /// An ungranted carrier request is refused by the *grant* check, not the
    /// presence check — and the two are distinguishable from outside. The
    /// peer below is online; a refusal that mentioned it would let any client
    /// enumerate the fleet's presence with a list of guesses.
    #[tokio::test]
    async fn an_ungranted_carrier_is_refused_before_presence() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let opened = tokio::spawn(async move { a_mux.open("@peer/b.example").await });
        let incoming = b.accept().await.expect("inbound stream");

        let enrolled = enroll("carrier-ungranted", 30);
        let (_peer_side, _hold) = pair();
        let registry = peers_with("b.example", enrolled.cert.clone(), _peer_side.handle());

        let err = serve_stream(
            incoming,
            "a.example",
            &[],
            &registry,
            EventLog::silent(),
            never_dial,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not granted"), "error was: {}", err);
        assert!(
            !err.contains("connected"),
            "an ungranted client learned the peer is online: {}",
            err
        );
        assert!(opened.await.unwrap().is_err());
    }

    /// Granted, but the peer is not connected: the refusal says so — the
    /// requester already proved it may reach this peer, so presence is not
    /// information it is being denied.
    #[tokio::test]
    async fn a_carrier_to_an_offline_peer_is_refused() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let opened = tokio::spawn(async move { a_mux.open("@peer/b.example").await });
        let incoming = b.accept().await.expect("inbound stream");

        let granted = ["@peer/b.example".to_string()];
        let err = serve_stream(
            incoming,
            "a.example",
            &granted,
            &no_peers(),
            EventLog::silent(),
            never_dial,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not connected"), "error was: {}", err);

        let refused = opened.await.unwrap().err().expect("refused").to_string();
        assert!(refused.contains("not connected"), "was: {}", refused);
    }

    /// A `<subject>/<service>` opened at the hub is a mistake worth naming:
    /// services exist inside a peer session, and the hub has no such table.
    #[tokio::test]
    async fn a_service_target_is_refused_at_the_hub() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let opened = tokio::spawn(async move { a_mux.open("b.example/web").await });
        let incoming = b.accept().await.expect("inbound stream");

        let granted = ["b.example/web".to_string()];
        let err = serve_stream(
            incoming,
            "a.example",
            &granted,
            &no_peers(),
            EventLog::silent(),
            never_dial,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("travel between peers"), "error was: {}", err);
        assert!(opened.await.unwrap().is_err());
    }

    /// The pairing branch end to end at the mux layer: A opens the carrier,
    /// the hub opens one on B's session and splices, and bytes written on one
    /// side arrive on the other — opaque to the hub, which sees only records.
    #[tokio::test]
    async fn a_carrier_pairs_two_peers() {
        // A's session with the hub, and B's — the hub holds the far end of
        // each. What it splices between them is the peer pair.
        let (a_side, mut hub_for_a) = pair();
        let a_mux = a_side.handle();
        let (mut b_side, hub_for_b) = pair();

        let b_task = tokio::spawn(async move {
            let incoming = b_side.accept().await.expect("carrier inbound");
            assert_eq!(incoming.target(), target::CARRIER_TARGET);
            let (_target, mut stream) = incoming.accept();

            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let enrolled = enroll("carrier-pair", 30);
        let registry = peers_with("b.example", enrolled.cert.clone(), hub_for_b.handle());

        let opened = tokio::spawn(async move { a_mux.open("@peer/b.example").await });
        let incoming = hub_for_a.accept().await.expect("carrier request");

        let served = tokio::spawn(async move {
            let granted = ["@peer/b.example".to_string()];
            serve_stream(
                incoming,
                "a.example",
                &granted,
                &registry,
                EventLog::silent(),
                never_dial,
            )
            .await
        });

        let mut stream = opened.await.unwrap().expect("carrier opens");
        stream.write_all(b"ping").await.unwrap();

        // B's reply arrives, and its half-close reaches A as EOF — the
        // splice mirrors closes the same way the dial pump does.
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "unexpected trailing bytes: {:?}", rest);

        drop(stream);
        b_task.await.unwrap();
        served.await.unwrap().unwrap();
    }

    /// The directory is gated by the same grant as the carrier: one entry,
    /// `@peer/<subject>`, means "may reach this peer", and both requests are
    /// that reach. A grant naming a *different* peer does not open it.
    #[tokio::test]
    async fn the_directory_needs_a_grant_naming_the_peer() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let opened = tokio::spawn(async move { a_mux.open("@cert/b.example").await });
        let incoming = b.accept().await.expect("inbound stream");

        let enrolled = enroll("directory-ungranted", 30);
        let (peer_side, _hold) = pair();
        let registry = peers_with("b.example", enrolled.cert.clone(), peer_side.handle());

        let granted = ["@peer/c.example".to_string()];
        let err = serve_stream(
            incoming,
            "a.example",
            &granted,
            &registry,
            EventLog::silent(),
            never_dial,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no grant names peer 'b.example'"),
            "was: {}",
            err
        );
        assert!(opened.await.unwrap().is_err());
    }

    /// The certificate handed back is the one the peer presented at its
    /// handshake, byte-for-byte decodable, and the reply ends at EOF so the
    /// requester's read-to-end lets go.
    #[tokio::test]
    async fn the_directory_returns_the_certificate_it_was_given() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let enrolled = enroll("directory-answer", 30);
        let (peer_side, _hold) = pair();
        let registry = peers_with("b.example", enrolled.cert.clone(), peer_side.handle());

        let opened = tokio::spawn(async move { a_mux.open("@cert/b.example").await });
        let incoming = b.accept().await.expect("inbound stream");

        let served = tokio::spawn(async move {
            let granted = ["@peer/b.example".to_string()];
            serve_stream(
                incoming,
                "a.example",
                &granted,
                &registry,
                EventLog::silent(),
                never_dial,
            )
            .await
        });

        let mut stream = opened.await.unwrap().expect("directory answers");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let decoded: temper::ca::TemperCertificate =
            postcard::from_bytes(&bytes).expect("the reply is the postcard certificate");
        assert_eq!(decoded.cert_id, enrolled.cert.cert_id);
        served.await.unwrap().unwrap();
    }

    // endregion: --- Peers
}

// endregion: --- Tests
