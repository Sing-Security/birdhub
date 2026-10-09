// ============================================================================
// NODE MODULE: the client node — one hub session, peer sessions, serving
// ============================================================================
//
// A node has exactly one hub session, kept up by a supervisor task whether
// the node is idle or busy. Presence at the hub *is* that session, so a node
// that only reconnects when it has traffic cannot be reached by peers while
// it has none. One task owns establishment and the accept side; every other
// path — local listeners, peer establishment — reads the session through a
// watch channel and never creates one. Two owners of "connect" would race and
// flap the hub's registry; one owner cannot.
//
// Reaching a peer is a three-step conversation with the hub, and then a
// session the hub is not part of:
//
//   1. `@cert/<subject>` — fetch the peer's certificate. It is signed by the
//      fleet CA, so the hub vouches for nothing; a lie earns a failed
//      handshake, and the subject check below is what makes it the *right*
//      member rather than merely a member.
//   2. `@peer/<subject>` — the hub opens a carrier on the peer's session and
//      splices the two streams. From here the hub copies bytes it holds no
//      keys for.
//   3. Inside that carrier the two peers run their own Temper session
//      (`Session::initiate` over the carrier's `Substream`) and multiplex
//      services as streams on it. This is the layer the hub cannot read.
//
// The same object serves the reverse direction: an inbound carrier is
// nested-accepted, and each incoming inner stream names a service, checked
// against the peer's *certificate subject* — proved by the nested handshake —
// before anything is dialed. The two authorization questions are therefore
// answered where each can be answered: the hub decides who may reach whom
// (its grant table, per `@peer/<subject>`), and the serving node decides who
// may use what (its own `[[services]]` clients list), the second by the
// peer's own proof rather than by anything the hub said.
//
// What this deliberately does not do yet: a dialing node drops the nested
// accept queue (it opens inner streams and accepts none), so a peer session
// is one-way until a consumer needs otherwise; and the carrier handshake is
// bounded by a semaphore rather than rate-limited per peer, which is enough
// against accidents but not against a hostile fleet member (WORK_QUEUE).

use crate::ca::CaPublicKeys;
use crate::config::{ServiceConfig, TransportConfig};
use crate::error::{Error, Result};
use crate::events::{EventLog, Kind};
use crate::identity::Identity;
use crate::mux::{IncomingStream, Mux, MuxSession};
use crate::relay;
use crate::target::{self, Target};
use crate::time::now_secs;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use temper::ca::TemperCertificate;
use temper::replay::SessionReplayGuard;
use temper::transport::{ResponderConfig, Session};
use temper::{CertValidity, PeerPolicy, TemperEntropy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{watch, Mutex, Semaphore};

/// How long a local connection waits for the hub session before it is told
/// the hub is unreachable. Long enough to cover a reconnect after a blip,
/// short enough that a `curl` against a node whose hub is down fails while
/// the operator is still watching.
const SESSION_WAIT: Duration = Duration::from_secs(30);

/// Reconnect pacing: a session that just died is re-established after a
/// second, and repeated failures back off to half a minute.
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Nested handshakes that may run at once. Each costs two post-quantum
/// signatures on this node, and the hub relays carriers without asking, so
/// without a bound a fleet member could spend this node's CPU at will.
const CARRIER_LIMIT: usize = 16;

/// A certificate read that stalls must not hold a local connection forever;
/// the hub writes a few kilobytes and closes.
const DIRECTORY_TIMEOUT: Duration = Duration::from_secs(10);

// region:    --- Node context

/// Everything the node's tasks share, and nothing that changes: identity,
/// papers, trust anchors, what it serves. `Arc`-shared rather than cloned so
/// the serving tasks — spawned per carrier and per service stream — borrow
/// the same state the dial path uses.
pub struct NodeContext {
    pub identity: Arc<Identity>,
    pub certificate: TemperCertificate,
    pub ca: CaPublicKeys,
    /// The hub this node connects to, pinned by certificate: address comes
    /// from `[peer] address`, identity from `[peer] hub_cert`.
    pub hub_certificate: TemperCertificate,
    /// Service name → what it dials and who may use it.
    pub services: BTreeMap<String, ServiceConfig>,
    /// Replay window for *nested* handshakes, shared across reconnects: a
    /// replayed flight 1 must be refused whether or not this node happens to
    /// have reconnected since the original went out.
    pub replay: Mutex<SessionReplayGuard>,
    /// Arc'd so a permit can be acquired *owned* (`acquire_owned`) and moved
    /// into the task that runs the handshake it is bounding.
    pub carriers: Arc<Semaphore>,
    /// Every line this node prints, as data — the same log the hub keeps.
    pub events: Arc<EventLog>,
}

impl NodeContext {
    pub fn new(
        identity: Identity,
        certificate: TemperCertificate,
        ca: CaPublicKeys,
        hub_certificate: TemperCertificate,
        services: BTreeMap<String, ServiceConfig>,
        events: Arc<EventLog>,
    ) -> Result<Self> {
        Ok(Self {
            identity: Arc::new(identity),
            certificate,
            ca,
            hub_certificate,
            services,
            replay: Mutex::new(SessionReplayGuard::new(
                temper::transport::DEFAULT_REPLAY_TTL_SECS,
                temper::replay::DEFAULT_REPLAY_CAPACITY,
            )?),
            carriers: Arc::new(Semaphore::new(CARRIER_LIMIT)),
            events,
        })
    }

    fn policy(&self, now: u64) -> PeerPolicy {
        PeerPolicy::Cert {
            ca_mldsa_pk: self.ca.mldsa_public_key.clone(),
            ca_slhdsa_pk: self.ca.slhdsa_public_key.clone(),
            validity: CertValidity::At(now),
        }
    }
}

// endregion: --- Node context

// region:    --- Node link

/// What the hub link is doing right now — the one fact a node view needs
/// that no session can answer, because it is also the state of having none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// No session, and no attempt has failed yet (startup, or just after a
    /// session ended cleanly).
    Connecting,
    Connected {
        session_id: u64,
    },
    /// The last attempt failed, or a session ended; the supervisor is
    /// sleeping before the next try.
    Backoff {
        retry_in_secs: u64,
        last_error: String,
    },
}

impl LinkState {
    pub fn label(&self) -> &'static str {
        match self {
            LinkState::Connecting => "connecting",
            LinkState::Connected { .. } => "connected",
            LinkState::Backoff { .. } => "backoff",
        }
    }
}

/// One transport's listener, as the Transports view reads it: what it is
/// configured to do, how many connections it has carried, and the last thing
/// that went wrong with the listener itself.
pub struct TransportRuntime {
    config: TransportConfig,
    accepted: AtomicU64,
    last_error: std::sync::Mutex<Option<String>>,
}

impl TransportRuntime {
    fn new(config: TransportConfig) -> Self {
        Self {
            config,
            accepted: AtomicU64::new(0),
            last_error: std::sync::Mutex::new(None),
        }
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .expect("transport error lock")
            .clone()
    }

    /// Count one accepted local connection.
    pub fn count_connection(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failure of the listener itself (bind, accept) — not of the
    /// connections it carries, whose reasons belong to the session log.
    pub fn failed(&self, message: impl Into<String>) {
        *self.last_error.lock().expect("transport error lock") = Some(message.into());
    }
}

/// A cached nested session with a peer, and when it was established.
struct PeerSession {
    mux: Mux,
    session_id: u64,
    since_unix: u64,
}

/// One cached peer session, as the Peers view reads it.
#[derive(Clone, Debug)]
pub struct PeerRow {
    pub subject: String,
    pub session_id: u64,
    pub since_unix: u64,
    /// False once the session is gone but not yet re-established; the cached
    /// record outlives the session by exactly one failed open.
    pub live: bool,
}

/// The node's connection to its hub, and the peer sessions that ride on it.
pub struct NodeLink {
    ctx: Arc<NodeContext>,
    server_address: String,
    /// The live session, published by the supervisor. `None` means "no
    /// session right now", and a change notification is exactly the wakeup
    /// every waiter is parked on.
    session_tx: watch::Sender<Option<Mux>>,
    session_rx: watch::Receiver<Option<Mux>>,
    /// Where the supervisor is: connecting, connected, or waiting to retry.
    /// The error a waiting local connection is told is read from here, so
    /// there is one record of "why", not two that can disagree.
    link_state: std::sync::Mutex<LinkState>,
    /// Nested sessions by peer subject, established on first use.
    peers: Mutex<HashMap<String, PeerSession>>,
    /// This node's listeners by name, in name order.
    transports: BTreeMap<String, Arc<TransportRuntime>>,
}

impl NodeLink {
    pub fn new(
        ctx: Arc<NodeContext>,
        server_address: String,
        transports: &[TransportConfig],
    ) -> Self {
        let (session_tx, session_rx) = watch::channel(None);
        Self {
            ctx,
            server_address,
            session_tx,
            session_rx,
            link_state: std::sync::Mutex::new(LinkState::Connecting),
            peers: Mutex::new(HashMap::new()),
            transports: transports
                .iter()
                .map(|config| {
                    (
                        config.name.clone(),
                        Arc::new(TransportRuntime::new(config.clone())),
                    )
                })
                .collect(),
        }
    }

    pub fn events(&self) -> Arc<EventLog> {
        self.ctx.events.clone()
    }

    pub fn context(&self) -> Arc<NodeContext> {
        self.ctx.clone()
    }

    pub fn server_address(&self) -> &str {
        &self.server_address
    }

    /// Where the hub link is now.
    pub fn link_state(&self) -> LinkState {
        self.link_state.lock().expect("link state lock").clone()
    }

    fn set_link_state(&self, state: LinkState) {
        *self.link_state.lock().expect("link state lock") = state;
    }

    /// The transports in name order — the order the config lists them in, and
    /// the order the view shows.
    pub fn transports(&self) -> Vec<Arc<TransportRuntime>> {
        self.transports.values().cloned().collect()
    }

    /// The cached peer sessions, by subject.
    ///
    /// `None` while a handshake holds the map — `peer_mux` holds this lock
    /// across establishment on purpose, and a view polling every frame must
    /// neither block behind a post-quantum handshake nor report "no peers"
    /// for a fleet it simply could not look at.
    pub fn peers_snapshot(&self) -> Option<Vec<PeerRow>> {
        let peers = self.peers.try_lock().ok()?;
        let mut rows: Vec<PeerRow> = peers
            .iter()
            .map(|(subject, peer)| PeerRow {
                subject: subject.clone(),
                session_id: peer.session_id,
                since_unix: peer.since_unix,
                live: !peer.mux.is_closed(),
            })
            .collect();
        rows.sort_by(|a, b| a.subject.cmp(&b.subject));
        Some(rows)
    }

    /// Start the supervisor: connect, serve, reconnect — forever.
    pub fn spawn_supervisor(self: &Arc<Self>) {
        let link = self.clone();
        tokio::spawn(link.supervise());
    }

    /// Drop the live hub session now; the supervisor reconnects on its own
    /// backoff. The operator's "reconnect" button — the same mux shutdown a
    /// hub kick uses, applied to this node's own session. A no-op while no
    /// session is up.
    pub fn reconnect(&self) {
        if let Some(mux) = (*self.session_rx.borrow()).clone() {
            mux.shutdown();
        }
    }

    /// The live hub session, waiting for the supervisor if it is between
    /// attempts.
    pub async fn session(&self) -> Result<Mux> {
        let mut rx = self.session_rx.clone();
        let wait = async {
            loop {
                let current: Option<Mux> = (*rx.borrow_and_update()).clone();
                if let Some(mux) = current {
                    if !mux.is_closed() {
                        return mux;
                    }
                    // The supervisor has not retired it yet; its retirement is
                    // the next change, and the reconnect the one after.
                }
                if rx.changed().await.is_err() {
                    // The sender lives in `self`; this is the type system's
                    // share of the work, not a reachable state.
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::time::timeout(SESSION_WAIT, wait).await.map_err(|_| {
            let why = match self.link_state() {
                LinkState::Backoff { last_error, .. } => last_error,
                _ => "connect attempts have not succeeded yet".to_string(),
            };
            Error::custom(format!(
                "no session to the hub at {} ({}s): {}",
                self.server_address,
                SESSION_WAIT.as_secs(),
                why
            ))
        })
    }

    /// The nested session to `subject`, established on first use and
    /// re-established once if the cached one turns out dead.
    ///
    /// The lock is deliberately held across the handshake: two local
    /// connections racing to reach the same new peer would otherwise both
    /// establish, and the slower insert would orphan the faster session. The
    /// price is that first contact with one peer serialises first contact
    /// with another — a handshake's worth of waiting, once per pair, for a
    /// cache that can never hold two sessions for one subject.
    async fn peer_mux(&self, subject: &str) -> Result<Mux> {
        let mut peers = self.peers.lock().await;
        if let Some(peer) = peers.get(subject) {
            if !peer.mux.is_closed() {
                return Ok(peer.mux.clone());
            }
        }
        let (mux, session_id) = self.establish_peer(subject).await?;
        peers.insert(
            subject.to_string(),
            PeerSession {
                mux: mux.clone(),
                session_id,
                since_unix: now_secs(),
            },
        );
        Ok(mux)
    }

    async fn forget_peer(&self, subject: &str) {
        let mut peers = self.peers.lock().await;
        if peers.get(subject).is_some_and(|peer| peer.mux.is_closed()) {
            peers.remove(subject);
        }
    }

    /// Directory lookup, carrier, nested handshake — with one retry when the
    /// failure was the hub session dying, not a refusal.
    async fn establish_peer(&self, subject: &str) -> Result<(Mux, u64)> {
        let mut last = None;
        for _ in 0..2 {
            let hub = self.session().await?;
            match establish_over(&self.ctx, &hub, subject).await {
                Ok(established) => return Ok(established),
                Err(e) if hub.is_closed() => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("a closed session is what loops"))
    }

    /// Carry one accepted local connection to its destination.
    pub async fn serve_local(&self, forward_to: &str, local: tokio::net::TcpStream) -> Result<()> {
        match target::parse(forward_to).map_err(Error::custom)? {
            Target::Dial { target } => {
                let hub = self.session().await?;
                let stream = match hub.open(&target).await {
                    Ok(stream) => stream,
                    Err(_) if hub.is_closed() => {
                        let hub = self.session().await?;
                        hub.open(&target).await.map_err(|e| {
                            Error::custom(format!("hub refused {}: {}", target, e.message()))
                        })?
                    }
                    Err(e) => {
                        return Err(Error::custom(format!(
                            "hub refused {}: {}",
                            target,
                            e.message()
                        )));
                    }
                };
                relay::run_pump(local, stream).await
            }
            Target::Peer { subject, service } => {
                let mux = self.peer_mux(&subject).await?;
                let stream = match mux.open(&service).await {
                    Ok(stream) => stream,
                    Err(_) if mux.is_closed() => {
                        self.forget_peer(&subject).await;
                        let mux = self.peer_mux(&subject).await?;
                        mux.open(&service).await.map_err(|e| {
                            Error::custom(format!(
                                "peer '{}' refused '{}': {}",
                                subject,
                                service,
                                e.message()
                            ))
                        })?
                    }
                    Err(e) => {
                        return Err(Error::custom(format!(
                            "peer '{}' refused '{}': {}",
                            subject,
                            service,
                            e.message()
                        )));
                    }
                };
                relay::run_pump(local, stream).await
            }
            other => Err(Error::custom(format!(
                "'{}' parses as {:?}, but a transport forwards to host:port or \
                 <subject>/<service>",
                forward_to, other
            ))),
        }
    }

    /// Connect, publish, serve until the session ends, retire, repeat.
    async fn supervise(self: Arc<Self>) {
        let mut backoff = RECONNECT_MIN;
        loop {
            self.set_link_state(LinkState::Connecting);
            match connect_session(&self.ctx, &self.server_address).await {
                Ok((mux, mux_session, session_id)) => {
                    self.session_tx.send_replace(Some(mux.clone()));
                    self.set_link_state(LinkState::Connected { session_id });
                    backoff = RECONNECT_MIN;
                    // Serves carriers for this session's lifetime; returns
                    // when the driver ends, which is the moment the session
                    // died. The accept side and the publish both end here.
                    serve_carriers(self.ctx.clone(), mux_session).await;
                    self.session_tx.send_replace(None);
                    self.set_link_state(LinkState::Backoff {
                        retry_in_secs: backoff.as_secs(),
                        last_error: "hub session ended".to_string(),
                    });
                }
                Err(e) => {
                    self.set_link_state(LinkState::Backoff {
                        retry_in_secs: backoff.as_secs(),
                        last_error: e.message(),
                    });
                    self.ctx
                        .events
                        .warn(Kind::Session, format!("Node: hub session: {}", e.message()));
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RECONNECT_MAX);
        }
    }
}

// endregion: --- Node link

// region:    --- Connecting

/// One handshake with the hub, checked end to end. Returns the multiplexed
/// handle, the accept side, and the session id (which the link publishes as
/// its state, so nothing has to reach into the mux to ask what it is).
async fn connect_session(
    ctx: &NodeContext,
    server_address: &str,
) -> Result<(Mux, MuxSession, u64)> {
    let now = now_secs();
    // Rebuilt per attempt so an expiry is enforced against the clock as it
    // is now: a node that runs longer than its certificate should be able to
    // outlive it is a node that stops re-authenticating.
    let policy = ctx.policy(now);

    let mut rng = TemperEntropy::new()?;
    let session = temper::transport::connect(
        server_address,
        &mut rng,
        &ctx.identity.signing,
        Some(&ctx.certificate),
        &policy,
        &ctx.hub_certificate.concealment.to_public_key(),
    )
    .await
    .map_err(|e| Error::custom(format!("handshake with {} failed: {}", server_address, e)))?;

    let presented = session.peer_identity().certificate.as_deref();
    check_hub_certificate(presented, &ctx.hub_certificate.cert_id)?;
    let presented = presented.expect("checked present above");
    let session_id = session.session_id();
    ctx.events.info(
        Kind::Session,
        format!(
            "Node: session {} with hub '{}' (cert={})",
            session_id, presented.subject_id, presented.cert_id
        ),
    );

    let (tx, rx) = session.split();
    let mux_session = MuxSession::initiator(tx, rx);
    Ok((mux_session.handle(), mux_session, session_id))
}

/// Check the certificate the hub presented is exactly the one `[peer]
/// hub_cert` pinned.
///
/// The handshake's policy already proved the certificate chains to the CA —
/// this is the different question "is this *our* hub". `cert_id` is a digest
/// of the certified content, so equal ids mean equal certificates; no other
/// CA member, however valid, can present the same id.
///
/// Takes the `Option` rather than being called after an unwrap because "no
/// certificate at all" and "a different certificate" are different operator
/// problems — the first is a hub that skipped enrollment, the second a stale
/// or substituted file.
fn check_hub_certificate(presented: Option<&TemperCertificate>, hub_cert_id: &str) -> Result<()> {
    let Some(presented) = presented else {
        return Err(Error::custom(
            "hub presented no certificate; [ca] requires one at every handshake",
        ));
    };
    if presented.cert_id != hub_cert_id {
        return Err(Error::custom(format!(
            "hub presented certificate {} ('{}') but [peer] hub_cert is {}",
            presented.cert_id, presented.subject_id, hub_cert_id
        )));
    }
    Ok(())
}

// endregion: --- Connecting

// region:    --- Peer sessions

/// Establish the nested session to `subject` over a carrier on `hub`.
///
/// The three steps are one function because they are one decision: the
/// certificate authorizes nothing until the handshake proves the peer holds
/// its keys, and the handshake proves nothing about *which* peer it is unless
/// the subject matches what was asked for. Splitting these apart would make
/// it possible to do one without the others.
async fn establish_over(ctx: &NodeContext, hub: &Mux, subject: &str) -> Result<(Mux, u64)> {
    // 1. The peer's certificate, from the hub's directory. The hub saw it at
    // the peer's handshake; verifying it is what turns the hub from an
    // authority into a carrier.
    let mut cert_stream = hub.open(&format!("@cert/{}", subject)).await.map_err(|e| {
        Error::custom(format!(
            "directory lookup for '{}': {}",
            subject,
            e.message()
        ))
    })?;
    let mut bytes = Vec::new();
    tokio::time::timeout(DIRECTORY_TIMEOUT, cert_stream.read_to_end(&mut bytes))
        .await
        .map_err(|_| Error::custom(format!("directory lookup for '{}' timed out", subject)))??;
    let certificate: TemperCertificate = postcard::from_bytes(&bytes)
        .map_err(|e| Error::custom(format!("directory returned a malformed certificate: {}", e)))?;
    ctx.ca.verify(&certificate, now_secs())?;
    if certificate.subject_id != subject {
        return Err(Error::custom(format!(
            "directory returned '{}' when asked for '{}'",
            certificate.subject_id, subject
        )));
    }

    // 2. The carrier: a byte pipe to that peer through the hub.
    let carrier = hub
        .open(&format!("@peer/{}", subject))
        .await
        .map_err(|e| Error::custom(format!("carrier to '{}': {}", subject, e.message())))?;

    // 3. Our own session with the peer, inside the carrier. The concealment
    // key comes from the CA-signed certificate above, so only that peer can
    // answer; the subject check below is what makes it the peer we asked for.
    let now = now_secs();
    let policy = ctx.policy(now);
    let mut rng = TemperEntropy::new()?;
    let session = Session::initiate(
        carrier,
        &mut rng,
        &ctx.identity.signing,
        Some(&ctx.certificate),
        &policy,
        &certificate.concealment.to_public_key(),
    )
    .await
    .map_err(|e| Error::custom(format!("peer session with '{}': {}", subject, e)))?;

    let presented = session.peer_identity().certificate.as_deref();
    match presented {
        Some(cert) if cert.subject_id == subject => {}
        Some(cert) => {
            return Err(Error::custom(format!(
                "peer session presented '{}' when '{}' was asked for",
                cert.subject_id, subject
            )));
        }
        None => {
            return Err(Error::custom(format!(
                "peer '{}' presented no certificate",
                subject
            )));
        }
    }
    let session_id = session.session_id();
    ctx.events.info(
        Kind::Pairing,
        format!("Node: peer session {} with '{}'", session_id, subject),
    );

    let (tx, rx) = session.split();
    // Only the handle is kept: this side opens inner streams and accepts
    // none, so dropping the accept queue is exactly right — an inbound inner
    // stream is refused rather than left hanging.
    Ok((MuxSession::initiator(tx, rx).handle(), session_id))
}

// endregion: --- Peer sessions

// region:    --- Serving

/// Accept carriers on one hub session until it ends.
///
/// Runs for every node, serving or not: a node that serves nothing still
/// refuses inbound carriers with a reason, and the uniform path means the
/// supervisor has exactly one thing to do with a session after publishing it.
async fn serve_carriers(ctx: Arc<NodeContext>, mut mux_session: MuxSession) {
    while let Some(incoming) = mux_session.accept().await {
        if incoming.target() != target::CARRIER_TARGET {
            incoming.refuse("this node accepts carriers only");
            continue;
        }
        // Taken before the spawn so a flood of carriers queues here — where
        // the hub's open for the next one simply waits — instead of spawning
        // an unbounded number of handshakes. Owned (hence the `Arc` and the
        // clone) because the permit lives in the spawned task, not here.
        let ctx = ctx.clone();
        let Ok(permit) = ctx.carriers.clone().acquire_owned().await else {
            return;
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = serve_carrier(&ctx, incoming).await {
                ctx.events.warn(
                    Kind::Pairing,
                    format!("Node: carrier ended: {}", e.message()),
                );
            }
        });
    }
}

/// Run the nested responder half on one carrier, then serve its inner streams.
async fn serve_carrier(ctx: &Arc<NodeContext>, incoming: IncomingStream) -> Result<()> {
    let (_target, stream) = incoming.accept();

    let now = now_secs();
    let policy = ctx.policy(now);
    let config = ResponderConfig {
        keypair: &ctx.identity.signing,
        certificate: Some(&ctx.certificate),
        policy: &policy,
        concealment: &ctx.identity.concealment,
        // No cookie: the carrier already authenticated the *hub* client, and
        // the nested handshake that follows proves the peer for itself. The
        // cookie defends a public listener from anonymous callers; this
        // stream has no anonymous callers.
        cookie: None,
        peer_tag: None,
        now_secs: now,
    };

    let mut rng = TemperEntropy::new()?;
    let mut replay = ctx.replay.lock().await;
    let session = Session::accept(stream, &mut rng, &config, &mut replay).await?;
    drop(replay);

    let peer = session.peer_identity();
    let Some(cert) = peer.certificate.as_deref() else {
        // Unreachable while the policy is `Cert`; the socket still closes.
        return Err(Error::custom("peer presented no certificate"));
    };
    let subject = cert.subject_id.clone();
    ctx.events.info(
        Kind::Pairing,
        format!(
            "Node: peer session {} with '{}'",
            session.session_id(),
            subject
        ),
    );

    let (tx, rx) = session.split();
    let mut mux = MuxSession::responder(tx, rx);
    while let Some(incoming) = mux.accept().await {
        let ctx = ctx.clone();
        let subject = subject.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_service(&ctx, &subject, incoming, |target: String| {
                tokio::net::TcpStream::connect(target)
            })
            .await
            {
                ctx.events
                    .warn(Kind::Refusal, format!("Node: {}", e.message()));
            }
        });
    }
    Ok(())
}

/// Answer one inner stream: is this a service, is this peer allowed to use
/// it, then dial and pump.
///
/// Generic over the dialer for the same reason the hub's branch is: "refused
/// without dialing" must be provable, and a closed port cannot prove it. The
/// refusal tests hand this a dialer that panics.
async fn serve_service<U, F, Fut>(
    ctx: &NodeContext,
    peer_subject: &str,
    incoming: IncomingStream,
    dial: F,
) -> Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(String) -> Fut + Send,
    Fut: std::future::Future<Output = std::io::Result<U>> + Send,
{
    let service_name = incoming.target().to_string();

    let Some(service) = ctx.services.get(&service_name) else {
        let reason = format!("'{}' does not serve '{}'", ctx.identity.name, service_name);
        incoming.refuse(&reason);
        return Err(Error::custom(reason));
    };

    // The allow-list is checked against the *nested* handshake's peer, so it
    // holds even if the hub lies about who is behind the carrier: the proof
    // travelled end to end.
    if !service
        .clients
        .iter()
        .any(|allowed| allowed == peer_subject)
    {
        let reason = format!(
            "'{}' does not permit '{}' to use '{}'",
            ctx.identity.name, peer_subject, service_name
        );
        incoming.refuse(&reason);
        return Err(Error::custom(reason));
    }

    match dial(service.target.clone()).await {
        Ok(upstream) => {
            ctx.events.info(
                Kind::Session,
                format!("Node: serving '{}' to '{}'", service_name, peer_subject),
            );
            let (_target, stream) = incoming.accept();
            relay::run_pump(upstream, stream).await
        }
        Err(e) => {
            let reason = e.to_string();
            incoming.refuse(&reason);
            Err(Error::custom(format!(
                "cannot connect to {}: {}",
                service.target, reason
            )))
        }
    }
}

// endregion: --- Serving

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PeerRegistry;
    use crate::relay::{MessageRx, MessageTx, RelayMessage};
    use crate::testutil::Fleet;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    // region: --- Hub certificate pin

    /// A second CA member — valid in every way — is still the wrong hub.
    #[test]
    fn a_different_ca_members_certificate_is_not_our_hub() {
        let fleet = Fleet::new("pin");
        let (_, ours) = fleet.enroll("pin-ours.example");
        let (_, theirs) = fleet.enroll("pin-theirs.example");

        // Positive control: the certificate we pinned passes.
        check_hub_certificate(Some(&ours), &ours.cert_id).unwrap();

        let err = check_hub_certificate(Some(&theirs), &ours.cert_id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("hub_cert"), "error was: {}", err);
        assert!(err.contains(&theirs.cert_id), "error was: {}", err);
    }

    /// "No certificate" is its own message, not an unwrap panic.
    #[test]
    fn a_hub_with_no_certificate_is_reported() {
        let fleet = Fleet::new("pin-none");
        let (_, ours) = fleet.enroll("pin-none.example");
        let err = check_hub_certificate(None, &ours.cert_id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no certificate"), "error was: {}", err);
    }

    // endregion: --- Hub certificate pin

    // region: --- Test relay

    /// In-memory sessions, crossed so what one side sends the other receives.
    /// The node tests drive whole carriers through these: the mux is real,
    /// the nested Temper handshakes on top are real, only TCP is absent —
    /// except where the test deliberately uses a loopback listener.
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
        (
            MuxSession::initiator(ChanTx(a_tx), ChanRx(b_rx)),
            MuxSession::responder(ChanTx(b_tx), ChanRx(a_rx)),
        )
    }

    /// The hub's two peer branches, reduced to what the node test needs: the
    /// directory hands back the registered certificate, and a carrier is
    /// opened on the peer's session and spliced. The grant checks and the
    /// refusal paths are relay.rs's tests; this is the byte path the peers
    /// depend on.
    async fn relay_carriers(mut hub_side: MuxSession, registry: Arc<PeerRegistry>) {
        while let Some(incoming) = hub_side.accept().await {
            match target::parse(incoming.target()).unwrap() {
                Target::Carrier { subject } => {
                    let Some((peer_mux, _cert)) = registry.get(&subject) else {
                        incoming.refuse("not connected");
                        continue;
                    };
                    let peer_stream = peer_mux.open(target::CARRIER_TARGET).await.unwrap();
                    let (_target, stream) = incoming.accept();
                    relay::run_pair(stream, peer_stream).await.unwrap();
                }
                Target::Directory { subject } => {
                    let Some((_mux, certificate)) = registry.get(&subject) else {
                        incoming.refuse("not connected");
                        continue;
                    };
                    let bytes = postcard::to_allocvec(&certificate).unwrap();
                    let (_target, mut stream) = incoming.accept();
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
                _ => incoming.refuse("not a carrier"),
            }
        }
    }

    /// An echo server on loopback — the "service" the serving node dials,
    /// reached over real TCP so the last hop of the path is real too.
    async fn echo_server() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        addr
    }

    fn context(
        fleet: &Fleet,
        name: &str,
        services: BTreeMap<String, ServiceConfig>,
    ) -> (Arc<NodeContext>, TemperCertificate) {
        let (identity, certificate) = fleet.enroll(name);
        let (_, hub_certificate) = fleet.enroll(&format!("hub-for-{}", name));
        let ctx = NodeContext::new(
            identity,
            certificate.clone(),
            fleet.ca.clone(),
            hub_certificate,
            services,
            crate::events::EventLog::quiet(),
        )
        .unwrap();
        (Arc::new(ctx), certificate)
    }

    /// The whole path, with every layer real: directory lookup, CA
    /// verification, carrier through a hub splice, nested Temper session,
    /// service allow-list, inner mux, and TCP to the service. One nested
    /// handshake serves all three assertions — allowed, not permitted,
    /// unknown service — because they are three opens on the same session.
    #[tokio::test]
    async fn a_peer_reaches_a_service_through_the_hub() {
        let fleet = Fleet::new("through-hub");
        let echo = echo_server().await;

        let web = ServiceConfig {
            name: "web".to_string(),
            target: echo.to_string(),
            clients: vec!["node-a.example".to_string()],
        };
        let db = ServiceConfig {
            name: "db".to_string(),
            target: echo.to_string(),
            clients: vec!["someone-else.example".to_string()],
        };
        let (ctx_a, _cert_a) = context(&fleet, "node-a.example", BTreeMap::new());
        let (ctx_b, cert_b) = context(
            &fleet,
            "node-b.example",
            BTreeMap::from([("web".to_string(), web), ("db".to_string(), db)]),
        );

        // A's session to the hub, and B's, with the hub's view of each.
        let (a_node, a_hub) = pair();
        let (b_node, b_hub) = pair();
        let registry = Arc::new(PeerRegistry::new());
        registry.insert("node-b.example", 1, 0, cert_b, b_hub.handle());
        tokio::spawn(relay_carriers(a_hub, registry));
        tokio::spawn(serve_carriers(ctx_b, b_node));

        // The node's side of the whole exchange: everything it knows about
        // the hub is this mux handle.
        let hub_mux = a_node.handle();
        let (peer_mux, _peer_session_id) = establish_over(&ctx_a, &hub_mux, "node-b.example")
            .await
            .expect("peer session establishes");

        // Allowed: bytes go there and back, through the nested session.
        let mut stream = peer_mux.open("web").await.expect("web is served");
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.shutdown().await.unwrap();
        drop(stream);

        // Not permitted: the refusal names the peer and the service, and the
        // same live session is still usable afterwards.
        let err = peer_mux
            .open("db")
            .await
            .err()
            .expect("db is refused")
            .message();
        assert!(err.contains("does not permit"), "error was: {}", err);
        assert!(err.contains("node-a.example"), "error was: {}", err);

        // Unknown: a service this node does not have, same session again.
        let err = peer_mux
            .open("nope")
            .await
            .err()
            .expect("nope is refused")
            .message();
        assert!(err.contains("does not serve"), "error was: {}", err);
    }

    // endregion: --- Test relay

    // region: --- Service refusals

    /// A service refusal reaches the dialing peer with its reason and never
    /// dials: the dialer below panics, so a refusal that connects first is a
    /// test failure rather than a slower refusal.
    #[tokio::test]
    async fn a_refused_service_is_named_and_never_dialed() {
        async fn never_dial(_target: String) -> std::io::Result<tokio::io::DuplexStream> {
            unreachable!("a refused service must never reach the dialer")
        }

        let fleet = Fleet::new("refuse-service");
        let (ctx_b, _cert_b) = context(
            &fleet,
            "node-b.example",
            BTreeMap::from([(
                "db".to_string(),
                ServiceConfig {
                    name: "db".to_string(),
                    target: "127.0.0.1:1".to_string(),
                    clients: vec!["someone-else.example".to_string()],
                },
            )]),
        );

        // Two sides of one session: the peer dials "db", the serving node
        // accepts the stream and must refuse it without reaching its dialer.
        let (dialer_session, mut serving_session) = pair();
        let dialer = dialer_session.handle();
        let opened = tokio::spawn(async move { dialer.open("db").await });
        let incoming = serving_session.accept().await.expect("inbound stream");

        let err = serve_service(&ctx_b, "node-a.example", incoming, never_dial)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not permit"), "error was: {}", err);

        let refused = opened.await.unwrap().err().expect("refused").message();
        assert!(
            refused.contains("does not permit"),
            "error was: {}",
            refused
        );
        assert!(refused.contains("node-a.example"), "error was: {}", refused);
    }

    // endregion: --- Service refusals
}

// endregion: --- Tests
