//! # Network transport — the session protocol over length-prefixed frames
//!
//! Framing:
//!
//! ```text
//! [ u32 little-endian length | postcard payload ]
//! ```
//!
//! implemented over tokio's `LengthDelimitedCodec` — the codec writes and
//! parses the 4-byte little-endian length field.
//!
//! # Protocol
//!
//! 1. [`connect`] dials TCP and runs the initiator half of the session
//!    protocol; [`Listener::accept`] answers with the responder half. The
//!    three flights ([`SessionInit`], [`SessionAccept`], [`SessionConfirm`])
//!    travel as ordinary frames — the identities inside them sealed, and every
//!    flight bound by the transcript signatures and confirm MACs (see
//!    [`crate::session`] and `PROTOCOL.md`).
//! 2. Every [`Session::send`] / [`Session::recv`] afterwards is one AEAD
//!    record per frame, sealed under the direction's record key — there is
//!    no plaintext mode once the session exists.
//!
//! A responder that requires an anti-DoS cookie interposes a flight 0
//! ([`SessionChallenge`]); [`Session::initiate`] handles that exchange itself,
//! and [`Listener::accept`] issues the cookie when its [`ResponderConfig`]
//! carries one.
//!
//! # Security boundary
//!
//! After the handshake: confidentiality and integrity (ChaCha20-Poly1305,
//! counter nonces — replay and reorder rejected), mutual authentication
//! (dual PQC transcript signatures, [`PeerPolicy`]), forward secrecy, and
//! concealment of both identities from a passive observer.
//!
//! Not provided here: rekeying, anonymity *from the peer* (mutual
//! authentication requires each side to learn who it talks to), and forward
//! secrecy of flight 1's identity seal, which is bound to the responder's
//! static concealment key. `PROTOCOL.md` carries the full list and what the
//! caller owns.
//!
//! # Feature
//!
//! Compiled only with the `transport` feature, which implies `std` (tokio is
//! std-only); every no_std configuration of this crate is untouched.

#![cfg(feature = "transport")]

use alloc::string::ToString;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::ca::TemperCertificate;
use crate::entropy::TemperEntropy;
use crate::envelope::{ConcealmentKeypair, ConcealmentPublicKey};
use crate::error::{Error, Result};
use crate::record::{RecordKey, RecordKeys};
use crate::replay::SessionReplayGuard;
use crate::seal::TemperKeypair;
use crate::session::{
	CookieContext, PROTOCOL_VERSION, PeerIdentity, PeerPolicy, SessionAccept, SessionChallenge, SessionConfirm,
	SessionInit, peek_version,
};
use crate::session_cookie::SessionCookie;

// region:    --- Framing

/// Largest accepted payload. A peer that declares a longer frame is rejected
/// by the codec with `InvalidData` before any body bytes are buffered.
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

/// The exact framing: `[u32 little-endian length][payload]`.
///
/// `LengthDelimitedCodec` defaults to a big-endian length field, so
/// `little_endian` is load-bearing: two peers compiled with different
/// settings still round-trip happily between themselves (each writes what it
/// expects to read) and fail only against the other implementation. The
/// byte-level test below pins this.
fn frame_codec() -> LengthDelimitedCodec {
	LengthDelimitedCodec::builder()
		.length_field_length(4)
		.little_endian()
		.max_frame_length(MAX_FRAME_LEN)
		.new_codec()
}

fn encode_message<M: Serialize>(message: &M) -> Result<Bytes> {
	let payload = postcard::to_allocvec(message).map_err(|e| Error::Serialization(e.to_string()))?;
	Ok(Bytes::from(payload))
}

fn decode_message<M: DeserializeOwned>(frame: &[u8]) -> Result<M> {
	postcard::from_bytes(frame).map_err(|e| Error::Serialization(e.to_string()))
}

/// Await the next frame. `Ok(None)` means the peer closed the connection
/// cleanly at a frame boundary.
async fn next_frame<S>(framed: &mut Framed<S, LengthDelimitedCodec>) -> Result<Option<Bytes>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	match framed.next().await {
		Some(Ok(frame)) => Ok(Some(frame.into())),
		Some(Err(err)) => Err(err.into()),
		None => Ok(None),
	}
}

// endregion: --- Framing

// region:    --- Session

/// An established connection: the three flights are done, both sides hold
/// the record keys, and each [`Session::send`] / [`Session::recv`] moves one
/// encrypted frame.
///
/// Generic over the byte stream so the session can run over anything
/// `AsyncRead + AsyncWrite` — TCP via [`connect`] and [`Listener`], or any
/// stream a consumer supplies directly (a duplex pipe, a TLS wrapper).
///
/// Deliberately not `Debug`: the derived output would print key material.
pub struct Session<S> {
	framed: Framed<S, LengthDelimitedCodec>,
	record: RecordKeys,
	peer: PeerIdentity,
	session_id: u64,
}

impl<S> Session<S>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	/// Run the three flights as the initiator over an established stream.
	///
	/// `rng` is caller-supplied (a seeded source makes the whole handshake
	/// reproducible in tests); `policy` decides which responder identities are
	/// acceptable. `responder_concealment` is the responder's published
	/// concealment key — the one piece of long-term material a client must know
	/// before it can hide anything, fetched out of band (a pinned config, a
	/// directory, a certificate).
	///
	/// The cookie is handled here rather than by the caller: flight 1 goes out
	/// carrying the all-zero placeholder, and if the responder wants a cookie
	/// it answers with a [`SessionChallenge`]; this then discards the first,
	/// unauthenticated flight, starts a **fresh** one carrying the cookie, and
	/// continues. A fresh flight, not a patched one, because the first flight's
	/// ephemeral keys and blinded id were already sent in the clear and there
	/// is nothing worth preserving from them.
	///
	/// Exactly one challenge round is permitted. A responder that challenges
	/// twice is not making progress, and looping on it would hand an attacker
	/// a traffic amplifier with the client as the amplifier.
	pub async fn initiate(
		io: S,
		rng: &mut TemperEntropy,
		keypair: &TemperKeypair,
		certificate: Option<&TemperCertificate>,
		policy: &PeerPolicy,
		responder_concealment: &ConcealmentPublicKey,
	) -> Result<Self> {
		let mut framed = Framed::new(io, frame_codec());
		let mut cookie = [0u8; 32];

		for attempt in 0..=1 {
			let (init, state) = crate::session::initiate(rng, keypair, certificate, responder_concealment, cookie)?;
			framed.send(encode_message(&init)?).await?;

			let reply = match next_frame(&mut framed).await? {
				Some(frame) => frame,
				None => return Err(handshake_eof()),
			};

			match decode_accept_reply(&reply)? {
				AcceptReply::Challenge(challenge) => {
					if attempt == 1 {
						return Err(Error::Protocol(
							"responder issued a second cookie challenge; refusing to loop".into(),
						));
					}
					if challenge.version != PROTOCOL_VERSION {
						return Err(unsupported_version(challenge.version));
					}
					cookie = challenge.cookie;
				}
				AcceptReply::Accept(accept) => {
					let (confirm, secrets) = crate::session::finalize_initiator(rng, &init, &accept, &state, policy)?;
					framed.send(encode_message(&confirm)?).await?;

					return Ok(Self {
						framed,
						record: secrets.record,
						peer: secrets.peer,
						session_id: secrets.session_id,
					});
				}
			}
		}

		// The loop returns on every path that completes; this is the type
		// system's share of the work, not a reachable state.
		Err(Error::Protocol("session cookie challenge did not resolve".into()))
	}

	/// Run the three flights as the responder over an accepted stream.
	///
	/// `replay` is consulted as soon as flight 1 is decoded — before flight 2
	/// is computed, which is the expensive half — so a replayed handshake is
	/// refused without the two SLH-DSA signatures it would otherwise cost.
	/// `config.now_secs` only has to be monotonic and in seconds; a counter
	/// since process start is as good as a wall clock, and this crate has no
	/// clock of its own. See [`SessionReplayGuard`] for what the guard defends.
	///
	/// A cookie is only a defence if the tag it is bound to is one the peer
	/// cannot choose, so this fails closed when `config.cookie` is set without
	/// a `peer_tag`, rather than issuing a value anyone can mint.
	pub async fn accept(
		io: S,
		rng: &mut TemperEntropy,
		config: &ResponderConfig<'_>,
		replay: &mut SessionReplayGuard,
	) -> Result<Self> {
		let mut framed = Framed::new(io, frame_codec());
		let first = match next_frame(&mut framed).await? {
			Some(frame) => frame,
			None => return Err(handshake_eof()),
		};

		let version = peek_version(&first)?;
		if version != PROTOCOL_VERSION {
			return Err(unsupported_version(version));
		}

		let cookie_pair = match (config.cookie, config.peer_tag.as_ref()) {
			(Some(cookie), Some(peer_tag)) => Some((cookie, peer_tag)),
			(Some(_), None) => {
				return Err(Error::Protocol(
					"anti-DoS cookie enabled without a trustworthy peer tag".into(),
				));
			}
			(None, _) => None,
		};

		let mut init: SessionInit = decode_message(&first)?;

		if let Some((cookie, peer_tag)) = cookie_pair
			&& !cookie.verify(&init.cookie, peer_tag, config.now_secs)
		{
			// The cheap refusal: one hash and 33 bytes, in place of the
			// decapsulation and two SLH-DSA signatures flight 2 costs.
			let challenge = SessionChallenge {
				version: PROTOCOL_VERSION,
				cookie: cookie.issue(peer_tag, config.now_secs),
			};
			framed.send(encode_message(&challenge)?).await?;

			let second = match next_frame(&mut framed).await? {
				Some(frame) => frame,
				None => return Err(handshake_eof()),
			};
			if peek_version(&second)? != PROTOCOL_VERSION {
				return Err(Error::Protocol(
					"initiator changed protocol version across the cookie challenge".into(),
				));
			}
			init = decode_message(&second)?;
		}

		replay.admit(init.proposal.session_id, config.now_secs)?;

		// `session::accept` re-verifies the cookie as the authoritative gate;
		// the check above only decides whether to ask first.
		let ctx = cookie_pair.map(|(cookie, peer_tag)| CookieContext {
			cookie,
			peer_tag,
			now_secs: config.now_secs,
		});
		let (accept, state) = crate::session::accept(
			rng,
			&init,
			config.keypair,
			config.certificate,
			config.concealment,
			config.policy,
			ctx,
		)?;
		framed.send(encode_message(&accept)?).await?;

		let confirm: SessionConfirm = match next_frame(&mut framed).await? {
			Some(frame) => decode_message(&frame)?,
			None => return Err(handshake_eof()),
		};
		let secrets = crate::session::finalize_responder(&init, &accept, &confirm, &state, config.policy)?;

		Ok(Self {
			framed,
			record: secrets.record,
			peer: secrets.peer,
			session_id: secrets.session_id,
		})
	}

	/// Send one message: postcard-encoded, then sealed as a single AEAD
	/// record.
	pub async fn send<M: Serialize>(&mut self, message: &M) -> Result<()> {
		let payload = encode_message(message)?;
		let record = self.record.send().seal(&payload)?;
		self.framed.send(Bytes::from(record)).await?;
		Ok(())
	}

	/// Receive one message: an AEAD record opened at the strict receive
	/// counter, then postcard-decoded. `Ok(None)` means the peer closed the
	/// connection cleanly at a frame boundary.
	pub async fn recv<M: DeserializeOwned>(&mut self) -> Result<Option<M>> {
		match next_frame(&mut self.framed).await? {
			Some(frame) => {
				let plaintext = self.record.recv().open(&frame)?;
				decode_message(&plaintext).map(Some)
			}
			None => Ok(None),
		}
	}

	/// The authenticated peer identity, as accepted by the policy.
	pub fn peer_identity(&self) -> &PeerIdentity {
		&self.peer
	}

	/// The session id (echoed from the initiator's proposal).
	pub fn session_id(&self) -> u64 {
		self.session_id
	}

	/// Borrow the underlying stream (e.g. `TcpStream::peer_addr`).
	pub fn get_ref(&self) -> &S {
		self.framed.get_ref()
	}

	/// Split into the sending and receiving halves, to drive them from two
	/// tasks.
	///
	/// The relay shape — read from one stream, write to another, in both
	/// directions at once — cannot use [`Session::send`] and [`Session::recv`],
	/// because each needs `&mut self` and a `select!` over both borrows the
	/// session twice. The record layer was already split-ready
	/// ([`RecordKeys::into_keys`]); this exposes the same split for the
	/// framing, so a relay gets two halves that borrow nothing of each other.
	///
	/// The replay window and the record counters are per-half and unchanged:
	/// the halves are the same session, not two sessions.
	pub fn split(self) -> (SessionTx<S>, SessionRx<S>) {
		let Self { framed, record, .. } = self;
		let (sink, stream) = framed.split();
		let (tx, rx) = record.into_keys();
		(SessionTx { sink, record: tx }, SessionRx { stream, record: rx })
	}
}

/// The sending half of a [`Session`].
///
/// Deliberately not `Debug`: the derived output would print key material.
pub struct SessionTx<S> {
	sink: futures_util::stream::SplitSink<Framed<S, LengthDelimitedCodec>, Bytes>,
	record: RecordKey,
}

impl<S> SessionTx<S>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	/// Send one message: postcard-encoded, then sealed as a single AEAD record.
	pub async fn send<M: Serialize>(&mut self, message: &M) -> Result<()> {
		let payload = encode_message(message)?;
		let record = self.record.seal(&payload)?;
		self.sink.send(Bytes::from(record)).await?;
		Ok(())
	}

	/// Close the writing direction. The receiving half stays usable.
	pub async fn close(&mut self) -> Result<()> {
		self.sink.close().await?;
		Ok(())
	}
}

/// The receiving half of a [`Session`].
///
/// Deliberately not `Debug`: the derived output would print key material.
pub struct SessionRx<S> {
	stream: futures_util::stream::SplitStream<Framed<S, LengthDelimitedCodec>>,
	record: RecordKey,
}

impl<S> SessionRx<S>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	/// Receive one message. `Ok(None)` means the peer closed the connection
	/// cleanly at a frame boundary.
	pub async fn recv<M: DeserializeOwned>(&mut self) -> Result<Option<M>> {
		match self.stream.next().await {
			Some(Ok(frame)) => {
				let plaintext = self.record.open(&frame)?;
				decode_message(&plaintext).map(Some)
			}
			Some(Err(err)) => Err(err.into()),
			None => Ok(None),
		}
	}
}

/// A clean close where the handshake still owed us a message: the peer went
/// away mid-flights. That is a protocol failure, not `Ok(None)`.
fn handshake_eof() -> Error {
	std::io::Error::new(
		std::io::ErrorKind::UnexpectedEof,
		"peer closed during the session handshake",
	)
	.into()
}

/// The one wording for "this build does not speak that version", shared by the
/// responder dispatch and the client's challenge handling so a peer cannot tell
/// which side of the connection noticed.
fn unsupported_version(version: u16) -> Error {
	Error::Protocol(alloc::format!(
		"unsupported session protocol version {} (this build speaks {})",
		version,
		PROTOCOL_VERSION
	))
}

// endregion: --- Session

// region:    --- Responder configuration

/// Everything the responder half needs.
///
/// `concealment` is required rather than optional: an initiator's identity
/// arrives sealed to that key, and there is nothing else to open it with.
///
/// `Copy`, so a caller (such as [`Listener::accept`]) can take one and amend a
/// field without disturbing the original. Deliberately not `Debug`: it holds
/// long-term secret keys, and this crate's other secret-bearing types are not
/// `Debug` either.
#[derive(Clone, Copy)]
pub struct ResponderConfig<'a> {
	/// The responder's long-term signing identity.
	pub keypair: &'a TemperKeypair,
	/// A certificate to present beside that identity, if the peer's policy
	/// wants one.
	pub certificate: Option<&'a TemperCertificate>,
	/// Which initiator identities are acceptable.
	pub policy: &'a PeerPolicy,
	/// The keypair that opens an initiator's sealed identity.
	pub concealment: &'a ConcealmentKeypair,
	/// Stateless anti-DoS cookie state. `None` accepts the all-zero cookie a
	/// client sends when no responder ever asked it for one.
	pub cookie: Option<&'a SessionCookie>,
	/// A stable, carrier-supplied tag for the peer, bound into the cookie.
	///
	/// Required whenever `cookie` is set. A cookie is only worth as much as
	/// the tag's integrity: on a carrier where the peer can choose its own tag
	/// (anything spoofable) the attacker simply presents its own, and the
	/// check is ceremony. [`peer_tag_from_addr`] derives one from a connected
	/// socket address.
	pub peer_tag: Option<[u8; 32]>,
	/// The caller's monotonic seconds — the same convention as the replay
	/// guard, and the same clock that drives cookie rotation.
	pub now_secs: u64,
}

/// A cookie tag derived from a connected peer's address.
///
/// Binds to IP **and** port. A TCP connection's peer address cannot change
/// under it, so a cookie issued during the handshake remains valid for that
/// handshake — and a value captured from someone else's connection does not
/// verify, because redeeming it would require holding that address.
///
/// The security of this rests entirely on the source address being
/// unforgeable, which is true of a `connect`ed TCP socket and false of a
/// datagram carrier. Do not build a tag this way for UDP.
pub fn peer_tag_from_addr(addr: std::net::SocketAddr) -> [u8; 32] {
	let mut hasher = blake3::Hasher::new();
	hasher.update(b"Temper.Transport.PeerTag");
	match addr.ip() {
		std::net::IpAddr::V4(ip) => {
			hasher.update(&[4]);
			hasher.update(&ip.octets());
		}
		std::net::IpAddr::V6(ip) => {
			hasher.update(&[6]);
			hasher.update(&ip.octets());
		}
	}
	hasher.update(&addr.port().to_le_bytes());
	*hasher.finalize().as_bytes()
}

/// What the initiator may find waiting after flight 1.
enum AcceptReply {
	/// A cookie is required; resend flight 1 carrying it.
	Challenge(SessionChallenge),
	/// Flight 2.
	Accept(SessionAccept),
}

/// Decode whichever of the two the responder sent.
///
/// Unambiguous without a discriminator: postcard rejects trailing bytes, and
/// these types are 33 bytes (a varint version plus the 32-byte cookie) and
/// several kilobytes respectively, so a frame that parses as one cannot parse
/// as the other.
fn decode_accept_reply(frame: &[u8]) -> Result<AcceptReply> {
	if let Ok(challenge) = postcard::from_bytes::<SessionChallenge>(frame) {
		return Ok(AcceptReply::Challenge(challenge));
	}
	Ok(AcceptReply::Accept(decode_message(frame)?))
}

// endregion: --- Responder configuration

// region:    --- Client

/// Dial `addr` and complete the three flights as the initiator, concealing both
/// identities from a passive observer.
///
/// `responder_concealment` is the responder's published concealment key — the
/// one piece of long-term material a client must know before it can hide
/// anything, fetched out of band (a pinned config, a directory, a certificate).
pub async fn connect(
	addr: impl ToSocketAddrs,
	rng: &mut TemperEntropy,
	keypair: &TemperKeypair,
	certificate: Option<&TemperCertificate>,
	policy: &PeerPolicy,
	responder_concealment: &ConcealmentPublicKey,
) -> Result<Session<TcpStream>> {
	let stream = TcpStream::connect(addr).await?;
	Session::initiate(stream, rng, keypair, certificate, policy, responder_concealment).await
}

// endregion: --- Client

// region:    --- Server

/// Seconds a listener remembers an accepted session id, unless told
/// otherwise. Long enough to cover a replay of a handshake that is still
/// interesting, short enough that the table turns over.
pub const DEFAULT_REPLAY_TTL_SECS: u64 = 60;

/// A bound TCP listener; [`Listener::accept`] runs the responder half of the
/// session protocol on each connection, with the per-connection identity,
/// certificate, and policy the caller supplies.
///
/// The listener owns the [`SessionReplayGuard`] the responder half needs: a
/// listener is exactly the long-lived thing that has somewhere to keep it.
pub struct Listener {
	inner: TcpListener,
	guard: SessionReplayGuard,
}

impl Listener {
	/// Bind to `addr`, with a default replay guard.
	pub async fn bind(addr: impl ToSocketAddrs) -> Result<Self> {
		Self::bind_with_replay(addr, DEFAULT_REPLAY_TTL_SECS, crate::replay::DEFAULT_REPLAY_CAPACITY).await
	}

	/// Bind to `addr` with an explicit replay window.
	///
	/// Size the capacity to the peak accept rate times `ttl_secs`; a table
	/// too small for that is one that drops entries early and forgets
	/// sessions it should still refuse. See [`SessionReplayGuard`].
	pub async fn bind_with_replay(addr: impl ToSocketAddrs, ttl_secs: u64, capacity: usize) -> Result<Self> {
		let inner = TcpListener::bind(addr).await?;
		Ok(Self {
			inner,
			guard: SessionReplayGuard::new(ttl_secs, capacity)?,
		})
	}

	/// The bound address — how a caller learns the port when binding port 0.
	pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
		Ok(self.inner.local_addr()?)
	}

	/// The listener's replay guard, for a caller that wants to ask whether an
	/// id has been seen or to clear the window.
	pub fn replay_guard(&self) -> &SessionReplayGuard {
		&self.guard
	}

	/// Accept one connection and complete the three flights as the responder.
	///
	/// The listener derives `config.peer_tag` from the accepted connection's
	/// peer address, overwriting whatever the caller passed: the listener is
	/// the only party that can see the address the peer is actually reachable
	/// at, so deriving it here is strictly better than trusting the caller's
	/// copy. A caller that has a better tag than "the address it connected
	/// from" should call [`Session::accept`] directly.
	pub async fn accept(
		&mut self,
		rng: &mut TemperEntropy,
		config: &ResponderConfig<'_>,
	) -> Result<Session<TcpStream>> {
		let (stream, peer) = self.inner.accept().await?;
		let mut config = *config;
		config.peer_tag = Some(peer_tag_from_addr(peer));
		Session::accept(stream, rng, &config, &mut self.guard).await
	}
}

// endregion: --- Server

// region:    --- Tests

#[cfg(test)]
mod tests {
	use super::*;
	use crate::seal::generate_keypair;
	use alloc::boxed::Box;
	use alloc::string::{String, ToString};
	use serde::{Deserialize, Serialize};
	use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

	/// Tests collapse foreign errors (tokio, postcard) into one boxed type;
	/// temper's own `Error` stays unshadowed for the tamper assertions.
	type TestResult<T> = core::result::Result<T, Box<dyn core::error::Error>>;

	// region: --- Framing (unchanged by the session rework)

	/// Byte-level: not a round-trip (a big-endian codec round-trips perfectly
	/// against itself), the frame is read raw and compared to the spec.
	#[tokio::test]
	async fn test_transport_frame_codec_writes_little_endian_prefix() -> TestResult<()> {
		// -- Setup & Fixtures
		let (io, mut raw) = duplex(4096);
		let mut framed = Framed::new(io, frame_codec());
		let message = fixture_message(1, "hello");
		let payload = postcard::to_allocvec(&message)?;

		// -- Exec
		framed.send(Bytes::from(payload.clone())).await?;

		// -- Check
		let mut header = [0u8; 4];
		raw.read_exact(&mut header).await?;
		assert_eq!(u32::from_le_bytes(header) as usize, payload.len());
		// Negative control: the payload is short, so its LE and BE encodings
		// differ — a codec flipped to the tokio default (big-endian) would
		// fail the assertion above, and cannot pass this one.
		assert_ne!(header, (payload.len() as u32).to_be_bytes());
		let mut body = alloc::vec![0u8; payload.len()];
		raw.read_exact(&mut body).await?;
		assert_eq!(body, payload);
		Ok(())
	}

	/// The read direction against the spec: bytes are assembled by hand
	/// (`[u32 LE][payload]`) and decoded with stock postcard, not with this
	/// module's own helpers.
	#[tokio::test]
	async fn test_transport_frame_codec_reads_hand_assembled_frame() -> TestResult<()> {
		// -- Setup & Fixtures
		let (io, mut raw) = duplex(4096);
		let mut framed = Framed::new(io, frame_codec());
		let message = fixture_message(7, "from the wire");
		let payload = postcard::to_allocvec(&message)?;

		// -- Exec
		raw.write_all(&(payload.len() as u32).to_le_bytes()).await?;
		raw.write_all(&payload).await?;
		let frame = framed.next().await.ok_or("clean close, expected a frame")??;
		let decoded: TestMessage = postcard::from_bytes(&frame)?;

		// -- Check
		assert_eq!(decoded, message);
		Ok(())
	}

	#[tokio::test]
	async fn test_transport_frame_codec_rejects_oversized_frame() -> TestResult<()> {
		// -- Setup & Fixtures
		let (io, mut raw) = duplex(64);
		let mut framed = Framed::new(io, frame_codec());

		// -- Exec
		raw.write_all(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes()).await?;
		let next = framed.next().await;

		// -- Check: rejected on the declared length, before any body arrives.
		match next {
			Some(Err(err)) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidData),
			other => return Err(alloc::format!("expected InvalidData, got {:?}", other).into()),
		}
		Ok(())
	}

	// endregion: --- Framing (unchanged by the session rework)

	// region: --- Session over TCP

	#[tokio::test]
	async fn test_transport_session_recv_closed_connection_is_none() -> TestResult<()> {
		// -- Setup & Fixtures
		let mut listener = Listener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let (mut c_rng, mut s_rng, client_kp, server_kp) = fixtures();
		let concealment = concealment_keypair()?;
		let responder_concealment = concealment.public();
		let config = config_for(&server_kp, &concealment);
		let (client, server) = tokio::join!(
			connect(
				addr,
				&mut c_rng,
				&client_kp,
				None,
				&PeerPolicy::AcceptAny,
				&responder_concealment
			),
			listener.accept(&mut s_rng, &config),
		);
		let (client, mut server) = (client?, server?);

		// -- Exec
		drop(client);
		let received: Option<TestMessage> = server.recv().await?;

		// -- Check
		assert!(received.is_none(), "a clean close must surface as Ok(None)");
		Ok(())
	}

	#[tokio::test]
	async fn test_transport_replayed_flight_one_is_refused_by_the_guard() -> TestResult<()> {
		// -- Setup & Fixtures: one genuine flight 1, captured as bytes.
		let mut c_rng = TemperEntropy::from_seed([0xD1; 32]);
		let mut s_rng = TemperEntropy::from_seed([0xD2; 32]);
		let client_kp = generate_keypair(&mut c_rng, "client@example").expect("keygen");
		let server_kp = generate_keypair(&mut s_rng, "server@example").expect("keygen");
		let concealment = concealment_keypair()?;
		let (init, _state) = crate::session::initiate(&mut c_rng, &client_kp, None, &concealment.public(), [0u8; 32])?;
		let id = init.proposal.session_id;
		let flight_one = encode_message(&init)?;

		let config = config_for(&server_kp, &concealment);
		// One guard across both connections: the second is only a replay
		// because the first was seen.
		let mut guard = replay_guard();

		// -- Exec: deliver the same flight 1 twice.
		let (io_i, io_r) = duplex(256 * 1024);
		let mut raw = Framed::new(io_i, frame_codec());
		raw.send(flight_one.clone()).await?;
		drop(raw); // the peer vanishes after flight 1 — no flight 3 will come
		let first = Session::accept(io_r, &mut s_rng, &config, &mut guard).await;

		let (io_i2, io_r2) = duplex(256 * 1024);
		let mut raw2 = Framed::new(io_i2, frame_codec());
		raw2.send(flight_one).await?;
		// Closed after flight 1 as well, so a responder that does *not*
		// refuse the replay fails on the missing flight 3 and returns,
		// rather than waiting for it forever. Without this the test would
		// hang instead of going red, which is a much worse failure mode to
		// leave in a suite.
		drop(raw2);
		let second = Session::accept(io_r2, &mut s_rng, &config, &mut guard).await;

		// -- Check: the first reached the flights and failed on EOF; the
		// second never got that far.
		assert!(first.is_err(), "an abandoned handshake must not succeed");
		assert!(guard.is_replay(id), "the first accept admitted the id");
		match second {
			Err(Error::Protocol(msg)) => assert!(msg.contains("replayed session id"), "got: {msg}"),
			Err(other) => panic!("expected the replay refusal, got {other:?}"),
			Ok(_) => panic!("the replayed handshake was accepted"),
		}
		Ok(())
	}

	// endregion: --- Session over TCP

	#[tokio::test]
	async fn test_transport_establishes_and_round_trips_encrypted() -> TestResult<()> {
		// -- Setup & Fixtures
		let (io_i, io_r) = duplex(256 * 1024);
		let (mut c_rng, mut s_rng, client_kp, server_kp) = fixtures();
		let concealment = concealment_keypair()?;
		let responder_concealment = concealment.public();
		let mut guard = replay_guard();
		let config = config_for(&server_kp, &concealment);

		// -- Exec
		let (initiator, responder) = tokio::join!(
			Session::initiate(
				io_i,
				&mut c_rng,
				&client_kp,
				None,
				&PeerPolicy::AcceptAny,
				&responder_concealment
			),
			Session::accept(io_r, &mut s_rng, &config, &mut guard),
		);
		let (mut initiator, mut responder) = (initiator?, responder?);

		initiator.send(&fixture_message(1, "ping")).await?;
		let request: TestMessage = responder.recv().await?.ok_or("server saw EOF")?;
		responder.send(&fixture_message(2, "pong")).await?;
		let response: TestMessage = initiator.recv().await?.ok_or("client saw EOF")?;

		// -- Check: records interop, and each side learned the other only by
		// opening a seal.
		assert_eq!(request, fixture_message(1, "ping"));
		assert_eq!(response, fixture_message(2, "pong"));
		assert_eq!(initiator.session_id(), responder.session_id());
		assert_eq!(initiator.peer_identity().key_id, server_kp.key_id);
		assert_eq!(responder.peer_identity().key_id, client_kp.key_id);
		Ok(())
	}

	#[tokio::test]
	async fn test_transport_cookie_challenge_round_trip() -> TestResult<()> {
		// -- Setup & Fixtures
		let (io_i, io_r) = duplex(256 * 1024);
		let (mut c_rng, mut s_rng, client_kp, server_kp) = fixtures();
		let concealment = concealment_keypair()?;
		let responder_concealment = concealment.public();
		let cookie = SessionCookie::new([0x5A; 32], 60);
		let peer_tag = [0x11; 32];

		// Enabling premise, asserted rather than assumed: the placeholder a
		// client sends when nobody has asked it for a cookie never verifies.
		// So a handshake that completes against this config can only have done
		// so by receiving the challenge and resending — the challenge path is
		// not merely present, it ran.
		assert!(!cookie.verify(&[0u8; 32], &peer_tag, 1000));

		let mut guard = replay_guard();
		let mut config = config_for(&server_kp, &concealment);
		config.cookie = Some(&cookie);
		config.peer_tag = Some(peer_tag);
		config.now_secs = 1000;

		// -- Exec
		let (initiator, responder) = tokio::join!(
			Session::initiate(
				io_i,
				&mut c_rng,
				&client_kp,
				None,
				&PeerPolicy::AcceptAny,
				&responder_concealment
			),
			Session::accept(io_r, &mut s_rng, &config, &mut guard),
		);
		let (mut initiator, mut responder) = (initiator?, responder?);

		initiator.send(&fixture_message(3, "after the cookie")).await?;
		let received: TestMessage = responder.recv().await?.ok_or("server saw EOF")?;

		// -- Check
		assert_eq!(received, fixture_message(3, "after the cookie"));
		assert_eq!(initiator.peer_identity().key_id, server_kp.key_id);
		Ok(())
	}

	#[tokio::test]
	async fn test_transport_listener_over_tcp_derives_the_peer_tag() -> TestResult<()> {
		// -- Setup & Fixtures: `peer_tag` deliberately left unset — the
		// listener is the party that can see where the peer really is.
		let mut listener = Listener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let (mut c_rng, mut s_rng, client_kp, server_kp) = fixtures();
		let concealment = concealment_keypair()?;
		let responder_concealment = concealment.public();
		let cookie = SessionCookie::new([0x5A; 32], 60);
		let mut config = config_for(&server_kp, &concealment);
		config.cookie = Some(&cookie);
		config.now_secs = 1000;

		// -- Exec
		let (client, server) = tokio::join!(
			connect(
				addr,
				&mut c_rng,
				&client_kp,
				None,
				&PeerPolicy::AcceptAny,
				&responder_concealment
			),
			listener.accept(&mut s_rng, &config),
		);
		let (mut client, mut server) = (client?, server?);

		client.send(&fixture_message(4, "over tcp")).await?;
		let received: TestMessage = server.recv().await?.ok_or("server saw EOF")?;

		// -- Check
		assert_eq!(received, fixture_message(4, "over tcp"));
		assert_eq!(client.peer_identity().key_id, server_kp.key_id);
		assert_eq!(server.peer_identity().key_id, client_kp.key_id);
		assert!(client.get_ref().peer_addr()?.ip().is_loopback());
		Ok(())
	}

	#[tokio::test]
	async fn test_transport_split_halves_stay_one_session() -> TestResult<()> {
		// -- Setup & Fixtures
		let (_, _, client_kp, server_kp) = fixtures();
		let (client, server) = establish(0x33, &client_kp, &server_kp).await?;
		let (mut c_tx, mut c_rx) = client.split();
		let (mut s_tx, mut s_rx) = server.split();

		// -- Exec
		c_tx.send(&fixture_message(1, "from the tx half")).await?;
		let at_server: TestMessage = s_rx.recv().await?.ok_or("server saw EOF")?;
		s_tx.send(&fixture_message(2, "and back")).await?;
		let at_client: TestMessage = c_rx.recv().await?.ok_or("client saw EOF")?;

		// -- Check: the split halves run the same record counters the whole
		// session would have — one send on each side, in each direction.
		assert_eq!(at_server, fixture_message(1, "from the tx half"));
		assert_eq!(at_client, fixture_message(2, "and back"));
		Ok(())
	}

	#[tokio::test]
	async fn test_transport_fresh_sessions_derive_different_records() -> TestResult<()> {
		// -- Setup & Fixtures: two handshakes over the SAME long-term keys.
		let (_, _, client_kp, server_kp) = fixtures();
		let (first_client, _) = establish(0x11, &client_kp, &server_kp).await?;
		let (second_client, _) = establish(0x22, &client_kp, &server_kp).await?;

		// -- Check: the ephemeral secrets are fresh, so the session ids differ
		// even though both peers present the same identities.
		assert_ne!(first_client.session_id(), second_client.session_id());
		assert_eq!(first_client.peer_identity().key_id, server_kp.key_id);
		Ok(())
	}

	// endregion: --- Session over TCP

	// region:    --- Support

	/// One full session over a fresh duplex. `ephemeral_seed` drives BOTH
	/// sides' handshake entropy — callers pass distinct values to prove that
	/// distinct handshakes derive distinct traffic keys.
	async fn establish(
		ephemeral_seed: u8,
		client_kp: &TemperKeypair,
		server_kp: &TemperKeypair,
	) -> TestResult<(Session<tokio::io::DuplexStream>, Session<tokio::io::DuplexStream>)> {
		let (io_i, io_r) = duplex(256 * 1024);
		let mut c_rng = TemperEntropy::from_seed([ephemeral_seed; 32]);
		let mut s_rng = TemperEntropy::from_seed([ephemeral_seed ^ 0xFF; 32]);
		let concealment = concealment_keypair()?;
		let responder_concealment = concealment.public();
		let mut guard = replay_guard();
		let config = config_for(server_kp, &concealment);
		let (i, r) = tokio::join!(
			Session::initiate(
				io_i,
				&mut c_rng,
				client_kp,
				None,
				&PeerPolicy::AcceptAny,
				&responder_concealment
			),
			Session::accept(io_r, &mut s_rng, &config, &mut guard),
		);
		Ok((i?, r?))
	}

	/// A fresh replay window for one test's responder side. Small, because a
	/// test that wants a refusal constructs it deliberately.
	fn replay_guard() -> SessionReplayGuard {
		SessionReplayGuard::new(60, 64).expect("a non-degenerate replay window")
	}

	/// A fresh concealment keypair for the responder side of a handshake.
	fn concealment_keypair() -> TestResult<ConcealmentKeypair> {
		let mut rng = TemperEntropy::from_seed([0xC3; 32]);
		Ok(ConcealmentKeypair::generate(&mut rng)?)
	}

	/// A responder config with no cookie, no tag, and the caller's clock.
	fn config_for<'a>(keypair: &'a TemperKeypair, concealment: &'a ConcealmentKeypair) -> ResponderConfig<'a> {
		ResponderConfig {
			keypair,
			certificate: None,
			policy: &PeerPolicy::AcceptAny,
			concealment,
			cookie: None,
			peer_tag: None,
			now_secs: 0,
		}
	}

	/// Seeded rngs and keypairs — every handshake in this suite is
	/// reproducible byte-for-byte.
	fn fixtures() -> (TemperEntropy, TemperEntropy, TemperKeypair, TemperKeypair) {
		let mut c_rng = TemperEntropy::from_seed([0xC1; 32]);
		let mut s_rng = TemperEntropy::from_seed([0xC2; 32]);
		let client_kp = generate_keypair(&mut c_rng, "client@example").expect("keygen");
		let server_kp = generate_keypair(&mut s_rng, "server@example").expect("keygen");
		(c_rng, s_rng, client_kp, server_kp)
	}

	#[derive(Debug, Serialize, Deserialize, PartialEq)]
	struct TestMessage {
		seq: u32,
		body: String,
	}

	fn fixture_message(seq: u32, body: &str) -> TestMessage {
		TestMessage {
			seq,
			body: body.to_string(),
		}
	}

	// endregion: --- Support
}

// endregion: --- Tests
