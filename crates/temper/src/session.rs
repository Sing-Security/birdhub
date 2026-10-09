//! Authenticated session protocol: a three-flight handshake that turns the
//! bare key agreement in [`crate::handshake`] into a mutually authenticated
//! session with concealed identities, its own record layer, and an optional
//! anti-DoS cookie.
//!
//! The bare handshake provides forward secrecy but no identity binding — an
//! active attacker can relay two bare handshakes and neither side can tell.
//! This module closes that gap: both flights are signed with the peer's dual
//! PQC identity keys (ML-DSA-65 + SLH-DSA-SHA2-128f), and confirmation MACs
//! keyed by the shared secret are folded into the key schedule, so a session
//! exists only after both sides prove possession of (a) the ephemeral shared
//! secret and (b) their static identity keys.
//!
//! Neither identity travels in the clear. Each peer's [`PeerIdentity`] is
//! sealed — flight 1's to the responder's static concealment key, flight 2's
//! to a key derived from the shared secret — and the bare handshake's identity
//! tags are freshly randomised per session, so no value on the wire repeats
//! between two sessions of the same peers.
//!
//! # Flights
//!
//! ```text
//! (optionally)  S → C   SessionChallenge   version, cookie          [flight 0]
//! C → S   SessionInit     version, bare proposal, cookie,
//!                         sealed_identity = Encap(postcard(I), K_R)
//! S → C   SessionAccept   acceptance,
//!                         sealed_responder = Seal(K_seal, postcard(R)),
//!                         responder_confirm, sig(H2)
//! C → S   SessionConfirm  initiator_confirm, sig(H3)                [flight 3]
//! ```
//!
//! [`PeerPolicy`] decides which peer identities are acceptable: `AcceptAny`
//! (signatures still must verify), `Pin` (exact key match), or `Cert` (a
//! [`TemperCertificate`] chaining to the given CA keys whose subject keys
//! equal the flight identity).
//!
//! # Transcript chain and key schedule
//!
//! See `PROTOCOL.md` for the full construction; in brief:
//!
//! ```text
//! H1 = H("Temper.Session.v2" || postcard(SessionInit))
//! H2 = H(H1 || postcard(acceptance) || postcard(sealed_responder))
//! H3 = H(H2 || postcard(initiator_confirm))
//! ```
//!
//! H2 covers the responder's identity *ciphertext*, not its plaintext: the
//! responder signs H2, the initiator decrypts first and then verifies the
//! signature under the decrypted keys. The initiator signs H3. Each confirm
//! MAC covers the transcript up to but not including itself — as in TLS 1.3's
//! Finished, a MAC cannot cover its own bytes and needs no signature cover
//! because only the two parties can derive it. The traffic keys derive from
//! the shared secret and H3, so they inherit every signature and MAC above
//! them.
//!
//! # Version numbering
//!
//! The wire version is [`PROTOCOL_VERSION`]` = 2` and the domain strings carry
//! a `.v2` suffix even though this build speaks no v1. That is deliberate: v1
//! put both identities in cleartext and had no cookie, so its flight shapes are
//! incompatible with these, and the version field is a *rejection* boundary
//! rather than a negotiation — a stale v1 peer stops at the version check with
//! "unsupported session protocol version 1 (this build speaks 2)" instead of
//! mis-decoding a struct that no longer has the same fields. Reusing the
//! number would turn a clean refusal into a confusing parse error. The field
//! also exists so a future breaking change has a name to negotiate under.
//!
//! # What is concealed, and from whom
//!
//! A **passive non-participant** sees neither peer's public keys, and no value
//! on the wire repeats between two sessions of the same peers. That is the
//! whole claim. It is not anonymity from the peer: mutual authentication
//! requires each side to learn who it talks to, so a responder that logs the
//! client it decrypted deanonymises it to itself. It is not anonymity from an
//! on-path participant (a MITM that completes a session, a compromised
//! responder, a relay that is itself a session party).
//!
//! # Forward secrecy of the seals
//!
//! `sealed_responder` is sealed under a key derived from the bare handshake's
//! shared `secret`, which only the two parties can compute, so a recorded
//! flight 2 does not open later even if the responder's long-term keys leak.
//!
//! `sealed_identity` in flight 1 is sealed to the responder's **static**
//! concealment key, not to a session secret — the responder has not yet
//! contributed anything. That seal is therefore not forward-secret: a recorded
//! flight 1 opens once the concealment key leaks, fleet-wide and
//! retrospectively. Rotate concealment keys per epoch.
//!
//! # Anti-DoS cookie
//!
//! [`crate::session_cookie`] gives the responder a stateless cookie it can hand
//! out in a [`SessionChallenge`] (flight 0). When required, [`accept`] verifies
//! it **before** the concealment decapsulation and before any signing, so a
//! flood of unvalidated flight 1s costs the responder two BLAKE3 hashes each,
//! not two SLH-DSA signatures. A cookie is only as strong as the carrier's
//! address integrity: on a carrier that cannot supply a trustworthy peer tag (a
//! pipe has no address), a peer-supplied tag makes it worthless — fail closed
//! there.
//!
//! # Soundness of the responder seal
//!
//! The responder signs `H2`, which covers `sealed_responder`. That proves a
//! holder of the signing key endorsed *a blob*; the blob decrypts only for a
//! session participant. It gives **consistency** — the identity the client
//! decrypts is the one the signer bound to this session — and **not identity**:
//! the client learns the verifying keys *from* the blob, so "the decrypted keys
//! equal the verifying keys" is a tautology. Identity comes from [`PeerPolicy`]
//! alone (`Pin`, `Cert`, an out-of-band directory). With `AcceptAny`, a
//! responder that seals its own true identity is behaving honestly and nothing
//! more is proven.
//!
//! # Not protected
//!
//! Replay of a fully captured handshake produces a second valid session —
//! deduplicate `session_id` server-side if that matters (see
//! [`crate::replay::SessionReplayGuard`]). Flight 1 is not forward-secret and
//! its cookie is only as good as the carrier's address. No automatic rekey.

#![cfg(feature = "session")]

use alloc::string::String;
use alloc::vec::Vec;

use blake3::Hasher;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::ca::TemperCertificate;
use crate::crypto_provider::get_crypto_provider;
use crate::entropy::TemperEntropy;
use crate::envelope::{ConcealmentKeypair, ConcealmentPublicKey, Envelope, aead_open, aead_seal};
use crate::error::{Error, Result};
use crate::handshake::{self, HandshakeAcceptance};
use crate::record::RecordKeys;
use crate::seal::TemperKeypair;
use crate::session_cookie::SessionCookie;

// region:    --- Constants

/// Wire protocol version. Bumped only for a breaking change to the flight
/// shapes or the transcript construction.
///
/// `2` because this build's protocol superseded an earlier one whose identities
/// travelled in the clear. That earlier shape is not compiled here — keeping the
/// number is what keeps the wire format compatible with peers built while it
/// was.
pub const PROTOCOL_VERSION: u16 = 2;

const DOMAIN_SESSION: &str = "Temper.Session.v2";
const DOMAIN_SERVER_CONFIRM: &str = "Temper.Session.v2.ServerConfirm";
const DOMAIN_CLIENT_CONFIRM: &str = "Temper.Session.v2.ClientConfirm";
const DOMAIN_C2S: &str = "Temper.Session.v2.C2S";
const DOMAIN_S2C: &str = "Temper.Session.v2.S2C";

/// Domain and AEAD associated data for the responder-identity seal.
///
/// Used as both the KDF domain that derives `seal_key_R` and the AAD the seal
/// authenticates under, so a `sealed_responder` ciphertext can never be
/// confused with any other AEAD output in this crate.
const DOMAIN_RESPONDER_SEAL: &str = "Temper.Session.v2.ResponderSeal";
const AAD_RESPONDER_SEAL: &[u8] = DOMAIN_RESPONDER_SEAL.as_bytes();

// endregion: --- Constants

// region:    --- Version Dispatch

/// Read the protocol version out of a flight 1 without decoding the rest.
///
/// `version` is the first declared field of every flight-1 type, so postcard
/// puts it first on the wire and a responder can check it before it commits to
/// a full decode. `u16` is decoded, not a raw byte: correct today only because
/// the version is below 128, and the varint does not promise that — a version of
/// 128 would be two bytes and a raw-byte peek would read the wrong thing.
///
/// Only the prefix is consumed; the caller decodes the whole slice and must
/// check that the decoded `version` field equals what was peeked (a struct that
/// failed to set its own `version` would otherwise slip through).
pub fn peek_version(flight1: &[u8]) -> Result<u16> {
	let (version, _rest) = postcard::take_from_bytes::<u16>(flight1)
		.map_err(|_| Error::Protocol("unreadable session flight 1: missing version field".into()))?;
	Ok(version)
}

// endregion: --- Version Dispatch

// region:    --- Wire Types

/// A peer's long-term identity as it travels in a flight: both public keys,
/// their digest as a human-checkable id, and optionally the certificate that
/// vouches for them.
///
/// Not `PartialEq` — equality is the policy's job, and a byte-for-byte
/// comparison is not what any policy wants anyway.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
	/// ML-DSA-65 public key (1952 bytes).
	pub mldsa_pk: Vec<u8>,
	/// SLH-DSA-SHA2-128f public key (32 bytes).
	pub slhdsa_pk: Vec<u8>,
	/// `hex(BLAKE3(mldsa_pk || slhdsa_pk))` — matches `TemperKeypair::key_id`.
	pub key_id: String,
	/// Certificate vouching for these keys, when the peer presents one.
	///
	/// Boxed: a `TemperCertificate` embeds a `Seal` (two signature blocks
	/// plus context), over half a kilobyte by value. Flights and
	/// [`SessionSecrets`] move `PeerIdentity` around by value; the box keeps
	/// that a couple of pointers instead of a struct copy. Serialization is
	/// unaffected — `Box<T>` encodes exactly as `T`.
	pub certificate: Option<alloc::boxed::Box<TemperCertificate>>,
}

impl core::fmt::Debug for PeerIdentity {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		// Redacted: the keys are public, but a session log has no business
		// carrying megabytes of them either.
		f.debug_struct("PeerIdentity")
			.field("key_id", &self.key_id)
			.field("certificate", &self.certificate.as_ref().map(|c| &c.cert_id))
			.finish_non_exhaustive()
	}
}

/// Flight 0: a responder that requires a cookie hands the client one before the
/// client commits to a flight 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionChallenge {
	/// The [`PROTOCOL_VERSION`] this responder speaks.
	pub version: u16,
	/// The stateless cookie to echo back in `SessionInit.cookie`.
	pub cookie: [u8; 32],
}

/// Flight 1: the initiator's version, bare proposal, cookie, and its identity
/// sealed to the responder's concealment key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInit {
	/// The [`PROTOCOL_VERSION`] this initiator speaks.
	pub version: u16,
	/// The bare key-agreement proposal (ephemeral keys, session id).
	pub proposal: crate::handshake::HandshakeProposal,
	/// The cookie from flight 0, or all-zero when no cookie was required.
	///
	/// Carried inside flight 1 (not beside it) so it lands in H1 and is covered
	/// by the responder's signature over H2: a MITM that swapped it would
	/// change H2 and fail the signature check.
	pub cookie: [u8; 32],
	/// `envelope::encapsulate(rng, postcard(PeerIdentity_I), K_conceal)` — the
	/// initiator's identity, readable only by the holder of the responder's
	/// concealment key.
	pub sealed_identity: Envelope,
}

/// Payload of flight 2: what the responder accepted, its sealed identity, and
/// the proof that it derived the shared secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAcceptBody {
	/// The bare key-agreement acceptance.
	pub acceptance: HandshakeAcceptance,
	/// `aead_seal(seal_key_R, AAD, postcard(PeerIdentity_R))` — the responder's
	/// identity, readable only by a holder of the session secret.
	pub sealed_responder: Vec<u8>,
	/// `keyed_hash(K_server, H2)` — only derivable with the shared secret.
	pub responder_confirm: [u8; 32],
}

/// Flight 2: the body plus the responder's dual signatures over H2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAccept {
	pub body: SessionAcceptBody,
	/// ML-DSA-65 signature over H2 by the responder identity's key.
	pub mldsa_sig: Vec<u8>,
	/// SLH-DSA signature over H2 by the responder identity's key.
	pub slhdsa_sig: Vec<u8>,
}

/// Payload of flight 3: the initiator's proof it derived the shared secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfirmBody {
	/// `keyed_hash(K_client, H2)` — only derivable with the shared secret.
	pub initiator_confirm: [u8; 32],
}

/// Flight 3: the body plus the initiator's dual signatures over H3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfirm {
	pub body: SessionConfirmBody,
	/// ML-DSA-65 signature over H3 by the initiator identity's key.
	pub mldsa_sig: Vec<u8>,
	/// SLH-DSA signature over H3 by the initiator identity's key.
	pub slhdsa_sig: Vec<u8>,
}

// endregion: --- Wire Types

// region:    --- Policy

/// Which peer identities a session may be established with.
///
/// Every variant still requires the peer's flight signatures to verify —
/// the policy only decides which identities are *acceptable*, never whether
/// a flight was authenticated.
#[derive(Debug, Clone)]
pub enum PeerPolicy {
	/// Accept any peer whose flight signatures verify. The authenticated
	/// [`PeerIdentity`] is returned in [`SessionSecrets::peer`] for the
	/// caller to record (trust-on-first-use style).
	AcceptAny,
	/// Accept exactly this identity — both keys must match byte for byte.
	Pin(PeerIdentity),
	/// Accept a peer presenting a certificate that verifies under these CA
	/// public keys and whose subject keys equal the flight identity.
	///
	/// The validity window is checked only if [`CertValidity::At`] names a
	/// time — no_std has no clock, so this module cannot read one. That
	/// choice is a required field rather than a default precisely because a
	/// silently-skipped window check is a check that passes for the wrong
	/// reason; the type makes the caller say which it means.
	Cert {
		/// The issuing CA's ML-DSA-65 public key.
		ca_mldsa_pk: Vec<u8>,
		/// The issuing CA's SLH-DSA public key.
		ca_slhdsa_pk: Vec<u8>,
		/// How to treat the certificate's `not_before`/`not_after` window.
		validity: CertValidity,
	},
}

/// How a [`PeerPolicy::Cert`] treats the certificate's validity window.
///
/// Only exists so that "we have no clock" is something a caller writes down,
/// rather than something that happens by omission. An unenforced *expiry*
/// check is the failure that matters: a revoked-by-expiry certificate
/// verifies its seal perfectly, so nothing else in the handshake notices it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertValidity {
	/// Enforce `not_before <= now <= not_after` against this Unix time in
	/// seconds. The caller supplies it — from a system clock, an RTC read, or
	/// a coarse timestamp the peer's own protocol carried.
	At(u64),
	/// This build has no clock, so the window is **not** enforced. A
	/// certificate that has expired, or is not yet valid, is accepted as long
	/// as its seal chains to the trusted CA. The default posture of the
	/// certificate model, and the one a long-lived deployment should not
	/// keep.
	NotChecked,
}

/// Apply a policy to a flight identity. `Ok(())` means "this identity may
/// hold the other end of the session".
pub(crate) fn check_policy(policy: &PeerPolicy, peer: &PeerIdentity) -> Result<()> {
	match policy {
		PeerPolicy::AcceptAny => Ok(()),
		PeerPolicy::Pin(expected) => {
			if expected.mldsa_pk == peer.mldsa_pk && expected.slhdsa_pk == peer.slhdsa_pk {
				Ok(())
			} else {
				Err(Error::Protocol("peer identity does not match the pinned keys".into()))
			}
		}
		PeerPolicy::Cert {
			ca_mldsa_pk,
			ca_slhdsa_pk,
			validity,
		} => {
			let cert = peer
				.certificate
				.as_deref()
				.ok_or_else(|| Error::Protocol("policy requires a certificate but the peer presented none".into()))?;
			let valid = crate::ca::verify_certificate(cert, ca_mldsa_pk, ca_slhdsa_pk)
				.map_err(|e| Error::Protocol(alloc::format!("certificate verification failed: {}", e)))?;
			if !valid {
				return Err(Error::Protocol(
					"peer certificate is not signed by the trusted CA".into(),
				));
			}
			if cert.mldsa_public_key != peer.mldsa_pk || cert.slhdsa_public_key != peer.slhdsa_pk {
				return Err(Error::Protocol(
					"peer certificate subject keys do not match the flight identity".into(),
				));
			}
			// Checked after the seal, not before: an unsigned `not_after` field
			// is attacker-controlled until the signature over it verifies.
			if let CertValidity::At(now) = validity {
				cert.check_validity(*now)
					.map_err(|e| Error::Protocol(alloc::format!("peer certificate validity: {}", e)))?;
			}
			Ok(())
		}
	}
}

// endregion: --- Policy

// region:    --- Session State

/// Initiator-side state between flight 1 and flight 3: the bare handshake's
/// ephemeral secrets plus the local signing keys used to sign flight 3.
/// Zeroized on drop; not `Debug`; deliberately not `Clone`.
pub struct SessionInitiator {
	pub(crate) handshake: handshake::InitiatorState,
	pub(crate) mldsa_sk: Vec<u8>,
	pub(crate) slhdsa_sk: Vec<u8>,
}

impl Drop for SessionInitiator {
	fn drop(&mut self) {
		self.mldsa_sk.zeroize();
		self.slhdsa_sk.zeroize();
	}
}

/// Responder-side state between flight 2 and its finalize.
///
/// Carries the initiator identity the responder decrypted in [`accept`]: the
/// identity arrives inside flight 1's seal, so there is no cleartext copy to
/// re-read at finalize time, and it must not be decrypted twice.
pub struct SessionResponder {
	pub(crate) handshake: handshake::ResponderState,
	pub(crate) initiator: PeerIdentity,
}

// endregion: --- Session State

// region:    --- Cookie Context

/// Everything [`accept`] needs to enforce a stateless cookie.
///
/// Passing this is what turns "flight 1 may carry a cookie" into "flight 1
/// must carry a valid one"; omitting it accepts the all-zero cookie a client
/// sends when no responder ever asked for one.
#[derive(Debug, Clone, Copy)]
pub struct CookieContext<'a> {
	/// The responder's cookie state (its secret and TTL).
	pub cookie: &'a SessionCookie,
	/// A stable, carrier-supplied tag for the peer. Must be trustworthy: on a
	/// carrier that cannot vouch for it, the cookie proves nothing.
	pub peer_tag: &'a [u8; 32],
	/// The caller's monotonic seconds — same convention as the replay guard.
	pub now_secs: u64,
}

// endregion: --- Cookie Context

// region:    --- Handshake Flights

/// Flight 1 — begin a session as the initiator.
///
/// The bare handshake's `local_id` is a **fresh random** value, not a digest of
/// the local identity: a deterministic blinding would itself be a stable
/// pseudonym, which is the property this protocol exists to remove. The
/// identity is concealed in `sealed_identity` instead, and the transcript still
/// binds both sides' public keys through the seals.
///
/// `cookie` is the value from flight 0, or all-zero when the responder
/// requires none.
pub fn initiate(
	rng: &mut TemperEntropy,
	keypair: &TemperKeypair,
	certificate: Option<&TemperCertificate>,
	responder_concealment: &ConcealmentPublicKey,
	cookie: [u8; 32],
) -> Result<(SessionInit, SessionInitiator)> {
	let initiator = peer_identity(keypair, certificate.cloned());
	let sealed_identity = responder_concealment.encapsulate(rng, &postcard_bytes(&initiator)?)?;

	let local_id = fresh_local_id(rng);
	let (proposal, handshake_state) = handshake::initiate(rng, &local_id)?;

	let state = SessionInitiator {
		handshake: handshake_state,
		mldsa_sk: keypair.mldsa_secret_key.clone(),
		slhdsa_sk: keypair.slhdsa_secret_key.clone(),
	};

	Ok((
		SessionInit {
			version: PROTOCOL_VERSION,
			proposal,
			cookie,
			sealed_identity,
		},
		state,
	))
}

/// Flight 2 — accept a session as the responder.
///
/// Ordering is the anti-DoS contract, and it is enforced here rather than left
/// to the caller:
///
/// 1. version check,
/// 2. cookie verification when `cookie` is supplied — before the concealment
///    decapsulation and before any signing, so an unvalidated peer is refused
///    for two BLAKE3 hashes,
/// 3. concealment decapsulation and the decrypted identity's `key_id`
///    consistency check,
/// 4. policy on the initiator's identity,
/// 5. only then the bare handshake and the two SLH-DSA signatures.
pub fn accept(
	rng: &mut TemperEntropy,
	init: &SessionInit,
	keypair: &TemperKeypair,
	certificate: Option<&TemperCertificate>,
	concealment: &ConcealmentKeypair,
	policy: &PeerPolicy,
	cookie: Option<CookieContext<'_>>,
) -> Result<(SessionAccept, SessionResponder)> {
	if init.version != PROTOCOL_VERSION {
		return Err(Error::Protocol(alloc::format!(
			"unsupported session protocol version {} (this build speaks {})",
			init.version,
			PROTOCOL_VERSION
		)));
	}

	// Anti-DoS first: refuse an unvalidated peer before any expensive work.
	if let Some(ctx) = cookie
		&& !ctx.cookie.verify(&init.cookie, ctx.peer_tag, ctx.now_secs)
	{
		return Err(Error::Protocol("session cookie missing or invalid".into()));
	}

	let initiator = decode_identity(&concealment.decapsulate(&init.sealed_identity)?)?;
	check_key_id(&initiator)?;
	check_policy(policy, &initiator)?;

	let local_id = fresh_local_id(rng);
	let (acceptance, handshake_state) = handshake::accept(rng, &init.proposal, &local_id)?;
	let responder = peer_identity(keypair, certificate.cloned());

	// The responder holds the encapsulated secret and its own ephemeral key,
	// so it derives the secret — and the seal key — immediately.
	let secret = handshake::finalize_responder(&init.proposal, &acceptance, &handshake_state);
	let h1 = transcript_h1(DOMAIN_SESSION, init)?;

	let seal_key = responder_seal_key(&secret, &h1, &acceptance)?;
	let sealed_responder = aead_seal(&seal_key, AAD_RESPONDER_SEAL, &postcard_bytes(&responder)?)?;

	// H2 covers the ciphertext, not the plaintext identity — a client proves
	// the signature by decrypting first, which only a participant can do.
	let h2 = transcript_h2(&h1, &acceptance, &sealed_responder)?;
	let server_key = derive_domain_key(DOMAIN_SERVER_CONFIRM, &secret, &h2);
	let responder_confirm = confirm_mac(&server_key, &h2);

	let provider = get_crypto_provider();
	let mldsa_sig = provider.mldsa_sign(&keypair.mldsa_secret_key, h2.as_bytes(), rng)?;
	let slhdsa_sig = provider.slhdsa_sign(&keypair.slhdsa_secret_key, h2.as_bytes(), rng)?;

	Ok((
		SessionAccept {
			body: SessionAcceptBody {
				acceptance,
				sealed_responder,
				responder_confirm,
			},
			mldsa_sig,
			slhdsa_sig,
		},
		SessionResponder {
			handshake: handshake_state,
			initiator,
		},
	))
}

/// Flight 3 + key derivation — initiator side.
///
/// Ordering inside this function is load-bearing and must not be reordered:
/// decrypt the responder's identity, **verify both signatures over H2 under
/// the decrypted keys**, then the confirm MAC, then the policy. Nothing here
/// branches on, logs, or `Debug`-prints the plaintext identity before the
/// signature step — a caller cannot opt out, because there is no point at
/// which the identity is observable before it has been authenticated.
pub fn finalize_initiator(
	rng: &mut TemperEntropy,
	init: &SessionInit,
	accept: &SessionAccept,
	state: &SessionInitiator,
	policy: &PeerPolicy,
) -> Result<(SessionConfirm, SessionSecrets)> {
	let secret = handshake::finalize_initiator(&init.proposal, &accept.body.acceptance, &state.handshake)?;
	let h1 = transcript_h1(DOMAIN_SESSION, init)?;

	let seal_key = responder_seal_key(&secret, &h1, &accept.body.acceptance)?;
	let responder = decode_identity(&aead_open(
		&seal_key,
		AAD_RESPONDER_SEAL,
		&accept.body.sealed_responder,
	)?)?;

	// H2 over the ciphertext, exactly as the responder computed it.
	let h2 = transcript_h2(&h1, &accept.body.acceptance, &accept.body.sealed_responder)?;

	// Signatures first: they are what makes the decrypted identity meaningful.
	let provider = get_crypto_provider();
	if !provider.mldsa_verify(&responder.mldsa_pk, h2.as_bytes(), &accept.mldsa_sig)
		|| !provider.slhdsa_verify(&responder.slhdsa_pk, h2.as_bytes(), &accept.slhdsa_sig)
	{
		return Err(Error::Protocol(
			"responder flight signatures failed verification".into(),
		));
	}

	// Only now is the identity signature-backed, so it is safe to inspect.
	check_key_id(&responder)?;

	let server_key = derive_domain_key(DOMAIN_SERVER_CONFIRM, &secret, &h2);
	if !ct_eq(&confirm_mac(&server_key, &h2), &accept.body.responder_confirm) {
		return Err(Error::Protocol("responder confirmation MAC mismatch".into()));
	}

	check_policy(policy, &responder)?;

	let client_key = derive_domain_key(DOMAIN_CLIENT_CONFIRM, &secret, &h2);
	let initiator_confirm = confirm_mac(&client_key, &h2);
	let h3 = transcript_h3(&h2, &initiator_confirm);
	let mldsa_sig = provider.mldsa_sign(&state.mldsa_sk, h3.as_bytes(), rng)?;
	let slhdsa_sig = provider.slhdsa_sign(&state.slhdsa_sk, h3.as_bytes(), rng)?;

	let c2s = derive_domain_key(DOMAIN_C2S, &secret, &h3);
	let s2c = derive_domain_key(DOMAIN_S2C, &secret, &h3);

	Ok((
		SessionConfirm {
			body: SessionConfirmBody { initiator_confirm },
			mldsa_sig,
			slhdsa_sig,
		},
		SessionSecrets {
			session_id: init.proposal.session_id,
			peer: responder,
			record: RecordKeys::initiator(c2s, s2c),
		},
	))
}

/// Key derivation — responder side, after flight 3 arrives.
///
/// Verifies the initiator's confirmation MAC and signatures against the
/// identity decrypted in [`accept`], and re-applies the policy so a caller
/// that shuffles flights cannot skip it.
pub fn finalize_responder(
	init: &SessionInit,
	accept: &SessionAccept,
	confirm: &SessionConfirm,
	state: &SessionResponder,
	policy: &PeerPolicy,
) -> Result<SessionSecrets> {
	let secret = handshake::finalize_responder(&init.proposal, &accept.body.acceptance, &state.handshake);
	let h1 = transcript_h1(DOMAIN_SESSION, init)?;
	let h2 = transcript_h2(&h1, &accept.body.acceptance, &accept.body.sealed_responder)?;

	// Confirm MAC first: if it fails, the signature check below would be
	// verifying an attacker-chosen transcript.
	let client_key = derive_domain_key(DOMAIN_CLIENT_CONFIRM, &secret, &h2);
	if !ct_eq(&confirm_mac(&client_key, &h2), &confirm.body.initiator_confirm) {
		return Err(Error::Protocol("initiator confirmation MAC mismatch".into()));
	}

	let h3 = transcript_h3(&h2, &confirm.body.initiator_confirm);
	let provider = get_crypto_provider();
	if !provider.mldsa_verify(&state.initiator.mldsa_pk, h3.as_bytes(), &confirm.mldsa_sig)
		|| !provider.slhdsa_verify(&state.initiator.slhdsa_pk, h3.as_bytes(), &confirm.slhdsa_sig)
	{
		return Err(Error::Protocol(
			"initiator flight signatures failed verification".into(),
		));
	}

	check_policy(policy, &state.initiator)?;

	let c2s = derive_domain_key(DOMAIN_C2S, &secret, &h3);
	let s2c = derive_domain_key(DOMAIN_S2C, &secret, &h3);

	Ok(SessionSecrets {
		session_id: init.proposal.session_id,
		peer: state.initiator.clone(),
		record: RecordKeys::responder(c2s, s2c),
	})
}

// endregion: --- Handshake Flights

// region:    --- Session Secrets

/// What a completed handshake leaves both sides agreeing on: the session id,
/// the authenticated peer identity, and the directional record keys.
///
/// Not `Debug` — the record keys would print.
pub struct SessionSecrets {
	/// Echoed from the initiator's bare proposal.
	pub session_id: u64,
	/// The peer identity this session was authenticated against, after the
	/// policy accepted it.
	pub peer: PeerIdentity,
	/// Send/receive record keys, oriented for this side.
	pub record: RecordKeys,
}

// endregion: --- Session Secrets

// region:    --- Transcript and Key Schedule

/// `H(domain || postcard(init))`.
pub(crate) fn transcript_h1<T: Serialize>(domain: &str, init: &T) -> Result<blake3::Hash> {
	let mut hasher = Hasher::new();
	hasher.update(domain.as_bytes());
	hasher.update(&postcard_bytes(init)?);
	Ok(hasher.finalize())
}

/// `H(H1 || postcard(acceptance) || postcard(tail))`.
///
/// H2 covers the responder flight's payload but *not* its confirm MAC or
/// signatures — a MAC cannot cover its own bytes, and the signatures are
/// *over* this hash rather than inside it.
///
/// `tail` is the sealed-identity ciphertext, so the hash covers bytes the
/// signature can be checked against without the identity being readable.
pub(crate) fn transcript_h2<T: Serialize>(
	h1: &blake3::Hash,
	acceptance: &HandshakeAcceptance,
	tail: &T,
) -> Result<blake3::Hash> {
	let mut hasher = Hasher::new();
	hasher.update(h1.as_bytes());
	hasher.update(&postcard_bytes(acceptance)?);
	hasher.update(&postcard_bytes(tail)?);
	Ok(hasher.finalize())
}

/// `H(H2 || initiator_confirm)`.
pub(crate) fn transcript_h3(h2: &blake3::Hash, initiator_confirm: &[u8; 32]) -> blake3::Hash {
	let mut hasher = Hasher::new();
	hasher.update(h2.as_bytes());
	hasher.update(initiator_confirm);
	hasher.finalize()
}

/// `derive_key(domain, parts[0] || parts[1] || …)`.
pub(crate) fn derive_key_parts(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
	let mut hasher = Hasher::new_derive_key(domain);
	for part in parts {
		hasher.update(part);
	}
	*hasher.finalize().as_bytes()
}

/// `derive_key(domain, secret || transcript)` — the one construction behind
/// the confirm keys and both traffic keys, so all four stay domain-separated
/// by construction.
pub(crate) fn derive_domain_key(domain: &str, secret: &[u8; 32], transcript: &blake3::Hash) -> [u8; 32] {
	derive_key_parts(domain, &[secret, transcript.as_bytes()])
}

pub(crate) fn confirm_mac(key: &[u8; 32], transcript: &blake3::Hash) -> [u8; 32] {
	*blake3::keyed_hash(key, transcript.as_bytes()).as_bytes()
}

/// Comparing MACs: branch-free so a caller measuring response time learns
/// nothing about how many leading bytes matched. The value compared is not
/// secret, but the comparison result feeds an authentication decision.
pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}
	diff == 0
}

pub(crate) fn postcard_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
	postcard::to_allocvec(value)
		.map_err(|e| Error::Serialization(alloc::format!("transcript serialization failed: {}", e)))
}

/// The 32-byte tag the bare handshake mixes into its KDF: the raw digest
/// behind `key_id`.
pub(crate) fn identity_tag(mldsa_pk: &[u8], slhdsa_pk: &[u8]) -> [u8; 32] {
	let mut hasher = Hasher::new();
	hasher.update(mldsa_pk);
	hasher.update(slhdsa_pk);
	*hasher.finalize().as_bytes()
}

pub(crate) fn peer_identity(keypair: &TemperKeypair, certificate: Option<TemperCertificate>) -> PeerIdentity {
	PeerIdentity {
		mldsa_pk: keypair.mldsa_public_key.clone(),
		slhdsa_pk: keypair.slhdsa_public_key.clone(),
		key_id: keypair.key_id.clone(),
		certificate: certificate.map(alloc::boxed::Box::new),
	}
}

/// `derive_key("Temper.Session.v2.ResponderSeal", secret || H1 || postcard(acceptance))`.
///
/// The key deliberately covers only what exists **before** the ciphertext it
/// protects — `secret`, `H1`, and the acceptance — exactly as TLS 1.3 derives
/// EncryptedExtensions keys from the transcript through ServerHello and then
/// appends the extensions as ciphertext. Including H2 (which contains the
/// ciphertext) would be circular.
fn responder_seal_key(secret: &[u8; 32], h1: &blake3::Hash, acceptance: &HandshakeAcceptance) -> Result<[u8; 32]> {
	let acceptance_bytes = postcard_bytes(acceptance)?;
	Ok(derive_key_parts(
		DOMAIN_RESPONDER_SEAL,
		&[secret, h1.as_bytes(), &acceptance_bytes],
	))
}

/// A fresh random 32-byte tag for the bare handshake's `local_id`.
///
/// Random rather than derived: a deterministic tag would be a stable pseudonym
/// that links every session of the same peer.
fn fresh_local_id(rng: &mut TemperEntropy) -> [u8; 32] {
	let mut id = [0u8; 32];
	rng.fill_bytes(&mut id);
	id
}

/// Decode a `PeerIdentity` from the plaintext of a seal.
fn decode_identity(bytes: &[u8]) -> Result<PeerIdentity> {
	postcard::from_bytes(bytes)
		.map_err(|e| Error::Serialization(alloc::format!("sealed peer identity decode failed: {}", e)))
}

/// A decrypted identity must carry the `key_id` its keys hash to.
///
/// The value is covered by the seal, so a mismatch means the sealer built it
/// wrong, and the cost of refusing is a BLAKE3 hash.
fn check_key_id(identity: &PeerIdentity) -> Result<()> {
	let expected = hex::encode(identity_tag(&identity.mldsa_pk, &identity.slhdsa_pk));
	if identity.key_id != expected {
		return Err(Error::Protocol(
			"peer identity key_id does not match its public keys".into(),
		));
	}
	Ok(())
}

// endregion: --- Transcript and Key Schedule
