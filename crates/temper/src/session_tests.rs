//! Functional tests for the session protocol: round trips, identity
//! concealment, the anti-DoS cookie gate, version dispatch, and a tamper case
//! per concealed field.
//!
//! Deterministic by construction — every fixture runs off
//! `TemperEntropy::from_seed`.
//!
//! The conformance suite in `session_math_tests.rs` recomputes the spec
//! formulas from raw primitives and plays a hostile responder; this file
//! exercises the four flight functions against each other.

#![cfg(all(test, feature = "session"))]

use crate::entropy::TemperEntropy;
use crate::envelope::ConcealmentKeypair;
use crate::error::Error;
use crate::seal::{TemperKeypair, generate_keypair};
use crate::session::{
	CookieContext, PROTOCOL_VERSION, PeerIdentity, PeerPolicy, SessionAccept, SessionInit, SessionInitiator,
	SessionResponder, accept, finalize_initiator, finalize_responder, initiate, peek_version,
};
use crate::session_cookie::SessionCookie;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

type TestResult<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

// region:    --- Tests

// region: --- Round trips

#[test]
fn test_round_trip_is_mutually_authenticated() -> TestResult<()> {
	// -- Setup & Fixtures
	let (client, server, client_kp, server_kp) = establish(0x20, 0x21, &PeerPolicy::AcceptAny, &PeerPolicy::AcceptAny)?;

	// -- Check: same session, each side authenticated THE other side — and
	// each side learned that peer's identity only by opening a seal.
	assert_eq!(client.session_id, server.session_id);
	assert_eq!(client.peer.key_id, server_kp.key_id);
	assert_eq!(server.peer.key_id, client_kp.key_id);
	Ok(())
}

#[test]
fn test_records_interop_in_both_directions() -> TestResult<()> {
	// -- Setup & Fixtures
	let (mut client, mut server, _c_kp, _s_kp) = establish(0x22, 0x23, &PeerPolicy::AcceptAny, &PeerPolicy::AcceptAny)?;

	// -- Exec: C2S then S2C.
	let c2s = client.record.send().seal(b"ping")?;
	let ping = server.record.recv().open(&c2s)?;
	let s2c = server.record.send().seal(b"pong")?;
	let pong = client.record.recv().open(&s2c)?;

	// -- Check
	assert_eq!(ping, b"ping");
	assert_eq!(pong, b"pong");

	// Negative control: the key schedule still gives each direction its
	// own key — a C2S record must not open on the initiator's receive side.
	assert!(client.record.recv().open(&c2s).is_err());
	Ok(())
}

#[test]
fn test_fresh_sessions_derive_different_keys() -> TestResult<()> {
	// -- Setup & Fixtures
	let (mut a, _, _, _) = establish(0x24, 0x25, &PeerPolicy::AcceptAny, &PeerPolicy::AcceptAny)?;
	let (mut b, _, _, _) = establish(0x26, 0x27, &PeerPolicy::AcceptAny, &PeerPolicy::AcceptAny)?;

	// -- Exec
	let ra = a.record.send().seal(b"same plaintext")?;
	let rb = b.record.send().seal(b"same plaintext")?;

	// -- Check
	assert_ne!(ra, rb);
	assert_ne!(a.session_id, b.session_id);
	Ok(())
}

#[test]
fn test_the_whole_handshake_is_reproducible_from_its_seeds() -> TestResult<()> {
	// Every fixture in this suite and in the conformance suite assumes a
	// handshake is a pure function of its entropy. Pin that here: the same
	// seeds must produce byte-identical records, because the moment they do
	// not, the golden vectors above stop describing this build.
	let (mut a_client, _, _, _) = establish(0x28, 0x29, &PeerPolicy::AcceptAny, &PeerPolicy::AcceptAny)?;
	let (mut b_client, _, _, _) = establish(0x28, 0x29, &PeerPolicy::AcceptAny, &PeerPolicy::AcceptAny)?;

	let a = a_client.record.send().seal(b"same plaintext")?;
	let b = b_client.record.send().seal(b"same plaintext")?;

	assert_eq!(a, b);
	Ok(())
}

// endregion: --- Round trips

// region: --- Identity concealment

#[test]
fn test_flight1_hides_the_initiator_identity() -> TestResult<()> {
	// -- Setup & Fixtures
	let mut c_rng = seeded_rng(0x30);
	let mut s_rng = seeded_rng(0x31);
	let client = make_keypair(&mut c_rng, "client@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	// -- Exec
	let (init, _state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let bytes = postcard_bytes(&init)?;

	// -- Check, positive control: the search is not broken — the keys ARE
	// findable in a byte string that does contain them.
	let mut haystack = alloc::vec![0u8; 8];
	haystack.extend_from_slice(&client.mldsa_public_key);
	assert!(
		contains(&haystack, &client.mldsa_public_key),
		"the byte search must find a key that is present"
	);

	// -- Check, the property: the flight carries neither key, nor the
	// deterministic key id that would link this session to the next, nor the
	// raw identity tag that id is the hex of.
	let tag = crate::session::identity_tag(&client.mldsa_public_key, &client.slhdsa_public_key);
	assert!(
		!contains(&bytes, &client.mldsa_public_key),
		"flight 1 leaked the ML-DSA key"
	);
	assert!(
		!contains(&bytes, &client.slhdsa_public_key),
		"flight 1 leaked the SLH-DSA key"
	);
	assert!(
		!contains(&bytes, client.key_id.as_bytes()),
		"flight 1 leaked the key id"
	);
	assert!(!contains(&bytes, &tag), "flight 1 leaked the identity tag");
	Ok(())
}

#[test]
fn test_initiator_id_is_blinded_per_session() -> TestResult<()> {
	// -- Setup & Fixtures: one identity, two sessions.
	let mut rng = seeded_rng(0x32);
	let client = make_keypair(&mut rng, "client@example");
	let mut s_rng = seeded_rng(0x33);
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let tag = crate::session::identity_tag(&client.mldsa_public_key, &client.slhdsa_public_key);

	// -- Exec
	let (a, _) = initiate(&mut rng, &client, None, &concealment.public(), [0u8; 32])?;
	let (b, _) = initiate(&mut rng, &client, None, &concealment.public(), [0u8; 32])?;

	// -- Check: the handshake id is fresh per session, so it is not a stable
	// pseudonym that would let an observer link two sessions to one identity.
	assert_ne!(a.proposal.initiator_id, b.proposal.initiator_id);
	assert_ne!(a.proposal.initiator_id, tag, "must not be the identity tag");
	assert_ne!(b.proposal.initiator_id, tag);
	Ok(())
}

#[test]
fn test_responder_recovers_the_initiator_identity() -> TestResult<()> {
	// -- Setup & Fixtures
	let rig = rig(0x34)?;

	// -- Check: the identity the responder acts on came out of the seal, and
	// is the initiator's — not merely "some identity that agrees with itself".
	assert_eq!(rig.s_state.initiator.key_id, rig.client.key_id);
	assert_eq!(rig.s_state.initiator.mldsa_pk, rig.client.mldsa_public_key);
	Ok(())
}

#[test]
fn test_wrong_concealment_key_cannot_open_flight1() -> TestResult<()> {
	// -- Setup & Fixtures: the client seals to a responder concealment key
	// that is not the one the responder holds.
	let mut c_rng = seeded_rng(0x35);
	let mut s_rng = seeded_rng(0x36);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let genuine = ConcealmentKeypair::generate(&mut s_rng)?;
	let other = ConcealmentKeypair::generate(&mut s_rng)?;

	let (init, _state) = initiate(&mut c_rng, &client, None, &genuine.public(), [0u8; 32])?;

	// -- Exec: hand it to a responder holding the wrong concealment key.
	let outcome = accept(&mut s_rng, &init, &server, None, &other, &PeerPolicy::AcceptAny, None);

	// -- Check
	assert!(outcome.is_err(), "a seal to another key must not open");
	Ok(())
}

// endregion: --- Identity concealment

// region: --- Anti-DoS cookie

#[test]
fn test_cookie_required_and_valid_is_accepted() -> TestResult<()> {
	// -- Setup & Fixtures
	let mut c_rng = seeded_rng(0x40);
	let mut s_rng = seeded_rng(0x41);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let cookie = SessionCookie::new([0x5A; 32], 60);
	let peer_tag = [0x11; 32];

	// -- Exec: flight 0 issues, the client echoes it in flight 1.
	let value = cookie.issue(&peer_tag, 1000);
	let (init, c_state) = initiate(&mut c_rng, &client, None, &concealment.public(), value)?;
	let ctx = CookieContext {
		cookie: &cookie,
		peer_tag: &peer_tag,
		now_secs: 1000,
	};
	let (accept, s_state) = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		Some(ctx),
	)?;

	// -- Check: the session completes end to end through the cookie gate.
	let (confirm, c_secrets) = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &PeerPolicy::AcceptAny)?;
	let s_secrets = finalize_responder(&init, &accept, &confirm, &s_state, &PeerPolicy::AcceptAny)?;
	assert_eq!(c_secrets.peer.key_id, server.key_id);
	assert_eq!(s_secrets.peer.key_id, client.key_id);
	Ok(())
}

#[test]
fn test_missing_cookie_is_refused() -> TestResult<()> {
	// -- Setup & Fixtures: the responder requires a cookie, the client sends
	// the all-zero placeholder it uses when nobody asked for one.
	let mut c_rng = seeded_rng(0x42);
	let mut s_rng = seeded_rng(0x43);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let cookie = SessionCookie::new([0x5A; 32], 60);
	let peer_tag = [0x11; 32];

	let (init, _state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let ctx = CookieContext {
		cookie: &cookie,
		peer_tag: &peer_tag,
		now_secs: 1000,
	};

	// -- Exec
	let outcome = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		Some(ctx),
	);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "session cookie missing or invalid");
	Ok(())
}

#[test]
fn test_cookie_bound_to_another_peer_tag_is_refused() -> TestResult<()> {
	// -- Setup & Fixtures: a valid cookie, but issued to a different peer —
	// one client must not be able to redeem another's.
	let mut c_rng = seeded_rng(0x44);
	let mut s_rng = seeded_rng(0x45);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let cookie = SessionCookie::new([0x5A; 32], 60);

	let value = cookie.issue(&[0x01; 32], 1000);
	let (init, _state) = initiate(&mut c_rng, &client, None, &concealment.public(), value)?;
	let ctx = CookieContext {
		cookie: &cookie,
		peer_tag: &[0x02; 32],
		now_secs: 1000,
	};

	// -- Exec
	let outcome = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		Some(ctx),
	);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "session cookie missing or invalid");
	Ok(())
}

#[test]
fn test_cookie_is_checked_before_the_expensive_work() -> TestResult<()> {
	// -- Setup & Fixtures: a flight 1 whose seal is garbage, paired with a bad
	// cookie. Whichever check runs first decides the error.
	let mut c_rng = seeded_rng(0x46);
	let mut s_rng = seeded_rng(0x47);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let cookie = SessionCookie::new([0x5A; 32], 60);
	let peer_tag = [0x11; 32];

	let (mut init, _state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let last = init.sealed_identity.mlkem_ciphertext.len() - 1;
	init.sealed_identity.mlkem_ciphertext[last] ^= 0x01;
	let ctx = CookieContext {
		cookie: &cookie,
		peer_tag: &peer_tag,
		now_secs: 1000,
	};

	// -- Exec: bad cookie AND a broken seal.
	let bad_cookie = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		Some(ctx),
	);

	// -- Check: the cookie is the verdict, so the gate ran first — an
	// unvalidated peer is refused before the decapsulation and before either
	// signature.
	assert_protocol_error(bad_cookie.map(|_| ()), "session cookie missing or invalid");

	// -- Negative control for the assertion above: with a *good* cookie the
	// same broken seal must now fail, and must not report a cookie error. If
	// it did, the first assertion would be passing for the wrong reason.
	let good = cookie.issue(&peer_tag, 1000);
	let ctx = CookieContext {
		cookie: &cookie,
		peer_tag: &peer_tag,
		now_secs: 1000,
	};
	let (mut init2, _state2) = initiate(&mut c_rng, &client, None, &concealment.public(), good)?;
	let last = init2.sealed_identity.mlkem_ciphertext.len() - 1;
	init2.sealed_identity.mlkem_ciphertext[last] ^= 0x01;
	let outcome = accept(
		&mut s_rng,
		&init2,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		Some(ctx),
	);
	match outcome {
		Err(err) => assert!(
			!alloc::format!("{err:?}").to_lowercase().contains("cookie"),
			"the seal is broken, so the failure must be the decapsulation, not the cookie: {err:?}"
		),
		Ok(_) => panic!("a corrupted seal must not open"),
	}
	Ok(())
}

// endregion: --- Anti-DoS cookie

// region: --- Version dispatch

#[test]
fn test_version_is_checked_first() -> TestResult<()> {
	// -- Setup & Fixtures: an init claiming an unsupported version with a
	// garbage seal. If the version gate were not first, the seal would fail and
	// mask it.
	let mut c_rng = seeded_rng(0x50);
	let mut s_rng = seeded_rng(0x51);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let (mut init, _state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	init.version = PROTOCOL_VERSION.wrapping_add(1);
	let last = init.sealed_identity.mlkem_ciphertext.len() - 1;
	init.sealed_identity.mlkem_ciphertext[last] ^= 0x01;

	// -- Exec
	let outcome = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		None,
	);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "unsupported session protocol version");
	Ok(())
}

#[test]
fn test_peek_version_reads_the_wire_version() -> TestResult<()> {
	// -- Setup & Fixtures
	let mut c_rng = seeded_rng(0x52);
	let mut s_rng = seeded_rng(0x53);
	let client = make_keypair(&mut c_rng, "client@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	// -- Exec
	let (init, _) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;

	// -- Check: the peek reads the same field the full decoders read, and it is
	// the sender's to set — flight 1 carries no signature, so this is a routing
	// hint, not an authenticated downgrade defence.
	let mut bytes = postcard_bytes(&init)?;
	assert_eq!(peek_version(&bytes)?, PROTOCOL_VERSION);
	bytes[0] = 0x7F;
	assert_eq!(peek_version(&bytes)?, 0x7F);

	// -- Negative control: a frame with no version field is not misread as one.
	assert!(peek_version(&[]).is_err());
	assert!(peek_version(&[0xFF]).is_err());
	Ok(())
}

// endregion: --- Version dispatch

// region: --- Tamper

#[test]
fn test_tampered_acceptance_is_rejected() -> TestResult<()> {
	// -- Setup & Fixtures
	let (mut c_rng, init, mut accept, c_state, _) = through_accept(0x60)?;
	let last = accept.body.acceptance.mlkem_ciphertext.len() - 1;
	accept.body.acceptance.mlkem_ciphertext[last] ^= 0x01;

	// -- Exec
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &PeerPolicy::AcceptAny);

	// -- Check: the acceptance feeds the shared secret, the seal key and H2,
	// so the responder's sealed identity no longer opens.
	assert!(outcome.is_err());
	Ok(())
}

#[test]
fn test_tampered_sealed_responder_is_rejected() -> TestResult<()> {
	// -- Setup & Fixtures
	let (mut c_rng, init, mut accept, c_state, _) = through_accept(0x61)?;
	let mid = accept.body.sealed_responder.len() / 2;
	accept.body.sealed_responder[mid] ^= 0x01;

	// -- Exec
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &PeerPolicy::AcceptAny);

	// -- Check: the seal is authenticated under a key derived only by a
	// participant, so a flipped ciphertext byte does not open.
	assert!(outcome.is_err());
	Ok(())
}

#[test]
fn test_tampered_confirm_mac_is_rejected() -> TestResult<()> {
	// -- Setup & Fixtures: the confirm MAC is NOT inside H2 (see the
	// transcript docs), so it is the MAC check — not the signature check —
	// that must catch this.
	let (mut c_rng, init, mut accept, c_state, _) = through_accept(0x62)?;
	accept.body.responder_confirm[0] ^= 0x01;

	// -- Exec
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &PeerPolicy::AcceptAny);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "responder confirmation MAC mismatch");
	Ok(())
}

#[test]
fn test_signatures_that_do_not_cover_h2_are_rejected() -> TestResult<()> {
	// -- Setup & Fixtures: replace the responder's signatures over H2 with
	// signatures over some other message. The sealed identity still opens, so
	// execution reaches the signature step — which must reject.
	let (mut c_rng, init, mut accept, c_state, _) = through_accept(0x63)?;
	let mut k_rng = seeded_rng(0x64);
	let impostor = make_keypair(&mut k_rng, "impostor@example");
	let provider = crate::crypto_provider::get_crypto_provider();
	let wrong = b"not the handshake transcript";
	accept.mldsa_sig = provider.mldsa_sign(&impostor.mldsa_secret_key, wrong, &mut k_rng)?;
	accept.slhdsa_sig = provider.slhdsa_sign(&impostor.slhdsa_secret_key, wrong, &mut k_rng)?;

	// -- Exec
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &PeerPolicy::AcceptAny);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "responder flight signatures failed verification");
	Ok(())
}

#[test]
fn test_tampered_initiator_confirm_is_rejected() -> TestResult<()> {
	// -- Setup & Fixtures
	let (mut c_rng, init, accept, c_state, s_state) = through_accept(0x65)?;
	let (mut confirm, _) = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &PeerPolicy::AcceptAny)?;
	confirm.body.initiator_confirm[0] ^= 0x01;

	// -- Exec
	let outcome = finalize_responder(&init, &accept, &confirm, &s_state, &PeerPolicy::AcceptAny);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "initiator confirmation MAC mismatch");
	Ok(())
}

// endregion: --- Tamper

// region: --- Policy

#[test]
fn test_pinned_policy_accepts_the_expected_identity() -> TestResult<()> {
	// -- Setup & Fixtures
	let mut c_rng = seeded_rng(0x70);
	let mut s_rng = seeded_rng(0x71);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let pin = PeerPolicy::Pin(identity_of(&server));

	// -- Exec: the initiator pins the responder it expects.
	let (init, c_state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let (accept, _s_state) = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;
	let (confirm, secrets) = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &pin)?;

	// -- Check
	assert_eq!(secrets.peer.key_id, server.key_id);
	assert_eq!(confirm.body.initiator_confirm.len(), 32);
	Ok(())
}

#[test]
fn test_pinned_policy_rejects_another_identity() -> TestResult<()> {
	// -- Setup & Fixtures: the initiator pins an identity that is not the one
	// inside the responder's seal.
	let mut c_rng = seeded_rng(0x72);
	let mut s_rng = seeded_rng(0x73);
	let mut o_rng = seeded_rng(0x74);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let other = make_keypair(&mut o_rng, "other@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;
	let pin = PeerPolicy::Pin(identity_of(&other));

	// -- Exec
	let (init, c_state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let (accept, _s_state) = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &c_state, &pin);

	// -- Check: identity is decided by policy, never by a valid signature.
	assert_protocol_error(outcome.map(|_| ()), "peer identity does not match the pinned keys");
	Ok(())
}

// endregion: --- Policy

// endregion: --- Tests

// region:    --- Support

fn seeded_rng(seed: u8) -> TemperEntropy {
	TemperEntropy::from_seed([seed; 32])
}

fn make_keypair(rng: &mut TemperEntropy, id: &str) -> TemperKeypair {
	generate_keypair(rng, id).expect("keygen must succeed under a seeded rng")
}

fn identity_of(keypair: &TemperKeypair) -> PeerIdentity {
	PeerIdentity {
		mldsa_pk: keypair.mldsa_public_key.clone(),
		slhdsa_pk: keypair.slhdsa_public_key.clone(),
		key_id: keypair.key_id.clone(),
		certificate: None,
	}
}

/// Whether `haystack` contains `needle` as a contiguous run. Used to prove a
/// key is absent from a serialized flight, not merely that it is unreferenced.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
	!needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Flights 1–2 of a handshake, plus the initiator's rng (flight 3 still
/// signs) and both post-accept states — for tamper and inspect tests.
struct Rig {
	c_rng: TemperEntropy,
	client: TemperKeypair,
	init: SessionInit,
	c_state: SessionInitiator,
	accept: SessionAccept,
	s_state: SessionResponder,
}

fn rig(seed: u8) -> TestResult<Rig> {
	let mut c_rng = seeded_rng(seed);
	let mut s_rng = seeded_rng(seed.wrapping_add(1));
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let (init, c_state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let (accept, s_state) = accept(
		&mut s_rng,
		&init,
		&server,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;

	Ok(Rig {
		c_rng,
		client,
		init,
		c_state,
		accept,
		s_state,
	})
}

/// Flights 1–2 plus the initiator's rng (flight 3 still signs), for tamper
/// tests that stop before flight 3.
#[allow(clippy::type_complexity)]
fn through_accept(
	seed: u8,
) -> TestResult<(
	TemperEntropy,
	SessionInit,
	SessionAccept,
	SessionInitiator,
	SessionResponder,
)> {
	let r = rig(seed)?;
	Ok((r.c_rng, r.init, r.accept, r.c_state, r.s_state))
}

/// A full session between freshly generated keypairs, returning both sides'
/// secrets and both keypairs.
#[allow(clippy::type_complexity)]
fn establish(
	client_seed: u8,
	server_seed: u8,
	client_policy: &PeerPolicy,
	server_policy: &PeerPolicy,
) -> TestResult<(
	crate::session::SessionSecrets,
	crate::session::SessionSecrets,
	TemperKeypair,
	TemperKeypair,
)> {
	let mut c_rng = seeded_rng(client_seed);
	let mut s_rng = seeded_rng(server_seed);
	let client = make_keypair(&mut c_rng, "client@example");
	let server = make_keypair(&mut s_rng, "server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let (init, c_state) = initiate(&mut c_rng, &client, None, &concealment.public(), [0u8; 32])?;
	let (accept, s_state) = accept(&mut s_rng, &init, &server, None, &concealment, server_policy, None)?;
	let (confirm, c_secrets) = finalize_initiator(&mut c_rng, &init, &accept, &c_state, client_policy)?;
	let s_secrets = finalize_responder(&init, &accept, &confirm, &s_state, server_policy)?;

	Ok((c_secrets, s_secrets, client, server))
}

fn assert_protocol_error<T>(outcome: crate::error::Result<T>, expected: &str) {
	match outcome {
		Err(Error::Protocol(msg)) => assert!(
			msg.contains(expected),
			"expected Protocol('{expected}'), got Protocol('{msg}')"
		),
		Err(other) => panic!("expected Protocol('{expected}'), got {other:?}"),
		Ok(_) => panic!("expected Protocol('{expected}'), but the step succeeded"),
	}
}

fn postcard_bytes<T: serde::Serialize>(value: &T) -> crate::error::Result<Vec<u8>> {
	postcard::to_allocvec(value).map_err(|e| Error::Serialization(e.to_string()))
}

// endregion: --- Support
