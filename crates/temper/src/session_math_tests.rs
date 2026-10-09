//! Mathematical conformance tests for the session protocol.
//!
//! Every expected value here is recomputed from the formulas in `PROTOCOL.md`
//! with raw BLAKE3 / ChaCha20-Poly1305 calls — never by calling this crate's
//! transcript or KDF helpers. The domain strings are spelled out literally so
//! that changing one in the source fails these tests instead of silently
//! changing the wire protocol.
//!
//! Both roles are played by the test against the real implementation. As
//! initiator it builds flight 1 itself and constructs flight 2 exactly as the
//! spec says, which the crate's initiator must accept; as responder it hands a
//! spec-built flight 1 to the crate and checks the crate's flight 2 against
//! values it recomputed. Where the spec admits a plausible wrong variant —
//! a seal key that folds in H2, one that drops the secret, H2 over the
//! plaintext identity instead of the ciphertext — a negative control asserts
//! the wrong variant does **not** reproduce what the implementation produced.

#![cfg(all(test, feature = "session"))]

use crate::crypto_provider::get_crypto_provider;
use crate::entropy::TemperEntropy;
use crate::envelope::{ConcealmentKeypair, aead_open, aead_seal};
use crate::error::{Error, Result};
use crate::handshake::{self, HandshakeAcceptance};
use crate::record::RecordKeys;
use crate::seal::{TemperKeypair, generate_keypair};
use crate::session::{PROTOCOL_VERSION, PeerIdentity, PeerPolicy, SessionInitiator};
use crate::session::{
	SessionAccept, SessionAcceptBody, SessionInit, SessionResponder, accept, finalize_initiator, finalize_responder,
};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use blake3::Hasher;
use chacha20poly1305::{
	ChaCha20Poly1305, Nonce,
	aead::{Aead, KeyInit, Payload},
};

type TestResult<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

// region:    --- Spec constants (literal — see the module docs)

const DOMAIN: &str = "Temper.Session.v2";
const DOMAIN_SERVER_CONFIRM: &str = "Temper.Session.v2.ServerConfirm";
const DOMAIN_CLIENT_CONFIRM: &str = "Temper.Session.v2.ClientConfirm";
const DOMAIN_C2S: &str = "Temper.Session.v2.C2S";
const DOMAIN_S2C: &str = "Temper.Session.v2.S2C";
const DOMAIN_RESPONDER_SEAL: &str = "Temper.Session.v2.ResponderSeal";
const AAD_RESPONDER_SEAL: &[u8] = DOMAIN_RESPONDER_SEAL.as_bytes();

// endregion: --- Spec constants (literal — see the module docs)

// region:    --- Spec constructions (independent of the crate's helpers)

struct TestError(String);

impl From<TestError> for Box<dyn core::error::Error> {
	fn from(e: TestError) -> Self {
		e.0.into()
	}
}

fn spec_err<E: core::fmt::Display>(e: E) -> TestError {
	TestError(e.to_string())
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
	let mut hasher = Hasher::new();
	for part in parts {
		hasher.update(part);
	}
	*hasher.finalize().as_bytes()
}

/// H1 = H("Temper.Session.v2" || postcard(SessionInit))
fn transcript_h1(init: &SessionInit) -> TestResult<[u8; 32]> {
	let bytes = postcard::to_allocvec(init).map_err(spec_err)?;
	Ok(hash(&[DOMAIN.as_bytes(), &bytes]))
}

/// H2 = H(H1 || postcard(acceptance) || sealed_responder)
///
/// The tail is the **ciphertext**. The `|| sealed_responder` here is the
/// postcard encoding of a `Vec<u8>`, which is what the crate's
/// domain-parameterised `transcript_h2` feeds it.
fn transcript_h2(h1: &[u8; 32], acceptance: &HandshakeAcceptance, sealed_responder: &[u8]) -> TestResult<[u8; 32]> {
	let acc = postcard::to_allocvec(acceptance).map_err(spec_err)?;
	let tail = postcard::to_allocvec(&sealed_responder.to_vec()).map_err(spec_err)?;
	Ok(hash(&[h1, &acc, &tail]))
}

/// The plausible mis-reading: H2 over the *plaintext* identity.
fn transcript_h2_over_plaintext(
	h1: &[u8; 32],
	acceptance: &HandshakeAcceptance,
	identity: &PeerIdentity,
) -> TestResult<[u8; 32]> {
	let acc = postcard::to_allocvec(acceptance).map_err(spec_err)?;
	let plain = postcard::to_allocvec(identity).map_err(spec_err)?;
	Ok(hash(&[h1, &acc, &plain]))
}

/// H3 = H(H2 || initiator_confirm)
fn transcript_h3(h2: &[u8; 32], initiator_confirm: &[u8; 32]) -> [u8; 32] {
	hash(&[h2, initiator_confirm])
}

/// K = BLAKE3.derive_key(domain, secret || transcript)
fn derive_key(domain: &str, secret: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
	let mut hasher = Hasher::new_derive_key(domain);
	hasher.update(secret);
	hasher.update(transcript);
	*hasher.finalize().as_bytes()
}

/// seal_key_R = BLAKE3.derive_key("Temper.Session.v2.ResponderSeal",
///                                secret || H1 || postcard(acceptance))
fn responder_seal_key(secret: &[u8; 32], h1: &[u8; 32], acceptance: &HandshakeAcceptance) -> TestResult<[u8; 32]> {
	let acc = postcard::to_allocvec(acceptance).map_err(spec_err)?;
	let mut hasher = Hasher::new_derive_key(DOMAIN_RESPONDER_SEAL);
	hasher.update(secret);
	hasher.update(h1);
	hasher.update(&acc);
	Ok(*hasher.finalize().as_bytes())
}

/// confirm = BLAKE3.keyed_hash(K, H2)
fn confirm_mac(key: &[u8; 32], h2: &[u8; 32]) -> [u8; 32] {
	*blake3::keyed_hash(key, h2).as_bytes()
}

/// The bare handshake's identity tag: raw BLAKE3(mldsa_pk || slhdsa_pk).
fn identity_tag(mldsa_pk: &[u8], slhdsa_pk: &[u8]) -> [u8; 32] {
	hash(&[mldsa_pk, slhdsa_pk])
}

/// ChaCha20-Poly1305 under a raw key, all-zero nonce, with AAD — the spec's
/// `aead_seal`, written out rather than called.
fn aead_seal_spec(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> TestResult<Vec<u8>> {
	let cipher = ChaCha20Poly1305::new(key.into());
	Ok(cipher
		.encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: plaintext, aad })
		.map_err(spec_err)?)
}

fn aead_open_spec(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> TestResult<Vec<u8>> {
	let cipher = ChaCha20Poly1305::new(key.into());
	Ok(cipher
		.decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: ciphertext, aad })
		.map_err(spec_err)?)
}

fn assert_protocol_error<T>(outcome: Result<T>, needle: &str) {
	match outcome {
		Err(Error::Protocol(msg)) => assert!(msg.contains(needle), "wrong Protocol error: {msg}"),
		other => panic!(
			"expected Protocol error containing {needle:?}, got is_err={}",
			other.is_err()
		),
	}
}

// endregion: --- Spec constructions (independent of the crate's helpers)

// region:    --- Fixtures

fn seeded_rng(seed: u8) -> TemperEntropy {
	TemperEntropy::from_seed([seed; 32])
}

fn keypair(rng: &mut TemperEntropy, id: &str) -> TemperKeypair {
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

fn postcard_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
	postcard::to_allocvec(value).map_err(|e| Error::Serialization(e.to_string()))
}

/// The test plays the initiator and builds flight 1 itself, sealing its
/// identity to the responder's concealment key with the public envelope API.
struct SpecInitiator {
	init: SessionInit,
	state: SessionInitiator,
	client_kp: TemperKeypair,
	concealment: ConcealmentKeypair,
	s_rng: TemperEntropy,
}

impl SpecInitiator {
	fn run(client_seed: u8, server_seed: u8) -> TestResult<Self> {
		let mut c_rng = seeded_rng(client_seed);
		let mut s_rng = seeded_rng(server_seed);
		let client_kp = keypair(&mut c_rng, "math-client@example");
		let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

		// A fixed local id is fine here: the property under test is the
		// transcript, and the crate's own use of a fresh random one is covered
		// by the functional suite.
		let local_id = [0x11; 32];
		let (proposal, handshake_state) = handshake::initiate(&mut c_rng, &local_id).map_err(spec_err)?;

		let sealed_identity = concealment
			.public()
			.encapsulate(&mut c_rng, &postcard_bytes(&identity_of(&client_kp))?)?;

		let init = SessionInit {
			version: PROTOCOL_VERSION,
			proposal,
			cookie: [0u8; 32],
			sealed_identity,
		};

		let state = SessionInitiator {
			handshake: handshake_state,
			mldsa_sk: client_kp.mldsa_secret_key.clone(),
			slhdsa_sk: client_kp.slhdsa_secret_key.clone(),
		};

		Ok(Self {
			init,
			state,
			client_kp,
			concealment,
			s_rng,
		})
	}
}

// endregion: --- Fixtures

// region:    --- Tests

// region: --- The responder's flight 2 is what the spec says

#[test]
fn test_flight_two_matches_the_spec() -> TestResult<()> {
	// -- Setup & Fixtures: the test owns flight 1, so it can recompute H1.
	let t = SpecInitiator::run(0x80, 0x81)?;
	let server_kp = {
		let mut rng = seeded_rng(0x82);
		keypair(&mut rng, "math-server@example")
	};

	// -- Exec: the crate answers flight 1.
	let mut s_rng = t.s_rng;
	let (accept, _s_state) = accept(
		&mut s_rng,
		&t.init,
		&server_kp,
		None,
		&t.concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;

	// -- Check: the seal opens under a key the spec derives from the secret,
	// H1 and the acceptance — so the implementation's H1 and seal key both
	// match the formula. (Wrong either way and this fails to authenticate.)
	//
	// The secret comes from `finalize_initiator`, which needs only the
	// initiator's own ephemeral state — which is why this test plays the
	// initiator: a test that played the responder would have to reconstruct
	// the responder's ephemeral secrets, and could only do so by trusting the
	// very implementation it is checking.
	let secret = handshake::finalize_initiator(&t.init.proposal, &accept.body.acceptance, &t.state.handshake)
		.map_err(spec_err)?;
	let h1 = transcript_h1(&t.init)?;
	let seal_key = responder_seal_key(&secret, &h1, &accept.body.acceptance)?;
	let opened = aead_open_spec(&seal_key, AAD_RESPONDER_SEAL, &accept.body.sealed_responder)?;
	let responder = postcard::from_bytes::<PeerIdentity>(&opened).map_err(spec_err)?;
	assert_eq!(responder.key_id, server_kp.key_id);

	// -- Check: H2 over the ciphertext, and the confirm MAC over H2.
	let h2 = transcript_h2(&h1, &accept.body.acceptance, &accept.body.sealed_responder)?;
	let server_key = derive_key(DOMAIN_SERVER_CONFIRM, &secret, &h2);
	assert_eq!(accept.body.responder_confirm, confirm_mac(&server_key, &h2));

	// -- Check: both signatures are over H2 and nothing else.
	let provider = get_crypto_provider();
	assert!(provider.mldsa_verify(&server_kp.mldsa_public_key, &h2, &accept.mldsa_sig));
	assert!(provider.slhdsa_verify(&server_kp.slhdsa_public_key, &h2, &accept.slhdsa_sig));
	Ok(())
}

#[test]
fn test_flight_three_and_record_keys_match_the_spec() -> TestResult<()> {
	// -- Setup & Fixtures
	let t = SpecInitiator::run(0x83, 0x84)?;
	let mut s_rng = t.s_rng;
	let mut o_rng = seeded_rng(0x85);
	let server_kp = keypair(&mut o_rng, "math-server@example");

	// -- Exec
	let (accept, s_state) = accept(
		&mut s_rng,
		&t.init,
		&server_kp,
		None,
		&t.concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;
	let (confirm, c_secrets) = finalize_initiator(&mut s_rng, &t.init, &accept, &t.state, &PeerPolicy::AcceptAny)?;

	// -- Check: the client's confirm is keyed by the spec's client key over H3.
	let secret = handshake::finalize_initiator(&t.init.proposal, &accept.body.acceptance, &t.state.handshake)
		.map_err(spec_err)?;
	let h1 = transcript_h1(&t.init)?;
	let h2 = transcript_h2(&h1, &accept.body.acceptance, &accept.body.sealed_responder)?;
	let client_key = derive_key(DOMAIN_CLIENT_CONFIRM, &secret, &h2);
	assert_eq!(confirm.body.initiator_confirm, confirm_mac(&client_key, &h2));

	// -- Check: the record keys are derive_key(domain, secret, H3), and the
	// directions still differ. A record the crate sealed must open under a
	// `RecordKeys` this test built from the spec's keys.
	let h3 = transcript_h3(&h2, &confirm.body.initiator_confirm);
	let c2s = derive_key(DOMAIN_C2S, &secret, &h3);
	let s2c = derive_key(DOMAIN_S2C, &secret, &h3);
	assert_ne!(c2s, s2c, "the two directions must not share a key");

	let mut spec_responder = RecordKeys::responder(c2s, s2c);
	let mut impl_initiator = c_secrets.record;
	let sealed = impl_initiator.send().seal(b"spec bytes")?;
	assert_eq!(spec_responder.recv().open(&sealed)?, b"spec bytes");

	// -- Check: and the crate's own responder finalize agrees with the
	// client, so the flights are consistent, not merely self-consistent.
	let s_secrets = finalize_responder(&t.init, &accept, &confirm, &s_state, &PeerPolicy::AcceptAny)?;
	assert_eq!(s_secrets.peer.key_id, t.client_kp.key_id);
	Ok(())
}

#[test]
fn test_a_spec_built_flight_two_is_accepted_by_the_initiator() -> TestResult<()> {
	// -- Setup & Fixtures: this time the test plays the responder and writes
	// every byte of flight 2.
	let mut c_rng = seeded_rng(0x86);
	let mut s_rng = seeded_rng(0x87);
	let client_kp = keypair(&mut c_rng, "math-client@example");
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let local_id = [0x33; 32];
	let (proposal, c_handshake) = handshake::initiate(&mut c_rng, &local_id).map_err(spec_err)?;
	let client_identity = identity_of(&client_kp);
	let sealed_identity = concealment
		.public()
		.encapsulate(&mut c_rng, &postcard_bytes(&client_identity)?)?;
	let init = SessionInit {
		version: PROTOCOL_VERSION,
		proposal,
		cookie: [0u8; 32],
		sealed_identity,
	};

	// The test's own bare handshake, so it holds the secret.
	let (acceptance, s_handshake) = handshake::accept(&mut s_rng, &init.proposal, &local_id).map_err(spec_err)?;
	let secret = handshake::finalize_responder(&init.proposal, &acceptance, &s_handshake);
	let h1 = transcript_h1(&init)?;
	let seal_key = responder_seal_key(&secret, &h1, &acceptance)?;
	let responder_identity = identity_of(&server_kp);
	let sealed_responder = aead_seal_spec(&seal_key, AAD_RESPONDER_SEAL, &postcard_bytes(&responder_identity)?)?;
	let h2 = transcript_h2(&h1, &acceptance, &sealed_responder)?;
	let server_key = derive_key(DOMAIN_SERVER_CONFIRM, &secret, &h2);
	let provider = get_crypto_provider();
	let accept = SessionAccept {
		body: SessionAcceptBody {
			acceptance,
			sealed_responder,
			responder_confirm: confirm_mac(&server_key, &h2),
		},
		mldsa_sig: provider.mldsa_sign(&server_kp.mldsa_secret_key, &h2, &mut s_rng)?,
		slhdsa_sig: provider.slhdsa_sign(&server_kp.slhdsa_secret_key, &h2, &mut s_rng)?,
	};

	// -- Exec: hand the hand-built flight 2 to the crate's initiator.
	let state = SessionInitiator {
		handshake: c_handshake,
		mldsa_sk: client_kp.mldsa_secret_key.clone(),
		slhdsa_sk: client_kp.slhdsa_secret_key.clone(),
	};
	let (confirm, c_secrets) = finalize_initiator(&mut c_rng, &init, &accept, &state, &PeerPolicy::AcceptAny)?;

	// -- Check
	assert_eq!(c_secrets.peer.key_id, server_kp.key_id);

	// -- Exec & Check: and the crate's responder accepts the flight 3 the
	// crate's initiator produced, over the same hand-built transcript.
	let s_state = SessionResponder {
		handshake: s_handshake,
		initiator: client_identity,
	};
	let s_secrets = finalize_responder(&init, &accept, &confirm, &s_state, &PeerPolicy::AcceptAny)?;
	assert_eq!(s_secrets.peer.key_id, client_kp.key_id);
	Ok(())
}

// endregion: --- The responder's flight 2 is what the spec says

// region: --- Negative controls

#[test]
fn test_seal_key_does_not_fold_in_h2() -> TestResult<()> {
	// -- Setup & Fixtures: a real flight 2, and the key that would have been
	// used had the seal key been derived from H2 — which contains the
	// ciphertext the key protects, and so is circular.
	let t = SpecInitiator::run(0x88, 0x89)?;
	let mut s_rng = t.s_rng;
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let (accept, _) = accept(
		&mut s_rng,
		&t.init,
		&server_kp,
		None,
		&t.concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;

	let secret = handshake::finalize_initiator(&t.init.proposal, &accept.body.acceptance, &t.state.handshake)
		.map_err(spec_err)?;
	let h1 = transcript_h1(&t.init)?;
	let h2 = transcript_h2(&h1, &accept.body.acceptance, &accept.body.sealed_responder)?;

	let mut circular = Hasher::new_derive_key(DOMAIN_RESPONDER_SEAL);
	circular.update(&secret);
	circular.update(&h1);
	circular.update(&postcard_bytes(&accept.body.acceptance)?);
	circular.update(&h2);
	let circular_key = *circular.finalize().as_bytes();

	// -- Check: the circular key does not open the real ciphertext. If the
	// implementation had used it, the spec key would not have opened it
	// either — and the test above asserts that it does.
	assert_ne!(circular_key, responder_seal_key(&secret, &h1, &accept.body.acceptance)?);
	assert!(aead_open_spec(&circular_key, AAD_RESPONDER_SEAL, &accept.body.sealed_responder).is_err());
	Ok(())
}

#[test]
fn test_seal_key_covers_the_session_secret() -> TestResult<()> {
	// -- Setup & Fixtures
	let t = SpecInitiator::run(0x8A, 0x8B)?;
	let mut s_rng = t.s_rng;
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let (accept, _) = accept(
		&mut s_rng,
		&t.init,
		&server_kp,
		None,
		&t.concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;

	let secret = handshake::finalize_initiator(&t.init.proposal, &accept.body.acceptance, &t.state.handshake)
		.map_err(spec_err)?;
	let h1 = transcript_h1(&t.init)?;

	// -- Exec: a key derived without the secret at all.
	let mut without_secret = Hasher::new_derive_key(DOMAIN_RESPONDER_SEAL);
	without_secret.update(&h1);
	without_secret.update(&postcard_bytes(&accept.body.acceptance)?);
	let key = *without_secret.finalize().as_bytes();

	// -- Check: anyone can derive this key — the acceptance is on the wire and
	// H1 is computable from flight 1 — so it must not be the real one.
	assert!(aead_open_spec(&key, AAD_RESPONDER_SEAL, &accept.body.sealed_responder).is_err());

	// The other plausible variant: the right parts, wrong order.
	let mut swapped = Hasher::new_derive_key(DOMAIN_RESPONDER_SEAL);
	swapped.update(&h1);
	swapped.update(&secret);
	swapped.update(&postcard_bytes(&accept.body.acceptance)?);
	let swapped_key = *swapped.finalize().as_bytes();
	assert!(aead_open_spec(&swapped_key, AAD_RESPONDER_SEAL, &accept.body.sealed_responder).is_err());
	Ok(())
}

#[test]
fn test_h2_covers_the_ciphertext_and_not_the_plaintext() -> TestResult<()> {
	// -- Setup & Fixtures
	let mut c_rng = seeded_rng(0x8C);
	let mut s_rng = seeded_rng(0x8D);
	let client_kp = keypair(&mut c_rng, "math-client@example");
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let local_id = [0x66; 32];
	let (proposal, c_handshake) = handshake::initiate(&mut c_rng, &local_id).map_err(spec_err)?;
	let client_identity = identity_of(&client_kp);
	let init = SessionInit {
		version: PROTOCOL_VERSION,
		proposal,
		cookie: [0u8; 32],
		sealed_identity: concealment
			.public()
			.encapsulate(&mut c_rng, &postcard_bytes(&client_identity)?)?,
	};

	let (acceptance, s_handshake) = handshake::accept(&mut s_rng, &init.proposal, &local_id).map_err(spec_err)?;
	let secret = handshake::finalize_responder(&init.proposal, &acceptance, &s_handshake);
	let h1 = transcript_h1(&init)?;
	let seal_key = responder_seal_key(&secret, &h1, &acceptance)?;
	let responder_identity = identity_of(&server_kp);
	let sealed_responder = aead_seal_spec(&seal_key, AAD_RESPONDER_SEAL, &postcard_bytes(&responder_identity)?)?;

	// -- Exec: a responder that signed H2-over-plaintext instead.
	let wrong_h2 = transcript_h2_over_plaintext(&h1, &acceptance, &responder_identity)?;
	let provider = get_crypto_provider();
	let accept = SessionAccept {
		body: SessionAcceptBody {
			acceptance,
			sealed_responder,
			responder_confirm: [0u8; 32], // never reached: signatures are checked first
		},
		mldsa_sig: provider.mldsa_sign(&server_kp.mldsa_secret_key, &wrong_h2, &mut s_rng)?,
		slhdsa_sig: provider.slhdsa_sign(&server_kp.slhdsa_secret_key, &wrong_h2, &mut s_rng)?,
	};

	let state = SessionInitiator {
		handshake: c_handshake,
		mldsa_sk: client_kp.mldsa_secret_key.clone(),
		slhdsa_sk: client_kp.slhdsa_secret_key.clone(),
	};
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &state, &PeerPolicy::AcceptAny);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "responder flight signatures failed verification");
	Ok(())
}

#[test]
fn test_responder_cannot_seal_one_identity_and_sign_with_another() -> TestResult<()> {
	// -- Setup & Fixtures: the seal names the real responder; the signatures
	// belong to someone else. This is the shape an impersonation takes.
	let mut c_rng = seeded_rng(0x8E);
	let mut s_rng = seeded_rng(0x8F);
	let mut o_rng = seeded_rng(0x90);
	let client_kp = keypair(&mut c_rng, "math-client@example");
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let impostor = keypair(&mut o_rng, "math-impostor@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let local_id = [0x77; 32];
	let (proposal, c_handshake) = handshake::initiate(&mut c_rng, &local_id).map_err(spec_err)?;
	let init = SessionInit {
		version: PROTOCOL_VERSION,
		proposal,
		cookie: [0u8; 32],
		sealed_identity: concealment
			.public()
			.encapsulate(&mut c_rng, &postcard_bytes(&identity_of(&client_kp))?)?,
	};

	let (acceptance, s_handshake) = handshake::accept(&mut s_rng, &init.proposal, &local_id).map_err(spec_err)?;
	let secret = handshake::finalize_responder(&init.proposal, &acceptance, &s_handshake);
	let h1 = transcript_h1(&init)?;
	let seal_key = responder_seal_key(&secret, &h1, &acceptance)?;
	let sealed_responder = aead_seal_spec(
		&seal_key,
		AAD_RESPONDER_SEAL,
		&postcard_bytes(&identity_of(&server_kp))?,
	)?;
	let h2 = transcript_h2(&h1, &acceptance, &sealed_responder)?;
	let server_key = derive_key(DOMAIN_SERVER_CONFIRM, &secret, &h2);
	let provider = get_crypto_provider();
	let accept = SessionAccept {
		body: SessionAcceptBody {
			acceptance,
			sealed_responder,
			responder_confirm: confirm_mac(&server_key, &h2),
		},
		mldsa_sig: provider.mldsa_sign(&impostor.mldsa_secret_key, &h2, &mut s_rng)?,
		slhdsa_sig: provider.slhdsa_sign(&impostor.slhdsa_secret_key, &h2, &mut s_rng)?,
	};

	let state = SessionInitiator {
		handshake: c_handshake,
		mldsa_sk: client_kp.mldsa_secret_key.clone(),
		slhdsa_sk: client_kp.slhdsa_secret_key.clone(),
	};

	// -- Exec
	let outcome = finalize_initiator(&mut c_rng, &init, &accept, &state, &PeerPolicy::AcceptAny);

	// -- Check: the keys come from the seal, so the impostor's signatures are
	// checked against the identity they are impersonating, and fail.
	assert_protocol_error(outcome.map(|_| ()), "responder flight signatures failed verification");
	Ok(())
}

#[test]
fn test_seal_is_bound_to_its_associated_data() -> TestResult<()> {
	// -- Setup & Fixtures
	let mut s_rng = seeded_rng(0x91);
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let identity = identity_of(&server_kp);
	let key = [0x9C; 32];

	// -- Exec: the crate's seal, opened with the wrong AAD.
	let sealed = aead_seal(&key, AAD_RESPONDER_SEAL, &postcard_bytes(&identity)?)?;

	// -- Check: correct AAD opens, empty and foreign AAD do not. Without the
	// AAD binding, a `sealed_responder` ciphertext would be interchangeable
	// with any other AEAD output under the same key.
	assert_eq!(
		aead_open(&key, AAD_RESPONDER_SEAL, &sealed)?,
		postcard_bytes(&identity)?
	);
	assert!(aead_open(&key, b"", &sealed).is_err());
	assert!(aead_open(&key, DOMAIN_SERVER_CONFIRM.as_bytes(), &sealed).is_err());
	Ok(())
}

#[test]
fn test_sealed_identity_key_id_must_match_its_keys() -> TestResult<()> {
	// -- Setup & Fixtures: a well-formed seal over a dishonest identity — the
	// key_id does not hash to the keys beside it.
	let mut c_rng = seeded_rng(0x92);
	let mut s_rng = seeded_rng(0x93);
	let client_kp = keypair(&mut c_rng, "math-client@example");
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let concealment = ConcealmentKeypair::generate(&mut s_rng)?;

	let mut identity = identity_of(&client_kp);
	identity.key_id = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
	// Positive control on the fixture: the honest id is what the keys hash to.
	assert_ne!(
		identity.key_id,
		hex::encode(identity_tag(&client_kp.mldsa_public_key, &client_kp.slhdsa_public_key))
	);

	let (proposal, _) = handshake::initiate(&mut c_rng, &[0x88; 32]).map_err(spec_err)?;
	let init = SessionInit {
		version: PROTOCOL_VERSION,
		proposal,
		cookie: [0u8; 32],
		sealed_identity: concealment.public().encapsulate(&mut c_rng, &postcard_bytes(&identity)?)?,
	};

	// -- Exec
	let outcome = accept(
		&mut s_rng,
		&init,
		&server_kp,
		None,
		&concealment,
		&PeerPolicy::AcceptAny,
		None,
	);

	// -- Check
	assert_protocol_error(outcome.map(|_| ()), "key_id does not match its public keys");
	Ok(())
}

#[test]
fn test_every_domain_is_distinct() -> TestResult<()> {
	// -- Setup & Fixtures: the same transcript bytes under each domain.
	let t = SpecInitiator::run(0x94, 0x95)?;
	let mut s_rng = t.s_rng;
	let server_kp = keypair(&mut s_rng, "math-server@example");
	let (accept, _) = accept(
		&mut s_rng,
		&t.init,
		&server_kp,
		None,
		&t.concealment,
		&PeerPolicy::AcceptAny,
		None,
	)?;
	let bytes = postcard_bytes(&t.init)?;

	// -- Check: no two domains name the same transcript. If two did, a value
	// derived for one purpose would verify for the other — a confirm MAC
	// reusable as a record key, or one direction's keys usable as the other's.
	let domains: [&[u8]; 6] = [
		DOMAIN.as_bytes(),
		DOMAIN_SERVER_CONFIRM.as_bytes(),
		DOMAIN_CLIENT_CONFIRM.as_bytes(),
		DOMAIN_C2S.as_bytes(),
		DOMAIN_S2C.as_bytes(),
		DOMAIN_RESPONDER_SEAL.as_bytes(),
	];
	let digests: Vec<[u8; 32]> = domains.iter().map(|d| hash(&[d, &bytes])).collect();
	for i in 0..digests.len() {
		for j in (i + 1)..digests.len() {
			assert_ne!(digests[i], digests[j], "domains {i} and {j} collide");
		}
	}
	// The seal's AAD is the seal domain itself, deliberately: the ciphertext is
	// bound to the one label that says what it is.
	assert_eq!(AAD_RESPONDER_SEAL, DOMAIN_RESPONDER_SEAL.as_bytes());

	// -- Check: the same holds for the record layer's directional keys.
	let secret = handshake::finalize_initiator(&t.init.proposal, &accept.body.acceptance, &t.state.handshake)
		.map_err(spec_err)?;
	let h2 = transcript_h2(
		&transcript_h1(&t.init)?,
		&accept.body.acceptance,
		&accept.body.sealed_responder,
	)?;
	assert_ne!(
		derive_key(DOMAIN_C2S, &secret, &h2),
		derive_key(DOMAIN_S2C, &secret, &h2)
	);
	Ok(())
}

// endregion: --- Negative controls

// endregion: --- Tests
