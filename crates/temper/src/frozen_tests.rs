//! Freeze tests for the serialization types that cross process, wire, and
//! on-disk boundaries: `Seal`, `SealContext`, `Envelope`,
//! `KernelChainEnvelope`, `HandshakeProposal`, `HandshakeAcceptance`, and —
//! under `session` — the protocol's wire types (CONTRIBUTING.md "Crypto
//! changes").
//!
//! Two independent directions:
//!
//! - Golden byte vectors — the exact postcard encoding as it ships today.
//!   Any field/order/encoding change fails here first.
//! - Proptest round-trips for every type — arbitrary values must survive
//!   serialize -> deserialize unchanged, which catches lossy decoders the
//!   golden vector cannot see.

#![cfg(all(test, feature = "signatures"))]

use crate::error::Error;
use crate::seal::{Seal, SealContext, SignatureBlock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

#[cfg(feature = "session")]
use crate::ca::{ConcealmentBinding, TemperCertificate};
#[cfg(feature = "envelope")]
use crate::envelope::{Envelope, KernelChainEnvelope};
#[cfg(feature = "envelope")]
use crate::handshake::{HandshakeAcceptance, HandshakeProposal};
#[cfg(feature = "session")]
use crate::session::{
	PeerIdentity, SessionAccept, SessionAcceptBody, SessionChallenge, SessionConfirm, SessionConfirmBody, SessionInit,
};

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

// region:    --- Tests

#[test]
fn test_frozen_seal_context_postcard_golden() -> Result<()> {
	// -- Setup & Fixtures
	let ctx = fixture_seal_context();

	// -- Exec
	let bytes = postcard::to_allocvec(&ctx).map_err(|e| Error::Serialization(e.to_string()))?;

	// -- Check
	assert_eq!(hex::encode(&bytes), GOLDEN_SEAL_CONTEXT_POSTCARD_HEX);
	Ok(())
}

proptest! {
	#[test]
	fn test_frozen_seal_context_postcard_roundtrip(ctx in arb_seal_context()) {
		// -- Exec
		let bytes = postcard_bytes(&ctx)?;
		let back: SealContext = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back, ctx);
	}

	#[test]
	fn test_frozen_seal_postcard_roundtrip(seal in arb_seal()) {
		// -- Exec
		let bytes = postcard_bytes(&seal)?;
		let back: Seal = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back, seal);
	}

	#[cfg(feature = "envelope")]
	#[test]
	fn test_frozen_envelope_postcard_roundtrip(envelope in arb_envelope()) {
		// -- Exec
		let bytes = postcard_bytes(&envelope)?;
		let back: Envelope = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back, envelope);
	}

	#[cfg(feature = "envelope")]
	#[test]
	fn test_frozen_kernel_chain_envelope_postcard_roundtrip(envelope in arb_kernel_chain_envelope()) {
		// -- Exec
		let bytes = postcard_bytes(&envelope)?;
		let back: KernelChainEnvelope = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back, envelope);
	}

	#[cfg(feature = "envelope")]
	#[test]
	fn test_frozen_handshake_proposal_postcard_roundtrip(proposal in arb_handshake_proposal()) {
		// -- Exec
		let bytes = postcard_bytes(&proposal)?;
		let back: HandshakeProposal = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back, proposal);
	}

	#[cfg(feature = "envelope")]
	#[test]
	fn test_frozen_handshake_acceptance_postcard_roundtrip(acceptance in arb_handshake_acceptance()) {
		// -- Exec
		let bytes = postcard_bytes(&acceptance)?;
		let back: HandshakeAcceptance = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back, acceptance);
	}

	#[cfg(feature = "session")]
	#[test]
	fn test_frozen_peer_identity_postcard_roundtrip(identity in arb_peer_identity()) {
		// -- Exec
		let bytes = postcard_bytes(&identity)?;
		let back: PeerIdentity = postcard_back(&bytes)?;

		// -- Check: the frozen types deliberately have no PartialEq
		// (identity equality is policy's job), so equality is judged by
		// re-encoding. Postcard's encoding is canonical for these shapes,
		// so a lossy decoder cannot reproduce the same bytes.
		prop_assert_eq!(postcard_bytes(&back)?, bytes);
	}

	#[cfg(feature = "session")]
	#[test]
	fn test_frozen_session_init_postcard_roundtrip(init in arb_session_init()) {
		// -- Exec
		let bytes = postcard_bytes(&init)?;
		let back: SessionInit = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(postcard_bytes(&back)?, bytes);
	}

	#[cfg(feature = "session")]
	#[test]
	fn test_frozen_session_accept_postcard_roundtrip(accept in arb_session_accept()) {
		// -- Exec
		let bytes = postcard_bytes(&accept)?;
		let back: SessionAccept = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(postcard_bytes(&back)?, bytes);
	}

	#[cfg(feature = "session")]
	#[test]
	fn test_frozen_session_confirm_postcard_roundtrip(confirm in arb_session_confirm()) {
		// -- Exec
		let bytes = postcard_bytes(&confirm)?;
		let back: SessionConfirm = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(postcard_bytes(&back)?, bytes);
	}

	#[cfg(feature = "session")]
	#[test]
	fn test_frozen_session_challenge_postcard_roundtrip(challenge in arb_session_challenge()) {
		// -- Exec
		let bytes = postcard_bytes(&challenge)?;
		let back: SessionChallenge = postcard_back(&bytes)?;

		// -- Check
		prop_assert_eq!(back.version, challenge.version);
		prop_assert_eq!(back.cookie, challenge.cookie);
		prop_assert_eq!(postcard_bytes(&back)?, bytes);
	}
}

#[cfg(feature = "session")]
#[test]
fn test_frozen_peer_identity_certified_postcard_golden() -> Result<()> {
	// -- Setup & Fixtures: the certificate variant pins the nested
	// TemperCertificate + Seal encoding that the plain fixture above
	// cannot reach (its certificate is `None`).
	let identity = fixture_peer_identity(Some(alloc::boxed::Box::new(fixture_certificate())));

	// -- Exec
	let bytes = postcard::to_allocvec(&identity).map_err(|e| Error::Serialization(e.to_string()))?;

	// -- Check
	assert_eq!(hex::encode(&bytes), GOLDEN_PEER_IDENTITY_CERTIFIED_POSTCARD_HEX);
	Ok(())
}

#[cfg(feature = "session")]
#[test]
fn test_frozen_session_challenge_postcard_golden() -> Result<()> {
	// -- Setup & Fixtures
	let challenge = fixture_session_challenge();

	// -- Exec
	let bytes = postcard::to_allocvec(&challenge).map_err(|e| Error::Serialization(e.to_string()))?;

	// -- Check: version varint then the 32-byte cookie — the whole flight 0.
	assert_eq!(hex::encode(&bytes), GOLDEN_SESSION_CHALLENGE_POSTCARD_HEX);
	Ok(())
}

#[cfg(feature = "session")]
#[test]
fn test_frozen_session_init_postcard_golden() -> Result<()> {
	// -- Setup & Fixtures
	let init = fixture_session_init();

	// -- Exec
	let bytes = postcard::to_allocvec(&init).map_err(|e| Error::Serialization(e.to_string()))?;

	// -- Check: one vector pins the nested shape — version, HandshakeProposal,
	// cookie, and the sealed Envelope. `version` is first, which is what makes
	// it peekable.
	assert_eq!(hex::encode(&bytes), GOLDEN_SESSION_INIT_POSTCARD_HEX);
	Ok(())
}

#[cfg(feature = "session")]
#[test]
fn test_frozen_session_accept_postcard_golden() -> Result<()> {
	// -- Setup & Fixtures
	let accept = fixture_session_accept();

	// -- Exec
	let bytes = postcard::to_allocvec(&accept).map_err(|e| Error::Serialization(e.to_string()))?;

	// -- Check
	assert_eq!(hex::encode(&bytes), GOLDEN_SESSION_ACCEPT_POSTCARD_HEX);
	Ok(())
}

// endregion: --- Tests

// region:    --- Support

/// Captured 2026-10-08 for the fixed fixture below; the postcard encoding
/// of `SealContext` is part of the frozen seal-id preimage, not an
/// implementation detail.
const GOLDEN_SEAL_CONTEXT_POSTCARD_HEX: &str = "0e54656d7065722e5365616c2e763114323032362d31302d30385430303a30303a30305a12676f6c64656e406578616d706c652e636f6d0c74656d7065722d302e352e30020e636c617373696669636174696f6e0a544f50205345435245540770726f6a65637416506f73742d5175616e74756d204d6967726174696f6e";

fn fixture_seal_context() -> SealContext {
	SealContext {
		domain: "Temper.Seal.v1".to_string(),
		timestamp: "2026-10-08T00:00:00Z".to_string(),
		signer_id: "golden@example.com".to_string(),
		tool_version: "temper-0.5.0".to_string(),
		metadata: BTreeMap::from([
			("classification".to_string(), "TOP SECRET".to_string()),
			("project".to_string(), "Post-Quantum Migration".to_string()),
		]),
	}
}

fn postcard_bytes<T: serde::Serialize>(value: &T) -> core::result::Result<Vec<u8>, TestCaseError> {
	postcard::to_allocvec(value).map_err(|e| TestCaseError::fail(e.to_string()))
}

fn postcard_back<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> core::result::Result<T, TestCaseError> {
	postcard::from_bytes(bytes).map_err(|e| TestCaseError::fail(e.to_string()))
}

// -- Strategies

fn arb_text() -> impl Strategy<Value = String> {
	prop::collection::vec(any::<char>(), 0..=16).prop_map(|chars| chars.into_iter().collect())
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
	prop::collection::vec(any::<u8>(), 0..=48)
}

fn arb_seal_context() -> impl Strategy<Value = SealContext> {
	(
		arb_text(),
		arb_text(),
		arb_text(),
		arb_text(),
		prop::collection::btree_map(arb_text(), arb_text(), 0..=4),
	)
		.prop_map(|(domain, timestamp, signer_id, tool_version, metadata)| SealContext {
			domain,
			timestamp,
			signer_id,
			tool_version,
			metadata,
		})
}

fn arb_signature_block() -> impl Strategy<Value = SignatureBlock> {
	(arb_text(), arb_bytes(), arb_text()).prop_map(|(algorithm, signature, key_id)| SignatureBlock {
		algorithm,
		signature,
		key_id,
	})
}

fn arb_seal() -> impl Strategy<Value = Seal> {
	(
		any::<u16>(),
		arb_text(),
		arb_signature_block(),
		arb_signature_block(),
		arb_seal_context(),
		arb_text(),
	)
		.prop_map(
			|(schema_version, content_hash, primary, backup, context, seal_id)| Seal {
				schema_version,
				content_hash,
				primary,
				backup,
				context,
				seal_id,
			},
		)
}

#[cfg(feature = "envelope")]
fn arb_envelope() -> impl Strategy<Value = Envelope> {
	(
		any::<u16>(),
		arb_bytes(),
		arb_bytes(),
		arb_bytes(),
		arb_bytes(),
		arb_text(),
	)
		.prop_map(
			|(schema_version, mlkem_ciphertext, x25519_ephemeral_public, ciphertext, nonce, envelope_id)| Envelope {
				schema_version,
				mlkem_ciphertext,
				x25519_ephemeral_public,
				ciphertext,
				nonce,
				envelope_id,
			},
		)
}

#[cfg(feature = "envelope")]
fn arb_kernel_chain_envelope() -> impl Strategy<Value = KernelChainEnvelope> {
	(
		any::<u16>(),
		arb_bytes(),
		arb_bytes(),
		arb_bytes(),
		arb_bytes(),
		arb_bytes(),
		arb_text(),
	)
		.prop_map(
			|(
				schema_version,
				mlkem_ct_recipient,
				mlkem_ct_kernel,
				x25519_ephemeral_pk,
				ciphertext,
				nonce,
				envelope_id,
			)| {
				KernelChainEnvelope {
					schema_version,
					mlkem_ct_recipient,
					mlkem_ct_kernel,
					x25519_ephemeral_pk,
					ciphertext,
					nonce,
					envelope_id,
				}
			},
		)
}

#[cfg(feature = "envelope")]
fn arb_handshake_proposal() -> impl Strategy<Value = HandshakeProposal> {
	(
		any::<u64>(),
		prop::array::uniform32(any::<u8>()),
		prop::array::uniform32(any::<u8>()),
		arb_bytes(),
	)
		.prop_map(
			|(session_id, initiator_id, ephemeral_x25519_pub, mlkem_public_key)| HandshakeProposal {
				session_id,
				initiator_id,
				ephemeral_x25519_pub,
				mlkem_public_key,
			},
		)
}

#[cfg(feature = "envelope")]
fn arb_handshake_acceptance() -> impl Strategy<Value = HandshakeAcceptance> {
	(
		any::<u64>(),
		prop::array::uniform32(any::<u8>()),
		prop::array::uniform32(any::<u8>()),
		arb_bytes(),
	)
		.prop_map(
			|(session_id, responder_id, ephemeral_x25519_pub, mlkem_ciphertext)| HandshakeAcceptance {
				session_id,
				responder_id,
				ephemeral_x25519_pub,
				mlkem_ciphertext,
			},
		)
}

#[cfg(feature = "session")]
fn arb_concealment_binding() -> impl Strategy<Value = ConcealmentBinding> {
	(any::<u16>(), arb_bytes(), arb_bytes()).prop_map(|(schema_version, mlkem_public_key, x25519_public_key)| {
		ConcealmentBinding {
			schema_version,
			mlkem_public_key,
			x25519_public_key,
		}
	})
}

#[cfg(feature = "session")]
fn arb_certificate() -> impl Strategy<Value = TemperCertificate> {
	(
		any::<u16>(),
		arb_text(),
		arb_text(),
		arb_text(),
		any::<u64>(),
		any::<u64>(),
		arb_bytes(),
		arb_bytes(),
		arb_concealment_binding(),
		arb_seal(),
	)
		.prop_map(
			|(
				schema_version,
				cert_id,
				subject_id,
				issuer_id,
				not_before,
				not_after,
				mldsa_public_key,
				slhdsa_public_key,
				concealment,
				seal,
			)| {
				TemperCertificate {
					schema_version,
					cert_id,
					subject_id,
					issuer_id,
					not_before,
					not_after,
					mldsa_public_key,
					slhdsa_public_key,
					concealment,
					seal,
				}
			},
		)
}

#[cfg(feature = "session")]
fn arb_peer_identity() -> impl Strategy<Value = PeerIdentity> {
	(
		arb_bytes(),
		arb_bytes(),
		arb_text(),
		prop::option::of(arb_certificate()),
	)
		.prop_map(|(mldsa_pk, slhdsa_pk, key_id, certificate)| PeerIdentity {
			mldsa_pk,
			slhdsa_pk,
			key_id,
			certificate: certificate.map(alloc::boxed::Box::new),
		})
}

#[cfg(feature = "session")]
fn arb_session_confirm() -> impl Strategy<Value = SessionConfirm> {
	(prop::array::uniform32(any::<u8>()), arb_bytes(), arb_bytes()).prop_map(
		|(initiator_confirm, mldsa_sig, slhdsa_sig)| SessionConfirm {
			body: SessionConfirmBody { initiator_confirm },
			mldsa_sig,
			slhdsa_sig,
		},
	)
}

#[cfg(feature = "session")]
fn arb_session_challenge() -> impl Strategy<Value = SessionChallenge> {
	(any::<u16>(), prop::array::uniform32(any::<u8>()))
		.prop_map(|(version, cookie)| SessionChallenge { version, cookie })
}

#[cfg(feature = "session")]
fn arb_session_init() -> impl Strategy<Value = SessionInit> {
	(
		any::<u16>(),
		arb_handshake_proposal(),
		prop::array::uniform32(any::<u8>()),
		arb_envelope(),
	)
		.prop_map(|(version, proposal, cookie, sealed_identity)| SessionInit {
			version,
			proposal,
			cookie,
			sealed_identity,
		})
}

#[cfg(feature = "session")]
fn arb_session_accept() -> impl Strategy<Value = SessionAccept> {
	(
		arb_handshake_acceptance(),
		arb_bytes(),
		prop::array::uniform32(any::<u8>()),
		arb_bytes(),
		arb_bytes(),
	)
		.prop_map(
			|(acceptance, sealed_responder, responder_confirm, mldsa_sig, slhdsa_sig)| SessionAccept {
				body: SessionAcceptBody {
					acceptance,
					sealed_responder,
					responder_confirm,
				},
				mldsa_sig,
				slhdsa_sig,
			},
		)
}

// -- Session fixtures and goldens (feature = "session")

#[cfg(feature = "session")]
fn fixture_peer_identity(certificate: Option<alloc::boxed::Box<TemperCertificate>>) -> PeerIdentity {
	PeerIdentity {
		mldsa_pk: vec![0xA5; 48],
		slhdsa_pk: vec![0x5A; 32],
		key_id: "golden-peer@example.com".to_string(),
		certificate,
	}
}

#[cfg(feature = "session")]
fn fixture_session_challenge() -> SessionChallenge {
	SessionChallenge {
		version: 2,
		cookie: [0x77; 32],
	}
}

#[cfg(feature = "session")]
fn fixture_envelope() -> Envelope {
	Envelope {
		schema_version: 1,
		// Fixed short lengths: this pins the encoding, not a realistic key
		// size.
		mlkem_ciphertext: vec![0xE1; 16],
		x25519_ephemeral_public: vec![0xE2; 32],
		ciphertext: vec![0xE3; 24],
		nonce: vec![0xE4; 12],
		envelope_id: "golden-envelope".to_string(),
	}
}

#[cfg(feature = "session")]
fn fixture_session_init() -> SessionInit {
	SessionInit {
		version: 2,
		proposal: HandshakeProposal {
			session_id: 0x0102030405060708,
			initiator_id: [0xAA; 32],
			ephemeral_x25519_pub: [0xBB; 32],
			mlkem_public_key: vec![0xCC; 48],
		},
		cookie: [0x77; 32],
		sealed_identity: fixture_envelope(),
	}
}

#[cfg(feature = "session")]
fn fixture_session_accept() -> SessionAccept {
	SessionAccept {
		body: SessionAcceptBody {
			acceptance: HandshakeAcceptance {
				session_id: 0x0102030405060708,
				responder_id: [0xBB; 32],
				ephemeral_x25519_pub: [0xCC; 32],
				mlkem_ciphertext: vec![0xDD; 32],
			},
			sealed_responder: vec![0xF1; 40],
			responder_confirm: [0xEE; 32],
		},
		mldsa_sig: vec![0x11; 24],
		slhdsa_sig: vec![0x22; 24],
	}
}

#[cfg(feature = "session")]
fn fixture_certificate() -> TemperCertificate {
	TemperCertificate {
		schema_version: 2,
		cert_id: "golden-cert".to_string(),
		subject_id: "golden-subject@example.com".to_string(),
		issuer_id: "golden-ca@example.com".to_string(),
		not_before: 1_700_000_000,
		not_after: 4_102_444_800,
		mldsa_public_key: vec![0xC3; 48],
		slhdsa_public_key: vec![0x3C; 32],
		concealment: ConcealmentBinding {
			schema_version: 1,
			mlkem_public_key: vec![0xC5; 48],
			x25519_public_key: vec![0x5C; 32],
		},
		seal: Seal {
			schema_version: 1,
			content_hash: "golden-content-hash".to_string(),
			primary: SignatureBlock {
				algorithm: "ML-DSA-65".to_string(),
				signature: vec![0x11; 24],
				key_id: "golden-primary".to_string(),
			},
			backup: SignatureBlock {
				algorithm: "SLH-DSA-SHA2-128f".to_string(),
				signature: vec![0x22; 24],
				key_id: "golden-backup".to_string(),
			},
			context: fixture_seal_context(),
			seal_id: "golden-seal-id".to_string(),
		},
	}
}

#[cfg(feature = "session")]
const GOLDEN_PEER_IDENTITY_CERTIFIED_POSTCARD_HEX: &str = "30a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a17676f6c64656e2d70656572406578616d706c652e636f6d01020b676f6c64656e2d636572741a676f6c64656e2d7375626a656374406578616d706c652e636f6d15676f6c64656e2d6361406578616d706c652e636f6d80e2cfaa0680ae99a40f30c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3203c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c0130c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5205c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c0113676f6c64656e2d636f6e74656e742d68617368094d4c2d4453412d3635181111111111111111111111111111111111111111111111110e676f6c64656e2d7072696d61727911534c482d4453412d534841322d31323866182222222222222222222222222222222222222222222222220d676f6c64656e2d6261636b75700e54656d7065722e5365616c2e763114323032362d31302d30385430303a30303a30305a12676f6c64656e406578616d706c652e636f6d0c74656d7065722d302e352e30020e636c617373696669636174696f6e0a544f50205345435245540770726f6a65637416506f73742d5175616e74756d204d6967726174696f6e0e676f6c64656e2d7365616c2d6964";

#[cfg(feature = "session")]
const GOLDEN_SESSION_CHALLENGE_POSTCARD_HEX: &str =
	"027777777777777777777777777777777777777777777777777777777777777777";
#[cfg(feature = "session")]
const GOLDEN_SESSION_INIT_POSTCARD_HEX: &str = "02888e98a8c0e0808101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb30cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc77777777777777777777777777777777777777777777777777777777777777770110e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e120e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e218e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e30ce4e4e4e4e4e4e4e4e4e4e4e40f676f6c64656e2d656e76656c6f7065";
#[cfg(feature = "session")]
const GOLDEN_SESSION_ACCEPT_POSTCARD_HEX: &str = "888e98a8c0e0808101bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc20dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd28f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1811111111111111111111111111111111111111111111111118222222222222222222222222222222222222222222222222";

// endregion: --- Support
