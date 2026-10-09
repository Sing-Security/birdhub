//! Tests for the Certificate Authority module.

#![cfg(all(test, feature = "signatures"))]

use crate::ca::{ConcealmentBinding, SubjectKeys, TemperCa, verify_certificate};
use crate::entropy::TemperEntropy;
use crate::seal::{TemperKeypair, generate_keypair};
use alloc::boxed::Box;
use alloc::string::ToString;

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

/// A deterministic concealment binding. Built from literal bytes rather than a
/// generated envelope keypair so these tests compile — and run — under
/// `signatures` alone, without the `envelope` feature.
fn concealment_fixture(seed: u8) -> ConcealmentBinding {
	ConcealmentBinding {
		schema_version: 1,
		mlkem_public_key: alloc::vec![seed; 48],
		x25519_public_key: alloc::vec![seed.wrapping_add(1); 32],
	}
}

/// The subject keys for `keypair`, with a deterministic concealment binding.
fn keys_fixture(keypair: &TemperKeypair, seed: u8) -> SubjectKeys {
	SubjectKeys {
		mldsa_public_key: keypair.mldsa_public_key.clone(),
		slhdsa_public_key: keypair.slhdsa_public_key.clone(),
		concealment: concealment_fixture(seed),
	}
}

// region:    --- Integration Tests

#[test]
fn test_ca_issue_and_verify_certificate() -> Result<()> {
	// Property: A certificate issued by a CA verifies successfully with that CA's keys.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC0; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;

	let subject_kp = generate_keypair(&mut rng, "alice@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD0);

	// -- Exec
	let cert = ca.issue_certificate(&mut rng, "alice@example.com", &keys, 0, 0)?;

	let valid = ca.verify_certificate(&cert)?;

	// -- Check
	assert!(valid, "Certificate issued by CA should verify successfully");
	assert_eq!(cert.subject_id, "alice@example.com");
	assert_eq!(cert.issuer_id, "root-ca@example.com");
	assert_eq!(cert.schema_version, 2);
	assert_eq!(cert.cert_id.len(), 64, "cert_id should be 64 hex characters");
	assert_eq!(
		cert.subject_keys(),
		keys,
		"certificate should carry the certified subject keys"
	);
	Ok(())
}

#[test]
fn test_ca_standalone_verify_certificate() -> Result<()> {
	// Property: verify_certificate() with explicit CA public keys produces the same result.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC1; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@test.com")?;
	let subject_kp = generate_keypair(&mut rng, "bob@test.com")?;
	let keys = keys_fixture(&subject_kp, 0xD1);

	// -- Exec
	let cert = ca.issue_certificate(&mut rng, "bob@test.com", &keys, 0, 0)?;

	let valid_via_method = ca.verify_certificate(&cert)?;
	let valid_via_fn = verify_certificate(&cert, &ca.keypair.mldsa_public_key, &ca.keypair.slhdsa_public_key)?;

	// -- Check
	assert!(valid_via_method, "method-based verification should pass");
	assert!(valid_via_fn, "standalone function verification should pass");
	Ok(())
}

#[test]
fn test_ca_verify_wrong_ca_key_fails() -> Result<()> {
	// Property: Verifying with a different CA's keys should fail.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC2; 32]);
	let ca_a = TemperCa::new(&mut rng, "ca-a@example.com")?;
	let ca_b = TemperCa::new(&mut rng, "ca-b@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "charlie@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD2);

	// -- Exec
	let cert = ca_a.issue_certificate(&mut rng, "charlie@example.com", &keys, 0, 0)?;

	// Verify with CA-B's keys (wrong CA)
	let valid = verify_certificate(&cert, &ca_b.keypair.mldsa_public_key, &ca_b.keypair.slhdsa_public_key)?;

	// -- Check
	assert!(!valid, "Certificate verified with wrong CA keys should be invalid");
	Ok(())
}

#[test]
fn test_ca_verify_tampered_subject_id_fails() -> Result<()> {
	// Property: Tampering with the subject_id should invalidate the certificate.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC3; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "dave@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD3);

	// -- Exec
	let mut cert = ca.issue_certificate(&mut rng, "dave@example.com", &keys, 0, 0)?;

	// Tamper: change the subject_id
	cert.subject_id = "eve@example.com".to_string();

	let valid = ca.verify_certificate(&cert)?;

	// -- Check
	assert!(!valid, "Certificate with tampered subject_id should be invalid");
	Ok(())
}

#[test]
fn test_ca_verify_tampered_public_key_fails() -> Result<()> {
	// Property: Tampering with the subject's public key should invalidate the certificate.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC4; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "frank@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD4);

	// -- Exec
	let mut cert = ca.issue_certificate(&mut rng, "frank@example.com", &keys, 0, 0)?;

	// Tamper: flip a byte in the subject's public key
	cert.mldsa_public_key[0] ^= 0xFF;

	let valid = ca.verify_certificate(&cert)?;

	// -- Check
	assert!(!valid, "Certificate with tampered public key should be invalid");
	Ok(())
}

#[test]
fn test_ca_verify_tampered_concealment_fails() -> Result<()> {
	// Property: Tampering with either half of the certified concealment key
	// should invalidate the certificate.
	//
	// This is the field the certificate exists to protect at first contact:
	// an initiator seals its identity to the concealment key it reads out of
	// the certificate, so an unauthenticated concealment key is an impostor's
	// key. Each half is flipped in turn — the ML-KEM and X25519 keys are
	// separate inputs to the signed content, so one passing would not
	// exercise the other.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xCB; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "mallory@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD5);

	let mut cert = ca.issue_certificate(&mut rng, "mallory@example.com", &keys, 0, 0)?;

	// -- Exec & Check: the positive control. Without this the tamper
	// assertions below would also pass on a certificate that never verified
	// at all, which is the one failure they are not meant to detect.
	assert!(
		ca.verify_certificate(&cert)?,
		"untampered certificate should verify before the flips"
	);

	// -- Exec & Check: ML-KEM half
	cert.concealment.mlkem_public_key[0] ^= 0xFF;
	assert!(
		!ca.verify_certificate(&cert)?,
		"Certificate with tampered concealment ML-KEM key should be invalid"
	);

	// -- Exec & Check: X25519 half (restore the first flip)
	cert.concealment.mlkem_public_key[0] ^= 0xFF;
	cert.concealment.x25519_public_key[0] ^= 0xFF;
	assert!(
		!ca.verify_certificate(&cert)?,
		"Certificate with tampered concealment X25519 key should be invalid"
	);
	Ok(())
}

// endregion: --- Integration Tests

// region:    --- Expiry Tests

#[test]
fn test_ca_certificate_not_expired_when_not_after_is_zero() -> Result<()> {
	// Property: A certificate with not_after == 0 never expires.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC5; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "grace@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD6);

	// -- Exec
	let cert = ca.issue_certificate(&mut rng, "grace@example.com", &keys, 0, 0)?;

	// -- Check: should never be expired regardless of current time
	assert!(!cert.is_expired(0), "should not be expired at t=0");
	assert!(!cert.is_expired(u64::MAX), "should not be expired at t=MAX");
	Ok(())
}

#[test]
fn test_ca_certificate_expires_correctly() -> Result<()> {
	// Property: A certificate with not_after set expires after that timestamp.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC6; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "henry@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD7);

	let expiry: u64 = 1_000_000;

	// -- Exec
	let cert = ca.issue_certificate(&mut rng, "henry@example.com", &keys, 0, expiry)?;

	// -- Check
	assert!(!cert.is_expired(expiry - 1), "should not be expired before not_after");
	assert!(!cert.is_expired(expiry), "should not be expired at not_after exactly");
	assert!(
		cert.is_expired(expiry + 1),
		"should be expired one second after not_after"
	);
	Ok(())
}

// endregion: --- Expiry Tests

// region:    --- Serialization Tests

#[test]
fn test_ca_certificate_serde_roundtrip() -> Result<()> {
	// Property: Serializing and deserializing a certificate produces an identical struct.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC7; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "ivan@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD8);

	let original_cert = ca.issue_certificate(&mut rng, "ivan@example.com", &keys, 100, 999_999)?;

	// -- Exec
	let bytes = original_cert.to_bytes()?;
	let restored_cert = crate::ca::TemperCertificate::from_bytes(&bytes)?;

	// -- Check
	assert_eq!(original_cert.cert_id, restored_cert.cert_id, "cert_id should match");
	assert_eq!(
		original_cert.subject_id, restored_cert.subject_id,
		"subject_id should match"
	);
	assert_eq!(
		original_cert.issuer_id, restored_cert.issuer_id,
		"issuer_id should match"
	);
	assert_eq!(
		original_cert.not_before, restored_cert.not_before,
		"not_before should match"
	);
	assert_eq!(
		original_cert.not_after, restored_cert.not_after,
		"not_after should match"
	);
	assert_eq!(
		original_cert.mldsa_public_key, restored_cert.mldsa_public_key,
		"mldsa_public_key should match"
	);
	assert_eq!(
		original_cert.slhdsa_public_key, restored_cert.slhdsa_public_key,
		"slhdsa_public_key should match"
	);
	assert_eq!(
		original_cert.concealment, restored_cert.concealment,
		"concealment binding should match"
	);

	// Verify the restored certificate still validates
	let valid = ca.verify_certificate(&restored_cert)?;
	assert!(valid, "restored certificate should still be valid");
	Ok(())
}

#[test]
fn test_ca_cert_id_is_deterministic() -> Result<()> {
	// Property: Issuing a certificate with identical inputs produces the same cert_id.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC8; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "judy@example.com")?;
	let keys = keys_fixture(&subject_kp, 0xD9);

	// -- Exec
	// The cert_id is BLAKE3(postcard(cert_content)) — deterministic from fields alone.
	let cert1 = ca.issue_certificate(&mut rng, "judy@example.com", &keys, 0, 0)?;
	let cert2 = ca.issue_certificate(&mut rng, "judy@example.com", &keys, 0, 0)?;

	// -- Check
	assert_eq!(
		cert1.cert_id, cert2.cert_id,
		"cert_id should be deterministic for same inputs"
	);
	assert_eq!(cert1.cert_id.len(), 64, "cert_id should be 64 hex characters");
	Ok(())
}

#[test]
fn test_ca_cert_id_covers_the_concealment_key() -> Result<()> {
	// Property: cert_id commits to the concealment key, not just the signing
	// keys. Two subjects with everything else identical but different
	// concealment keys must get different ids — an id that ignored the
	// concealment binding would let two certificates for the same signing
	// key be confused for one another by anything keyed on cert_id.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xCA; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "karl@example.com")?;

	let cert_a = ca.issue_certificate(&mut rng, "karl@example.com", &keys_fixture(&subject_kp, 0xAA), 0, 0)?;
	let cert_b = ca.issue_certificate(&mut rng, "karl@example.com", &keys_fixture(&subject_kp, 0xBB), 0, 0)?;

	// -- Check
	assert_ne!(
		cert_a.cert_id, cert_b.cert_id,
		"cert_id should differ when only the concealment key differs"
	);
	Ok(())
}

#[cfg(feature = "envelope")]
#[test]
fn test_ca_concealment_binding_roundtrips_to_public_key() -> Result<()> {
	// Property: a binding taken from a published concealment key rebuilds
	// that exact key after a certificate round trip — including the derived
	// key_id, which is not stored in the certificate and must be recomputed
	// to the same value.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xCE; 32]);
	let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
	let subject_kp = generate_keypair(&mut rng, "nina@example.com")?;
	let concealment_kp = crate::envelope::generate_envelope_keypair(&mut rng)?;
	let concealment_public = crate::envelope::ConcealmentPublicKey::from_keypair(&concealment_kp);

	let keys = SubjectKeys {
		mldsa_public_key: subject_kp.mldsa_public_key.clone(),
		slhdsa_public_key: subject_kp.slhdsa_public_key.clone(),
		concealment: ConcealmentBinding::from_public_key(&concealment_public),
	};
	assert_eq!(
		keys.concealment.to_public_key(),
		concealment_public,
		"binding should rebuild the published key before any signing"
	);

	// -- Exec
	let cert = ca.issue_certificate(&mut rng, "nina@example.com", &keys, 0, 0)?;
	let bytes = cert.to_bytes()?;
	let restored = crate::ca::TemperCertificate::from_bytes(&bytes)?;

	// -- Check
	assert_eq!(
		restored.concealment.to_public_key(),
		concealment_public,
		"certified concealment key should rebuild the publisher's exact key"
	);
	Ok(())
}

// region:    --- CA Identity Tests

#[test]
fn test_ca_id_matches_keypair_signer_id() -> Result<()> {
	// Property: ca.ca_id() matches the keypair's signer_id.

	// -- Setup & Fixtures
	let mut rng = TemperEntropy::from_seed([0xC9; 32]);
	let ca = TemperCa::new(&mut rng, "my-ca@example.com")?;

	// -- Check
	assert_eq!(ca.ca_id(), "my-ca@example.com");
	assert_eq!(ca.ca_id(), ca.keypair.signer_id);
	Ok(())
}

// endregion: --- CA Identity Tests
