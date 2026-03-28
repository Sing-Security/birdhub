//! Tests for the Certificate Authority module.

#![cfg(all(test, feature = "signatures"))]

#[cfg(test)]
mod tests {
	use crate::ca::{TemperCa, verify_certificate};
	use crate::entropy::TemperEntropy;
	use crate::seal::generate_keypair;
	use alloc::string::ToString;

	// region:    --- Integration Tests

	#[test]
	fn test_ca_issue_and_verify_certificate() {
		// Property: A certificate issued by a CA verifies successfully with that CA's keys.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC0; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");

		let subject_kp = generate_keypair(&mut rng, "alice@example.com").expect("subject keygen failed");

		// -- Exec
		let cert = ca
			.issue_certificate(
				&mut rng,
				"alice@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("issue_certificate failed");

		let valid = ca.verify_certificate(&cert).expect("verify_certificate failed");

		// -- Check
		assert!(valid, "Certificate issued by CA should verify successfully");
		assert_eq!(cert.subject_id, "alice@example.com");
		assert_eq!(cert.issuer_id, "root-ca@example.com");
		assert_eq!(cert.schema_version, 1);
		assert_eq!(cert.cert_id.len(), 64, "cert_id should be 64 hex characters");
	}

	#[test]
	fn test_ca_standalone_verify_certificate() {
		// Property: verify_certificate() with explicit CA public keys produces the same result.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC1; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@test.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "bob@test.com").expect("subject keygen failed");

		// -- Exec
		let cert = ca
			.issue_certificate(
				&mut rng,
				"bob@test.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("issue_certificate failed");

		let valid_via_method = ca.verify_certificate(&cert).expect("verify via method failed");
		let valid_via_fn = verify_certificate(&cert, &ca.keypair.mldsa_public_key, &ca.keypair.slhdsa_public_key)
			.expect("verify via function failed");

		// -- Check
		assert!(valid_via_method, "method-based verification should pass");
		assert!(valid_via_fn, "standalone function verification should pass");
	}

	#[test]
	fn test_ca_verify_wrong_ca_key_fails() {
		// Property: Verifying with a different CA's keys should fail.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC2; 32]);
		let ca_a = TemperCa::new(&mut rng, "ca-a@example.com").expect("CA A creation failed");
		let ca_b = TemperCa::new(&mut rng, "ca-b@example.com").expect("CA B creation failed");
		let subject_kp = generate_keypair(&mut rng, "charlie@example.com").expect("keygen failed");

		// -- Exec
		let cert = ca_a
			.issue_certificate(
				&mut rng,
				"charlie@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("issue_certificate failed");

		// Verify with CA-B's keys (wrong CA)
		let valid = verify_certificate(&cert, &ca_b.keypair.mldsa_public_key, &ca_b.keypair.slhdsa_public_key)
			.expect("verify_certificate should not error");

		// -- Check
		assert!(!valid, "Certificate verified with wrong CA keys should be invalid");
	}

	#[test]
	fn test_ca_verify_tampered_subject_id_fails() {
		// Property: Tampering with the subject_id should invalidate the certificate.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC3; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "dave@example.com").expect("keygen failed");

		// -- Exec
		let mut cert = ca
			.issue_certificate(
				&mut rng,
				"dave@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("issue_certificate failed");

		// Tamper: change the subject_id
		cert.subject_id = "eve@example.com".to_string();

		let valid = ca.verify_certificate(&cert).expect("verify_certificate should not error");

		// -- Check
		assert!(!valid, "Certificate with tampered subject_id should be invalid");
	}

	#[test]
	fn test_ca_verify_tampered_public_key_fails() {
		// Property: Tampering with the subject's public key should invalidate the certificate.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC4; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "frank@example.com").expect("keygen failed");

		// -- Exec
		let mut cert = ca
			.issue_certificate(
				&mut rng,
				"frank@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("issue_certificate failed");

		// Tamper: flip a byte in the subject's public key
		cert.mldsa_public_key[0] ^= 0xFF;

		let valid = ca.verify_certificate(&cert).expect("verify_certificate should not error");

		// -- Check
		assert!(!valid, "Certificate with tampered public key should be invalid");
	}

	// endregion: --- Integration Tests

	// region:    --- Expiry Tests

	#[test]
	fn test_ca_certificate_not_expired_when_not_after_is_zero() {
		// Property: A certificate with not_after == 0 never expires.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC5; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "grace@example.com").expect("keygen failed");

		// -- Exec
		let cert = ca
			.issue_certificate(
				&mut rng,
				"grace@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("issue_certificate failed");

		// -- Check: should never be expired regardless of current time
		assert!(!cert.is_expired(0), "should not be expired at t=0");
		assert!(!cert.is_expired(u64::MAX), "should not be expired at t=MAX");
	}

	#[test]
	fn test_ca_certificate_expires_correctly() {
		// Property: A certificate with not_after set expires after that timestamp.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC6; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "henry@example.com").expect("keygen failed");

		let expiry: u64 = 1_000_000;

		// -- Exec
		let cert = ca
			.issue_certificate(
				&mut rng,
				"henry@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				expiry,
			)
			.expect("issue_certificate failed");

		// -- Check
		assert!(!cert.is_expired(expiry - 1), "should not be expired before not_after");
		assert!(!cert.is_expired(expiry), "should not be expired at not_after exactly");
		assert!(
			cert.is_expired(expiry + 1),
			"should be expired one second after not_after"
		);
	}

	// endregion: --- Expiry Tests

	// region:    --- Serialization Tests

	#[test]
	fn test_ca_certificate_serde_roundtrip() {
		// Property: Serializing and deserializing a certificate produces an identical struct.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC7; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "ivan@example.com").expect("keygen failed");

		let original_cert = ca
			.issue_certificate(
				&mut rng,
				"ivan@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				100,
				999_999,
			)
			.expect("issue_certificate failed");

		// -- Exec
		let bytes = original_cert.to_bytes().expect("serialization failed");
		let restored_cert = crate::ca::TemperCertificate::from_bytes(&bytes).expect("deserialization failed");

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

		// Verify the restored certificate still validates
		let valid = ca.verify_certificate(&restored_cert).expect("verify after restore failed");
		assert!(valid, "restored certificate should still be valid");
	}

	#[test]
	fn test_ca_cert_id_is_deterministic() {
		// Property: Issuing a certificate with identical inputs produces the same cert_id.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC8; 32]);
		let ca = TemperCa::new(&mut rng, "root-ca@example.com").expect("CA creation failed");
		let subject_kp = generate_keypair(&mut rng, "judy@example.com").expect("keygen failed");

		// -- Exec
		// The cert_id is BLAKE3(postcard(cert_content)) — deterministic from fields alone.
		let cert1 = ca
			.issue_certificate(
				&mut rng,
				"judy@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("first issue failed");
		let cert2 = ca
			.issue_certificate(
				&mut rng,
				"judy@example.com",
				&subject_kp.mldsa_public_key,
				&subject_kp.slhdsa_public_key,
				0,
				0,
			)
			.expect("second issue failed");

		// -- Check
		assert_eq!(
			cert1.cert_id, cert2.cert_id,
			"cert_id should be deterministic for same inputs"
		);
		assert_eq!(cert1.cert_id.len(), 64, "cert_id should be 64 hex characters");
	}

	// endregion: --- Serialization Tests

	// region:    --- CA Identity Tests

	#[test]
	fn test_ca_id_matches_keypair_signer_id() {
		// Property: ca.ca_id() matches the keypair's signer_id.

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xC9; 32]);
		let ca = TemperCa::new(&mut rng, "my-ca@example.com").expect("CA creation failed");

		// -- Check
		assert_eq!(ca.ca_id(), "my-ca@example.com");
		assert_eq!(ca.ca_id(), ca.keypair.signer_id);
	}

	// endregion: --- CA Identity Tests
}
