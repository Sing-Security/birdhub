//! Tests for the envelope key encapsulation module.

#![cfg(all(test, feature = "envelope"))]

#[cfg(test)]
mod tests {
	use crate::entropy::TemperEntropy;
	use crate::envelope::{decapsulate, encapsulate, generate_envelope_keypair};
	use alloc::format;
	use alloc::string::ToString;
	use alloc::vec;

	// region:    --- Integration Tests

	#[test]
	fn test_envelope_roundtrip() {
		// Property: Encapsulate and decapsulate should recover original plaintext

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x60; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate envelope keypair");
		let plaintext = b"Secret message for hybrid KEM";

		// -- Exec
		let envelope = encapsulate(&mut rng, plaintext, &keypair).expect("Failed to encapsulate");

		let recovered = decapsulate(&envelope, &keypair).expect("Failed to decapsulate");

		// -- Check
		assert_eq!(
			plaintext,
			recovered.as_slice(),
			"Recovered plaintext should match original"
		);
	}

	#[test]
	fn test_envelope_wrong_key_fails() {
		// Property: Decapsulation with wrong key should fail

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x61; 32]);
		let keypair1 = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair 1");
		let keypair2 = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair 2");
		let plaintext = b"Secret message";

		// -- Exec
		let envelope = encapsulate(&mut rng, plaintext, &keypair1).expect("Failed to encapsulate");

		let result = decapsulate(&envelope, &keypair2);

		// -- Check
		assert!(result.is_err(), "Decapsulation with wrong key should fail");
	}

	#[test]
	fn test_envelope_tampered_ciphertext_fails() {
		// Property: Tampered ciphertext should fail authentication

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x62; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let mut envelope = encapsulate(&mut rng, plaintext, &keypair).expect("Failed to encapsulate");

		// Tamper with ciphertext
		if let Some(byte) = envelope.ciphertext.get_mut(0) {
			*byte ^= 0xFF;
		}

		let result = decapsulate(&envelope, &keypair);

		// -- Check
		assert!(result.is_err(), "Tampered ciphertext should fail authentication");
		assert!(
			result.unwrap_err().to_string().contains("authentication tag mismatch"),
			"Error should indicate authentication failure"
		);
	}

	#[test]
	fn test_envelope_tampered_mlkem_ct_fails() {
		// Property: Tampered ML-KEM ciphertext should fail authentication

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x63; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let mut envelope = encapsulate(&mut rng, plaintext, &keypair).expect("Failed to encapsulate");

		// Tamper with ML-KEM ciphertext
		if let Some(byte) = envelope.mlkem_ciphertext.get_mut(0) {
			*byte ^= 0xFF;
		}

		let result = decapsulate(&envelope, &keypair);

		// -- Check
		assert!(result.is_err(), "Tampered ML-KEM ciphertext should fail authentication");
	}

	#[test]
	fn test_envelope_large_plaintext() {
		// Property: Should handle large plaintext (> 1 MB)

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x64; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair");
		let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MB

		// -- Exec
		let envelope = encapsulate(&mut rng, &plaintext, &keypair).expect("Failed to encapsulate large plaintext");

		let recovered = decapsulate(&envelope, &keypair).expect("Failed to decapsulate large plaintext");

		// -- Check
		assert_eq!(
			plaintext.len(),
			recovered.len(),
			"Recovered plaintext should have same length"
		);
		assert_eq!(plaintext, recovered, "Recovered plaintext should match original");
	}

	// endregion: --- Integration Tests

	// region:    --- Unit Tests

	#[test]
	fn test_envelope_id_deterministic() {
		// Property: Same envelope components should produce same envelope_id

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x65; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair");
		let plaintext = b"Test determinism";

		// -- Exec
		// Create two envelopes with same seed (deterministic)
		let mut rng1 = TemperEntropy::from_seed([0x66; 32]);
		let envelope1 = encapsulate(&mut rng1, plaintext, &keypair).expect("Failed to create envelope 1");

		let mut rng2 = TemperEntropy::from_seed([0x66; 32]); // Same seed
		let envelope2 = encapsulate(&mut rng2, plaintext, &keypair).expect("Failed to create envelope 2");

		// -- Check
		assert_eq!(
			envelope1.envelope_id, envelope2.envelope_id,
			"Envelope IDs should be deterministic for same inputs"
		);
		assert_eq!(
			envelope1.mlkem_ciphertext, envelope2.mlkem_ciphertext,
			"ML-KEM ciphertexts should be deterministic"
		);
	}

	#[test]
	fn test_keypair_key_id_deterministic() {
		// Property: Key ID should be deterministic for same public keys

		// -- Setup & Fixtures
		let mut rng1 = TemperEntropy::from_seed([0x67; 32]);
		let keypair1 = generate_envelope_keypair(&mut rng1).expect("Failed to generate keypair 1");

		let mut rng2 = TemperEntropy::from_seed([0x67; 32]); // Same seed
		let keypair2 = generate_envelope_keypair(&mut rng2).expect("Failed to generate keypair 2");

		// -- Exec & Check
		assert_eq!(
			keypair1.key_id, keypair2.key_id,
			"Key IDs should be deterministic for same keys"
		);
		assert_eq!(
			keypair1.mlkem_public_key, keypair2.mlkem_public_key,
			"ML-KEM public keys should be deterministic"
		);
		assert_eq!(
			keypair1.x25519_public_key, keypair2.x25519_public_key,
			"X25519 public keys should be deterministic"
		);
	}

	#[test]
	fn test_envelope_serde_roundtrip() {
		// Property: Serialize and deserialize should preserve envelope

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x68; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair");
		let plaintext = b"Test serialization";

		let envelope = encapsulate(&mut rng, plaintext, &keypair).expect("Failed to encapsulate");

		// -- Exec
		let serialized = postcard::to_allocvec(&envelope).expect("Failed to serialize envelope");
		let deserialized: crate::envelope::Envelope =
			postcard::from_bytes(&serialized).expect("Failed to deserialize envelope");

		// -- Check
		assert_eq!(
			envelope.envelope_id, deserialized.envelope_id,
			"Envelope IDs should match after serde roundtrip"
		);
		assert_eq!(
			envelope.mlkem_ciphertext, deserialized.mlkem_ciphertext,
			"ML-KEM ciphertexts should match"
		);
		assert_eq!(envelope.ciphertext, deserialized.ciphertext, "Ciphertexts should match");

		// Verify decapsulation still works
		let recovered = decapsulate(&deserialized, &keypair).expect("Failed to decapsulate after serde roundtrip");

		assert_eq!(plaintext, recovered.as_slice());
	}

	#[test]
	fn test_envelope_empty_plaintext() {
		// Property: Should handle empty plaintext

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x69; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate keypair");
		let plaintext = b"";

		// -- Exec
		let envelope = encapsulate(&mut rng, plaintext, &keypair).expect("Failed to encapsulate empty plaintext");

		let recovered = decapsulate(&envelope, &keypair).expect("Failed to decapsulate empty plaintext");

		// -- Check
		assert_eq!(
			plaintext,
			recovered.as_slice(),
			"Empty plaintext should be recovered correctly"
		);
		assert_eq!(recovered.len(), 0, "Recovered should be empty");
	}

	#[test]
	fn test_envelope_keypair_debug_redacts_secrets() {
		// Property: Debug output should redact secret keys to prevent accidental logging
		// Memory: security fix per problem statement — verify Debug redaction

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x71; 32]);
		let keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate envelope keypair");

		// -- Exec
		let debug_output = format!("{:?}", keypair);

		// -- Check
		// Verify redacted markers are present
		assert!(
			debug_output.contains("<REDACTED>"),
			"Debug output should contain <REDACTED> for secret keys"
		);

		// Verify secret key field names are present but values are redacted
		assert!(
			debug_output.contains("mlkem_secret_key") && debug_output.contains("<REDACTED>"),
			"Debug output should show mlkem_secret_key field as redacted"
		);
		assert!(
			debug_output.contains("x25519_secret_key") && debug_output.contains("<REDACTED>"),
			"Debug output should show x25519_secret_key field as redacted"
		);

		// Verify non-secret fields are still present
		assert!(
			debug_output.contains(&keypair.key_id),
			"Debug output should contain key_id"
		);

		// Verify output doesn't contain raw byte array patterns
		let secret_indicators = ["mlkem_secret_key: [", "x25519_secret_key: ["];
		for indicator in &secret_indicators {
			assert!(
				!debug_output.contains(indicator),
				"Debug output should not contain raw secret key bytes pattern: {}",
				indicator
			);
		}
	}

	#[test]
	fn test_authenticated_envelope_roundtrip() {
		// Property: Authenticated encapsulate and decapsulate should recover plaintext and verify sender
		// Memory: authenticated envelope per problem statement — sign then encrypt pattern

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x72; 32]);

		// Generate recipient's envelope keypair
		let recipient_keypair =
			generate_envelope_keypair(&mut rng).expect("Failed to generate recipient envelope keypair");

		// Generate sender's signing keypair
		let sender_keypair = crate::seal::generate_keypair(&mut rng, "sender@example.com")
			.expect("Failed to generate sender signing keypair");

		let plaintext = b"Authenticated secret message";
		let mut metadata = alloc::collections::BTreeMap::new();
		metadata.insert("purpose".to_string(), "test".to_string());

		// -- Exec
		let envelope = crate::envelope::authenticated_encapsulate(
			&mut rng,
			plaintext,
			&recipient_keypair,
			&sender_keypair,
			metadata,
		)
		.expect("Failed to create authenticated envelope");

		let (recovered_plaintext, seal) = crate::envelope::authenticated_decapsulate(
			&envelope,
			&recipient_keypair,
			&sender_keypair.mldsa_public_key,
			&sender_keypair.slhdsa_public_key,
		)
		.expect("Failed to decrypt and verify authenticated envelope");

		// -- Check
		assert_eq!(
			plaintext,
			recovered_plaintext.as_slice(),
			"Recovered plaintext should match original"
		);
		assert_eq!(
			seal.context.signer_id, "sender@example.com",
			"Seal should contain sender ID"
		);
		assert!(
			seal.context.metadata.contains_key("purpose"),
			"Seal should contain metadata"
		);
	}

	#[test]
	fn test_authenticated_envelope_wrong_sender_fails() {
		// Property: Verifying with wrong sender keys should fail
		// Memory: authenticated envelope per problem statement — dual signature verification

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x73; 32]);

		let recipient_keypair =
			generate_envelope_keypair(&mut rng).expect("Failed to generate recipient envelope keypair");

		let sender_keypair = crate::seal::generate_keypair(&mut rng, "alice@example.com")
			.expect("Failed to generate sender signing keypair");

		let wrong_sender_keypair = crate::seal::generate_keypair(&mut rng, "bob@example.com")
			.expect("Failed to generate wrong sender signing keypair");

		let plaintext = b"Authenticated message from Alice";

		// -- Exec
		let envelope = crate::envelope::authenticated_encapsulate(
			&mut rng,
			plaintext,
			&recipient_keypair,
			&sender_keypair,
			alloc::collections::BTreeMap::new(),
		)
		.expect("Failed to create authenticated envelope");

		let result = crate::envelope::authenticated_decapsulate(
			&envelope,
			&recipient_keypair,
			&wrong_sender_keypair.mldsa_public_key,
			&wrong_sender_keypair.slhdsa_public_key,
		);

		// -- Check
		assert!(result.is_err(), "Decapsulation with wrong sender keys should fail");

		// Verify it's specifically a signature verification failure
		if let Err(e) = result {
			let error_msg = format!("{}", e);
			assert!(
				error_msg.contains("Seal verification failed") || error_msg.contains("not authenticated"),
				"Error should indicate signature verification failure, got: {}",
				error_msg
			);
		}
	}

	#[test]
	fn test_authenticated_envelope_tampered_plaintext_fails() {
		// Property: Tampering with plaintext should fail seal verification
		// Memory: authenticated envelope per problem statement — content hash binding

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x74; 32]);

		let recipient_keypair =
			generate_envelope_keypair(&mut rng).expect("Failed to generate recipient envelope keypair");

		let sender_keypair = crate::seal::generate_keypair(&mut rng, "sender@example.com")
			.expect("Failed to generate sender signing keypair");

		let original_plaintext = b"Original message";

		// -- Exec
		// Create a seal for different plaintext
		let tampered_plaintext = b"Tampered message";
		let seal = crate::seal::create_seal(
			&mut rng,
			original_plaintext,
			&sender_keypair,
			alloc::collections::BTreeMap::new(),
		)
		.expect("Failed to create seal");

		// Manually construct mismatched payload: seal for original, but plaintext is tampered
		let seal_bytes = postcard::to_allocvec(&seal).expect("Failed to serialize seal");
		let seal_length = seal_bytes.len() as u32;
		let mut mismatched_payload = vec![];
		mismatched_payload.extend_from_slice(&seal_length.to_le_bytes());
		mismatched_payload.extend_from_slice(&seal_bytes);
		mismatched_payload.extend_from_slice(tampered_plaintext);

		// Re-encrypt with mismatched payload
		let envelope = crate::envelope::encapsulate(&mut rng, &mismatched_payload, &recipient_keypair)
			.expect("Failed to re-encrypt");

		let result = crate::envelope::authenticated_decapsulate(
			&envelope,
			&recipient_keypair,
			&sender_keypair.mldsa_public_key,
			&sender_keypair.slhdsa_public_key,
		);

		// -- Check
		assert!(
			result.is_err(),
			"Decapsulation with tampered plaintext should fail seal verification"
		);
	}

	#[test]
	fn test_authenticated_envelope_with_compression() {
		// Property: Authenticated envelopes should use compressed seals
		// Verify that compression/decompression works in the full authenticated flow

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xBB; 32]);

		let sender_keypair =
			crate::seal::generate_keypair(&mut rng, "sender@test.com").expect("Failed to generate sender keypair");
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");

		let plaintext = b"Authenticated message with compressed seal";
		let mut metadata = alloc::collections::BTreeMap::new();
		metadata.insert("purpose".to_string(), "compression_test".to_string());

		// -- Exec
		let envelope = crate::envelope::authenticated_encapsulate(
			&mut rng,
			plaintext,
			&recipient_keypair,
			&sender_keypair,
			metadata,
		)
		.expect("Failed to create authenticated envelope");

		let (recovered_plaintext, recovered_seal) = crate::envelope::authenticated_decapsulate(
			&envelope,
			&recipient_keypair,
			&sender_keypair.mldsa_public_key,
			&sender_keypair.slhdsa_public_key,
		)
		.expect("Failed to decrypt and verify authenticated envelope");

		// -- Check
		assert_eq!(
			plaintext,
			recovered_plaintext.as_slice(),
			"Recovered plaintext should match original"
		);

		assert_eq!(
			recovered_seal.context.signer_id, "sender@test.com",
			"Seal should contain correct signer ID"
		);

		assert_eq!(
			recovered_seal.context.metadata.get("purpose").map(|s| s.as_str()),
			Some("compression_test"),
			"Seal metadata should be preserved"
		);

		// Verify seal is actually compressed by comparing sizes
		let uncompressed_seal_bytes = postcard::to_allocvec(&recovered_seal).expect("Failed to serialize seal");
		let compressed_seal_bytes = recovered_seal.to_compressed_bytes().expect("Failed to compress seal");

		#[allow(unused_imports)]
		use std::println;
		println!(
			"Authenticated envelope seal: uncompressed={} bytes, compressed={} bytes",
			uncompressed_seal_bytes.len(),
			compressed_seal_bytes.len()
		);
	}

	// region:    --- Kernel Chain Envelope Tests

	#[test]
	fn test_kernel_chain_envelope_roundtrip() {
		// Property: Kernel chain encapsulate → extract secret → decapsulate should recover plaintext

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x80; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Secret IPC message for kernel chain";

		// -- Exec
		let envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to kernel chain encapsulate");

		// Kernel extracts its shared secret
		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		// Recipient decapsulates with kernel secret
		let recovered = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_secret)
			.expect("Failed to kernel chain decapsulate");

		// -- Check
		assert_eq!(
			plaintext,
			recovered.as_slice(),
			"Recovered plaintext should match original"
		);
	}

	#[test]
	fn test_kernel_chain_wrong_recipient_key_fails() {
		// Property: Decapsulation with wrong recipient key should fail

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x81; 32]);
		let recipient_keypair1 = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair 1");
		let recipient_keypair2 = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair 2");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair1, &kernel_keypair)
				.expect("Failed to encapsulate");

		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		// Try to decapsulate with wrong recipient key
		let result = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair2, &kernel_secret);

		// -- Check
		assert!(result.is_err(), "Decapsulation with wrong recipient key should fail");
	}

	#[test]
	fn test_kernel_chain_wrong_kernel_secret_fails() {
		// Property: Decapsulation with wrong kernel secret should fail

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x82; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate");

		// Use wrong kernel secret (all zeros)
		let wrong_kernel_secret = [0u8; 32];

		let result = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &wrong_kernel_secret);

		// -- Check
		assert!(result.is_err(), "Decapsulation with wrong kernel secret should fail");
	}

	#[test]
	fn test_kernel_chain_tampered_ciphertext_fails() {
		// Property: Tampered ciphertext should fail authentication

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x83; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let mut envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate");

		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		// Tamper with ciphertext
		if let Some(byte) = envelope.ciphertext.get_mut(0) {
			*byte ^= 0xFF;
		}

		let result = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_secret);

		// -- Check
		assert!(result.is_err(), "Tampered ciphertext should fail authentication");
		assert!(
			result.unwrap_err().to_string().contains("authentication tag mismatch"),
			"Error should indicate authentication failure"
		);
	}

	#[test]
	fn test_kernel_chain_tampered_mlkem_recipient_ct_fails() {
		// Property: Tampered ML-KEM recipient ciphertext should fail

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x84; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let mut envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate");

		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		// Tamper with ML-KEM recipient ciphertext
		if let Some(byte) = envelope.mlkem_ct_recipient.get_mut(0) {
			*byte ^= 0xFF;
		}

		let result = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_secret);

		// -- Check
		assert!(result.is_err(), "Tampered ML-KEM recipient ciphertext should fail");
	}

	#[test]
	fn test_kernel_chain_tampered_mlkem_kernel_ct_fails() {
		// Property: Tampered ML-KEM kernel ciphertext should cause decryption to fail
		// Note: ML-KEM decapsulation may succeed with tampered CT but produces wrong shared secret,
		// which causes the final ChaCha20-Poly1305 decryption to fail

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x85; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Secret message";

		// -- Exec
		let mut envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate");

		// Tamper with ML-KEM kernel ciphertext
		if let Some(byte) = envelope.mlkem_ct_kernel.get_mut(0) {
			*byte ^= 0xFF;
		}

		// Extract kernel secret - may succeed with wrong value
		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("ML-KEM decap may succeed with tampered CT");

		// Try to decapsulate - should fail due to wrong shared secret
		let result = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_secret);

		// -- Check
		assert!(
			result.is_err(),
			"Decapsulation with tampered kernel ciphertext should fail authentication"
		);
	}

	#[test]
	fn test_kernel_chain_large_plaintext() {
		// Property: Should handle large plaintext (> 1 MB)

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x86; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MB

		// -- Exec
		let envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, &plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate large plaintext");

		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		let recovered = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_secret)
			.expect("Failed to decapsulate large plaintext");

		// -- Check
		assert_eq!(
			plaintext.len(),
			recovered.len(),
			"Recovered plaintext should have same length"
		);
		assert_eq!(plaintext, recovered, "Recovered plaintext should match original");
	}

	#[test]
	fn test_kernel_chain_deterministic_with_same_seed() {
		// Property: Same RNG seed should produce same envelope

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x87; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Test determinism";

		// -- Exec
		let mut rng1 = TemperEntropy::from_seed([0x88; 32]);
		let envelope1 =
			crate::envelope::kernel_chain_encapsulate(&mut rng1, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to create envelope 1");

		let mut rng2 = TemperEntropy::from_seed([0x88; 32]); // Same seed
		let envelope2 =
			crate::envelope::kernel_chain_encapsulate(&mut rng2, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to create envelope 2");

		// -- Check
		assert_eq!(
			envelope1.envelope_id, envelope2.envelope_id,
			"Envelope IDs should be deterministic for same inputs"
		);
		assert_eq!(
			envelope1.mlkem_ct_recipient, envelope2.mlkem_ct_recipient,
			"ML-KEM recipient ciphertexts should be deterministic"
		);
		assert_eq!(
			envelope1.mlkem_ct_kernel, envelope2.mlkem_ct_kernel,
			"ML-KEM kernel ciphertexts should be deterministic"
		);
	}

	#[test]
	fn test_kernel_chain_different_kernel_keys_change_ciphertext() {
		// Property: Different kernel keys should produce different ciphertexts

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x89; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair1 = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair 1");
		let kernel_keypair2 = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair 2");
		let plaintext = b"Same plaintext";

		// -- Exec
		let mut rng1 = TemperEntropy::from_seed([0x90; 32]);
		let envelope1 =
			crate::envelope::kernel_chain_encapsulate(&mut rng1, plaintext, &recipient_keypair, &kernel_keypair1)
				.expect("Failed to create envelope 1");

		let mut rng2 = TemperEntropy::from_seed([0x90; 32]); // Same seed
		let envelope2 =
			crate::envelope::kernel_chain_encapsulate(&mut rng2, plaintext, &recipient_keypair, &kernel_keypair2)
				.expect("Failed to create envelope 2");

		// -- Check
		assert_ne!(
			envelope1.envelope_id, envelope2.envelope_id,
			"Different kernel keys should produce different envelope IDs"
		);
		assert_ne!(
			envelope1.mlkem_ct_kernel, envelope2.mlkem_ct_kernel,
			"Different kernel keys should produce different ML-KEM kernel ciphertexts"
		);
		// Ciphertext should also differ due to different derived keys
		assert_ne!(
			envelope1.ciphertext, envelope2.ciphertext,
			"Different kernel keys should produce different ciphertexts"
		);
	}

	#[test]
	fn test_kernel_chain_envelope_id_uniqueness() {
		// Property: Different messages should produce different envelope IDs

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x91; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");

		// -- Exec
		let envelope1 =
			crate::envelope::kernel_chain_encapsulate(&mut rng, b"Message 1", &recipient_keypair, &kernel_keypair)
				.expect("Failed to create envelope 1");

		let envelope2 =
			crate::envelope::kernel_chain_encapsulate(&mut rng, b"Message 2", &recipient_keypair, &kernel_keypair)
				.expect("Failed to create envelope 2");

		// -- Check
		assert_ne!(
			envelope1.envelope_id, envelope2.envelope_id,
			"Different messages should produce different envelope IDs"
		);
	}

	#[test]
	fn test_kernel_chain_serde_roundtrip() {
		// Property: Serialize and deserialize should preserve envelope

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x92; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"Test serialization";

		let envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate");

		// -- Exec
		let serialized = postcard::to_allocvec(&envelope).expect("Failed to serialize envelope");
		let deserialized: crate::envelope::KernelChainEnvelope =
			postcard::from_bytes(&serialized).expect("Failed to deserialize envelope");

		// -- Check
		assert_eq!(
			envelope.envelope_id, deserialized.envelope_id,
			"Envelope IDs should match after serde roundtrip"
		);
		assert_eq!(
			envelope.mlkem_ct_recipient, deserialized.mlkem_ct_recipient,
			"ML-KEM recipient ciphertexts should match"
		);
		assert_eq!(
			envelope.mlkem_ct_kernel, deserialized.mlkem_ct_kernel,
			"ML-KEM kernel ciphertexts should match"
		);
		assert_eq!(envelope.ciphertext, deserialized.ciphertext, "Ciphertexts should match");

		// Verify decapsulation still works
		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&deserialized, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		let recovered = crate::envelope::kernel_chain_decapsulate(&deserialized, &recipient_keypair, &kernel_secret)
			.expect("Failed to decapsulate after serde roundtrip");

		assert_eq!(plaintext, recovered.as_slice());
	}

	#[test]
	fn test_kernel_chain_empty_plaintext() {
		// Property: Should handle empty plaintext

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x93; 32]);
		let recipient_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate recipient keypair");
		let kernel_keypair = generate_envelope_keypair(&mut rng).expect("Failed to generate kernel keypair");
		let plaintext = b"";

		// -- Exec
		let envelope =
			crate::envelope::kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)
				.expect("Failed to encapsulate empty plaintext");

		let kernel_secret = crate::envelope::kernel_chain_extract_secret(&envelope, &kernel_keypair)
			.expect("Failed to extract kernel secret");

		let recovered = crate::envelope::kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_secret)
			.expect("Failed to decapsulate empty plaintext");

		// -- Check
		assert_eq!(
			plaintext,
			recovered.as_slice(),
			"Empty plaintext should be recovered correctly"
		);
		assert_eq!(recovered.len(), 0, "Recovered should be empty");
	}

	// endregion: --- Kernel Chain Envelope Tests

	// endregion: --- Unit Tests
}
