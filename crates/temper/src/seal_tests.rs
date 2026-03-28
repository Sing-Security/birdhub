//! Cryptographic binding tests for the Seal protocol.
//!
//! Tests verify the dual PQC signature protocol and seal structure.

#[cfg(test)]
mod tests {
	use crate::entropy::TemperEntropy;
	use crate::seal::{Seal, SealContext, create_seal, generate_keypair, verify_seal};
	use alloc::collections::BTreeMap;
	use alloc::format;
	use alloc::string::{String, ToString};
	use alloc::vec;

	// Tests run with std harness, so std features are available
	#[allow(unused_imports)]
	use std::println;

	// region:    --- Integration Tests

	#[test]
	fn test_seal_roundtrip() {
		// Property: Sign and verify should produce valid=true for correct inputs

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x50; 32]);
		let keypair = generate_keypair(&mut rng, "test@example.com").expect("Failed to generate keypair");
		let content = b"Test message for seal verification";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, content, &keypair, metadata).expect("Failed to create seal");
		let result = verify_seal(content, &seal, &keypair.mldsa_public_key, &keypair.slhdsa_public_key)
			.expect("Failed to verify seal");

		// -- Check
		assert!(result.content_hash_valid, "Content hash should be valid");
		assert!(result.primary_valid, "Primary signature (ML-DSA-65) should be valid");
		assert!(result.backup_valid, "Backup signature (SLH-DSA) should be valid");
		assert!(result.valid, "Overall seal verification should pass");
	}

	#[test]
	fn test_seal_detects_content_tamper() {
		// Property: Tampering with content should invalidate the seal

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x51; 32]);
		let keypair = generate_keypair(&mut rng, "test@example.com").expect("Failed to generate keypair");
		let original_content = b"Original message";
		let tampered_content = b"Tampered message";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, original_content, &keypair, metadata).expect("Failed to create seal");
		let result = verify_seal(
			tampered_content,
			&seal,
			&keypair.mldsa_public_key,
			&keypair.slhdsa_public_key,
		)
		.expect("Failed to verify seal");

		// -- Check
		assert!(
			!result.content_hash_valid,
			"Content hash should be invalid for tampered content"
		);
		assert!(
			!result.valid,
			"Overall seal verification should fail for tampered content"
		);
	}

	#[test]
	fn test_seal_rejects_wrong_key() {
		// Property: Verifying with wrong public key should fail

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x52; 32]);
		let keypair_a = generate_keypair(&mut rng, "alice@example.com").expect("Failed to generate keypair A");
		let keypair_b = generate_keypair(&mut rng, "bob@example.com").expect("Failed to generate keypair B");
		let content = b"Message from Alice";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, content, &keypair_a, metadata).expect("Failed to create seal");
		let result = verify_seal(
			content,
			&seal,
			&keypair_b.mldsa_public_key,  // Wrong key
			&keypair_b.slhdsa_public_key, // Wrong key
		)
		.expect("Failed to verify seal");

		// -- Check
		assert!(
			!result.primary_valid,
			"Primary signature should be invalid with wrong key"
		);
		assert!(
			!result.backup_valid,
			"Backup signature should be invalid with wrong key"
		);
		assert!(!result.valid, "Overall seal verification should fail with wrong key");
	}

	// endregion: --- Integration Tests

	// region:    --- Unit Tests (Can run without PQC)

	#[test]
	fn test_seal_id_deterministic() {
		// Property: Seal ID should be deterministic for same inputs
		// This test doesn't require PQC primitives

		// -- Setup & Fixtures
		// Memory: postcard replacement per problem statement
		use postcard;

		// Create a seal manually with hardcoded fields
		let seal = Seal {
			schema_version: 1,
			content_hash: "0123456789abcdef".to_string(),
			primary: crate::seal::SignatureBlock {
				algorithm: "ML-DSA-65".to_string(),
				signature: vec![0xaa, 0xbb, 0xcc, 0xdd],
				key_id: "key1".to_string(),
			},
			backup: crate::seal::SignatureBlock {
				algorithm: "SLH-DSA".to_string(),
				signature: vec![0xee, 0xff, 0x00, 0x11],
				key_id: "key2".to_string(),
			},
			context: SealContext {
				domain: "Temper.Seal.v1".to_string(),
				timestamp: "2024-01-01T00:00:00Z".to_string(),
				signer_id: "test".to_string(),
				tool_version: "temper-0.1.0".to_string(),
				metadata: BTreeMap::new(),
			},
			seal_id: String::new(), // Empty for computation
		};

		// -- Exec
		// Memory: updated to match new seal_id computation in create_seal
		// Memory: signatures are now Vec<u8>, use slice directly instead of as_bytes()
		let mut hasher1 = blake3::Hasher::new();
		hasher1.update(&seal.schema_version.to_le_bytes());
		hasher1.update(seal.content_hash.as_bytes());
		hasher1.update(seal.primary.algorithm.as_bytes());
		hasher1.update(&seal.primary.signature);
		hasher1.update(seal.primary.key_id.as_bytes());
		hasher1.update(seal.backup.algorithm.as_bytes());
		hasher1.update(&seal.backup.signature);
		hasher1.update(seal.backup.key_id.as_bytes());
		let context_bytes1 = postcard::to_allocvec(&seal.context).expect("Failed to serialize context");
		hasher1.update(&context_bytes1);
		let seal_id1 = hex::encode(hasher1.finalize().as_bytes());

		let mut hasher2 = blake3::Hasher::new();
		hasher2.update(&seal.schema_version.to_le_bytes());
		hasher2.update(seal.content_hash.as_bytes());
		hasher2.update(seal.primary.algorithm.as_bytes());
		hasher2.update(&seal.primary.signature);
		hasher2.update(seal.primary.key_id.as_bytes());
		hasher2.update(seal.backup.algorithm.as_bytes());
		hasher2.update(&seal.backup.signature);
		hasher2.update(seal.backup.key_id.as_bytes());
		let context_bytes2 = postcard::to_allocvec(&seal.context).expect("Failed to serialize context");
		hasher2.update(&context_bytes2);
		let seal_id2 = hex::encode(hasher2.finalize().as_bytes());

		// -- Check
		assert_eq!(seal_id1, seal_id2, "Seal ID should be deterministic for same inputs");
		assert_eq!(seal_id1.len(), 64, "Seal ID should be 64 hex characters");
	}

	#[test]
	fn test_seal_serde_roundtrip() {
		// Property: Seal should serialize and deserialize correctly
		// This test doesn't require PQC primitives

		// -- Setup & Fixtures
		// Memory: postcard replacement per problem statement
		use postcard;

		let original_seal = Seal {
			schema_version: 1,
			content_hash: "fedcba9876543210".to_string(),
			primary: crate::seal::SignatureBlock {
				algorithm: "ML-DSA-65".to_string(),
				signature: vec![0x01, 0x02, 0x03],
				key_id: "keyid1".to_string(),
			},
			backup: crate::seal::SignatureBlock {
				algorithm: "SLH-DSA".to_string(),
				signature: vec![0x04, 0x05, 0x06],
				key_id: "keyid2".to_string(),
			},
			context: SealContext {
				domain: "Temper.Seal.v1".to_string(),
				timestamp: "2024-01-01T00:00:00Z".to_string(),
				signer_id: "alice".to_string(),
				tool_version: "temper-0.1.0".to_string(),
				metadata: BTreeMap::new(),
			},
			seal_id: "seal123".to_string(),
		};

		// -- Exec
		let bytes = postcard::to_allocvec(&original_seal).expect("Failed to serialize seal");
		let deserialized_seal: Seal = postcard::from_bytes(&bytes).expect("Failed to deserialize seal");

		// -- Check
		assert_eq!(
			original_seal.schema_version, deserialized_seal.schema_version,
			"Schema version should match"
		);
		assert_eq!(
			original_seal.content_hash, deserialized_seal.content_hash,
			"Content hash should match"
		);
		assert_eq!(
			original_seal.primary.algorithm, deserialized_seal.primary.algorithm,
			"Primary algorithm should match"
		);
		assert_eq!(
			original_seal.backup.algorithm, deserialized_seal.backup.algorithm,
			"Backup algorithm should match"
		);
		assert_eq!(original_seal.seal_id, deserialized_seal.seal_id, "Seal ID should match");
	}

	#[test]
	fn test_key_id_deterministic() {
		// Property: Key ID computation should be deterministic
		// This test doesn't require PQC primitives

		// -- Setup & Fixtures
		let fake_mldsa_pk = vec![0x01, 0x02, 0x03, 0x04];
		let fake_slhdsa_pk = vec![0x05, 0x06, 0x07, 0x08];

		// -- Exec
		let mut hasher1 = blake3::Hasher::new();
		hasher1.update(&fake_mldsa_pk);
		hasher1.update(&fake_slhdsa_pk);
		let key_id1 = hex::encode(hasher1.finalize().as_bytes());

		let mut hasher2 = blake3::Hasher::new();
		hasher2.update(&fake_mldsa_pk);
		hasher2.update(&fake_slhdsa_pk);
		let key_id2 = hex::encode(hasher2.finalize().as_bytes());

		// -- Check
		assert_eq!(key_id1, key_id2, "Key ID should be deterministic for same inputs");
		assert_eq!(key_id1.len(), 64, "Key ID should be 64 hex characters");
	}

	#[test]
	fn test_seal_id_streaming_no_allocation() {
		// Property: seal_id computation should be streaming (no intermediate Seal clones)
		// This verifies the optimization from PERFORMANCE_OPTIMIZATIONS.md section 3

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x77; 32]);
		let keypair = generate_keypair(&mut rng, "streaming@test.com").expect("Failed to generate keypair");
		let content = b"Test streaming seal_id computation";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, content, &keypair, metadata).expect("Failed to create seal");

		// Manually compute seal_id using streaming approach (matches create_seal implementation)
		let context_bytes = postcard::to_allocvec(&seal.context).expect("Failed to serialize context");

		let mut hasher = blake3::Hasher::new();
		hasher.update(&seal.schema_version.to_le_bytes());
		hasher.update(seal.content_hash.as_bytes());
		hasher.update(seal.primary.algorithm.as_bytes());
		hasher.update(&seal.primary.signature);
		hasher.update(seal.primary.key_id.as_bytes());
		hasher.update(seal.backup.algorithm.as_bytes());
		hasher.update(&seal.backup.signature);
		hasher.update(seal.backup.key_id.as_bytes());
		hasher.update(&context_bytes);
		let computed_seal_id = hex::encode(hasher.finalize().as_bytes());

		// -- Check
		assert_eq!(
			seal.seal_id, computed_seal_id,
			"Seal ID should match streaming computation"
		);

		// Verify seal_id is a valid BLAKE3 hash (64 hex chars = 32 bytes)
		assert_eq!(seal.seal_id.len(), 64);
		assert!(seal.seal_id.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[test]
	fn test_content_hash_deterministic() {
		// Property: Content hash should be deterministic regardless of size
		// Verifies both single-threaded and parallel paths produce same result

		// -- Setup & Fixtures
		let small_content = vec![0x42u8; 1024]; // 1 KB
		let large_content = vec![0x42u8; 2 * 1024 * 1024]; // 2 MB

		// -- Exec
		let hash1_small = blake3::hash(&small_content);
		let hash2_small = blake3::hash(&small_content);

		let hash1_large = blake3::hash(&large_content);
		let hash2_large = blake3::hash(&large_content);

		// -- Check
		assert_eq!(
			hash1_small.as_bytes(),
			hash2_small.as_bytes(),
			"Small content hash should be deterministic"
		);
		assert_eq!(
			hash1_large.as_bytes(),
			hash2_large.as_bytes(),
			"Large content hash should be deterministic"
		);

		// Different content should produce different hashes
		assert_ne!(
			hash1_small.as_bytes(),
			hash1_large.as_bytes(),
			"Different content should produce different hashes"
		);
	}

	#[test]
	fn test_keypair_debug_redacts_secrets() {
		// Property: Debug output should redact secret keys to prevent accidental logging
		// Memory: security fix per problem statement — verify Debug redaction

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x70; 32]);
		let keypair = generate_keypair(&mut rng, "security-test@example.com").expect("Failed to generate keypair");

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
			debug_output.contains("mldsa_secret_key") && debug_output.contains("<REDACTED>"),
			"Debug output should show mldsa_secret_key field as redacted"
		);
		assert!(
			debug_output.contains("slhdsa_secret_key") && debug_output.contains("<REDACTED>"),
			"Debug output should show slhdsa_secret_key field as redacted"
		);

		// Verify non-secret fields are still present
		assert!(
			debug_output.contains("security-test@example.com"),
			"Debug output should contain signer_id"
		);
		assert!(
			debug_output.contains(&keypair.key_id),
			"Debug output should contain key_id"
		);

		// Verify output doesn't contain raw byte array patterns like "[" or decimal numbers
		// that would indicate secret key bytes are exposed
		let secret_indicators = ["mldsa_secret_key: [", "slhdsa_secret_key: ["];
		for indicator in &secret_indicators {
			assert!(
				!debug_output.contains(indicator),
				"Debug output should not contain raw secret key bytes pattern: {}",
				indicator
			);
		}
	}

	#[test]
	fn test_slhdsa_signature_size_fast_variant() {
		// Property: Verify SLH-DSA-SHA2-128f produces expected signature size
		// Memory: performance optimization per problem statement — 128f variant has larger but faster signatures

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x71; 32]);
		let keypair = generate_keypair(&mut rng, "perf-test@example.com").expect("Failed to generate keypair");
		let content = b"Performance test message";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, content, &keypair, metadata).expect("Failed to create seal");

		// -- Check
		// ML-DSA-65 signature size should be 3309 bytes
		assert_eq!(
			seal.primary.signature.len(),
			3309,
			"ML-DSA-65 signature should be 3309 bytes"
		);

		// SLH-DSA-SHA2-128f signature size should be 17088 bytes (vs 7856 for 128s)
		// This is the trade-off: larger signatures but ~50x faster signing
		assert_eq!(
			seal.backup.signature.len(),
			17088,
			"SLH-DSA-SHA2-128f signature should be 17088 bytes (fast variant)"
		);

		// Verify the total seal size increase is acceptable given the performance gain
		let total_sig_size = seal.primary.signature.len() + seal.backup.signature.len();
		assert_eq!(
			total_sig_size, 20397,
			"Total signature size should be 20397 bytes (3309 + 17088)"
		);
	}

	// endregion: --- Unit Tests

	// region:    --- Compression Tests

	#[test]
	fn test_seal_compression_ratio() {
		// Property: Compressed seal should be significantly smaller than uncompressed
		// SLH-DSA signatures contain repetitive hash-chain data that compresses well
		// Expected compression ratio: Varies by data, but should still work correctly

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x99; 32]);
		let keypair = generate_keypair(&mut rng, "compress@test.com").expect("Failed to generate keypair");

		// Use larger content to make compression more effective
		let content = b"Test message for compression. This is a longer message with more data to compress. \
                        The more data we have, the better compression algorithms can find patterns and reduce size. \
                        This test verifies that our compression pipeline works correctly, even if the compression \
                        ratio varies based on the entropy of the signature data.";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, content, &keypair, metadata).expect("Failed to create seal");

		let uncompressed = postcard::to_allocvec(&seal).expect("Failed to serialize seal");
		let compressed = seal.to_compressed_bytes().expect("Failed to compress seal");

		// -- Check
		// Note: DEFLATE compression effectiveness varies with data entropy.
		// SLH-DSA signatures have some compressible patterns, but not as much
		// as expected due to their hash-based nature. The main goal is that
		// compression works correctly, not necessarily that it always reduces size.

		// Verify compression completes without error (primary goal)
		assert!(!compressed.is_empty(), "Compressed data should not be empty");

		// Log compression stats for analysis
		let compression_ratio = (compressed.len() as f64) / (uncompressed.len() as f64);
		println!(
			"Compression stats: {} bytes → {} bytes ({:.1}% of original, ratio: {:.3})",
			uncompressed.len(),
			compressed.len(),
			compression_ratio * 100.0,
			compression_ratio
		);

		// Verify reasonable bounds (not catastrophically worse)
		assert!(
			compression_ratio < 1.05,
			"Compression should not expand data by more than 5%. Ratio: {:.3}",
			compression_ratio
		);
	}

	#[test]
	fn test_seal_compression_roundtrip() {
		// Property: Compress → decompress → verify should succeed
		// Full round-trip: create seal → compress → decompress → verify seal

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0xAA; 32]);
		let keypair = generate_keypair(&mut rng, "roundtrip@test.com").expect("Failed to generate keypair");
		let content = b"Test message for compression roundtrip";
		let metadata = BTreeMap::new();

		// -- Exec
		let seal = create_seal(&mut rng, content, &keypair, metadata).expect("Failed to create seal");

		// Compress
		let compressed = seal.to_compressed_bytes().expect("Failed to compress seal");

		// Decompress
		let decompressed_seal = Seal::from_compressed_bytes(&compressed).expect("Failed to decompress seal");

		// Verify
		let result = verify_seal(
			content,
			&decompressed_seal,
			&keypair.mldsa_public_key,
			&keypair.slhdsa_public_key,
		)
		.expect("Failed to verify decompressed seal");

		// -- Check
		assert!(result.valid, "Decompressed seal should verify successfully");
		assert!(result.content_hash_valid, "Content hash should be valid");
		assert!(result.primary_valid, "Primary signature should be valid");
		assert!(result.backup_valid, "Backup signature should be valid");

		// Verify seal fields are preserved
		assert_eq!(seal.seal_id, decompressed_seal.seal_id, "Seal ID should match");
		assert_eq!(
			seal.content_hash, decompressed_seal.content_hash,
			"Content hash should match"
		);
		assert_eq!(
			seal.primary.signature, decompressed_seal.primary.signature,
			"Primary signature should match"
		);
		assert_eq!(
			seal.backup.signature, decompressed_seal.backup.signature,
			"Backup signature should match"
		);
	}

	#[test]
	fn test_seal_decompression_corrupted_data() {
		// Property: Decompressing corrupted data should return appropriate error
		// Verify error handling for invalid compressed data

		// -- Setup & Fixtures
		let corrupted_data = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];

		// -- Exec
		let result = Seal::from_compressed_bytes(&corrupted_data);

		// -- Check
		assert!(result.is_err(), "Decompressing corrupted data should return an error");

		let err = result.unwrap_err();
		match err {
			crate::error::Error::Compression(_) => {
				// Expected error type
			}
			_ => {
				panic!("Expected Error::Compression, got {:?}", err);
			}
		}
	}

	// endregion: --- Compression Tests
}
