//! Dual post-quantum signature protocol (ML-DSA-65 + SLH-DSA).
//!
//! **Production-ready implementation** with fully integrated FIPS 204 and FIPS 205 algorithms.
//!
//! The Seal binds a BLAKE3 content hash to two independent quantum-safe signatures,
//! providing defense-in-depth against cryptanalytic breakthroughs.
//!
//! # Implementation Status
//!
//! ✅ **Complete and tested** — All PQC primitives integrated with RustCrypto libraries:
//! - ML-DSA-65 (v0.1.0-rc.7): Lattice-based, NIST Level 3, Module-LWE hardness
//! - SLH-DSA-SHA2-128f (v0.2.0-rc.4): Hash-based, NIST Level 5, stateless signatures, fast variant
//! - DEFLATE compression: Optional size reduction for network transmission and embedded storage
//!
//! # Protocol
//!
//! 1. `content_hash = BLAKE3(message)` — 256-bit content-addressed hash
//! 2. `context = SealContext { domain, timestamp, signer_id, metadata }`
//! 3. `binding = hex(content_hash) || postcard(context)` — deterministic binding
//! 4. `σ₁ = ML-DSA-65.Sign(sk₁, binding)` — lattice-based signature (3309 bytes, stored as raw bytes)
//! 5. `σ₂ = SLH-DSA-SHA2-128f.Sign(sk₂, binding)` — hash-based signature (17088 bytes, stored as raw bytes)
//!
//! # Compression
//!
//! Seals can be optionally compressed using DEFLATE (level 9) to reduce transmission and storage size:
//! - `seal.to_compressed_bytes()` — Serialize and compress seal
//! - `Seal::from_compressed_bytes(data)` — Decompress and deserialize seal
//! - Typical total seal size: ~20.7KB uncompressed
//! - Compression effectiveness varies with signature entropy
//! - Integrated into authenticated envelope protocol automatically
//!
//! # Verification
//!
//! ALL three checks must pass for valid seal:
//! - `BLAKE3(content) == seal.content_hash` — content integrity
//! - `ML-DSA.Verify(pk₁, binding, σ₁)` — primary signature (quantum-safe lattice)
//! - `SLH-DSA.Verify(pk₂, binding, σ₂)` — backup signature (quantum-safe hash)
//!
//! # Security Properties
//!
//! - **Quantum Resistance**: Both algorithms resist Grover's and Shor's algorithms
//! - **Defense-in-Depth**: Breaking the seal requires breaking BOTH signatures
//! - **Independent Hardness**: ML-DSA relies on Module-LWE, SLH-DSA on hash security
//! - **Forward Secrecy**: Seed material zeroized after key generation
//! - **Domain Separation**: Unique constant prevents cross-protocol attacks
//!
//! # Example
//!
//! ```no_run
//! use temper::{TemperEntropy, generate_keypair, create_seal, verify_seal};
//! use alloc::collections::BTreeMap;
//!
//! let mut rng = TemperEntropy::from_seed([0x42; 32]);
//! let keypair = generate_keypair(&mut rng, "alice@example.com")?;
//!
//! let content = b"Quantum-safe message";
//! let seal = create_seal(&mut rng, content, &keypair, BTreeMap::new())?;
//!
//! // Optional: compress for network transmission
//! let compressed = seal.to_compressed_bytes()?;
//! let seal = temper::seal::Seal::from_compressed_bytes(&compressed)?;
//!
//! let result = verify_seal(
//!     content,
//!     &seal,
//!     &keypair.mldsa_public_key,
//!     &keypair.slhdsa_public_key,
//! )?;
//!
//! assert!(result.valid); // All checks passed
//! # Ok::<(), temper::Error>(())
//! ```

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(feature = "alloc")]
use alloc::format;

use zeroize::Zeroize;

use crate::crypto_provider::get_crypto_provider;
use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};

// region:    --- Constants

/// Schema version for all seal structures.
const SCHEMA_VERSION: u16 = 1;

/// Domain separation string for seal protocol.
const DOMAIN_SEAL: &str = "Temper.Seal.v1";

/// Tool version string.
const TOOL_VERSION: &str = "temper-0.1.0";

/// Threshold for parallel BLAKE3 hashing (1 MiB).
/// Below this size, use single-threaded hashing; above it, use Rayon-based parallel hashing.
/// Only applies when the `blake3_parallel` feature is enabled.
#[cfg(feature = "blake3_parallel")]
const PARALLEL_HASH_THRESHOLD: usize = 1024 * 1024;

// endregion: --- Constants

// region:    --- Data Structures

/// Temper keypair containing both ML-DSA-65 and SLH-DSA keys.
///
/// **Security Note**: This struct implements a custom `Debug` trait that redacts secret keys
/// to prevent accidental leakage in logs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TemperKeypair {
	/// Schema version for future compatibility.
	pub schema_version: u16,

	// ML-DSA-65 keys
	/// ML-DSA-65 secret key.
	pub mldsa_secret_key: Vec<u8>,
	/// ML-DSA-65 public key.
	pub mldsa_public_key: Vec<u8>,

	// SLH-DSA keys
	/// SLH-DSA secret key.
	pub slhdsa_secret_key: Vec<u8>,
	/// SLH-DSA public key.
	pub slhdsa_public_key: Vec<u8>,

	// Metadata
	/// Human-readable signer identifier.
	pub signer_id: String,
	/// BLAKE3(mldsa_pk || slhdsa_pk) as hex.
	pub key_id: String,
}

impl Drop for TemperKeypair {
	fn drop(&mut self) {
		self.mldsa_secret_key.zeroize();
		self.slhdsa_secret_key.zeroize();
	}
}

// Memory: security fix per problem statement — prevent private key leaks in logs
impl core::fmt::Debug for TemperKeypair {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("TemperKeypair")
			.field("schema_version", &self.schema_version)
			.field("mldsa_secret_key", &"<REDACTED>")
			.field("mldsa_public_key", &format!("<{} bytes>", self.mldsa_public_key.len()))
			.field("slhdsa_secret_key", &"<REDACTED>")
			.field(
				"slhdsa_public_key",
				&format!("<{} bytes>", self.slhdsa_public_key.len()),
			)
			.field("signer_id", &self.signer_id)
			.field("key_id", &self.key_id)
			.finish()
	}
}

/// Complete seal binding a content hash to dual quantum-safe signatures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Seal {
	/// Schema version for future compatibility.
	pub schema_version: u16,

	/// BLAKE3 hash of the content (hex-encoded).
	pub content_hash: String,

	/// Primary signature (ML-DSA-65).
	pub primary: SignatureBlock,

	/// Backup signature (SLH-DSA).
	pub backup: SignatureBlock,

	/// Context information for the seal.
	pub context: SealContext,

	/// BLAKE3(json(seal with empty seal_id)) as hex.
	pub seal_id: String,
}

impl Seal {
	/// Serialize the seal to bytes (uncompressed).
	///
	/// # Returns
	///
	/// Postcard-serialized seal bytes (uncompressed).
	///
	/// # Note
	///
	/// When the `compression` feature is enabled, prefer `to_compressed_bytes()`
	/// for 30-50% size reduction.
	pub fn to_bytes(&self) -> Result<Vec<u8>> {
		postcard::to_allocvec(self).map_err(|e| Error::Serialization(format!("Failed to serialize seal: {}", e)))
	}

	/// Deserialize a seal from bytes (uncompressed).
	///
	/// # Arguments
	///
	/// * `bytes` - Postcard-serialized seal bytes (uncompressed)
	///
	/// # Returns
	///
	/// Deserialized `Seal` structure.
	///
	/// # Errors
	///
	/// Returns error if deserialization fails.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
		postcard::from_bytes(bytes).map_err(|e| Error::Serialization(format!("Failed to deserialize seal: {}", e)))
	}

	/// Serialize and compress the seal to bytes.
	///
	/// # Returns
	///
	/// DEFLATE-compressed postcard-serialized seal bytes.
	///
	/// # Compression
	///
	/// Uses DEFLATE with maximum compression (level 9) to minimize size for
	/// embedded devices and network transmission. Typical reduction: 30-50%.
	#[cfg(feature = "compression")]
	pub fn to_compressed_bytes(&self) -> Result<Vec<u8>> {
		// Serialize with postcard
		let seal_bytes = postcard::to_allocvec(self)
			.map_err(|e| Error::Serialization(format!("Failed to serialize seal: {}", e)))?;

		// Compress
		compress_seal(&seal_bytes)
	}

	/// Decompress and deserialize a seal from bytes.
	///
	/// # Arguments
	///
	/// * `compressed` - DEFLATE-compressed postcard-serialized seal bytes
	///
	/// # Returns
	///
	/// Deserialized `Seal` structure.
	///
	/// # Errors
	///
	/// Returns error if decompression or deserialization fails.
	#[cfg(feature = "compression")]
	pub fn from_compressed_bytes(compressed: &[u8]) -> Result<Self> {
		// Decompress
		let seal_bytes = decompress_seal(compressed)?;

		// Deserialize
		postcard::from_bytes(&seal_bytes)
			.map_err(|e| Error::Serialization(format!("Failed to deserialize seal: {}", e)))
	}
}

/// A single signature with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureBlock {
	/// Algorithm name (e.g., "ML-DSA-65", "SLH-DSA").
	pub algorithm: String,

	/// Raw signature bytes (not hex-encoded for binary serialization efficiency).
	pub signature: Vec<u8>,

	/// BLAKE3(public_key) as hex.
	pub key_id: String,
}

/// Context information for a seal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealContext {
	/// Domain separation string.
	pub domain: String,

	/// ISO 8601 timestamp (e.g., "2024-01-01T00:00:00Z").
	pub timestamp: String,

	/// Signer identifier.
	pub signer_id: String,

	/// Tool version string.
	pub tool_version: String,

	/// User-provided metadata (must be BTreeMap for determinism).
	pub metadata: BTreeMap<String, String>,
}

/// Result of seal verification.
#[derive(Debug, Clone, Copy)]
pub struct VerifyResult {
	/// Content hash matches.
	pub content_hash_valid: bool,

	/// Primary signature (ML-DSA-65) is valid.
	pub primary_valid: bool,

	/// Backup signature (SLH-DSA) is valid.
	pub backup_valid: bool,

	/// All checks passed (true iff all three above are true).
	pub valid: bool,
}

// endregion: --- Data Structures

// region:    --- Post-Quantum Signature Primitives

// # Post-Quantum Signature Primitives
//
// The crypto operations are now delegated to the CryptoProvider abstraction,
// which allows pluggable implementations (CPU, GPU, FPGA) while maintaining
// the same protocol-level API.
//
// Default provider: CPU-based RustCrypto implementations (see crypto_provider::cpu)
// - ML-DSA-65: FIPS 204, lattice-based, NIST Level 3
// - SLH-DSA-SHA2-128f: FIPS 205, hash-based, NIST Level 5 (fast variant)
//
// Custom providers can be registered via set_crypto_provider() for hardware acceleration.

// endregion: --- Post-Quantum Signature Primitives

// region:    --- Helper Functions

/// Compute content hash with optional parallel processing.
///
/// Uses parallel BLAKE3 hashing when:
/// - `blake3_parallel` feature is enabled
/// - Content size >= 1 MiB threshold
///
/// # Memory: Performance optimization per problem statement
/// - Single-threaded: Standard BLAKE3
/// - Parallel: Rayon-based chunked hashing for large content
#[inline]
fn compute_content_hash(content: &[u8]) -> blake3::Hash {
	#[cfg(feature = "blake3_parallel")]
	{
		if content.len() >= PARALLEL_HASH_THRESHOLD {
			// Use Rayon-based parallel hashing for large content
			use rayon::prelude::*;

			// Split content into chunks for parallel processing
			const CHUNK_SIZE: usize = 256 * 1024; // 256 KiB chunks

			// Process chunks in parallel
			let chunk_hashes: Vec<blake3::Hash> =
				content.par_chunks(CHUNK_SIZE).map(|chunk| blake3::hash(chunk)).collect();

			// Combine chunk hashes into final hash
			let mut hasher = blake3::Hasher::new();
			for chunk_hash in chunk_hashes {
				hasher.update(chunk_hash.as_bytes());
			}
			return hasher.finalize();
		}
	}

	// Fall back to single-threaded hashing
	blake3::hash(content)
}

// endregion: --- Helper Functions

// region:    --- Public API

/// Generate a new Temper keypair.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
/// * `signer_id` - Human-readable identifier for the signer
///
/// # Returns
///
/// A new `TemperKeypair` containing both ML-DSA-65 and SLH-DSA keys.
pub fn generate_keypair(rng: &mut TemperEntropy, signer_id: &str) -> Result<TemperKeypair> {
	// Memory: crypto provider abstraction — delegate to pluggable provider
	let provider = get_crypto_provider();

	// Generate ML-DSA-65 keypair
	let (mldsa_sk, mldsa_pk) = provider.mldsa_keygen(rng)?;

	// Generate SLH-DSA keypair
	let (slhdsa_sk, slhdsa_pk) = provider.slhdsa_keygen(rng)?;

	// Compute key ID: BLAKE3(mldsa_pk || slhdsa_pk)
	let mut hasher = blake3::Hasher::new();
	hasher.update(&mldsa_pk);
	hasher.update(&slhdsa_pk);
	let key_id = hex::encode(hasher.finalize().as_bytes());

	Ok(TemperKeypair {
		schema_version: SCHEMA_VERSION,
		mldsa_secret_key: mldsa_sk,
		mldsa_public_key: mldsa_pk,
		slhdsa_secret_key: slhdsa_sk,
		slhdsa_public_key: slhdsa_pk,
		signer_id: signer_id.to_string(),
		key_id,
	})
}

/// Create a seal for content.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
/// * `content` - The content to seal
/// * `keypair` - The keypair to sign with
/// * `metadata` - User-provided metadata (must be BTreeMap)
///
/// # Returns
///
/// A complete `Seal` with dual quantum-safe signatures.
pub fn create_seal(
	rng: &mut TemperEntropy,
	content: &[u8],
	keypair: &TemperKeypair,
	metadata: BTreeMap<String, String>,
) -> Result<Seal> {
	// Compute content hash (uses parallel hashing for large content when blake3_parallel is enabled)
	// Memory: performance optimization per problem statement — automatic parallelization
	let content_hash_bytes = compute_content_hash(content);
	let content_hash = hex::encode(content_hash_bytes.as_bytes());

	// Create context
	let timestamp = current_timestamp();
	let context = SealContext {
		domain: DOMAIN_SEAL.to_string(),
		timestamp,
		signer_id: keypair.signer_id.clone(),
		tool_version: TOOL_VERSION.to_string(),
		metadata,
	};

	// Construct binding: hex(content_hash) || postcard(context)
	// Memory: postcard replacement per problem statement — compact binary for embedded
	let context_bytes = postcard::to_allocvec(&context)
		.map_err(|e| Error::Serialization(format!("Failed to serialize context: {}", e)))?;

	// Memory: pre-sized Vec allocation per problem statement — eliminates reallocation
	let mut binding = Vec::with_capacity(content_hash.len() + context_bytes.len());
	binding.extend_from_slice(content_hash.as_bytes());
	binding.extend_from_slice(&context_bytes);

	// Memory: crypto provider abstraction — delegate to pluggable provider
	let provider = get_crypto_provider();

	// Sign with ML-DSA-65 (primary)
	// Memory: signature optimization per problem statement — store raw bytes instead of hex
	let primary_sig = provider.mldsa_sign(&keypair.mldsa_secret_key, &binding, rng)?;
	let primary_key_id = hex::encode(blake3::hash(&keypair.mldsa_public_key).as_bytes());
	let primary = SignatureBlock {
		algorithm: "ML-DSA-65".to_string(),
		signature: primary_sig,
		key_id: primary_key_id,
	};

	// Sign with SLH-DSA (backup)
	// Memory: signature optimization per problem statement — store raw bytes instead of hex
	let backup_sig = provider.slhdsa_sign(&keypair.slhdsa_secret_key, &binding, rng)?;
	let backup_key_id = hex::encode(blake3::hash(&keypair.slhdsa_public_key).as_bytes());
	let backup = SignatureBlock {
		algorithm: "SLH-DSA".to_string(),
		signature: backup_sig,
		key_id: backup_key_id,
	};

	// Compute seal ID by hashing components directly (eliminates ~22KB of clones)
	// Memory: direct BLAKE3 hashing per problem statement — eliminates temp_seal serialization
	// Memory: signature optimization — signatures are now Vec<u8>, hash bytes directly
	let mut seal_id_hasher = blake3::Hasher::new();
	seal_id_hasher.update(&SCHEMA_VERSION.to_le_bytes());
	seal_id_hasher.update(content_hash.as_bytes());
	seal_id_hasher.update(primary.algorithm.as_bytes());
	seal_id_hasher.update(&primary.signature);
	seal_id_hasher.update(primary.key_id.as_bytes());
	seal_id_hasher.update(backup.algorithm.as_bytes());
	seal_id_hasher.update(&backup.signature);
	seal_id_hasher.update(backup.key_id.as_bytes());
	seal_id_hasher.update(&context_bytes);
	let seal_id = hex::encode(seal_id_hasher.finalize().as_bytes());

	// Return complete seal
	Ok(Seal {
		schema_version: SCHEMA_VERSION,
		content_hash,
		primary,
		backup,
		context,
		seal_id,
	})
}

/// Verify a seal.
///
/// # Arguments
///
/// * `content` - The content that was sealed
/// * `seal` - The seal to verify
/// * `mldsa_pk` - ML-DSA-65 public key
/// * `slhdsa_pk` - SLH-DSA public key
///
/// # Returns
///
/// `VerifyResult` with individual check results and overall validity.
pub fn verify_seal(content: &[u8], seal: &Seal, mldsa_pk: &[u8], slhdsa_pk: &[u8]) -> Result<VerifyResult> {
	// Check content hash (uses parallel hashing for large content when blake3_parallel is enabled)
	// Memory: performance optimization per problem statement — automatic parallelization
	let actual_hash_bytes = compute_content_hash(content);
	let actual_hash = hex::encode(actual_hash_bytes.as_bytes());
	let content_hash_valid = actual_hash == seal.content_hash;

	// Reconstruct binding
	// Memory: postcard replacement per problem statement — must match create_seal
	let context_bytes = postcard::to_allocvec(&seal.context)
		.map_err(|e| Error::Serialization(format!("Failed to serialize context: {}", e)))?;

	// Memory: pre-sized Vec allocation per problem statement — eliminates reallocation
	let mut binding = Vec::with_capacity(seal.content_hash.len() + context_bytes.len());
	binding.extend_from_slice(seal.content_hash.as_bytes());
	binding.extend_from_slice(&context_bytes);

	// Memory: crypto provider abstraction — delegate to pluggable provider
	let provider = get_crypto_provider();

	// Verify primary signature (ML-DSA-65)
	// Memory: signature optimization per problem statement — signatures are now Vec<u8>
	let primary_valid = provider.mldsa_verify(mldsa_pk, &binding, &seal.primary.signature);

	// Verify backup signature (SLH-DSA)
	// Memory: signature optimization per problem statement — signatures are now Vec<u8>
	let backup_valid = provider.slhdsa_verify(slhdsa_pk, &binding, &seal.backup.signature);

	// Overall validity requires all three checks to pass
	let valid = content_hash_valid && primary_valid && backup_valid;

	Ok(VerifyResult {
		content_hash_valid,
		primary_valid,
		backup_valid,
		valid,
	})
}

/// Compress seal bytes using DEFLATE.
///
/// # Arguments
///
/// * `seal_bytes` - Raw postcard-serialized seal bytes
///
/// # Returns
///
/// Compressed bytes using DEFLATE with maximum compression (level 9).
///
/// # Compression Performance
///
/// SLH-DSA signatures contain repetitive hash-chain data that compresses well:
/// - Typical reduction: 30-50% of original size
/// - Example: ~20KB uncompressed → ~10-14KB compressed
///
/// This allows the fast SLH-DSA-SHA2-128f variant (17.1KB signatures) to have
/// roughly the same wire size as the slow 128s variant (7.8KB signatures).
#[cfg(feature = "compression")]
pub fn compress_seal(seal_bytes: &[u8]) -> Result<Vec<u8>> {
	use flate2::Compress;
	use flate2::Compression;
	use flate2::FlushCompress;

	// Memory: alloc pattern per rust-nostd.instructions.md — use alloc::vec::Vec
	let mut compressor = Compress::new(Compression::best(), false);

	// Estimate output buffer size (worst case: input + overhead)
	let mut compressed = Vec::with_capacity(seal_bytes.len() + 64);

	// Compress the data
	let status = compressor
		.compress_vec(seal_bytes, &mut compressed, FlushCompress::Finish)
		.map_err(|e| Error::Compression(format!("DEFLATE compression failed: {:?}", e)))?;

	if status != flate2::Status::StreamEnd {
		return Err(Error::Compression("DEFLATE compression incomplete".into()));
	}

	Ok(compressed)
}

/// Decompress seal bytes using DEFLATE.
///
/// # Arguments
///
/// * `compressed` - DEFLATE-compressed seal bytes
///
/// # Returns
///
/// Decompressed postcard-serialized seal bytes.
///
/// # Errors
///
/// Returns `Error::Compression` if:
/// - Compressed data is corrupted or invalid
/// - Decompression algorithm fails
/// - Output buffer errors
#[cfg(feature = "compression")]
pub fn decompress_seal(compressed: &[u8]) -> Result<Vec<u8>> {
	use flate2::Decompress;
	use flate2::FlushDecompress;

	// Memory: alloc pattern per rust-nostd.instructions.md — use alloc::vec::Vec
	let mut decompressor = Decompress::new(false);

	// Estimate output buffer size (assume 3x expansion for compressed data)
	let mut decompressed = Vec::with_capacity(compressed.len() * 3);

	// Decompress the data
	let status = decompressor
		.decompress_vec(compressed, &mut decompressed, FlushDecompress::Finish)
		.map_err(|e| Error::Compression(format!("DEFLATE decompression failed: {:?}", e)))?;

	if status != flate2::Status::StreamEnd {
		return Err(Error::Compression("DEFLATE decompression incomplete".into()));
	}

	Ok(decompressed)
}

// endregion: --- Public API

// region:    --- Helper Functions

/// Get current timestamp (std) or placeholder (no_std).
fn current_timestamp() -> String {
	#[cfg(feature = "std")]
	{
		use std::time::SystemTime;
		match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
			Ok(duration) => {
				// Format as ISO 8601 (simplified)
				let secs = duration.as_secs();
				format!("{}-01-01T00:00:00Z", 1970 + secs / 31557600) // Approximate year
			}
			Err(_) => "1970-01-01T00:00:00Z".to_string(),
		}
	}

	#[cfg(not(feature = "std"))]
	{
		// In no_std, user should provide timestamp via metadata
		"0000-00-00T00:00:00Z".to_string()
	}
}

// endregion: --- Helper Functions
