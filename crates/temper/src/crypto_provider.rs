//! Crypto Provider abstraction for pluggable Post-Quantum Cryptography implementations.
//!
//! This module defines the `CryptoProvider` trait that abstracts the ML-DSA and SLH-DSA
//! signature primitives. This allows the core protocol to remain independent of the
//! specific implementation, enabling hardware acceleration (GPU/FPGA) without breaking
//! `no_std` support.
//!
//! # Architecture
//!
//! - **Default**: CPU-based pure Rust implementation (RustCrypto libraries)
//! - **Pluggable**: External implementations can be registered via global provider
//! - **Zero-config**: No setup required for default CPU behavior
//!
//! # Example
//!
//! ```no_run
//! use temper::crypto_provider::{CryptoProvider, get_crypto_provider};
//!
//! // Default CPU provider is automatically available
//! let provider = get_crypto_provider();
//! ```

// Memory: no_std pattern per rust-nostd.instructions.md — use alloc for heap types
#[cfg(all(feature = "alloc", feature = "signatures"))]
use alloc::vec::Vec;

#[cfg(feature = "signatures")]
use crate::entropy::TemperEntropy;
#[cfg(feature = "signatures")]
use crate::error::Result;

// region:    --- Modules

#[cfg(feature = "signatures")]
pub mod cpu;

// endregion: --- Modules

// region:    --- CryptoProvider Trait (signatures feature only)

#[cfg(feature = "signatures")]

/// Abstraction for Post-Quantum Cryptography signature operations.
///
/// This trait allows plugging in different implementations of ML-DSA and SLH-DSA,
/// such as hardware-accelerated versions (GPU, FPGA) while maintaining the same
/// protocol-level API.
///
/// # Implementation Requirements
///
/// - **Thread Safety**: Implementations must be `Send + Sync` for concurrent use
/// - **no_std Compatible**: Must work in embedded environments (alloc only)
/// - **Deterministic**: Same inputs must produce same outputs (for verification)
/// - **Zeroization**: Must zeroize sensitive key material after use
///
/// # Security Properties
///
/// Implementations must provide:
/// - ML-DSA-65: NIST Level 3 security (Module-LWE hardness)
/// - SLH-DSA: NIST Level 5 security (hash-based signatures)
pub trait CryptoProvider: Send + Sync {
	/// Generate ML-DSA-65 keypair.
	///
	/// # Algorithm
	///
	/// FIPS 204 ML-DSA-65 (lattice-based, NIST security level 3)
	///
	/// # Key Sizes
	///
	/// - Secret key: 4032 bytes
	/// - Public key: 1952 bytes
	/// - Signature: 3309 bytes
	///
	/// # Returns
	///
	/// `(secret_key, public_key)` tuple as byte vectors
	fn mldsa_keygen(&self, rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)>;

	/// Sign a message with ML-DSA-65.
	///
	/// # Arguments
	///
	/// * `sk` - ML-DSA-65 secret key (4032 bytes)
	/// * `message` - Message to sign
	/// * `rng` - Random number generator (may be unused by deterministic schemes)
	///
	/// # Returns
	///
	/// Signature bytes (3309 bytes)
	fn mldsa_sign(&self, sk: &[u8], message: &[u8], rng: &mut TemperEntropy) -> Result<Vec<u8>>;

	/// Verify an ML-DSA-65 signature.
	///
	/// # Arguments
	///
	/// * `pk` - ML-DSA-65 public key (1952 bytes)
	/// * `message` - Message that was signed
	/// * `signature` - Signature to verify (3309 bytes)
	///
	/// # Returns
	///
	/// `true` if signature is valid, `false` otherwise
	fn mldsa_verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool;

	/// Generate SLH-DSA keypair.
	///
	/// # Algorithm
	///
	/// FIPS 205 SLH-DSA-SHA2-128f (hash-based, fast variant)
	///
	/// # Key Sizes
	///
	/// - Secret key: 64 bytes
	/// - Public key: 32 bytes
	/// - Signature: 17088 bytes
	///
	/// # Returns
	///
	/// `(secret_key, public_key)` tuple as byte vectors
	fn slhdsa_keygen(&self, rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)>;

	/// Sign a message with SLH-DSA.
	///
	/// # Arguments
	///
	/// * `sk` - SLH-DSA secret key (64 bytes)
	/// * `message` - Message to sign
	/// * `rng` - Random number generator (may be unused by deterministic schemes)
	///
	/// # Returns
	///
	/// Signature bytes (17088 bytes for 128f variant)
	fn slhdsa_sign(&self, sk: &[u8], message: &[u8], rng: &mut TemperEntropy) -> Result<Vec<u8>>;

	/// Verify an SLH-DSA signature.
	///
	/// # Arguments
	///
	/// * `pk` - SLH-DSA public key (32 bytes)
	/// * `message` - Message that was signed
	/// * `signature` - Signature to verify (17088 bytes for 128f variant)
	///
	/// # Returns
	///
	/// `true` if signature is valid, `false` otherwise
	fn slhdsa_verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

// endregion: --- CryptoProvider Trait

// region:    --- Global Provider (signatures feature only)

#[cfg(feature = "signatures")]
use spin::Mutex;

// Global static provider using CPU implementation by default
// Memory: lazy initialization pattern — CPU provider is default, zero-config
#[cfg(feature = "signatures")]
static GLOBAL_PROVIDER: Mutex<Option<&'static dyn CryptoProvider>> = Mutex::new(None);

#[cfg(feature = "signatures")]
/// Get the current crypto provider.
///
/// Returns the CPU provider by default (zero-config). If a custom provider has been
/// registered via `set_crypto_provider()`, that will be returned instead.
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently.
///
/// # Example
///
/// ```no_run
/// use temper::crypto_provider::get_crypto_provider;
///
/// let provider = get_crypto_provider();
/// // Use provider for crypto operations
/// ```
#[cfg(feature = "signatures")]
pub fn get_crypto_provider() -> &'static dyn CryptoProvider {
	let guard = GLOBAL_PROVIDER.lock();
	match *guard {
		Some(provider) => provider,
		None => {
			// Memory: default to CPU provider — zero-config behavior
			drop(guard); // Release lock before accessing CPU_PROVIDER
			&cpu::CPU_PROVIDER
		}
	}
}

/// Set a custom crypto provider.
///
/// This allows registering a hardware-accelerated implementation (e.g., GPU, FPGA)
/// to replace the default CPU provider.
///
/// # Safety
///
/// The provider must be a static reference that lives for the entire program lifetime.
/// This is typically satisfied by using `lazy_static!` or similar for custom providers.
///
/// # Example
///
/// ```no_run
/// use temper::crypto_provider::{CryptoProvider, set_crypto_provider};
///
/// // Assuming you have a custom provider
/// // static MY_PROVIDER: MyGpuProvider = MyGpuProvider::new();
/// // set_crypto_provider(&MY_PROVIDER);
/// ```
#[cfg(feature = "signatures")]
pub fn set_crypto_provider(provider: &'static dyn CryptoProvider) {
	let mut guard = GLOBAL_PROVIDER.lock();
	*guard = Some(provider);
}

// endregion: --- Global Provider
