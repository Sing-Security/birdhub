//! Hardened entropy generation with multi-source pooling and ChaCha20 DRBG.
//!
//! Architecture:
//! ```text
//! EntropySource(s) → BLAKE3 keyed-hash pool → BLAKE3 derive_key → ChaCha20Rng DRBG
//! ```
//!
//! The DRBG automatically re-seeds every 2²⁰ (1,048,576) bytes to maintain forward secrecy.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use spin::Mutex;

use crate::entropy_source::EntropySource;
use crate::error::{Error, Result};

// region:    --- Domain Separation Constants

/// Domain separation for initial DRBG seed derivation.
const DOMAIN_DRBG_INIT: &str = "Temper.DRBG.Init.v1";

/// Domain separation for DRBG re-seeding.
const DOMAIN_DRBG_RESEED: &str = "Temper.DRBG.Reseed.v1";

// endregion: --- Domain Separation Constants

/// Re-seed threshold: 2²⁰ = 1,048,576 bytes.
const RESEED_THRESHOLD: u64 = 1 << 20;

/// Internal state for the entropy generator.
struct EntropyState {
	/// BLAKE3 hasher pool for mixing entropy sources.
	pool: blake3::Hasher,

	/// ChaCha20 DRBG for cryptographically secure random output.
	drbg: ChaCha20Rng,

	/// Number of bytes generated since last re-seed.
	bytes_since_reseed: u64,

	/// Total number of bytes generated over lifetime.
	total_bytes_emitted: u64,

	/// Number of times the DRBG has been re-seeded.
	reseed_count: u64,

	/// Number of entropy sources used during initialization.
	source_count: usize,
}

/// Health metrics for the entropy generator (no heap allocations).
#[derive(Debug, Clone, Copy)]
pub struct EntropyHealth {
	/// Number of entropy sources used.
	pub source_count: usize,

	/// Total bytes emitted over lifetime.
	pub total_bytes_emitted: u64,

	/// Number of re-seeds performed.
	pub reseed_count: u64,
}

/// Hardened CSPRNG with multi-source entropy pooling and automatic re-seeding.
///
/// # Examples
///
/// ```ignore
/// // Desktop (std feature)
/// let mut rng = TemperEntropy::new()?;
/// let random_u64 = rng.next_u64();
///
/// // Embedded (no_std with alloc)
/// let mut hw_rng = HardwareTrng;
/// let mut rng = TemperEntropy::from_sources(&mut [&mut hw_rng])?;
/// let random_u32 = rng.next_u32();
/// ```
pub struct TemperEntropy {
	state: Mutex<EntropyState>,
}

impl TemperEntropy {
	/// Create entropy generator from multiple sources (universal constructor).
	///
	/// This works on both embedded (no_std) and desktop (std) environments.
	///
	/// # Arguments
	///
	/// * `sources` - Array of mutable references to entropy sources
	///
	/// # Returns
	///
	/// Initialized `TemperEntropy` instance or error if entropy collection fails.
	pub fn from_sources(sources: &mut [&mut dyn EntropySource]) -> Result<Self> {
		if sources.is_empty() {
			return Err(Error::Custom("At least one entropy source required".into()));
		}

		// Initialize BLAKE3 hasher for entropy collection
		let mut pool = blake3::Hasher::new();

		// Collect entropy from all sources
		let mut total_collected = 0;
		for source in sources.iter_mut() {
			if !source.is_available() {
				continue;
			}

			let mut buf = [0u8; 64];
			match source.fill_entropy(&mut buf) {
				Ok(n) => {
					pool.update(&buf[..n]);
					total_collected += n;
				}
				Err(_e) => {
					// Log error but continue with other sources (std only)
				}
			}
		}

		if total_collected == 0 {
			return Err(Error::EntropySourceFailed(
				"Failed to collect entropy from any source".into(),
			));
		}

		// Derive initial DRBG seed using BLAKE3 derive_key
		let pool_material = pool.finalize();
		let seed_bytes = blake3::derive_key(DOMAIN_DRBG_INIT, pool_material.as_bytes());
		let drbg = ChaCha20Rng::from_seed(seed_bytes);

		// Re-initialize pool for future re-seeding
		let mut pool = blake3::Hasher::new();
		pool.update(pool_material.as_bytes());

		let state = EntropyState {
			pool,
			drbg,
			bytes_since_reseed: 0,
			total_bytes_emitted: 0,
			reseed_count: 0,
			source_count: sources.len(),
		};

		Ok(Self {
			state: Mutex::new(state),
		})
	}

	/// Create entropy generator from OS + jitter + process sources (std only).
	///
	/// This is a convenience constructor for desktop environments.
	#[cfg(feature = "std")]
	pub fn new() -> Result<Self> {
		use crate::entropy_source::{JitterEntropy, OsEntropy, ProcessEntropy};

		let mut os_source =
			OsEntropy::new().map_err(|e| Error::EntropySourceFailed(alloc::format!("OS source failed: {}", e)))?;
		let mut jitter_source = JitterEntropy::new();
		let mut process_source = ProcessEntropy::new();

		Self::from_sources(&mut [&mut os_source, &mut jitter_source, &mut process_source])
	}

	/// Create entropy generator using `getrandom` (alloc-only, non-std targets).
	///
	/// On targets with OS support (Linux, macOS, Windows), `getrandom` uses the
	/// native OS entropy source (`/dev/urandom`, `getrandom()` syscall, etc.).
	/// On bare-metal targets without OS entropy, this falls back to the registered
	/// custom handler (zero-fill stub — callers should prefer `from_sources` there).
	///
	/// This constructor allows code that uses `alloc` but not `std` (e.g. userspace
	/// crucibles compiled with `default-features = false, features = ["alloc", …]`)
	/// to create a `TemperEntropy` without providing explicit entropy sources.
	#[cfg(all(feature = "alloc", not(feature = "std")))]
	pub fn new() -> Result<Self> {
		let mut seed_bytes = [0u8; 64];
		getrandom::getrandom(&mut seed_bytes).map_err(|_| Error::EntropySourceFailed("getrandom failed".into()))?;

		let mut pool = blake3::Hasher::new();
		pool.update(&seed_bytes);
		let pool_material = pool.finalize();
		let drbg_seed = blake3::derive_key(DOMAIN_DRBG_INIT, pool_material.as_bytes());
		let drbg = ChaCha20Rng::from_seed(drbg_seed);

		let mut pool = blake3::Hasher::new();
		pool.update(pool_material.as_bytes());

		// Zero sensitive seed bytes
		seed_bytes.fill(0);

		Ok(Self {
			state: Mutex::new(EntropyState {
				pool,
				drbg,
				bytes_since_reseed: 0,
				total_bytes_emitted: 0,
				reseed_count: 0,
				source_count: 1,
			}),
		})
	}

	/// Create entropy generator from a fixed seed (testing only).
	///
	/// **WARNING:** This is deterministic and should NEVER be used in production.
	pub fn from_seed(seed: [u8; 32]) -> Self {
		let mut pool = blake3::Hasher::new();
		pool.update(&seed);

		let pool_material = pool.finalize();
		let seed_bytes = blake3::derive_key(DOMAIN_DRBG_INIT, pool_material.as_bytes());
		let drbg = ChaCha20Rng::from_seed(seed_bytes);

		// Re-initialize pool
		let mut pool = blake3::Hasher::new();
		pool.update(pool_material.as_bytes());

		let state = EntropyState {
			pool,
			drbg,
			bytes_since_reseed: 0,
			total_bytes_emitted: 0,
			reseed_count: 0,
			source_count: 1,
		};

		Self {
			state: Mutex::new(state),
		}
	}

	/// Get health metrics (no heap allocations).
	pub fn health(&self) -> EntropyHealth {
		let state = self.state.lock();
		EntropyHealth {
			source_count: state.source_count,
			total_bytes_emitted: state.total_bytes_emitted,
			reseed_count: state.reseed_count,
		}
	}

	/// Re-seed the DRBG with fresh entropy.
	///
	/// This is called automatically when the re-seed threshold is reached.
	fn reseed(state: &mut EntropyState) -> Result<()> {
		// Collect fresh entropy from OS (if available)
		let mut fresh_entropy = [0u8; 64];

		#[cfg(feature = "std")]
		{
			getrandom::getrandom(&mut fresh_entropy).map_err(|_| Error::ReseedFailed)?;
		}

		// In no_std without std, we rely on the existing pool state
		// (This is less ideal but maintains forward secrecy via ChaCha20)
		#[cfg(not(feature = "std"))]
		{
			// Use current DRBG state to generate fresh entropy for mixing
			state.drbg.fill_bytes(&mut fresh_entropy);
		}

		// Update pool with fresh entropy
		state.pool.update(&fresh_entropy);

		// Derive new seed from updated pool
		let pool_material = state.pool.finalize();
		let new_seed = blake3::derive_key(DOMAIN_DRBG_RESEED, pool_material.as_bytes());

		// Re-initialize pool with the material
		state.pool = blake3::Hasher::new();
		state.pool.update(pool_material.as_bytes());

		// Create new DRBG
		state.drbg = ChaCha20Rng::from_seed(new_seed);

		// Reset counter and increment reseed count
		state.bytes_since_reseed = 0;
		state.reseed_count += 1;

		// Zeroize sensitive buffers
		fresh_entropy.fill(0);

		Ok(())
	}
}

impl RngCore for TemperEntropy {
	fn next_u32(&mut self) -> u32 {
		let mut state = self.state.lock();

		// Check if re-seed needed
		if state.bytes_since_reseed >= RESEED_THRESHOLD {
			let _ = Self::reseed(&mut state);
		}

		let value = state.drbg.next_u32();
		state.bytes_since_reseed += 4;
		state.total_bytes_emitted += 4;

		value
	}

	fn next_u64(&mut self) -> u64 {
		let mut state = self.state.lock();

		// Check if re-seed needed
		if state.bytes_since_reseed >= RESEED_THRESHOLD {
			let _ = Self::reseed(&mut state);
		}

		let value = state.drbg.next_u64();
		state.bytes_since_reseed += 8;
		state.total_bytes_emitted += 8;

		value
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		let mut state = self.state.lock();

		// Check if re-seed needed
		if state.bytes_since_reseed >= RESEED_THRESHOLD {
			let _ = Self::reseed(&mut state);
		}

		state.drbg.fill_bytes(dest);
		state.bytes_since_reseed += dest.len() as u64;
		state.total_bytes_emitted += dest.len() as u64;
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
		self.fill_bytes(dest);
		Ok(())
	}
}

// Mark as cryptographically secure RNG
impl rand_core::CryptoRng for TemperEntropy {}
