//! Entropy source trait and implementations.
//!
//! Platform-agnostic interface for entropy collection. Embedded users can implement
//! this trait for their hardware RNG (STM32 TRNG, ESP32 RNG, etc.).

#[cfg(feature = "alloc")]
use alloc::string::String;

use derive_more::{Display, From};

/// Error types specific to entropy sources.
#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum EntropyError {
	/// Source is not available
	#[from(String, &String, &str)]
	NotAvailable(String),

	/// Failed to collect entropy
	CollectionFailed(String),

	/// Insufficient entropy collected
	InsufficientData { requested: usize, collected: usize },
}

/// Platform-agnostic entropy source trait.
///
/// Embedded systems should implement this for their hardware RNG.
/// Desktop systems can use the built-in implementations (OsEntropy, JitterEntropy, ProcessEntropy).
pub trait EntropySource {
	/// Human-readable name of this entropy source.
	fn name(&self) -> &str;

	/// Fill the buffer with entropy bytes.
	///
	/// Returns the number of bytes written, which may be less than `buf.len()`.
	fn fill_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError>;

	/// Check if this entropy source is currently available.
	fn is_available(&self) -> bool;
}

// region:    --- Built-in Entropy Sources (std only)

/// Operating system entropy source.
///
/// Uses `getrandom` to collect entropy from the OS CSPRNG.
#[cfg(feature = "std")]
pub struct OsEntropy;

#[cfg(feature = "std")]
impl OsEntropy {
	/// Create a new OS entropy source.
	pub fn new() -> core::result::Result<Self, EntropyError> {
		Ok(Self)
	}
}

#[cfg(feature = "std")]
impl EntropySource for OsEntropy {
	fn name(&self) -> &str {
		"OS-RNG"
	}

	fn fill_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError> {
		use alloc::format;

		getrandom::getrandom(buf).map_err(|e| EntropyError::CollectionFailed(format!("getrandom failed: {}", e)))?;
		Ok(buf.len())
	}

	fn is_available(&self) -> bool {
		true
	}
}

/// Jitter-based entropy source.
///
/// Measures timing variance from `std::time::Instant` across tight loops.
/// This provides a small amount of entropy from CPU scheduling jitter and
/// microarchitectural timing variations.
#[cfg(feature = "std")]
pub struct JitterEntropy {
	iterations: usize,
}

#[cfg(feature = "std")]
impl JitterEntropy {
	/// Create a new jitter entropy source with default iterations (1024).
	pub fn new() -> Self {
		Self { iterations: 1024 }
	}

	/// Create a jitter entropy source with custom iteration count.
	pub fn with_iterations(iterations: usize) -> Self {
		Self { iterations }
	}

	/// Collect jitter by measuring timing variance.
	fn collect_jitter(&self) -> [u8; 32] {
		use std::time::Instant;

		let mut hasher = blake3::Hasher::new();

		for _ in 0..self.iterations {
			let start = Instant::now();

			// Tight loop to create timing variance
			let mut acc = 0u64;
			for i in 0..100 {
				acc = acc.wrapping_add(i).wrapping_mul(0x123456789ABCDEF);
			}

			let elapsed = start.elapsed();

			// Hash the timing and computation result
			hasher.update(&elapsed.as_nanos().to_le_bytes());
			hasher.update(&acc.to_le_bytes());
		}

		*hasher.finalize().as_bytes()
	}
}

#[cfg(feature = "std")]
impl EntropySource for JitterEntropy {
	fn name(&self) -> &str {
		"Jitter"
	}

	fn fill_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError> {
		let jitter_bytes = self.collect_jitter();
		let to_copy = core::cmp::min(buf.len(), jitter_bytes.len());
		buf[..to_copy].copy_from_slice(&jitter_bytes[..to_copy]);
		Ok(to_copy)
	}

	fn is_available(&self) -> bool {
		true
	}
}

/// Process-based entropy source.
///
/// Uses process ID, thread ID, and heap ASLR addresses as entropy sources.
/// This provides a small amount of entropy from OS-level randomization.
#[cfg(feature = "std")]
pub struct ProcessEntropy;

#[cfg(feature = "std")]
impl ProcessEntropy {
	/// Create a new process entropy source.
	pub fn new() -> Self {
		Self
	}

	/// Collect process-related entropy.
	fn collect_process_data(&self) -> [u8; 32] {
		use alloc::boxed::Box;
		use alloc::format;

		let mut hasher = blake3::Hasher::new();

		// Process ID
		let pid = std::process::id();
		hasher.update(&pid.to_le_bytes());

		// Thread ID (format as string since ThreadId is opaque)
		let tid = format!("{:?}", std::thread::current().id());
		hasher.update(tid.as_bytes());

		// Heap address (ASLR)
		let heap_addr = Box::new(0u64);
		let addr = &*heap_addr as *const u64 as usize;
		hasher.update(&addr.to_le_bytes());

		// Stack address
		let stack_var = 0u64;
		let stack_addr = &stack_var as *const u64 as usize;
		hasher.update(&stack_addr.to_le_bytes());

		*hasher.finalize().as_bytes()
	}
}

#[cfg(feature = "std")]
impl EntropySource for ProcessEntropy {
	fn name(&self) -> &str {
		"Process"
	}

	fn fill_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError> {
		let process_bytes = self.collect_process_data();
		let to_copy = core::cmp::min(buf.len(), process_bytes.len());
		buf[..to_copy].copy_from_slice(&process_bytes[..to_copy]);
		Ok(to_copy)
	}

	fn is_available(&self) -> bool {
		true
	}
}

// endregion: --- Built-in Entropy Sources
