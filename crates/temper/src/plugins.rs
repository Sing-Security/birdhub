//! Plugin infrastructure for dynamic crypto provider loading (std only).
//!
//! This module provides infrastructure for loading external crypto providers at runtime,
//! such as GPU or FPGA implementations. This is a placeholder for future dynamic loading
//! capabilities and is only available when the `std` feature is enabled.
//!
//! # Future Capabilities
//!
//! - **Dynamic Library Loading**: Load crypto providers from shared libraries (.so, .dylib, .dll)
//! - **Provider Discovery**: Automatic discovery of available hardware accelerators
//! - **Hot Swapping**: Switch providers at runtime based on workload
//!
//! # Example (Future)
//!
//! ```ignore
//! use temper::plugins::load_provider;
//!
//! // Load GPU-accelerated provider
//! let provider = load_provider("libtemper_cuda.so")?;
//! temper::set_crypto_provider(&*provider);
//! ```

#[cfg(feature = "std")]
use std::path::Path;

// Memory: no_std pattern per rust-nostd.instructions.md — use alloc for heap types
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use crate::crypto_provider::CryptoProvider;
#[cfg(feature = "std")]
use crate::error::{Error, Result};

// region:    --- Plugin Loading (Placeholder)

/// Plugin metadata for external crypto providers.
///
/// This structure will be used to describe dynamically loaded providers
/// once dynamic loading is implemented.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PluginMetadata {
	/// Plugin name (e.g., "CUDA Provider", "FPGA Provider")
	pub name: String,

	/// Plugin version
	pub version: String,

	/// Supported algorithms
	pub algorithms: Vec<String>,

	/// Hardware requirements
	pub hardware_requirements: String,
}

/// Load a crypto provider from a dynamic library (placeholder).
///
/// # Arguments
///
/// * `path` - Path to the shared library (.so, .dylib, .dll)
///
/// # Returns
///
/// A boxed `CryptoProvider` implementation.
///
/// # Errors
///
/// Returns an error if:
/// - Library file not found
/// - Library lacks required symbols
/// - Provider initialization fails
///
/// # Future Implementation
///
/// This will use `libloading` or similar to dynamically load providers:
///
/// ```ignore
/// use libloading::{Library, Symbol};
///
/// let lib = Library::new(path)?;
/// let constructor: Symbol<fn() -> Box<dyn CryptoProvider>> =
///     lib.get(b"temper_provider_new")?;
/// let provider = constructor();
/// ```
#[cfg(feature = "std")]
pub fn load_provider<P: AsRef<Path>>(_path: P) -> Result<Box<dyn CryptoProvider>> {
	// Memory: placeholder implementation — actual dynamic loading to be added in future
	Err(Error::Custom(
		"Dynamic provider loading not yet implemented. Use set_crypto_provider() with static providers.".into(),
	))
}

/// Discover available hardware accelerators (placeholder).
///
/// # Returns
///
/// List of discovered provider metadata.
///
/// # Future Implementation
///
/// This will probe for available hardware:
/// - CUDA GPU availability
/// - OpenCL devices
/// - FPGA devices
/// - TPU availability
#[cfg(feature = "std")]
pub fn discover_providers() -> Vec<PluginMetadata> {
	// Memory: placeholder implementation — actual hardware discovery to be added in future
	vec![]
}

// endregion: --- Plugin Loading (Placeholder)

// region:    --- Tests

#[cfg(all(test, feature = "std"))]
mod tests {
	use super::*;

	#[test]
	fn test_discover_providers_placeholder() {
		// -- Setup & Fixtures
		// (none)

		// -- Exec
		let providers = discover_providers();

		// -- Check
		assert_eq!(providers.len(), 0, "Placeholder should return empty list");
	}

	#[test]
	fn test_load_provider_placeholder() {
		// -- Setup & Fixtures
		let path = "/nonexistent/provider.so";

		// -- Exec
		let result = load_provider(path);

		// -- Check
		assert!(result.is_err(), "Placeholder should return error");
	}
}

// endregion: --- Tests
