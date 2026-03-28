//! Example hardware TRNG entropy source implementation.
//!
//! This module demonstrates how to integrate a hardware True Random Number Generator
//! with the Temper entropy system. This is particularly useful for embedded systems
//! with dedicated hardware entropy sources.
//!
//! # Example Hardware Platforms
//!
//! - **STM32**: STM32F4/F7/H7 series with built-in RNG peripheral
//! - **ESP32**: ESP32/ESP32-S3 with hardware RNG
//! - **nRF52**: Nordic nRF52 series with TRNG peripheral
//! - **ATSAM**: Microchip ATSAM series with TRNG
//!
//! # Usage
//!
//! Enable the `hardware_example` feature to compile this module:
//!
//! ```toml
//! [dependencies]
//! temper = { version = "0.1", features = ["hardware_example"] }
//! ```
//!
//! Then implement the `EntropySource` trait for your hardware:
//!
//! ```ignore
//! use temper::entropy_source::EntropySource;
//! use temper::TemperEntropy;
//!
//! // Your hardware-specific implementation
//! struct MyHardwareTrng {
//!     // Hardware peripheral handle
//! }
//!
//! impl EntropySource for MyHardwareTrng {
//!     fn name(&self) -> &str {
//!         "STM32-TRNG"
//!     }
//!
//!     fn fill_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
//!         // Read from hardware RNG peripheral
//!         // ...
//!         Ok(buf.len())
//!     }
//!
//!     fn is_available(&self) -> bool {
//!         true
//!     }
//! }
//!
//! // Use with TemperEntropy
//! let mut hw_rng = MyHardwareTrng::new();
//! let mut entropy = TemperEntropy::from_sources(&mut [&mut hw_rng])?;
//! ```

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::entropy_source::{EntropyError, EntropySource};

/// Example hardware TRNG entropy source.
///
/// This is a template implementation that demonstrates the pattern for integrating
/// hardware random number generators. In a real implementation, replace the placeholder
/// logic with actual hardware peripheral access.
///
/// # Platform-Specific Notes
///
/// ## STM32 (using stm32f4xx-hal)
///
/// ```ignore
/// use stm32f4xx_hal::rng::Rng;
///
/// pub struct Stm32Trng {
///     rng: Rng,
/// }
///
/// impl EntropySource for Stm32Trng {
///     fn fill_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
///         for byte in buf.iter_mut() {
///             *byte = self.rng.gen::<u8>();
///         }
///         Ok(buf.len())
///     }
/// }
/// ```
///
/// ## ESP32 (using esp-idf-hal)
///
/// ```ignore
/// use esp_idf_hal::rng::Rng;
///
/// pub struct Esp32Trng {
///     rng: Rng,
/// }
///
/// impl EntropySource for Esp32Trng {
///     fn fill_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
///         self.rng.fill_bytes(buf);
///         Ok(buf.len())
///     }
/// }
/// ```
///
/// ## Nordic nRF52 (using nrf52840-hal)
///
/// ```ignore
/// use nrf52840_hal::rng::Rng;
///
/// pub struct Nrf52Trng {
///     rng: Rng,
/// }
///
/// impl EntropySource for Nrf52Trng {
///     fn fill_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
///         self.rng.random(buf);
///         Ok(buf.len())
///     }
/// }
/// ```
pub struct HardwareTrng {
	/// Placeholder for hardware peripheral handle.
	/// In a real implementation, this would be a reference to the RNG peripheral.
	_phantom: core::marker::PhantomData<()>,
}

impl HardwareTrng {
	/// Create a new hardware TRNG entropy source.
	///
	/// In a real implementation, this would initialize the hardware peripheral.
	///
	/// # Example
	///
	/// ```ignore
	/// // STM32 example
	/// let dp = stm32f4xx_hal::pac::Peripherals::take().unwrap();
	/// let rng = dp.RNG.constrain();
	/// let hw_trng = HardwareTrng::new(rng);
	/// ```
	pub fn new() -> Self {
		Self {
			_phantom: core::marker::PhantomData,
		}
	}

	/// Placeholder for hardware entropy collection.
	///
	/// **IMPORTANT**: This is a placeholder that generates deterministic "entropy"
	/// for demonstration purposes only. In a real implementation, replace this with
	/// actual hardware RNG peripheral access.
	///
	/// # Real Implementation Pattern
	///
	/// ```ignore
	/// fn read_hardware_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
	///     for byte in buf.iter_mut() {
	///         // Read from hardware RNG peripheral
	///         *byte = self.rng.read_u8()
	///             .map_err(|_| EntropyError::CollectionFailed("RNG read failed".into()))?;
	///     }
	///     Ok(buf.len())
	/// }
	/// ```
	fn read_hardware_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError> {
		// **PLACEHOLDER**: In a real implementation, this would read from hardware RNG.
		// For demonstration, we'll use a simple counter pattern.

		// WARNING: This is NOT cryptographically secure!
		// Replace with actual hardware RNG access.
		for (i, byte) in buf.iter_mut().enumerate() {
			*byte = (i as u8).wrapping_mul(0x5A).wrapping_add(0x3C);
		}

		Ok(buf.len())
	}
}

impl Default for HardwareTrng {
	fn default() -> Self {
		Self::new()
	}
}

impl EntropySource for HardwareTrng {
	fn name(&self) -> &str {
		"Hardware-TRNG-Example"
	}

	fn fill_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError> {
		self.read_hardware_entropy(buf)
	}

	fn is_available(&self) -> bool {
		// In a real implementation, check if hardware RNG is initialized and ready
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hardware_trng_basic() {
		let mut hw_rng = HardwareTrng::new();

		assert!(hw_rng.is_available());
		assert_eq!(hw_rng.name(), "Hardware-TRNG-Example");

		let mut buf = [0u8; 32];
		let result = hw_rng.fill_entropy(&mut buf);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), 32);
	}

	#[test]
	fn test_hardware_trng_with_entropy() {
		use crate::TemperEntropy;
		use rand_core::RngCore;

		let mut hw_rng = HardwareTrng::new();
		let entropy_result = TemperEntropy::from_sources(&mut [&mut hw_rng]);

		// Should succeed with hardware source
		assert!(entropy_result.is_ok());

		let mut rng = entropy_result.unwrap();

		// Should be able to generate random numbers
		let random_u64 = rng.next_u64();
		assert_ne!(random_u64, 0); // Basic sanity check
	}
}
