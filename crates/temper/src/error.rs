//! Error types for the Temper cryptographic protocol.
//!
//! Uses `derive_more` for no_std compatible error handling.

use derive_more::{Display, From};

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Result type alias using Temper's Error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur in Temper operations.
#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	/// Custom error with a message
	#[from(String, &String, &str)]
	Custom(String),

	// region:    --- Entropy Errors
	/// Insufficient entropy available
	InsufficientEntropy {
		/// Required number of bytes
		required: usize,
		/// Available number of bytes
		available: usize,
	},

	/// Entropy source failed to provide data
	EntropySourceFailed(String),

	/// Entropy source is not available
	EntropyUnavailable,

	/// Re-seeding the DRBG failed
	ReseedFailed,

	/// Mutex lock was poisoned
	LockPoisoned,
	// endregion: --- Entropy Errors

	// region:    --- Cryptographic Errors
	/// Signature verification failed
	InvalidSignature(String),

	/// General cryptographic operation error
	CryptoError(String),

	/// Key generation failed
	KeyGenError(String),
	// endregion: --- Cryptographic Errors

	// region:    --- Serialization Errors
	/// Serialization or deserialization failed
	Serialization(String),

	/// Compression or decompression failed
	Compression(String),
	// endregion: --- Serialization Errors
}

/// Implement std::error::Error trait when std feature is enabled.
#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Error {
	/// Create a custom error with a message.
	pub fn custom(msg: impl Into<String>) -> Self {
		Self::Custom(msg.into())
	}
}
