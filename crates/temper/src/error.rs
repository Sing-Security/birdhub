//! Error types for the Temper cryptographic protocol.
//!
//! Uses `derive_more` for no_std compatible error handling.

use derive_more::{Display, From};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::string::ToString;

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
	// endregion:    --- Serialization Errors

	// region:    --- Protocol Errors
	/// Protocol-level failure: version mismatch, identity or policy
	/// rejection, failed handshake confirmation, or a record that did not
	/// authenticate (bad tag, replayed or out-of-order sequence). Distinct
	/// from [`Error::CryptoError`] so callers can tell a peer's protocol
	/// behaviour apart from a local implementation fault.
	Protocol(String),
	// endregion:    --- Protocol Errors

	// region:    --- Transport Errors
	/// Network, framing, or stream I/O failure. Only constructible with the
	/// `transport` feature (which implies `std`), so no_std configurations
	/// carry the exact same `Error` shape they had before the feature
	/// existed.
	#[cfg(feature = "transport")]
	Io(std::io::Error),
	// endregion: --- Transport Errors
}

// region:    --- Custom

impl Error {
	/// Create a custom error with a message.
	pub fn custom(msg: impl Into<String>) -> Self {
		Self::Custom(msg.into())
	}

	/// Create a custom error from any [`core::error::Error`].
	pub fn custom_from_err(err: impl core::error::Error) -> Self {
		Self::custom(err.to_string())
	}
}

// endregion: --- Custom

// region:    --- Transport

// The one external error type, cfg'd with its only producer (transport
// frames). A manual impl rather than a derive_more `#[from]`: an explicit
// `#[cfg]` on both halves of the pair cannot drift apart.
#[cfg(feature = "transport")]
impl From<std::io::Error> for Error {
	fn from(err: std::io::Error) -> Self {
		Self::Io(err)
	}
}

// endregion: --- Transport

// region:    --- Error Boilerplate

impl core::error::Error for Error {}

// endregion: --- Error Boilerplate
