//! Certificate Authority (CA) for issuing and verifying quantum-safe certificates.
//!
//! Provides a [`TemperCa`] that can issue [`TemperCertificate`]s binding a subject
//! identity to a quantum-safe keypair.  The certificate is backed by a dual
//! post-quantum Seal (ML-DSA-65 + SLH-DSA) created by the CA's [`TemperKeypair`].
//!
//! # Protocol
//!
//! ## Issuance
//! 1. Serialize the certificate content fields into `CertContent` → postcard bytes.
//! 2. `seal = create_seal(rng, cert_content_bytes, ca_keypair, metadata)`.
//! 3. Return a `TemperCertificate` carrying those fields plus the seal.
//!
//! ## Verification
//! 1. Reconstruct `cert_content_bytes` from certificate fields (same deterministic form).
//! 2. `result = verify_seal(cert_content_bytes, &cert.seal, ca_mldsa_pk, ca_slhdsa_pk)`.
//! 3. `true` iff content hash matches **and** both PQC signatures are valid.
//!
//! # Example
//!
//! ```ignore
//! use forgecore_temper::{TemperEntropy, ca::TemperCa, seal::generate_keypair};
//!
//! let mut rng = TemperEntropy::from_seed([0x42; 32]);
//! let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
//!
//! let subject_kp = generate_keypair(&mut rng, "alice@example.com")?;
//! let cert = ca.issue_certificate(
//!     &mut rng,
//!     "alice@example.com",
//!     &subject_kp.mldsa_public_key,
//!     &subject_kp.slhdsa_public_key,
//!     0,    // not_before: immediately valid
//!     0,    // not_after:  no expiry
//! )?;
//!
//! assert!(ca.verify_certificate(&cert)?);
//! # Ok::<(), forgecore_temper::Error>(())
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};
use crate::seal::{Seal, TemperKeypair, create_seal, generate_keypair, verify_seal};

// region:    --- Constants

const CA_SCHEMA_VERSION: u16 = 1;
const CA_CERT_DOMAIN: &str = "Temper.CA.Cert.v1";

// endregion: --- Constants

// region:    --- Internal Content Struct

/// Canonical representation of certificate fields that the CA signs.
///
/// Serialized with postcard and passed to [`create_seal`] as the content bytes.
/// Must be reconstructed identically during [`verify_certificate`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CertContent {
	schema_version: u16,
	domain: String,
	subject_id: String,
	issuer_id: String,
	not_before: u64,
	not_after: u64,
	mldsa_public_key: Vec<u8>,
	slhdsa_public_key: Vec<u8>,
}

// endregion: --- Internal Content Struct

// region:    --- TemperCertificate

/// A quantum-safe certificate issued by a [`TemperCa`].
///
/// Binds a `subject_id` to the subject's ML-DSA-65 and SLH-DSA public keys,
/// signed by the CA's dual PQC signatures via a [`Seal`].
///
/// # Verification
///
/// ```ignore
/// // If you have the full CA object:
/// let valid = ca.verify_certificate(&cert)?;
///
/// // If you only have the CA's public keys:
/// let valid = forgecore_temper::ca::verify_certificate(
///     &cert,
///     &ca.keypair.mldsa_public_key,
///     &ca.keypair.slhdsa_public_key,
/// )?;
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemperCertificate {
	/// Schema version for forward compatibility.
	pub schema_version: u16,

	/// Unique certificate identifier — BLAKE3(postcard(cert content)) as hex.
	pub cert_id: String,

	/// Subject identity (who this certificate is for).
	pub subject_id: String,

	/// Issuer identity — the CA's `signer_id`.
	pub issuer_id: String,

	/// Certificate validity start (Unix seconds; 0 = immediately valid).
	pub not_before: u64,

	/// Certificate validity end (Unix seconds; 0 = no expiry).
	pub not_after: u64,

	/// Subject's ML-DSA-65 public key (1952 bytes).
	pub mldsa_public_key: Vec<u8>,

	/// Subject's SLH-DSA public key (32 bytes).
	pub slhdsa_public_key: Vec<u8>,

	/// CA's dual PQC signature binding all certificate fields.
	pub seal: Seal,
}

impl TemperCertificate {
	/// Returns `true` if the certificate has expired at `current_time_secs`.
	///
	/// Always returns `false` when `not_after == 0` (no expiry configured).
	pub fn is_expired(&self, current_time_secs: u64) -> bool {
		if self.not_after == 0 {
			return false;
		}
		current_time_secs > self.not_after
	}

	/// Serialize the certificate to postcard bytes.
	pub fn to_bytes(&self) -> Result<Vec<u8>> {
		postcard::to_allocvec(self).map_err(|e| Error::Serialization(format!("Failed to serialize certificate: {}", e)))
	}

	/// Deserialize a certificate from postcard bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
		postcard::from_bytes(bytes)
			.map_err(|e| Error::Serialization(format!("Failed to deserialize certificate: {}", e)))
	}
}

// endregion: --- TemperCertificate

// region:    --- TemperCa

/// Quantum-safe Certificate Authority backed by dual PQC signatures.
///
/// Issues [`TemperCertificate`]s binding a subject identity to public keys,
/// signed with the CA's ML-DSA-65 + SLH-DSA [`TemperKeypair`].
pub struct TemperCa {
	/// CA's signing keypair (holds both ML-DSA-65 and SLH-DSA keys).
	pub keypair: TemperKeypair,
}

impl TemperCa {
	/// Create a new Certificate Authority with a freshly generated keypair.
	///
	/// # Arguments
	///
	/// * `rng` - Entropy source for key generation
	/// * `ca_id` - Human-readable identifier for this CA (e.g. `"root-ca@example.com"`)
	pub fn new(rng: &mut TemperEntropy, ca_id: &str) -> Result<Self> {
		let keypair = generate_keypair(rng, ca_id)?;
		Ok(Self { keypair })
	}

	/// Return this CA's signer identifier.
	pub fn ca_id(&self) -> &str {
		&self.keypair.signer_id
	}

	/// Issue a [`TemperCertificate`] for a subject.
	///
	/// # Arguments
	///
	/// * `rng` - Entropy source for the dual-PQC signing operations
	/// * `subject_id` - Human-readable subject identifier
	/// * `subject_mldsa_pk` - Subject's ML-DSA-65 public key (1952 bytes)
	/// * `subject_slhdsa_pk` - Subject's SLH-DSA public key (32 bytes)
	/// * `not_before` - Validity start in Unix seconds (0 = immediately valid)
	/// * `not_after` - Validity end in Unix seconds (0 = no expiry)
	pub fn issue_certificate(
		&self,
		rng: &mut TemperEntropy,
		subject_id: &str,
		subject_mldsa_pk: &[u8],
		subject_slhdsa_pk: &[u8],
		not_before: u64,
		not_after: u64,
	) -> Result<TemperCertificate> {
		let (content_bytes, cert_id) = build_cert_content(
			CA_SCHEMA_VERSION,
			subject_id,
			&self.keypair.signer_id,
			not_before,
			not_after,
			subject_mldsa_pk,
			subject_slhdsa_pk,
		)?;

		let seal = create_seal(rng, &content_bytes, &self.keypair, BTreeMap::new())?;

		Ok(TemperCertificate {
			schema_version: CA_SCHEMA_VERSION,
			cert_id,
			subject_id: subject_id.to_string(),
			issuer_id: self.keypair.signer_id.clone(),
			not_before,
			not_after,
			mldsa_public_key: subject_mldsa_pk.to_vec(),
			slhdsa_public_key: subject_slhdsa_pk.to_vec(),
			seal,
		})
	}

	/// Verify that a certificate was issued by this CA.
	///
	/// Returns `true` if the certificate's seal is valid under this CA's keypair.
	pub fn verify_certificate(&self, cert: &TemperCertificate) -> Result<bool> {
		verify_certificate(cert, &self.keypair.mldsa_public_key, &self.keypair.slhdsa_public_key)
	}
}

// endregion: --- TemperCa

// region:    --- Standalone Verification

/// Verify a [`TemperCertificate`] using the issuing CA's public keys.
///
/// Use this when the verifier holds the CA's public keys but not the full
/// [`TemperCa`] object.
///
/// # Arguments
///
/// * `cert` - The certificate to verify
/// * `ca_mldsa_pk` - CA's ML-DSA-65 public key (1952 bytes)
/// * `ca_slhdsa_pk` - CA's SLH-DSA public key (32 bytes)
///
/// # Returns
///
/// `true` iff all three checks pass:
/// - Content hash of the reconstructed cert fields matches the seal
/// - CA's ML-DSA-65 signature is valid
/// - CA's SLH-DSA signature is valid
pub fn verify_certificate(cert: &TemperCertificate, ca_mldsa_pk: &[u8], ca_slhdsa_pk: &[u8]) -> Result<bool> {
	let (content_bytes, _) = build_cert_content(
		cert.schema_version,
		&cert.subject_id,
		&cert.issuer_id,
		cert.not_before,
		cert.not_after,
		&cert.mldsa_public_key,
		&cert.slhdsa_public_key,
	)?;

	let result = verify_seal(&content_bytes, &cert.seal, ca_mldsa_pk, ca_slhdsa_pk)?;
	Ok(result.valid)
}

// endregion: --- Standalone Verification

// region:    --- Helpers

/// Build the canonical postcard-serialized cert content bytes and compute the cert_id.
///
/// Returns `(content_bytes, cert_id_hex)`.
fn build_cert_content(
	schema_version: u16,
	subject_id: &str,
	issuer_id: &str,
	not_before: u64,
	not_after: u64,
	mldsa_public_key: &[u8],
	slhdsa_public_key: &[u8],
) -> Result<(Vec<u8>, String)> {
	let content = CertContent {
		schema_version,
		domain: CA_CERT_DOMAIN.to_string(),
		subject_id: subject_id.to_string(),
		issuer_id: issuer_id.to_string(),
		not_before,
		not_after,
		mldsa_public_key: mldsa_public_key.to_vec(),
		slhdsa_public_key: slhdsa_public_key.to_vec(),
	};

	let bytes = postcard::to_allocvec(&content)
		.map_err(|e| Error::Serialization(format!("Failed to serialize cert content: {}", e)))?;

	let cert_id = hex::encode(blake3::hash(&bytes).as_bytes());
	Ok((bytes, cert_id))
}

// endregion: --- Helpers
