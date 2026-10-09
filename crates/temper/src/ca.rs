//! Certificate Authority (CA) for issuing and verifying quantum-safe certificates.
//!
//! Provides a [`TemperCa`] that can issue [`TemperCertificate`]s binding a subject
//! identity to its quantum-safe public keys — both the signing keys and the
//! concealment key (see [`ConcealmentBinding`] for why the latter is certified).
//! The certificate is backed by a dual post-quantum Seal (ML-DSA-65 + SLH-DSA)
//! created by the CA's [`TemperKeypair`].
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
//! use temper::{TemperEntropy, ca::{ConcealmentBinding, SubjectKeys, TemperCa}, seal::generate_keypair};
//!
//! let mut rng = TemperEntropy::from_seed([0x42; 32]);
//! let ca = TemperCa::new(&mut rng, "root-ca@example.com")?;
//!
//! let subject_kp = generate_keypair(&mut rng, "alice@example.com")?;
//! let subject_keys = SubjectKeys {
//!     mldsa_public_key: subject_kp.mldsa_public_key.clone(),
//!     slhdsa_public_key: subject_kp.slhdsa_public_key.clone(),
//!     concealment: ConcealmentBinding::from_public_key(&subject_concealment_public),
//! };
//!
//! let cert = ca.issue_certificate(
//!     &mut rng,
//!     "alice@example.com",
//!     &subject_keys,
//!     0,    // not_before: immediately valid
//!     0,    // not_after:  no expiry
//! )?;
//!
//! assert!(ca.verify_certificate(&cert)?);
//! # Ok::<(), temper::Error>(())
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};
use crate::seal::{Seal, TemperKeypair, create_seal, generate_keypair, verify_seal};

// region:    --- Constants

// Schema 2 adds the subject's concealment public key to the signed content.
// The bump is deliberately a hard break: a schema-1 certificate does not
// verify under this code (the domain string differs too), because a v1 cert
// cannot answer the one question first contact actually has — is the
// concealment key I am about to seal my identity to the peer's? Silently
// accepting one would turn "certified" into "certified, minus the part that
// matters". No schema-1 certificate was ever issued outside tests.
const CA_SCHEMA_VERSION: u16 = 2;
const CA_CERT_DOMAIN: &str = "Temper.CA.Cert.v2";

// endregion: --- Constants

// region:    --- Concealment Binding

/// A subject's long-term concealment public key, as certified.
///
/// A certificate that signs only the subject's signing keys still leaves the
/// first flight unauthenticated. The initiator seals its identity to the
/// responder's concealment key, taken from whatever identity document it
/// holds; an impostor who substitutes a key it controls opens that flight —
/// learning exactly the identity the seal exists to hide — without ever
/// completing the handshake, because nothing but the responder's word said
/// which concealment key was the right one. Signing the concealment key into
/// the certificate removes the last input a first contact takes on faith.
///
/// The `key_id` a [`ConcealmentPublicKey`](crate::envelope::ConcealmentPublicKey)
/// carries is *not* stored here: it is derived from the two keys, so a stored
/// copy would be a second source that can disagree with the first.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConcealmentBinding {
	/// Format version of the concealment key (mirrors the envelope schema).
	pub schema_version: u16,

	/// ML-KEM-1024 public (encapsulation) key.
	pub mlkem_public_key: Vec<u8>,

	/// X25519 public key.
	pub x25519_public_key: Vec<u8>,
}

#[cfg(feature = "envelope")]
impl ConcealmentBinding {
	/// The binding to certify for a published concealment key.
	pub fn from_public_key(public: &crate::envelope::ConcealmentPublicKey) -> Self {
		Self {
			schema_version: public.schema_version,
			mlkem_public_key: public.mlkem_public_key.clone(),
			x25519_public_key: public.x25519_public_key.clone(),
		}
	}

	/// Rebuild the published form — the key an initiator encapsulates to.
	pub fn to_public_key(&self) -> crate::envelope::ConcealmentPublicKey {
		crate::envelope::ConcealmentPublicKey::from_parts(
			self.schema_version,
			self.mlkem_public_key.clone(),
			self.x25519_public_key.clone(),
		)
	}
}

// endregion: --- Concealment Binding

// region:    --- Subject Keys

/// The public keys a [`TemperCertificate`] binds to its subject.
///
/// Grouped rather than passed as three positional key arguments: a signing
/// keypair and a concealment key are one identity, and an API of five
/// `&[u8]`-shaped arguments is one transposition away from certifying the
/// wrong key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectKeys {
	/// Subject's ML-DSA-65 public key (1952 bytes).
	pub mldsa_public_key: Vec<u8>,

	/// Subject's SLH-DSA public key (32 bytes).
	pub slhdsa_public_key: Vec<u8>,

	/// Subject's concealment public key.
	pub concealment: ConcealmentBinding,
}

// endregion: --- Subject Keys

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
	concealment: ConcealmentBinding,
}

// endregion: --- Internal Content Struct

// region:    --- TemperCertificate

/// A quantum-safe certificate issued by a [`TemperCa`].
///
/// Binds a `subject_id` to the subject's ML-DSA-65 and SLH-DSA public keys
/// *and* to its concealment public key ([`ConcealmentBinding`]), signed by the
/// CA's dual PQC signatures via a [`Seal`].
///
/// # Verification
///
/// ```ignore
/// // If you have the full CA object:
/// let valid = ca.verify_certificate(&cert)?;
///
/// // If you only have the CA's public keys:
/// let valid = temper::ca::verify_certificate(
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

	/// Subject's certified concealment public key.
	pub concealment: ConcealmentBinding,

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

	/// Returns `true` if the certificate is not yet valid at
	/// `current_time_secs`.
	///
	/// Always returns `false` when `not_before == 0` (valid immediately).
	///
	/// This is the half `is_expired` does not cover, and it matters: a
	/// certificate issued for a future window verifies its seal perfectly
	/// well, so without this check an attacker who can obtain a
	/// not-yet-current certificate can present it early.
	pub fn is_not_yet_valid(&self, current_time_secs: u64) -> bool {
		if self.not_before == 0 {
			return false;
		}
		current_time_secs < self.not_before
	}

	/// Both ends of the validity window, as a verdict rather than a boolean.
	///
	/// Prefer this to calling [`is_expired`](Self::is_expired) and
	/// [`is_not_yet_valid`](Self::is_not_yet_valid) separately: a caller that
	/// checks only one of the two has a check that passes for the wrong
	/// reason, and the failure is silent.
	pub fn check_validity(&self, current_time_secs: u64) -> Result<()> {
		if self.is_not_yet_valid(current_time_secs) {
			return Err(Error::CryptoError(format!(
				"certificate is not valid until {}, presented at {}",
				self.not_before, current_time_secs
			)));
		}
		if self.is_expired(current_time_secs) {
			return Err(Error::CryptoError(format!(
				"certificate expired at {}, presented at {}",
				self.not_after, current_time_secs
			)));
		}
		Ok(())
	}

	/// The certificate's subject keys as one value — the form
	/// [`build_cert_content`] signs, and what a verifier compares a
	/// presented identity against.
	pub fn subject_keys(&self) -> SubjectKeys {
		SubjectKeys {
			mldsa_public_key: self.mldsa_public_key.clone(),
			slhdsa_public_key: self.slhdsa_public_key.clone(),
			concealment: self.concealment.clone(),
		}
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
	/// * `subject_keys` - Subject's signing and concealment public keys
	/// * `not_before` - Validity start in Unix seconds (0 = immediately valid)
	/// * `not_after` - Validity end in Unix seconds (0 = no expiry)
	pub fn issue_certificate(
		&self,
		rng: &mut TemperEntropy,
		subject_id: &str,
		subject_keys: &SubjectKeys,
		not_before: u64,
		not_after: u64,
	) -> Result<TemperCertificate> {
		let (content_bytes, cert_id) = build_cert_content(
			CA_SCHEMA_VERSION,
			subject_id,
			&self.keypair.signer_id,
			not_before,
			not_after,
			subject_keys,
		)?;

		let seal = create_seal(rng, &content_bytes, &self.keypair, BTreeMap::new())?;

		Ok(TemperCertificate {
			schema_version: CA_SCHEMA_VERSION,
			cert_id,
			subject_id: subject_id.to_string(),
			issuer_id: self.keypair.signer_id.clone(),
			not_before,
			not_after,
			mldsa_public_key: subject_keys.mldsa_public_key.clone(),
			slhdsa_public_key: subject_keys.slhdsa_public_key.clone(),
			concealment: subject_keys.concealment.clone(),
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
		&cert.subject_keys(),
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
	subject_keys: &SubjectKeys,
) -> Result<(Vec<u8>, String)> {
	let content = CertContent {
		schema_version,
		domain: CA_CERT_DOMAIN.to_string(),
		subject_id: subject_id.to_string(),
		issuer_id: issuer_id.to_string(),
		not_before,
		not_after,
		mldsa_public_key: subject_keys.mldsa_public_key.clone(),
		slhdsa_public_key: subject_keys.slhdsa_public_key.clone(),
		concealment: subject_keys.concealment.clone(),
	};

	let bytes = postcard::to_allocvec(&content)
		.map_err(|e| Error::Serialization(format!("Failed to serialize cert content: {}", e)))?;

	let cert_id = hex::encode(blake3::hash(&bytes).as_bytes());
	Ok((bytes, cert_id))
}

// endregion: --- Helpers
