//! Stub surface compiled in place of the `seal` / `envelope` modules when their
//! features are off.
//!
//! The public paths are unchanged: `lib.rs` re-exports every item at the
//! crate root under the same cfg that used to guard its definition, so this
//! module stays private.

#[cfg(any(not(feature = "signatures"), all(not(feature = "envelope"), feature = "alloc")))]
use crate::{Result, TemperEntropy};

// -- Signatures stubs

#[cfg(not(feature = "signatures"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Seal;

#[cfg(not(feature = "signatures"))]
pub struct SealContext;

#[cfg(not(feature = "signatures"))]
pub struct SignatureBlock;

#[cfg(not(feature = "signatures"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemperKeypair;

#[cfg(not(feature = "signatures"))]
#[derive(Debug, Clone)]
pub struct VerifyResult {
	pub valid: bool,
}

#[cfg(not(feature = "signatures"))]
impl VerifyResult {
	pub fn is_valid(&self) -> bool {
		self.valid
	}
}

#[cfg(not(feature = "signatures"))]
pub fn generate_keypair(_rng: &mut TemperEntropy) -> Result<TemperKeypair> {
	Ok(TemperKeypair)
}

#[cfg(not(feature = "signatures"))]
pub fn create_seal(
	_rng: &mut TemperEntropy,
	_data: &[u8],
	_keypair: &impl core::fmt::Debug, // Accept any keypair type
	_context: &[u8],
) -> Result<Seal> {
	Ok(Seal)
}

#[cfg(not(feature = "signatures"))]
pub fn verify_seal(_content: &[u8], _seal: &Seal, _mldsa_pk: &[u8], _slhdsa_pk: &[u8]) -> Result<VerifyResult> {
	Ok(VerifyResult { valid: true })
}

// -- Envelope stubs

#[cfg(not(feature = "envelope"))]
pub struct Envelope;

#[cfg(not(feature = "envelope"))]
pub struct KernelChainEnvelope;

#[cfg(not(feature = "envelope"))]
#[derive(Debug, Clone)]
pub struct EnvelopeKeypair {
	#[cfg(feature = "alloc")]
	pub public_key: alloc::vec::Vec<u8>,
	#[cfg(not(feature = "alloc"))]
	pub public_key: (),

	#[cfg(feature = "alloc")]
	pub private_key: alloc::vec::Vec<u8>,
	#[cfg(not(feature = "alloc"))]
	pub private_key: (),
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn generate_envelope_keypair() -> Result<EnvelopeKeypair> {
	Ok(EnvelopeKeypair {
		public_key: alloc::vec::Vec::new(),
		private_key: alloc::vec::Vec::new(),
	})
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn encapsulate(_public_key: &EnvelopeKeypair) -> Result<(Envelope, [u8; 32])> {
	Ok((Envelope, [0u8; 32]))
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn decapsulate(_envelope: &Envelope, _secret_key: &EnvelopeKeypair) -> Result<[u8; 32]> {
	Ok([0u8; 32])
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn authenticated_encapsulate(_public_key: &EnvelopeKeypair, _data: &[u8]) -> Result<alloc::vec::Vec<u8>> {
	Ok(alloc::vec::Vec::new())
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn authenticated_decapsulate(_envelope: &[u8], _secret_key: &EnvelopeKeypair) -> Result<alloc::vec::Vec<u8>> {
	Ok(alloc::vec::Vec::new())
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn kernel_chain_encapsulate(
	_rng: &mut TemperEntropy,
	_plaintext: &[u8],
	_recipient_keypair: &EnvelopeKeypair,
	_kernel_keypair: &EnvelopeKeypair,
) -> Result<KernelChainEnvelope> {
	Ok(KernelChainEnvelope)
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn kernel_chain_decapsulate(
	_envelope: &KernelChainEnvelope,
	_recipient_keypair: &EnvelopeKeypair,
	_kernel_shared_secret: &[u8; 32],
) -> Result<alloc::vec::Vec<u8>> {
	Ok(alloc::vec::Vec::new())
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn kernel_chain_extract_secret(
	_envelope: &KernelChainEnvelope,
	_kernel_keypair: &EnvelopeKeypair,
) -> Result<[u8; 32]> {
	Ok([0u8; 32])
}
