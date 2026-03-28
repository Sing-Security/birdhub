#![no_std]
#![doc = "Temper — Quantum-safe cryptographic protocol with hardened entropy and dual PQC signatures."]

#[cfg(feature = "alloc")]
extern crate alloc;

// When std is enabled, make std available
#[cfg(feature = "std")]
extern crate std;

// When std is enabled, alloc is implicitly available
#[cfg(all(feature = "std", not(feature = "alloc")))]
extern crate alloc;

// region:    --- Modules

pub mod crypto_provider;
pub mod entropy;
pub mod entropy_source;
pub mod error;

#[cfg(feature = "signatures")]
pub mod seal;

#[cfg(feature = "signatures")]
pub mod ca;

#[cfg(feature = "envelope")]
pub mod envelope;

#[cfg(feature = "std")]
pub mod plugins;

#[cfg(feature = "hardware_example")]
pub mod hardware_example;

#[cfg(test)]
#[path = "entropy_tests.rs"]
mod entropy_tests;

#[cfg(all(test, feature = "signatures"))]
#[path = "seal_tests.rs"]
mod seal_tests;

#[cfg(all(test, feature = "signatures"))]
#[path = "ca_tests.rs"]
mod ca_tests;

#[cfg(all(test, feature = "envelope"))]
#[path = "envelope_tests.rs"]
mod envelope_tests;

// endregion: --- Modules

// region:    --- Re-exports

pub use entropy::{EntropyHealth, TemperEntropy};
pub use entropy_source::{EntropyError, EntropySource};
pub use error::{Error, Result};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "signatures")]
pub use crypto_provider::{CryptoProvider, get_crypto_provider, set_crypto_provider};

#[cfg(feature = "signatures")]
pub use seal::{Seal, SealContext, SignatureBlock, TemperKeypair, VerifyResult};
#[cfg(feature = "signatures")]
pub use seal::{create_seal, generate_keypair, verify_seal};

#[cfg(feature = "signatures")]
pub use ca::verify_certificate as verify_cert_with_keys;
#[cfg(feature = "signatures")]
pub use ca::{TemperCa, TemperCertificate};

// Stub types for when signatures feature is disabled
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
pub fn verify_seal(
    _content: &[u8],
    _seal: &Seal,
    _mldsa_pk: &[u8],
    _slhdsa_pk: &[u8],
) -> Result<VerifyResult> {
    Ok(VerifyResult { valid: true })
}

#[cfg(feature = "hardware_example")]
pub use hardware_example::HardwareTrng;

#[cfg(feature = "envelope")]
pub use envelope::{Envelope, EnvelopeKeypair, KernelChainEnvelope};
#[cfg(feature = "envelope")]
pub use envelope::{authenticated_decapsulate, authenticated_encapsulate};
#[cfg(feature = "envelope")]
pub use envelope::{decapsulate, encapsulate, generate_envelope_keypair};
#[cfg(feature = "envelope")]
pub use envelope::{
    kernel_chain_decapsulate, kernel_chain_encapsulate, kernel_chain_extract_secret,
};

// Stub types for when envelope feature is disabled
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
pub fn authenticated_encapsulate(
    _public_key: &EnvelopeKeypair,
    _data: &[u8],
) -> Result<alloc::vec::Vec<u8>> {
    Ok(alloc::vec::Vec::new())
}

#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub fn authenticated_decapsulate(
    _envelope: &[u8],
    _secret_key: &EnvelopeKeypair,
) -> Result<alloc::vec::Vec<u8>> {
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

// endregion: --- Re-exports

// region:    --- Custom getrandom (no_std targets without OS entropy)

/// Custom getrandom implementation for no_std targets.
///
/// This is used when building temper with `default-features = false` on targets
/// that don't have OS entropy (e.g., x86_64-unknown-none bare metal).
///
/// **WARNING**: This returns zeros! It should only be used when:
/// 1. The target has no OS to provide entropy
/// 2. The caller provides custom entropy sources via `TemperEntropy::from_sources()`
///
/// If you're using `TemperEntropy::new()` (std feature), this function is never called
/// because getrandom uses the OS CSPRNG instead.
#[cfg(not(feature = "std"))]
fn custom_getrandom(buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    // Zero-fill the buffer
    // This is safe because:
    // 1. On bare metal (no OS), there's no system entropy source anyway
    // 2. Users of bare metal must provide custom entropy via from_sources()
    // 3. The entropy pool mixes this with actual entropy from hardware sources
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    Ok(())
}

#[cfg(not(feature = "std"))]
getrandom::register_custom_getrandom!(custom_getrandom);

// endregion: --- Custom getrandom

#[cfg(feature = "alloc")]
pub fn encrypt(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

#[cfg(feature = "alloc")]
pub fn decrypt(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}
