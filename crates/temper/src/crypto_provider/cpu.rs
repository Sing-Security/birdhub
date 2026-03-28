//! CPU-based Post-Quantum Cryptography implementation using RustCrypto libraries.
//!
//! This is the default provider that uses pure Rust implementations of ML-DSA and SLH-DSA
//! from the RustCrypto project. It works in both `std` and `no_std` environments.
//!
//! # Algorithms
//!
//! - **ML-DSA-65**: FIPS 204, lattice-based, NIST Level 3 security
//! - **SLH-DSA-SHA2-128f**: FIPS 205, hash-based, NIST Level 5 security (fast variant)
//!
//! # Performance
//!
//! - ML-DSA-65 signing: ~1-2ms on modern CPUs
//! - SLH-DSA-SHA2-128f signing: ~10-20ms (50x faster than 128s variant)
//! - Both verification operations: ~1-2ms
//!
//! # Example
//!
//! ```no_run
//! use temper::crypto_provider::{CryptoProvider, cpu::CpuProvider};
//! use temper::TemperEntropy;
//!
//! let provider = CpuProvider;
//! let mut rng = TemperEntropy::from_seed([0x42; 32]);
//! let (sk, pk) = provider.mldsa_keygen(&mut rng)?;
//! # Ok::<(), temper::Error>(())
//! ```

// Memory: no_std pattern per rust-nostd.instructions.md — use alloc for heap types
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// Memory: PQC library imports from original seal.rs implementation
use ml_dsa::signature::{Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{EncodedVerifyingKey as MlEncodedVerifyingKey, KeyGen, MlDsa65};
use slh_dsa::Sha2_128f;
use slh_dsa::signature::{Keypair as SlhKeypair, Signer as SlhSigner, Verifier as SlhVerifier};
use zeroize::Zeroize;

use crate::crypto_provider::CryptoProvider;
use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};
use rand_core::RngCore;

// region:    --- CpuProvider

/// CPU-based crypto provider using RustCrypto PQC libraries.
///
/// This is a zero-sized type (ZST) that implements `CryptoProvider` using pure Rust
/// implementations from the RustCrypto project.
///
/// # Thread Safety
///
/// All operations are stateless and thread-safe.
pub struct CpuProvider;

// Memory: global static pattern per crypto_provider.rs — singleton CPU provider
/// Global CPU provider instance (zero-config default).
pub static CPU_PROVIDER: CpuProvider = CpuProvider;

impl CryptoProvider for CpuProvider {
    #[inline]
    fn mldsa_keygen(&self, rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)> {
        // Memory: ML-DSA keygen logic moved from seal.rs lines 311-323
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);

        let seed = ml_dsa::Seed::from(seed_bytes);
        let keypair = MlDsa65::from_seed(&seed);
        let pk = keypair.verifying_key().encode().as_slice().to_vec();
        let sk = seed.as_slice().to_vec();

        seed_bytes.zeroize();

        Ok((sk, pk))
    }

    #[inline]
    fn mldsa_sign(&self, sk: &[u8], message: &[u8], _rng: &mut TemperEntropy) -> Result<Vec<u8>> {
        // Memory: ML-DSA signing logic moved from seal.rs lines 327-334
        let seed = ml_dsa::Seed::try_from(sk)
            .map_err(|_| Error::CryptoError("Invalid ML-DSA-65 seed".into()))?;
        let keypair = MlDsa65::from_seed(&seed);
        let signature = MlSigner::try_sign(&keypair, message)
            .map_err(|_| Error::CryptoError("ML-DSA-65 signing failed".into()))?;
        Ok(signature.encode().as_slice().to_vec())
    }

    #[inline]
    fn mldsa_verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Memory: ML-DSA verification logic moved from seal.rs lines 338-349
        let encoded_pk = match MlEncodedVerifyingKey::<MlDsa65>::try_from(pk) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded_pk);
        let signature = match ml_dsa::Signature::<MlDsa65>::try_from(signature) {
            Ok(value) => value,
            Err(_) => return false,
        };
        MlVerifier::verify(&verifying_key, message, &signature).is_ok()
    }

    #[inline]
    fn slhdsa_keygen(&self, rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)> {
        // Memory: SLH-DSA keygen logic moved from seal.rs lines 363-381
        let mut sk_seed = [0u8; 16];
        let mut sk_prf = [0u8; 16];
        let mut pk_seed = [0u8; 16];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);

        let signing_key =
            slh_dsa::SigningKey::<Sha2_128f>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        let sk = signing_key.to_bytes().as_slice().to_vec();
        let pk = signing_key.verifying_key().to_bytes().as_slice().to_vec();

        sk_seed.zeroize();
        sk_prf.zeroize();
        pk_seed.zeroize();

        Ok((sk, pk))
    }

    #[inline]
    fn slhdsa_sign(&self, sk: &[u8], message: &[u8], _rng: &mut TemperEntropy) -> Result<Vec<u8>> {
        // Memory: SLH-DSA signing logic moved from seal.rs lines 385-391
        let signing_key = slh_dsa::SigningKey::<Sha2_128f>::try_from(sk)
            .map_err(|_| Error::CryptoError("Invalid SLH-DSA signing key".into()))?;
        let signature = SlhSigner::try_sign(&signing_key, message)
            .map_err(|_| Error::CryptoError("SLH-DSA signing failed".into()))?;
        Ok(signature.to_bytes().as_slice().to_vec())
    }

    #[inline]
    fn slhdsa_verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Memory: SLH-DSA verification logic moved from seal.rs lines 395-405
        let verifying_key = match slh_dsa::VerifyingKey::<Sha2_128f>::try_from(pk) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let signature = match slh_dsa::Signature::<Sha2_128f>::try_from(signature) {
            Ok(value) => value,
            Err(_) => return false,
        };
        SlhVerifier::verify(&verifying_key, message, &signature).is_ok()
    }
}

// endregion: --- CpuProvider

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_provider_mldsa_roundtrip() {
        // -- Setup & Fixtures
        let provider = CpuProvider;
        let mut rng = TemperEntropy::from_seed([0x42; 32]);
        let message = b"Test message for ML-DSA-65";

        // -- Exec
        let (sk, pk) = provider.mldsa_keygen(&mut rng).unwrap();
        let signature = provider.mldsa_sign(&sk, message, &mut rng).unwrap();
        let valid = provider.mldsa_verify(&pk, message, &signature);

        // -- Check
        assert!(valid, "ML-DSA-65 signature verification should succeed");
        assert_eq!(pk.len(), 1952, "ML-DSA-65 public key should be 1952 bytes");
        assert_eq!(
            signature.len(),
            3309,
            "ML-DSA-65 signature should be 3309 bytes"
        );
    }

    #[test]
    fn test_cpu_provider_mldsa_invalid_signature() {
        // -- Setup & Fixtures
        let provider = CpuProvider;
        let mut rng = TemperEntropy::from_seed([0x42; 32]);
        let message = b"Test message";

        // -- Exec
        let (sk, pk) = provider.mldsa_keygen(&mut rng).unwrap();
        let mut signature = provider.mldsa_sign(&sk, message, &mut rng).unwrap();
        signature[0] ^= 0xFF; // Corrupt signature
        let valid = provider.mldsa_verify(&pk, message, &signature);

        // -- Check
        assert!(
            !valid,
            "ML-DSA-65 verification should fail for corrupted signature"
        );
    }

    #[test]
    fn test_cpu_provider_slhdsa_roundtrip() {
        // -- Setup & Fixtures
        let provider = CpuProvider;
        let mut rng = TemperEntropy::from_seed([0x42; 32]);
        let message = b"Test message for SLH-DSA";

        // -- Exec
        let (sk, pk) = provider.slhdsa_keygen(&mut rng).unwrap();
        let signature = provider.slhdsa_sign(&sk, message, &mut rng).unwrap();
        let valid = provider.slhdsa_verify(&pk, message, &signature);

        // -- Check
        assert!(valid, "SLH-DSA signature verification should succeed");
        assert_eq!(pk.len(), 32, "SLH-DSA public key should be 32 bytes");
        assert_eq!(
            signature.len(),
            17088,
            "SLH-DSA signature should be 17088 bytes"
        );
    }

    #[test]
    fn test_cpu_provider_slhdsa_invalid_signature() {
        // -- Setup & Fixtures
        let provider = CpuProvider;
        let mut rng = TemperEntropy::from_seed([0x42; 32]);
        let message = b"Test message";

        // -- Exec
        let (sk, pk) = provider.slhdsa_keygen(&mut rng).unwrap();
        let mut signature = provider.slhdsa_sign(&sk, message, &mut rng).unwrap();
        signature[100] ^= 0xFF; // Corrupt signature
        let valid = provider.slhdsa_verify(&pk, message, &signature);

        // -- Check
        assert!(
            !valid,
            "SLH-DSA verification should fail for corrupted signature"
        );
    }
}

// endregion: --- Tests
