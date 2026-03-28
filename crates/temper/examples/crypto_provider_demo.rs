//! Demo of the CryptoProvider abstraction.
//!
//! This example shows:
//! 1. Default CPU provider (zero-config)
//! 2. How to query the current provider
//! 3. How the provider is used internally by seal operations

use forgecore_temper::crypto_provider::get_crypto_provider;
use forgecore_temper::{TemperEntropy, create_seal, generate_keypair, verify_seal};
use std::collections::BTreeMap;

fn main() -> Result<(), forgecore_temper::Error> {
	println!("=== Temper Crypto Provider Demo ===\n");

	// 1. Query the current provider (default is CPU)
	println!("1. Current Provider:");
	let provider = get_crypto_provider();
	println!("   Using default CPU provider (RustCrypto pure Rust implementation)");
	println!("   - ML-DSA-65: FIPS 204, lattice-based");
	println!("   - SLH-DSA-SHA2-128f: FIPS 205, hash-based (fast variant)\n");

	// 2. Use provider directly (normally you wouldn't do this)
	println!("2. Direct Provider Usage:");
	let mut rng = TemperEntropy::from_seed([0x42; 32]);
	let (mldsa_sk, mldsa_pk) = provider.mldsa_keygen(&mut rng)?;
	println!("   Generated ML-DSA-65 keypair:");
	println!("   - Secret key size: {} bytes", mldsa_sk.len());
	println!("   - Public key size: {} bytes\n", mldsa_pk.len());

	// 3. Use provider indirectly through seal operations (normal usage)
	println!("3. Provider Used by Seal Operations:");
	let mut rng = TemperEntropy::from_seed([0x43; 32]);
	let keypair = generate_keypair(&mut rng, "demo@example.com")?;
	println!("   ✓ Generated Temper keypair (uses provider internally)");

	let content = b"Quantum-safe message protected by dual PQC signatures";
	let seal = create_seal(&mut rng, content, &keypair, BTreeMap::new())?;
	println!("   ✓ Created seal (provider signs with both ML-DSA and SLH-DSA)");

	let result = verify_seal(content, &seal, &keypair.mldsa_public_key, &keypair.slhdsa_public_key)?;
	println!("   ✓ Verified seal (provider verifies both signatures)");
	println!("   - Content hash valid: {}", result.content_hash_valid);
	println!("   - Primary (ML-DSA) valid: {}", result.primary_valid);
	println!("   - Backup (SLH-DSA) valid: {}", result.backup_valid);
	println!("   - Overall valid: {}\n", result.valid);

	println!("4. Future: Hardware Acceleration");
	println!("   The provider abstraction allows plugging in GPU/FPGA implementations:");
	println!("   - set_crypto_provider(&MY_GPU_PROVIDER);");
	println!("   - All seal operations automatically use hardware acceleration");
	println!("   - No protocol changes required\n");

	println!("=== Demo Complete ===");
	Ok(())
}
