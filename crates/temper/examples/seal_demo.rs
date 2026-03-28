//! Demonstration of the Temper dual PQC signature protocol.
//!
//! This example shows how to:
//! 1. Generate quantum-safe keypairs (ML-DSA-65 + SLH-DSA)
//! 2. Create seals binding content to dual signatures
//! 3. Verify seals with both primary and backup signatures
//! 4. Detect tampering attempts
//!
//! Run with: cargo run --example seal_demo

use forgecore_temper::{TemperEntropy, create_seal, generate_keypair, verify_seal};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("═══════════════════════════════════════════════════════════");
	println!("  Temper Dual PQC Signature Demo");
	println!("  ML-DSA-65 (FIPS 204) + SLH-DSA (FIPS 205)");
	println!("═══════════════════════════════════════════════════════════\n");

	// Initialize CSPRNG with hardened entropy
	println!("1. Initializing TemperEntropy (OS + jitter + process)...");
	let mut rng = TemperEntropy::new()?;
	println!("   ✅ Entropy pool initialized with multi-source mixing\n");

	// Generate quantum-safe keypair
	println!("2. Generating keypair for alice@example.com...");
	let keypair = generate_keypair(&mut rng, "alice@example.com")?;
	println!(
		"   ✅ ML-DSA-65 keypair: {} byte secret, {} byte public",
		keypair.mldsa_secret_key.len(),
		keypair.mldsa_public_key.len()
	);
	println!(
		"   ✅ SLH-DSA keypair: {} byte secret, {} byte public",
		keypair.slhdsa_secret_key.len(),
		keypair.slhdsa_public_key.len()
	);
	println!("   ✅ Key ID: {}...\n", &keypair.key_id[..16]);

	// Create a seal for sensitive content
	println!("3. Creating seal for sensitive document...");
	let content = b"CLASSIFIED: Quantum-resistant cryptographic protocol specifications";

	let mut metadata = BTreeMap::new();
	metadata.insert("classification".to_string(), "TOP SECRET".to_string());
	metadata.insert("department".to_string(), "R&D".to_string());
	metadata.insert("project".to_string(), "Post-Quantum Migration".to_string());

	let seal = create_seal(&mut rng, content, &keypair, metadata)?;

	println!("   ✅ Content hash: {}...", &seal.content_hash[..16]);
	println!(
		"   ✅ Primary (ML-DSA-65): {} byte signature",
		hex::decode(&seal.primary.signature)?.len()
	);
	println!(
		"   ✅ Backup (SLH-DSA): {} byte signature",
		hex::decode(&seal.backup.signature)?.len()
	);
	println!("   ✅ Seal ID: {}...\n", &seal.seal_id[..16]);

	// Verify the seal
	println!("4. Verifying seal integrity...");
	let result = verify_seal(content, &seal, &keypair.mldsa_public_key, &keypair.slhdsa_public_key)?;

	println!(
		"   Content hash valid: {}",
		if result.content_hash_valid { "✅" } else { "❌" }
	);
	println!(
		"   Primary (ML-DSA-65) valid: {}",
		if result.primary_valid { "✅" } else { "❌" }
	);
	println!(
		"   Backup (SLH-DSA) valid: {}",
		if result.backup_valid { "✅" } else { "❌" }
	);
	println!(
		"   Overall seal valid: {}\n",
		if result.valid { "✅ PASS" } else { "❌ FAIL" }
	);

	// Demonstrate tamper detection
	println!("5. Testing tamper detection...");
	let tampered_content = b"UNCLASSIFIED: Modified document (tampered)";
	let tamper_result = verify_seal(
		tampered_content,
		&seal,
		&keypair.mldsa_public_key,
		&keypair.slhdsa_public_key,
	)?;

	println!(
		"   Content hash valid: {}",
		if tamper_result.content_hash_valid { "✅" } else { "❌" }
	);
	println!(
		"   Overall seal valid: {}\n",
		if tamper_result.valid {
			"✅ PASS"
		} else {
			"❌ FAIL (expected)"
		}
	);

	// Test with wrong keypair
	println!("6. Testing key isolation...");
	let wrong_keypair = generate_keypair(&mut rng, "eve@attacker.com")?;
	let wrong_key_result = verify_seal(
		content,
		&seal,
		&wrong_keypair.mldsa_public_key,
		&wrong_keypair.slhdsa_public_key,
	)?;

	println!(
		"   Primary signature valid: {}",
		if wrong_key_result.primary_valid { "✅" } else { "❌" }
	);
	println!(
		"   Backup signature valid: {}",
		if wrong_key_result.backup_valid { "✅" } else { "❌" }
	);
	println!(
		"   Overall seal valid: {}\n",
		if wrong_key_result.valid {
			"✅ PASS"
		} else {
			"❌ FAIL (expected)"
		}
	);

	println!("═══════════════════════════════════════════════════════════");
	println!("  Summary");
	println!("═══════════════════════════════════════════════════════════");
	println!("✅ Quantum-safe keypair generation (ML-DSA-65 + SLH-DSA)");
	println!("✅ Dual signature creation with content binding");
	println!("✅ Three-way verification (hash + lattice + hash-based)");
	println!("✅ Tamper detection via content hash mismatch");
	println!("✅ Key isolation via signature verification");
	println!("\n🔒 Defense-in-depth: Both signatures must be broken to forge");
	println!("🌐 Quantum-resistant: FIPS 204 + FIPS 205 algorithms");
	println!("📦 no_std compatible: Works on embedded devices");

	Ok(())
}
