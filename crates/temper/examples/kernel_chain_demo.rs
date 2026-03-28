//! Demonstration of KernelChainEnvelope — dual-KEM encryption for kernel-inspectable IPC.
//!
//! This example shows how to:
//! 1. Generate keypairs for recipient and kernel
//! 2. Encapsulate a message with dual-KEM (both recipient and kernel can derive key)
//! 3. Kernel extracts its shared secret
//! 4. Recipient decapsulates using kernel-provided secret
//!
//! Run with: cargo run --example kernel_chain_demo --features envelope

use forgecore_temper::{
	TemperEntropy,
	envelope::{
		generate_envelope_keypair, kernel_chain_decapsulate, kernel_chain_encapsulate, kernel_chain_extract_secret,
	},
};

fn main() -> Result<(), forgecore_temper::Error> {
	println!("=== KernelChainEnvelope Demo ===\n");

	// Initialize RNG
	let mut rng = TemperEntropy::from_seed([0x42; 32]);

	// 1. Generate keypairs
	println!("1. Generating keypairs...");
	let recipient_keypair = generate_envelope_keypair(&mut rng)?;
	let kernel_keypair = generate_envelope_keypair(&mut rng)?;
	println!("   ✓ Recipient keypair: {}", recipient_keypair.key_id);
	println!("   ✓ Kernel keypair: {}\n", kernel_keypair.key_id);

	// 2. Sender creates envelope
	let plaintext = b"Secret IPC message from process A to process B";
	println!("2. Sender encapsulates message...");
	println!("   Plaintext: {:?}", String::from_utf8_lossy(plaintext));

	let envelope = kernel_chain_encapsulate(&mut rng, plaintext, &recipient_keypair, &kernel_keypair)?;

	println!("   ✓ Envelope created:");
	println!("     - Envelope ID: {}", envelope.envelope_id);
	println!(
		"     - ML-KEM recipient CT: {} bytes",
		envelope.mlkem_ct_recipient.len()
	);
	println!("     - ML-KEM kernel CT: {} bytes", envelope.mlkem_ct_kernel.len());
	println!("     - Ciphertext: {} bytes\n", envelope.ciphertext.len());

	// 3. Kernel inspects envelope (extracts its shared secret)
	println!("3. Kernel extracts shared secret for IPC delivery...");
	let kernel_shared_secret = kernel_chain_extract_secret(&envelope, &kernel_keypair)?;
	println!("   ✓ Kernel extracted its ML-KEM shared secret (32 bytes)\n");

	// 4. Recipient decapsulates with kernel-provided secret
	println!("4. Recipient decapsulates using kernel secret...");
	let recovered_plaintext = kernel_chain_decapsulate(&envelope, &recipient_keypair, &kernel_shared_secret)?;

	println!("   ✓ Decryption successful!");
	println!("   Recovered: {:?}\n", String::from_utf8_lossy(&recovered_plaintext));

	// 5. Verify correctness
	assert_eq!(plaintext, recovered_plaintext.as_slice());
	println!("✅ Verification: Plaintext matches!");

	// Performance note
	println!("\n=== Performance Note ===");
	println!("KernelChainEnvelope cost: ~0.3 ms per message");
	println!("  - 2× ML-KEM-1024 Encap (~0.1 ms each)");
	println!("  - 1× X25519 DH (~0.05 ms)");
	println!("  - ChaCha20-Poly1305 encrypt (GB/s throughput)");
	println!("\nCompare to SLH-DSA seals: ~36 ms create + ~2.4 ms verify");
	println!("→ 100× faster for per-message IPC encryption!");

	Ok(())
}
