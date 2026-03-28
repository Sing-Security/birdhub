//! Benchmarks for seal creation and verification.
//!
//! Run with: cargo bench --bench seal_bench

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use temper::{TemperEntropy, create_seal, generate_keypair, verify_seal};

use std::collections::BTreeMap;

/// Benchmark seal creation for various content sizes.
fn bench_create_seal(c: &mut Criterion) {
	let mut group = c.benchmark_group("create_seal");

	// Test content sizes: 1KB, 64KB, 1MB, 10MB
	let sizes = vec![
		("1KB", 1024),
		("64KB", 64 * 1024),
		("1MB", 1024 * 1024),
		("10MB", 10 * 1024 * 1024),
	];

	for (label, size) in sizes {
		group.throughput(Throughput::Bytes(size as u64));

		// Setup
		let mut rng = TemperEntropy::from_seed([0x42; 32]);
		let keypair = generate_keypair(&mut rng, "bench@example.com").expect("Failed to generate keypair");
		let content = vec![0x55u8; size];
		let metadata = BTreeMap::new();

		group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
			let mut rng = TemperEntropy::from_seed([0x42; 32]);
			b.iter(|| {
				create_seal(
					black_box(&mut rng),
					black_box(&content),
					black_box(&keypair),
					black_box(metadata.clone()),
				)
				.expect("Seal creation failed")
			});
		});
	}

	group.finish();
}

/// Benchmark seal verification for various content sizes.
fn bench_verify_seal(c: &mut Criterion) {
	let mut group = c.benchmark_group("verify_seal");

	// Test content sizes: 1KB, 64KB, 1MB, 10MB
	let sizes = vec![
		("1KB", 1024),
		("64KB", 64 * 1024),
		("1MB", 1024 * 1024),
		("10MB", 10 * 1024 * 1024),
	];

	for (label, size) in sizes {
		group.throughput(Throughput::Bytes(size as u64));

		// Setup
		let mut rng = TemperEntropy::from_seed([0x42; 32]);
		let keypair = generate_keypair(&mut rng, "bench@example.com").expect("Failed to generate keypair");
		let content = vec![0x55u8; size];
		let metadata = BTreeMap::new();

		let seal = create_seal(&mut rng, &content, &keypair, metadata).expect("Failed to create seal");

		group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
			b.iter(|| {
				verify_seal(
					black_box(&content),
					black_box(&seal),
					black_box(&keypair.mldsa_public_key),
					black_box(&keypair.slhdsa_public_key),
				)
				.expect("Seal verification failed")
			});
		});
	}

	group.finish();
}

/// Benchmark seal roundtrip (create + verify) for typical sizes.
fn bench_seal_roundtrip(c: &mut Criterion) {
	let mut group = c.benchmark_group("seal_roundtrip");

	// Typical document sizes
	let sizes = vec![
		("small_doc", 4 * 1024),        // 4KB
		("medium_doc", 256 * 1024),     // 256KB
		("large_doc", 2 * 1024 * 1024), // 2MB
	];

	for (label, size) in sizes {
		group.throughput(Throughput::Bytes(size as u64));

		let content = vec![0x55u8; size];

		group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
			b.iter(|| {
				let mut rng = TemperEntropy::from_seed([0x42; 32]);
				let keypair = generate_keypair(&mut rng, "bench@example.com").expect("Failed to generate keypair");
				let metadata = BTreeMap::new();

				let seal = create_seal(&mut rng, &content, &keypair, metadata).expect("Failed to create seal");

				verify_seal(&content, &seal, &keypair.mldsa_public_key, &keypair.slhdsa_public_key)
					.expect("Failed to verify seal")
			});
		});
	}

	group.finish();
}

criterion_group!(benches, bench_create_seal, bench_verify_seal, bench_seal_roundtrip);
criterion_main!(benches);
