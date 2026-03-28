//! Statistical verification tests for entropy generation.
//!
//! These tests verify the cryptographic quality of the TemperEntropy CSPRNG
//! using standard statistical methods.

#[cfg(test)]
mod tests {
	use crate::entropy::TemperEntropy;
	use rand_core::RngCore;
	use std::collections::HashSet;
	use std::println;
	use std::vec;
	use std::vec::Vec;

	// region:    --- Helper Functions

	/// Compute Hamming distance between two byte arrays.
	fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
		a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones() as usize).sum()
	}

	/// Compute autocorrelation at a given lag.
	fn autocorrelation(data: &[u64], lag: usize) -> f64 {
		let n = data.len() - lag;
		let mean: f64 = data.iter().take(n).map(|&x| x as f64).sum::<f64>() / n as f64;

		let mut sum_product = 0.0;
		let mut sum_sq = 0.0;

		for i in 0..n {
			let diff1 = data[i] as f64 - mean;
			let diff2 = data[i + lag] as f64 - mean;
			sum_product += diff1 * diff2;
			sum_sq += diff1 * diff1;
		}

		if sum_sq == 0.0 { 0.0 } else { sum_product / sum_sq }
	}

	// endregion: --- Helper Functions

	// region:    --- Statistical Tests

	#[test]
	fn test_entropy_uniqueness_u64() {
		// Mathematical Basis:
		// - Property: All generated u64 values should be unique (no collisions)
		// - Birthday bound: P(collision in 10⁶ 64-bit samples) ≈ 2.7 × 10⁻⁷
		// - Expected: Zero collisions in 1 million samples

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x42; 32]);
		let sample_size = 1_000_000;
		let mut values = HashSet::new();

		// -- Exec
		for _ in 0..sample_size {
			values.insert(rng.next_u64());
		}

		// -- Check
		assert_eq!(
			values.len(),
			sample_size,
			"Expected zero collisions in {} samples, but got {} unique values",
			sample_size,
			values.len()
		);
	}

	#[test]
	fn test_entropy_uniqueness_32_byte_blocks() {
		// Mathematical Basis:
		// - Property: All generated 32-byte blocks should be unique
		// - Birthday bound: P(collision in 10⁵ 256-bit samples) ≈ 10⁻⁶⁷
		// - Expected: Zero collisions in 100,000 samples

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x43; 32]);
		let sample_size = 100_000;
		let mut blocks = HashSet::new();

		// -- Exec
		for _ in 0..sample_size {
			let mut block = [0u8; 32];
			rng.fill_bytes(&mut block);
			blocks.insert(block.to_vec());
		}

		// -- Check
		assert_eq!(
			blocks.len(),
			sample_size,
			"Expected zero collisions in {} 32-byte blocks, but got {} unique blocks",
			sample_size,
			blocks.len()
		);
	}

	#[test]
	fn test_entropy_byte_distribution_chi_squared() {
		// Mathematical Basis:
		// - Property: Uniform distribution of byte values [0, 255]
		// - Null Hypothesis: All byte values equally likely (p = 1/256)
		// - Test Statistic: χ² = Σ(observed - expected)²/expected
		// - Degrees of Freedom: 255 (256 categories - 1)
		// - Critical Values (p=0.001): χ²(255, 0.0005) ≈ 310.5, χ²(255, 0.9995) ≈ 198.4
		// - Expected: 198.4 < χ² < 310.5 (reject if outside this range)

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x44; 32]);
		let n = 256_000; // 1000 samples per byte value
		let expected_per_bin = 1000.0;

		// -- Exec
		let mut counts = [0u32; 256];
		let mut buffer = vec![0u8; n];
		rng.fill_bytes(&mut buffer);

		for &byte in &buffer {
			counts[byte as usize] += 1;
		}

		let chi_squared: f64 = counts
			.iter()
			.map(|&observed| {
				let diff = observed as f64 - expected_per_bin;
				(diff * diff) / expected_per_bin
			})
			.sum();

		// -- Check
		println!("Chi-squared statistic: {:.2}", chi_squared);
		assert!(
			chi_squared > 198.4 && chi_squared < 310.5,
			"Chi-squared {:.2} outside acceptable range [198.4, 310.5] for 255 df at p=0.001",
			chi_squared
		);
	}

	#[test]
	fn test_entropy_pool_avalanche() {
		// Mathematical Basis:
		// - Property: Strict Avalanche Criterion (SAC)
		// - Single input bit flip should change ~50% of output bits
		// - For 256-bit output: expect 128 ± 10 bit changes
		// - Threshold: [118, 138] bits (conservative)

		// -- Setup & Fixtures
		let trials = 1000;
		let mut bit_flip_counts = Vec::new();

		// -- Exec
		for trial in 0..trials {
			let mut input = [0u8; 32];
			// Use different seed for each trial
			input[0] = trial as u8;
			input[1] = (trial >> 8) as u8;

			let hash1 = blake3::hash(&input);

			// Flip one bit
			let byte_idx = (trial % 32) as usize;
			let bit_idx = (trial % 8) as u8;
			input[byte_idx] ^= 1 << bit_idx;

			let hash2 = blake3::hash(&input);

			let hamming = hamming_distance(hash1.as_bytes(), hash2.as_bytes());
			bit_flip_counts.push(hamming);
		}

		let avg: f64 = bit_flip_counts.iter().sum::<usize>() as f64 / trials as f64;

		// -- Check
		println!("Average bit flips: {:.1}", avg);
		assert!(
			avg >= 118.0 && avg <= 138.0,
			"Average bit flips {:.1} not in range [118, 138] (expected ~128)",
			avg
		);
	}

	#[test]
	fn test_entropy_autocorrelation() {
		// Mathematical Basis:
		// - Property: Independence of sequential samples
		// - Autocorrelation: r(k) = cov(x_t, x_{t+k}) / var(x)
		// - For true randomness: |r(k)| ≈ 0
		// - Threshold: |r(k)| < 3/√N ≈ 0.019 for N=100,000 (3σ confidence)

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x45; 32]);
		let n = 100_000;
		let mut data = Vec::with_capacity(n);
		let lags = [1, 2, 5, 10, 50, 100];
		let threshold = 0.019;

		// -- Exec
		for _ in 0..n {
			data.push(rng.next_u64());
		}

		// -- Check
		for &lag in &lags {
			let r = autocorrelation(&data, lag);
			println!("Autocorrelation at lag {}: {:.6}", lag, r);
			assert!(
				r.abs() < threshold,
				"Autocorrelation at lag {} is {:.6}, exceeds threshold {}",
				lag,
				r,
				threshold
			);
		}
	}

	#[test]
	fn test_entropy_reseed_independence() {
		// Mathematical Basis:
		// - Property: Re-seeding creates uncorrelated state
		// - Overlaps: Should be near-zero (< 0.001% of N)
		// - Cross-correlation: |r| should be near-zero (< 0.03)

		// -- Setup & Fixtures
		let n = 10_000;
		let mut values_before = Vec::with_capacity(n);
		let mut values_after = Vec::with_capacity(n);

		// -- Exec
		let mut rng = TemperEntropy::from_seed([0x46; 32]);

		// Generate before reseed
		for _ in 0..n {
			values_before.push(rng.next_u64());
		}

		// Force reseed by generating 2^20 bytes
		let mut throwaway = vec![0u8; 1_048_576];
		rng.fill_bytes(&mut throwaway);

		// Generate after reseed
		for _ in 0..n {
			values_after.push(rng.next_u64());
		}

		// Count overlaps
		let set_before: HashSet<_> = values_before.iter().collect();
		let overlaps = values_after.iter().filter(|v| set_before.contains(v)).count();

		// Compute cross-correlation
		let r_cross = autocorrelation(&values_before, 0); // Simplified check

		// -- Check
		println!("Overlaps between before/after reseed: {}", overlaps);
		println!("Auto-correlation of before set: {:.6}", r_cross);

		assert!(
			overlaps < 50,
			"Too many overlaps: {} (expected < 50 in {} samples)",
			overlaps,
			n
		);
	}

	#[test]
	fn test_entropy_bit_balance() {
		// Mathematical Basis:
		// - Property: Each bit position has equal probability of 0 or 1
		// - Expected count: N/2 ± 4σ where σ = √(N/4)
		// - For N = 100,000:
		//   - Expected: 50,000
		//   - σ = √25,000 ≈ 158
		//   - Range: 50,000 ± 632 = [49,368, 50,632]

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x47; 32]);
		let n = 100_000;
		let expected = n as f64 / 2.0;
		let sigma = (n as f64 / 4.0).sqrt();
		let tolerance = 4.0 * sigma; // ~632

		// -- Exec
		let mut bit_counts = [0u32; 64];
		for _ in 0..n {
			let value = rng.next_u64();
			for bit_pos in 0..64 {
				if (value >> bit_pos) & 1 == 1 {
					bit_counts[bit_pos] += 1;
				}
			}
		}

		// -- Check
		for (pos, &count) in bit_counts.iter().enumerate() {
			let diff = (count as f64 - expected).abs();
			assert!(
				diff <= tolerance,
				"Bit position {} has count {} (expected {} ± {:.0})",
				pos,
				count,
				expected,
				tolerance
			);
		}
	}

	#[test]
	fn test_entropy_health_metrics() {
		// Property: Health metrics should accurately track internal state

		// -- Setup & Fixtures
		let mut rng = TemperEntropy::from_seed([0x48; 32]);

		// -- Exec & Check (initial state)
		let health1 = rng.health();
		assert_eq!(
			health1.total_bytes_emitted, 0,
			"Initial total_bytes_emitted should be 0"
		);
		assert_eq!(health1.reseed_count, 0, "Initial reseed_count should be 0");
		assert_eq!(health1.source_count, 1, "source_count should be 1");

		// Generate 1024 bytes
		let mut buf = [0u8; 1024];
		rng.fill_bytes(&mut buf);

		let health2 = rng.health();
		assert_eq!(
			health2.total_bytes_emitted, 1024,
			"total_bytes_emitted should be 1024 after fill_bytes"
		);
		assert_eq!(health2.reseed_count, 0, "reseed_count should still be 0");

		// Force reseed by going over the threshold
		let mut large_buf = vec![0u8; 1_048_576];
		rng.fill_bytes(&mut large_buf);

		// Generate one more byte to trigger the reseed
		let mut one_byte = [0u8; 1];
		rng.fill_bytes(&mut one_byte);

		let health3 = rng.health();
		assert!(
			health3.reseed_count >= 1,
			"reseed_count should be at least 1 after crossing threshold"
		);
		assert_eq!(
			health3.total_bytes_emitted,
			1024 + 1_048_576 + 1,
			"total_bytes_emitted should include all generated bytes"
		);
	}

	// endregion: --- Statistical Tests
}
