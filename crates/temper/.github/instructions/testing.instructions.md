---
applyTo: "src/*_tests.rs"
---

# Testing Instructions

## Pattern Memory for Tests

**Before writing any test**, recall and reuse these established patterns:

### Memory: Test Structure Pattern
- **Origin**: All existing tests in `entropy_tests.rs`, `seal_tests.rs`
- **Pattern**: Three-section comment structure (Setup/Exec/Check)
- **Reason**: Consistent, readable, and maintainable test code

### Memory: Mathematical Documentation Pattern
- **Origin**: `entropy_tests.rs` chi-squared, autocorrelation tests
- **Pattern**: Document statistical basis with formulas and thresholds
- **Reason**: Tests are mathematical proofs, not just code checks

### Memory: Statistical Threshold Values
- **Chi-squared**: [198.4, 310.5] for 255 df at p=0.001 (from `test_entropy_byte_distribution`)
- **Autocorrelation**: |r| < 0.019 for N=100,000 (from `test_autocorrelation`)
- **Bit balance**: N/2 ± 4σ where σ = √(N/4) (from `test_bit_balance`)
- **Avalanche**: 128 ± 10 bit flips for 256-bit output (from `test_avalanche`)
- **Reason**: Reuse proven thresholds from existing statistical tests

**When creating new tests**: Apply these patterns FIRST, then adapt to specific needs.

---

## Test Structure

**ALL tests MUST follow the three-section pattern:**

```rust
#[test]
fn test_example() {
    // -- Setup & Fixtures
    let mut rng = TemperEntropy::from_seed([0x42; 32]);
    let sample_size = 1_000_000;
    
    // -- Exec
    let mut values = HashSet::new();
    for _ in 0..sample_size {
        values.insert(rng.next_u64());
    }
    
    // -- Check
    assert_eq!(
        values.len(), 
        sample_size,
        "Expected zero collisions in {} samples", 
        sample_size
    );
}
```

### Section 1: Setup & Fixtures

- Initialize test data
- Create test instances
- Define constants and parameters
- Set up mocks or test doubles

### Section 2: Exec

- Execute the function/method under test
- Perform the operations being tested
- Collect results for verification

### Section 3: Check

- Assert expected outcomes
- Verify invariants
- Include actual values in assertion messages
- Document what's being checked

## Mathematical Documentation

**Every statistical test MUST include comments explaining the math.**

### Template

```rust
#[test]
fn test_statistical_property() {
    // Mathematical Basis:
    // - Property: [What property is being tested]
    // - Null Hypothesis: [What H₀ assumes]
    // - Test Statistic: [Formula for the statistic]
    // - Threshold: [Critical value and significance level]
    // - Expected: [What outcome indicates correctness]
    
    // -- Setup & Fixtures
    // ...
}
```

### Example: Chi-Squared Test

```rust
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
    let mut rng = TemperEntropy::from_seed([0x42; 32]);
    let n = 256_000;  // 1000 samples per byte value
    let expected_per_bin = 1000.0;
    
    // -- Exec
    let mut counts = [0u32; 256];
    let mut buffer = vec![0u8; n];
    rng.fill_bytes(&mut buffer);
    for &byte in &buffer {
        counts[byte as usize] += 1;
    }
    
    let chi_squared: f64 = counts.iter()
        .map(|&observed| {
            let diff = observed as f64 - expected_per_bin;
            (diff * diff) / expected_per_bin
        })
        .sum();
    
    // -- Check
    assert!(
        chi_squared > 198.4 && chi_squared < 310.5,
        "Chi-squared {} outside acceptable range [198.4, 310.5] for 255 df at p=0.001",
        chi_squared
    );
    println!("Chi-squared statistic: {:.2}", chi_squared);
}
```

## Statistical Test Categories

### 1. Uniqueness Tests

**Purpose:** Verify no collisions in random samples.

**Method:** Generate N samples, insert into `HashSet`, verify `set.len() == N`.

**Birthday Bound:**
- For k-bit outputs: P(collision in N samples) ≈ N²/2^(k+1)
- 64-bit: P(collision in 10⁶) ≈ 2.7 × 10⁻⁷
- 256-bit: P(collision in 10⁵) ≈ 10⁻⁶⁷

**Example:**
```rust
#[test]
fn test_entropy_uniqueness_u64() {
    // Birthday bound: P(collision in 10⁶ 64-bit samples) ≈ 10⁻⁷
    
    // -- Setup & Fixtures
    let mut rng = TemperEntropy::from_seed([0x42; 32]);
    let mut values = HashSet::new();
    
    // -- Exec
    for _ in 0..1_000_000 {
        values.insert(rng.next_u64());
    }
    
    // -- Check
    assert_eq!(values.len(), 1_000_000, "Expected zero collisions");
}
```

### 2. Distribution Tests (Chi-Squared)

**Purpose:** Verify uniform distribution.

**Method:** 
1. Generate N samples
2. Count frequency of each category
3. Compute χ² = Σ(O_i - E_i)²/E_i
4. Compare to critical values from chi-squared table

**Critical Values (df = 255, α = 0.001):**
- Lower: 198.4
- Upper: 310.5

### 3. Avalanche Tests

**Purpose:** Verify Strict Avalanche Criterion (SAC).

**Method:**
1. Hash random input → output A
2. Flip 1 bit in input → output B
3. Compute Hamming distance between A and B
4. Expect ~50% of bits to flip (128 ± tolerance for 256-bit)

**Threshold:** 128 ± 10 bits for 256-bit hash

```rust
#[test]
fn test_entropy_pool_avalanche() {
    // Strict Avalanche Criterion: Single input bit flip should change ~50% output bits
    // For 256-bit output, expect 128 ± 10 bit changes
    
    // -- Setup & Fixtures
    let trials = 1000;
    let mut bit_flip_counts = Vec::new();
    
    // -- Exec
    for _ in 0..trials {
        let mut input = [0u8; 32];
        getrandom::getrandom(&mut input).unwrap();
        
        let hash1 = blake3::hash(&input);
        
        // Flip one random bit
        let byte_idx = input[0] as usize % 32;
        let bit_idx = input[1] % 8;
        input[byte_idx] ^= 1 << bit_idx;
        
        let hash2 = blake3::hash(&input);
        
        let hamming = hamming_distance(hash1.as_bytes(), hash2.as_bytes());
        bit_flip_counts.push(hamming);
    }
    
    let avg: f64 = bit_flip_counts.iter().sum::<usize>() as f64 / trials as f64;
    
    // -- Check
    assert!(
        avg >= 118.0 && avg <= 138.0,
        "Average bit flips {} not in range [118, 138] (expected ~128)",
        avg
    );
}
```

### 4. Autocorrelation Tests

**Purpose:** Verify independence of sequential samples.

**Method:**
1. Generate N samples: x₁, x₂, ..., xₙ
2. Compute autocorrelation at lag k: r(k) = cov(x_t, x_{t+k}) / var(x)
3. For true randomness: |r(k)| ≈ 0

**Threshold:** |r(k)| < 3/√N (3σ confidence)

For N = 100,000: threshold ≈ 0.019

```rust
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
    
    sum_product / sum_sq
}
```

### 5. Independence Tests (Re-seed)

**Purpose:** Verify re-seeding creates uncorrelated state.

**Method:**
1. Generate N samples → Set A
2. Re-seed
3. Generate N samples → Set B
4. Count overlaps (should be ~0)
5. Compute cross-correlation (should be ~0)

**Threshold:** 
- Overlaps: < 0.001% of N
- Cross-correlation: |r| < 0.03

### 6. Bit Balance Tests

**Purpose:** Verify each bit position has equal probability.

**Method:**
1. Generate N samples (e.g., N u64 values)
2. For each of 64 bit positions, count 1s
3. Expect each count ≈ N/2

**Threshold:** N/2 ± 4σ where σ = √(N/4)

For N = 100,000:
- Expected: 50,000
- σ = √25,000 ≈ 158
- Range: 50,000 ± 632 = [49,368, 50,632]

```rust
#[test]
fn test_entropy_bit_balance() {
    // Each bit position should have equal probability of 0 or 1
    // Expected count: N/2 ± 4σ where σ = √(N/4)
    
    // -- Setup & Fixtures
    let mut rng = TemperEntropy::from_seed([0x42; 32]);
    let n = 100_000;
    let expected = n as f64 / 2.0;
    let sigma = (n as f64 / 4.0).sqrt();
    let tolerance = 4.0 * sigma;  // ~632
    
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
            "Bit position {} has count {} (expected {} ± {})",
            pos, count, expected, tolerance
        );
    }
}
```

### 7. Health Metrics Tests

**Purpose:** Verify internal state tracking.

**Method:**
1. Create instance with known state
2. Perform operations
3. Query health metrics
4. Verify counters match expectations

**No complex math needed** — just counter verification.

## Cryptographic Tests

### Seal Tests (mostly ignored until PQC wired)

```rust
#[test]
#[ignore]  // Remove ignore once ML-DSA and SLH-DSA are wired
fn test_seal_roundtrip() {
    // -- Setup & Fixtures
    let mut rng = TemperEntropy::from_seed([0x42; 32]);
    let keypair = generate_keypair(&mut rng, "test@example.com").unwrap();
    let content = b"Test message";
    
    // -- Exec
    let seal = create_seal(&mut rng, content, &keypair, BTreeMap::new()).unwrap();
    let result = verify_seal(
        content, 
        &seal, 
        &keypair.mldsa_public_key,
        &keypair.slhdsa_public_key
    ).unwrap();
    
    // -- Check
    assert!(result.valid, "Seal verification failed");
    assert!(result.content_hash_valid);
    assert!(result.primary_valid);
    assert!(result.backup_valid);
}
```

### Non-Ignored Tests

Tests that don't require PQC primitives:

- Seal ID determinism (uses BLAKE3 only)
- Serde roundtrip (uses serde_json only)
- Key ID computation (uses BLAKE3 only)

## Assertion Best Practices

### Include Actual Values

```rust
// ❌ Bad
assert!(value < 100);

// ✅ Good
assert!(
    value < 100,
    "Expected value < 100, got {}",
    value
);
```

### Document What's Being Checked

```rust
// ✅ Good
assert_eq!(
    result.len(),
    expected_len,
    "Unexpected result length after processing {} items",
    input.len()
);
```

### Print Diagnostic Info

```rust
// Print summary statistics
println!("Chi-squared: {:.2}", chi_squared);
println!("Average bit flips: {:.1}", avg_flips);
```

## Test Naming Conventions

- `test_<module>_<property>` — e.g., `test_entropy_uniqueness`
- `test_<module>_<property>_<variant>` — e.g., `test_entropy_uniqueness_u64`
- `test_<function>_<scenario>` — e.g., `test_seal_detects_tamper`

## Helper Functions

Keep helpers in the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones() as usize)
            .sum()
    }
    
    #[test]
    fn test_example() {
        // ...
    }
}
```

## Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test --test entropy_tests

# Specific test
cargo test test_entropy_uniqueness

# Include ignored tests
cargo test -- --ignored

# Show print output
cargo test -- --nocapture
```

## Test Checklist

Before committing:

- [ ] All tests follow three-section structure
- [ ] Statistical tests include mathematical documentation
- [ ] Assertions include actual values in messages
- [ ] Helper functions are documented
- [ ] No `unwrap()` in test setup (use `expect()` with message)
- [ ] Print statements for diagnostic values
- [ ] Tests have descriptive names
- [ ] Ignored tests have comment explaining why

---

**Remember:** Tests are documentation. Future maintainers should understand WHY a test passes by reading the comments.
