---
applyTo: "src/entropy*.rs"
---

# Entropy Module Instructions

## Pattern Memory for Entropy

**Before modifying entropy code**, recall and reuse these established patterns:

### Memory: Domain Separation Constants
- **Origin**: `entropy.rs` lines 19-22
- **Pattern**: 
  ```rust
  const DOMAIN_POOL: &str = "Temper.Pool.v1.desmond";
  const DOMAIN_DRBG_INIT: &str = "Temper.DRBG.Init.v1";
  const DOMAIN_DRBG_RESEED: &str = "Temper.DRBG.Reseed.v1";
  ```
- **Reason**: Prevents cross-protocol attacks, consistent naming scheme

### Memory: Re-seed Trigger
- **Origin**: `entropy.rs` RESEED_THRESHOLD
- **Value**: `1_048_576` (2²⁰ bytes)
- **Reason**: Forward secrecy without excessive performance impact

### Memory: Thread Safety Pattern
- **Origin**: `entropy.rs` TemperEntropy structure
- **Pattern**: `state: Mutex<EntropyState>` using `spin::Mutex`
- **Reason**: no_std compatible concurrency, not `std::sync::Mutex`

### Memory: Health Metrics Structure
- **Origin**: `entropy.rs` EntropyHealth
- **Pattern**: `Copy` type with read-only snapshot fields
- **Reason**: Diagnostics without exposing mutable internal state

**When extending entropy**: Apply these patterns to maintain consistency.

---

## Overview

The entropy module implements a hardened CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) with multi-source entropy pooling, BLAKE3-based mixing, and ChaCha20 DRBG output.

## Architecture

```
┌─────────────────┐
│ Entropy Sources │ (OS, Jitter, Process, Hardware TRNG)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  BLAKE3 Pool    │ (Keyed hash with domain separation)
│  "Temper.Pool"  │
└────────┬────────┘
         │ derive_key("Temper.DRBG.Init.v1")
         ▼
┌─────────────────┐
│ ChaCha20 DRBG   │ (RngCore + CryptoRng implementation)
└────────┬────────┘
         │
         ▼
    Random Bytes
```

## Key Components

### 1. EntropySource Trait

**Purpose:** Platform-agnostic interface for entropy collection.

**Pattern:**
```rust
pub trait EntropySource {
    fn name(&self) -> &str;
    fn fill_entropy(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EntropyError>;
    fn is_available(&self) -> bool;
}
```

**Built-in Sources (std only):**
- `OsEntropy` — Wraps `getrandom::getrandom()` or `rand::rngs::OsRng`
- `JitterEntropy` — Measures `std::time::Instant` timing variance across tight loops
- `ProcessEntropy` — Uses PID, thread ID, heap address (ASLR)

**Embedded Sources (user-provided):**
- STM32 TRNG via `stm32f4xx_hal::rng`
- ESP32 RNG via `esp-idf-hal::rng`
- ADC noise sampling
- External hardware RNG chips

### 2. TemperEntropy

**Purpose:** Main CSPRNG with automatic re-seeding and health tracking.

**State Structure:**
```rust
struct EntropyState {
    pool: blake3::Hasher,           // Keyed with domain "Temper.Pool.v1.desmond"
    drbg: ChaCha20Rng,              // ChaCha20 DRBG
    bytes_since_reseed: u64,        // Counter for re-seed trigger
    total_bytes_emitted: u64,       // Lifetime counter
    reseed_count: u64,              // Number of re-seeds performed
    source_count: usize,            // Number of entropy sources used
}
```

**Thread Safety:**
- Wrap `EntropyState` in `spin::Mutex` (NOT `std::sync::Mutex`)
- Lock only during `fill_bytes`, minimize lock duration

**Constructors:**
```rust
// Universal constructor (works on embedded + desktop)
pub fn from_sources(sources: &mut [&mut dyn EntropySource]) -> Result<Self>

// Convenience constructor (std only)
#[cfg(feature = "std")]
pub fn new() -> Result<Self>

// Deterministic seed (testing only)
pub fn from_seed(seed: [u8; 32]) -> Self
```

### 3. Re-seed Logic

**Trigger:** Every 2²⁰ (1,048,576) bytes

**Process:**
1. Check `bytes_since_reseed >= 1_048_576`
2. Collect 64 bytes from `getrandom::getrandom()`
3. Update BLAKE3 pool: `pool.update(fresh_entropy)`
4. Derive new seed: `pool.derive_key("Temper.DRBG.Reseed.v1")`
5. Create new ChaCha20Rng from seed
6. Reset `bytes_since_reseed = 0`, increment `reseed_count`

**Error Handling:**
- If re-seed fails, return `Error::ReseedFailed`
- Never continue generating random bytes after failed re-seed

### 4. Domain Separation Constants

```rust
const DOMAIN_POOL: &str = "Temper.Pool.v1.desmond";
const DOMAIN_DRBG_INIT: &str = "Temper.DRBG.Init.v1";
const DOMAIN_DRBG_RESEED: &str = "Temper.DRBG.Reseed.v1";
```

**Usage:**
- Pool initialization: `blake3::Hasher::new_keyed(derive_key(DOMAIN_POOL))`
- Initial DRBG seed: `pool.derive_key(DOMAIN_DRBG_INIT)`
- Re-seed DRBG: `pool.derive_key(DOMAIN_DRBG_RESEED)`

### 5. RngCore + CryptoRng Implementation

**Implement:**
```rust
impl rand_core::RngCore for TemperEntropy {
    fn next_u32(&mut self) -> u32 { /* ... */ }
    fn next_u64(&mut self) -> u64 { /* ... */ }
    fn fill_bytes(&mut self, dest: &mut [u8]) { /* ... */ }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> { /* ... */ }
}

impl rand_core::CryptoRng for TemperEntropy {}
```

**Pattern:**
1. Lock the `spin::Mutex<EntropyState>`
2. Check if re-seed needed
3. Generate bytes from DRBG
4. Update counters
5. Unlock

### 6. EntropyHealth

**Purpose:** Diagnostic information without exposing internal state.

```rust
#[derive(Debug, Clone, Copy)]
pub struct EntropyHealth {
    pub source_count: usize,
    pub total_bytes_emitted: u64,
    pub reseed_count: u64,
}
```

**Rules:**
- Must be `Copy` (no heap allocations)
- Read-only snapshot, never allows mutation
- Accessed via `pub fn health(&self) -> EntropyHealth`

### 7. Zeroization

**Rule:** Zero all sensitive buffers after use.

```rust
let mut seed_bytes = [0u8; 32];
// ... use seed_bytes ...
seed_bytes.fill(0); // Explicit zeroization
```

**Apply to:**
- Temporary seed buffers
- Entropy collection buffers
- Any buffer containing key material

### 8. Fork Detection (std only)

**Optional Enhancement:**
```rust
#[cfg(feature = "std")]
struct ForkDetector {
    last_pid: u32,
}

impl ForkDetector {
    fn check_and_update(&mut self) -> bool {
        let current_pid = std::process::id();
        if current_pid != self.last_pid {
            self.last_pid = current_pid;
            true // Fork detected
        } else {
            false
        }
    }
}
```

If fork detected, force immediate re-seed to prevent parent/child state sharing.

## Testing Requirements

**See `.github/instructions/testing.instructions.md` for details.**

Statistical tests must verify:
1. Uniqueness (no collisions in large samples)
2. Uniform distribution (chi-squared test)
3. Avalanche effect (bit flips cause ~50% output change)
4. Autocorrelation (no patterns between sequential outputs)
5. Re-seed independence (outputs before/after re-seed are uncorrelated)
6. Bit balance (each bit position has equal probability)
7. Health metrics accuracy

## Common Pitfalls

❌ **DON'T:**
- Use `std::sync::Mutex` — Not available in `no_std`
- Use `HashMap` for metadata — Non-deterministic
- Call `unwrap()` on entropy collection — Return errors properly
- Forget to check re-seed threshold
- Use `getrandom` without feature gates

✅ **DO:**
- Use `spin::Mutex` for thread safety
- Use `BTreeMap` for deterministic ordering
- Return `Result<T>` for all fallible operations
- Check `bytes_since_reseed` before every generation
- Gate `getrandom` usage with `#[cfg(feature = "std")]`
- Document all domain separation constants
- Zeroize sensitive buffers

## Integration Example

**Embedded (no_std):**
```rust
struct HardwareTrng; // Custom implementation

impl EntropySource for HardwareTrng {
    fn name(&self) -> &str { "STM32-TRNG" }
    fn fill_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
        // Read from hardware RNG peripheral
    }
    fn is_available(&self) -> bool { true }
}

let mut hw_rng = HardwareTrng;
let mut entropy = TemperEntropy::from_sources(&mut [&mut hw_rng])?;
```

**Desktop (std):**
```rust
#[cfg(feature = "std")]
let mut entropy = TemperEntropy::new()?; // Auto-collects OS + jitter + process
```

## Performance Considerations

- **Lock duration:** Minimize `Mutex` hold time
- **Re-seed cost:** ~100μs on modern CPU (acceptable overhead)
- **Hot path:** ChaCha20 generation is ~1GB/sec, no allocations
- **Cold path:** Entropy collection and pooling (only at init + re-seed)

## Security Properties

1. **Prediction Resistance:** Even if attacker observes all previous outputs, cannot predict future outputs (relies on ChaCha20 security + re-seeding)
2. **Forward Secrecy:** Compromising current state doesn't reveal previous outputs (DRBG is one-way)
3. **Backward Secrecy:** Re-seeding with fresh entropy prevents prediction after compromise
4. **Multi-source Hardening:** Failure of one entropy source doesn't compromise security (BLAKE3 pool mixes all sources)

## References

- NIST SP 800-90A (DRBG Recommendations)
- ChaCha20 specification (RFC 8439)
- BLAKE3 specification
- "Cryptographic Extraction and Key Derivation" (Krawczyk, 2010)
