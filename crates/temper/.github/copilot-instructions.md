# Copilot Instructions for Temper

**Trust these instructions.** They define the architecture, patterns, and testing practices for the Temper cryptographic protocol crate.

---

## Memory and Pattern Awareness

**These instructions are living memory.** You MUST actively recall and apply patterns from previous work:

### Pattern Memory System

1. **Scan before coding**: Read ALL `.md` files in `.github/` and review existing code patterns before making changes
2. **Persist conventions**: Apply established patterns (region comments, error handling, test structure) across all tasks
3. **Annotate patterns**: Add `// Memory: ...` comments when applying patterns from other files
4. **Evolve meta-patterns**: Update instruction files when discovering new reusable patterns

**Memory Sources** (read before every task):
- `.github/copilot-instructions.md` (this file) — Root architectural principles
- `.github/instructions/*.instructions.md` — Module-specific patterns  
- `.github/agents/temper.agent.md` — Agent identity and memory guidelines
- `README.md` — Public documentation patterns
- `src/*.rs` — Implementation patterns
- `src/*_tests.rs` — Mathematical test patterns

**What to remember and reuse:**
- Region comment ordering: Modules → Re-exports → Public API → Tests
- Error enum pattern: `derive_more` with `#[from]` attributes for no_std
- Domain separation: Unique constants like `"Temper.Pool.v1.desmond"`
- Test structure: Setup/Exec/Check with mathematical documentation
- Statistical thresholds: Chi-square [198.4, 310.5] for 255 df at p=0.001
- Re-seed pattern: Every 2²⁰ bytes with domain-specific KDF

**Pattern traceability example:**
```rust
// Memory: region comment ordering per lib.rs pattern
// region:    --- Modules

// Memory: error pattern from error.rs — derive_more for no_std compatibility
#[derive(Debug, Display, From)]

// Memory: domain separation per entropy.instructions.md — prevents cross-protocol attacks
const DOMAIN_EXAMPLE: &str = "Temper.Example.v1";
```

For complete memory and pattern guidelines, see `.github/agents/temper.agent.md` section "Memory and Pattern Awareness".

---

## Repository Overview

**Temper** is a quantum-safe cryptographic protocol crate written in 100% Rust. It is designed to be fully `#![no_std]` compatible, enabling deployment on embedded systems (Cortex-M, RISC-V MCUs, etc.) as well as standard server environments.

**Key Features:**
- Hardened entropy generation with multi-source pooling
- Dual post-quantum signature protocol (ML-DSA-65 + SLH-DSA)
- BLAKE3-based content addressing and domain separation
- ChaCha20 DRBG for cryptographically secure random number generation
- Zero allocations in hot paths, `alloc` only for setup and metadata

---

## Mission Statement

> **Build cryptography that is mathematically provable, quantum-resistant, and embeddable. Every operation must be verifiable through statistical or algebraic proof.**

We prioritize:
1. **Mathematical correctness** — All algorithms must have well-defined security properties
2. **Quantum resistance** — Use only post-quantum cryptographic primitives
3. **Embeddability** — `#![no_std]` first, std features are optional
4. **Determinism** — Same inputs must produce same outputs (use `BTreeMap`, never `HashMap`)
5. **Verifiability** — Every claim must be testable through statistical or cryptographic tests

---

## Build & Test Commands

```bash
# Standard build (with std feature)
cargo build

# Embedded build (no_std with alloc only)
cargo build --no-default-features --features alloc

# Run all tests
cargo test

# Run specific test module
cargo test --test entropy_tests

# Check for compilation without default features
cargo check --no-default-features --features alloc
```

---

## Repository Structure

```
.github/
├── copilot-instructions.md           # This file - Root Copilot instructions
└── instructions/
    ├── entropy.instructions.md       # Entropy module guidance
    ├── seal.instructions.md          # Seal module guidance
    ├── rust-nostd.instructions.md    # no_std patterns
    └── testing.instructions.md       # Statistical test methods

Cargo.toml                            # Dependency manifest (no_std compatible)
README.md                             # Public documentation
src/
├── lib.rs                            # Crate root (no_std entry point)
├── error.rs                          # Error types using derive_more
├── entropy_source.rs                 # EntropySource trait and built-in implementations
├── entropy.rs                        # TemperEntropy CSPRNG (BLAKE3 pool + ChaCha20 DRBG)
├── seal.rs                           # Dual PQC signature protocol
├── envelope.rs                       # Stub for future ML-KEM key encapsulation
├── entropy_tests.rs                  # Statistical verification (chi-squared, autocorrelation, etc.)
└── seal_tests.rs                     # Cryptographic binding tests
```

**File Descriptions:**
- `error.rs` — Error enum using `derive_more` for `no_std` compatibility
- `entropy_source.rs` — Platform-agnostic entropy trait. Desktop sources (OS, jitter, process) are behind `#[cfg(feature = "std")]`
- `entropy.rs` — Main CSPRNG. Multi-source entropy → BLAKE3 pool → ChaCha20 DRBG. Thread-safe via `spin::Mutex`
- `seal.rs` — Dual signature protocol. BLAKE3 content hash + ML-DSA-65 + SLH-DSA for quantum-safe signing
- `envelope.rs` — Future: ML-KEM-1024 hybrid key encapsulation (v0.2.0)
- `entropy_tests.rs` — Statistical tests: chi-squared, avalanche, autocorrelation, bit balance
- `seal_tests.rs` — Cryptographic tests: roundtrip, tamper detection, key isolation

---

## Critical Architecture Patterns

### 1. **`no_std` First**

**Rule:** Everything must work without `std`. Use `alloc` for heap types, `core` for primitives.

**Import Rules:**
- ✅ `use alloc::vec::Vec;`
- ✅ `use alloc::string::String;`
- ✅ `use alloc::collections::BTreeMap;`
- ✅ `use alloc::format!;`
- ✅ `use alloc::vec!;`
- ✅ `use core::fmt;`
- ✅ `use core::result::Result;`
- ❌ `use std::vec::Vec;` — NEVER
- ❌ `use std::collections::HashMap;` — NEVER
- ❌ `use std::sync::Mutex;` — Use `spin::Mutex` instead

**Feature Gates:**
```rust
// Only use std features behind gates
#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
pub fn new() -> Result<Self> {
    // std-dependent convenience methods
}
```

### 2. **Determinism is Non-Negotiable**

**Rule:** Same inputs MUST produce same outputs. Use deterministic data structures and algorithms.

- Use `BTreeMap` from `alloc::collections`, never `HashMap` (iteration order is non-deterministic)
- Use BLAKE3 for content-addressed IDs (same as desmond pattern)
- All serialization must be canonical (postcard for binary, deterministic ordering)
- No reliance on memory addresses, ASLR, or timing outside of entropy collection

**Example:**
```rust
use alloc::collections::BTreeMap;

let mut metadata: BTreeMap<String, String> = BTreeMap::new();
metadata.insert("key".into(), "value".into());
// Iteration order is always sorted by key
```

### 3. **Schema Versioning**

**Rule:** All exported structs MUST include a `schema_version: u16` field.

```rust
pub struct Seal {
    pub schema_version: u16,  // Always first field
    pub content_hash: String,
    // ... other fields
}
```

This allows future evolution of the protocol while maintaining backward compatibility.

### 4. **Domain Separation**

**Rule:** All cryptographic operations MUST use domain separation strings.

**Constants Pattern:**
```rust
const DOMAIN_POOL: &str = "Temper.Pool.v1.desmond";
const DOMAIN_DRBG_INIT: &str = "Temper.DRBG.Init.v1";
const DOMAIN_DRBG_RESEED: &str = "Temper.DRBG.Reseed.v1";
const DOMAIN_SEAL: &str = "Temper.Seal.v1";
```

Use these as context strings in BLAKE3 `derive_key()` operations to prevent cross-protocol attacks.

### 5. **Error Pattern**

**Rule:** Use `derive_more` for `no_std` compatible error handling.

```rust
use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
    #[from(String, &String, &str)]
    Custom(String),
    
    InsufficientEntropy { required: usize, available: usize },
    // ... other variants
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
```

### 6. **Testing Pattern**

**Rule:** All tests MUST follow the three-section comment structure.

```rust
#[test]
fn test_entropy_uniqueness() {
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

**Mathematical Documentation:**
Every statistical test MUST include comments explaining:
- The statistical property being tested
- The mathematical threshold/criterion
- Why the threshold is meaningful

Example:
```rust
// Test chi-squared goodness of fit for uniform distribution
// χ² = Σ(observed - expected)²/expected
// For 255 degrees of freedom, critical value at p=0.001 is 310.5
```

### 7. **Region Comments**

**Rule:** Use region markers to organize code sections (same as desmond).

```rust
// region:    --- Modules
mod error;
mod entropy;
// endregion: --- Modules

// region:    --- Re-exports
pub use error::{Error, Result};
// endregion: --- Re-exports
```

### 8. **Module Organization**

**Rule:** `lib.rs` must declare all modules with region comments, then re-export public API.

```rust
#![no_std]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
extern crate alloc;

// region:    --- Modules
pub mod error;
pub mod entropy;
// endregion: --- Modules

// region:    --- Re-exports
pub use entropy::TemperEntropy;
// endregion: --- Re-exports
```

---

## Path-Specific Instructions

**When working on entropy modules** (`src/entropy*.rs`):
→ See `.github/instructions/entropy.instructions.md`

**When working on seal modules** (`src/seal*.rs`):
→ See `.github/instructions/seal.instructions.md`

**When working on any Rust file** (`**/*.rs`):
→ See `.github/instructions/rust-nostd.instructions.md`

**When writing tests** (`src/*_tests.rs`):
→ See `.github/instructions/testing.instructions.md`

---

## Quick Reference Do's and Don'ts

### ✅ DO

- Use `alloc::vec::Vec`, `alloc::string::String`, `alloc::collections::BTreeMap`
- Use `spin::Mutex` for thread-safe state
- Use `derive_more` for error handling
- Use `core::fmt` for Display implementations
- Use BLAKE3 for content addressing
- Use domain separation constants for all crypto operations
- Include `schema_version` in all exported structs
- Document mathematical basis of tests
- Use region comments for organization
- Gate std-dependent code with `#[cfg(feature = "std")]`
- Zeroize sensitive buffers after use
- Test with both `--no-default-features --features alloc` and default features

### ❌ DON'T

- Use `std::vec::Vec`, `std::string::String`, `std::collections::*` without feature gates
- Use `std::sync::Mutex` (not available in `no_std`)
- Use `HashMap` (non-deterministic iteration)
- Use `println!` without feature gates (use `core::fmt`)
- Rely on memory addresses or ASLR for determinism
- Add dependencies without verifying `no_std` compatibility
- Skip mathematical documentation in tests
- Ignore compiler warnings
- Commit secrets or test keys to the repository
- Use `unwrap()` in library code (return `Result` instead)

---

## Security Notes

1. **Entropy Sources:** Desktop systems use OS + jitter + process entropy. Embedded systems must provide custom `EntropySource` implementations (e.g., hardware TRNG).

2. **Re-seeding:** The DRBG automatically re-seeds every 2²⁰ (1,048,576) bytes to maintain forward secrecy.

3. **PQC Primitives:** ML-DSA-65 and SLH-DSA are wrapped as `todo!()` stubs. Wire to RustCrypto crates when available.

4. **Zeroization:** All sensitive key material and entropy buffers must be zeroized after use.

5. **Side Channels:** Constant-time operations are delegated to underlying crypto primitives (BLAKE3, ChaCha20, PQC libs).

---

## Dependency Guidelines

All dependencies must be `no_std` compatible. Verify with:
```bash
cargo tree --no-default-features --features alloc
```

**Approved Dependencies:**
- `blake3` — Cryptographic hash function
- `rand_chacha` — ChaCha20 DRBG
- `rand_core` — RNG trait definitions
- `getrandom` — OS entropy (feature-gated for std)
- `serde`, `postcard` — Serialization (`alloc` feature)
- `spin` — Spinlock mutex for `no_std`
- `hex` — Hex encoding (`alloc` feature)
- `zeroize` — Secure memory clearing
- `derive_more` — Error derive macros

**Version Compatibility:**
- Check crates.io for latest compatible versions
- Ensure `rand_chacha`, `rand_core`, and `rand` (dev-dep) versions align
- Use `default-features = false` for all dependencies
- Enable only required features (e.g., `["alloc"]`, `["derive"]`)

---

**Remember:** This is a cryptographic library. Every line of code must be justified by a security property, mathematical proof, or industry standard. When in doubt, document the reasoning and cite sources.
