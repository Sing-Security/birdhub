---
applyTo: "**/*.rs"
---

# Rust no_std Patterns

## Pattern Memory for no_std

**Before writing any Rust code**, recall and reuse these established patterns:

### Memory: Import Pattern
- **Origin**: All `src/*.rs` files
- **Pattern**: `use alloc::*` for heap types, `use core::*` for primitives, `use spin::Mutex` for concurrency
- **Anti-Pattern**: NEVER `use std::*` without `#[cfg(feature = "std")]`
- **Reason**: Embedded compatibility, no_std is non-negotiable

### Memory: Determinism via BTreeMap
- **Origin**: All serializable structs (seal.rs, entropy.rs)
- **Pattern**: `BTreeMap<K, V>` from `alloc::collections`
- **Anti-Pattern**: NEVER `HashMap` (iteration order is non-deterministic)
- **Reason**: Reproducible builds, deterministic serialization

### Memory: Error Handling Pattern
- **Origin**: `error.rs`
- **Pattern**: 
  ```rust
  use derive_more::{Display, From};
  #[derive(Debug, Display, From)]
  #[display("{self:?}")]
  pub enum Error { ... }
  ```
- **Reason**: no_std compatible, avoids implementing Display manually

### Memory: Feature Gate Pattern
- **Origin**: Multiple files with std-dependent code
- **Pattern**: 
  ```rust
  #[cfg(feature = "std")]
  impl std::error::Error for Error {}
  ```
- **Reason**: Conditional compilation for std-only functionality

### Memory: Thread Safety Pattern
- **Origin**: `entropy.rs` Mutex usage
- **Pattern**: `spin::Mutex<T>` (NOT `std::sync::Mutex<T>`)
- **Reason**: no_std spinlock, available in embedded environments

**When writing new Rust code**: Apply these patterns FIRST to avoid std dependencies.

---

## Core Principle

**The crate MUST compile with `#![no_std]` at the root.** All std functionality is behind `#[cfg(feature = "std")]` gates.

## Import Rules

### ✅ ALWAYS Use

```rust
// Collections
use alloc::vec::Vec;
use alloc::vec;  // For vec! macro
use alloc::string::String;
use alloc::string::ToString;
use alloc::format;  // For format! macro
use alloc::collections::BTreeMap;  // NEVER HashMap

// Core types
use core::fmt;
use core::result::Result;
use core::option::Option;

// Concurrency (no_std spinlock)
use spin::Mutex;
```

### ❌ NEVER Use (without feature gates)

```rust
// These are FORBIDDEN without #[cfg(feature = "std")]
use std::vec::Vec;           // Use alloc::vec::Vec
use std::string::String;     // Use alloc::string::String
use std::collections::*;     // Use alloc::collections::BTreeMap
use std::sync::Mutex;        // Use spin::Mutex
use std::time::*;            // Feature-gate time operations
use std::process::*;         // Feature-gate process operations
use println!;                // Not available in no_std
```

## Crate Root Pattern

**Every Rust file in the crate should be aware that the crate root is `no_std`.**

```rust
// src/lib.rs
#![no_std]
#![doc = include_str!("../README.md")]

// Declare alloc dependency
#[cfg(feature = "alloc")]
extern crate alloc;

// For std feature (std implies alloc)
#[cfg(all(feature = "std", not(feature = "alloc")))]
extern crate alloc;
```

## Feature Gate Pattern

### Standard Error Trait

```rust
use core::fmt;

#[derive(Debug)]
pub enum Error {
    Custom(String),
    // ...
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Only implement std::error::Error when std is enabled
#[cfg(feature = "std")]
impl std::error::Error for Error {}
```

### Time Operations

```rust
// Function only available with std
#[cfg(feature = "std")]
pub fn timestamp_now() -> String {
    use std::time::SystemTime;
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    format!("{}", since_epoch.as_secs())
}

// no_std alternative requires user input
#[cfg(not(feature = "std"))]
pub fn create_with_timestamp(timestamp: &str) -> Self {
    // User must provide timestamp
}
```

### Process Operations

```rust
#[cfg(feature = "std")]
fn get_process_entropy() -> Vec<u8> {
    use std::process;
    let pid = process::id();
    let tid = std::thread::current().id();  // Note: ThreadId is std-only
    // ...
}
```

### Convenience Constructors

```rust
impl TemperEntropy {
    // Universal constructor (works everywhere)
    pub fn from_sources(sources: &mut [&mut dyn EntropySource]) -> Result<Self> {
        // ... implementation using only alloc/core
    }
    
    // Convenience constructor (std only)
    #[cfg(feature = "std")]
    pub fn new() -> Result<Self> {
        let mut os_source = OsEntropy::new()?;
        let mut jitter_source = JitterEntropy::new();
        Self::from_sources(&mut [&mut os_source, &mut jitter_source])
    }
}
```

## Mutex Pattern

**NEVER use `std::sync::Mutex` — it's not available in `no_std`.**

```rust
use spin::Mutex;  // Spinlock, works in no_std

pub struct TemperEntropy {
    state: Mutex<EntropyState>,
}

impl TemperEntropy {
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut state = self.state.lock();
        // ... use state
        // Lock automatically released when state goes out of scope
    }
}
```

**Note:** `spin::Mutex` doesn't have poisoning like `std::sync::Mutex`. No need to handle `PoisonError`.

## String Formatting

```rust
use core::fmt;
use alloc::string::String;
use alloc::format;

// Display trait
impl fmt::Display for MyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MyType {{ field: {} }}", self.field)
    }
}

// Building strings
let s = format!("value: {}", 42);  // alloc::format! works in no_std
```

**DON'T use `println!`** — it's not available in `no_std`. For debugging, use `core::fmt` with a custom writer.

## Error Handling with derive_more

```rust
use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
    // Automatic From<String> and From<&str>
    #[from(String, &String, &str)]
    Custom(String),
    
    // Struct-like variants
    InsufficientEntropy { required: usize, available: usize },
    
    // Newtype variants
    CryptoError(String),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Usage
fn example() -> Result<()> {
    Err("something failed")?  // Automatically converts &str to Error::Custom
}
```

## Collections

### BTreeMap (deterministic)

```rust
use alloc::collections::BTreeMap;

let mut map: BTreeMap<String, String> = BTreeMap::new();
map.insert("key".into(), "value".into());

// Iteration is always in sorted key order (deterministic)
for (k, v) in &map {
    // ...
}
```

**NEVER use `HashMap`** — iteration order is non-deterministic, breaks reproducibility.

### Vec

```rust
use alloc::vec::Vec;
use alloc::vec;

let v: Vec<u8> = Vec::new();
let v2 = vec![1, 2, 3];  // alloc::vec! macro
```

## Heap Allocation Check

**Embedded targets MUST provide a global allocator.** Example with `embedded-alloc`:

```rust
// In embedded binary (not in library crate)
#[global_allocator]
static ALLOCATOR: embedded_alloc::Heap = embedded_alloc::Heap::empty();

fn main() {
    const HEAP_SIZE: usize = 8192;
    static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe { ALLOCATOR.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    
    // Now can use Vec, String, etc.
}
```

## Conditional Compilation Tips

### Check Multiple Features

```rust
#[cfg(all(feature = "std", feature = "alloc"))]
// Both features enabled

#[cfg(any(feature = "std", feature = "alloc"))]
// At least one enabled

#[cfg(not(feature = "std"))]
// std is NOT enabled
```

### Platform-Specific Code

```rust
#[cfg(target_os = "linux")]
fn platform_specific() { }

#[cfg(target_arch = "arm")]
fn arm_specific() { }
```

## Dependency Configuration

**Cargo.toml pattern:**

```toml
[dependencies]
# Core crypto (no_std compatible)
blake3 = { version = "1", default-features = false }

# Serialization (enable alloc feature)
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
serde_json = { version = "1", default-features = false, features = ["alloc"] }

# DRBG (no_std compatible)
rand_chacha = { version = "0.3", default-features = false }
rand_core = { version = "0.6", default-features = false }

# Entropy (requires std, feature-gated)
getrandom = { version = "0.2", default-features = false }

# Thread safety (no_std spinlock)
spin = "0.9"
```

**Feature configuration:**

```toml
[features]
default = ["std"]
std = ["alloc", "blake3/std", "rand_chacha/std", "getrandom/std"]
alloc = []
```

## Testing in no_std

Tests run under `std` by default. To test `no_std` compilation:

```bash
# Check that it compiles without std
cargo check --no-default-features --features alloc

# Build without std
cargo build --no-default-features --features alloc

# Tests still run under std (uses std test harness)
cargo test
```

For true `no_std` testing on embedded hardware, use `defmt-test` or custom test runners.

## Common Errors and Fixes

### Error: "can't find crate for `std`"

**Cause:** Trying to use `std::` without feature gate.

**Fix:**
```rust
// Before
use std::vec::Vec;

// After
use alloc::vec::Vec;
```

### Error: "use of unstable library feature 'allocator_api'"

**Cause:** Trying to use nightly-only allocator features.

**Fix:** Use stable APIs only. Avoid `Box::new_in()`, `Vec::new_in()`, etc.

### Error: "format argument must be a string literal"

**Cause:** Using `format!` incorrectly.

**Fix:**
```rust
// Use alloc::format! macro
use alloc::format;

let s = format!("value: {}", x);
```

### Error: "Mutex is ambiguous"

**Cause:** Both `std::sync::Mutex` and `spin::Mutex` in scope.

**Fix:**
```rust
// Be explicit
use spin::Mutex;  // For no_std
// OR
use std::sync::Mutex;  // Only with #[cfg(feature = "std")]
```

## Verification Checklist

Before committing, verify:

- [ ] `cargo build --no-default-features --features alloc` succeeds
- [ ] `cargo build` (with std) succeeds
- [ ] No `use std::` without `#[cfg(feature = "std")]`
- [ ] All `Mutex` uses are `spin::Mutex`
- [ ] All `HashMap` replaced with `BTreeMap`
- [ ] `derive_more` used for error handling
- [ ] `#![no_std]` at crate root
- [ ] `extern crate alloc;` declared
- [ ] All tests pass with `cargo test`

## Quick Reference Card

| Need | no_std | std |
|------|---------|-----|
| String | `alloc::string::String` | `std::string::String` |
| Vec | `alloc::vec::Vec` | `std::vec::Vec` |
| Map (deterministic) | `alloc::collections::BTreeMap` | `std::collections::BTreeMap` |
| Mutex | `spin::Mutex` | `std::sync::Mutex` |
| Format | `alloc::format!` | `std::format!` |
| Result | `core::result::Result` | `std::result::Result` |
| Display | `core::fmt::Display` | `std::fmt::Display` |
| Error trait | N/A (feature-gated) | `std::error::Error` |
| Time | N/A (user-provided) | `std::time::*` |
| Process ID | N/A | `std::process::id()` |

---

**Remember:** When in doubt, use `alloc::` or `core::`, never `std::` (unless behind `#[cfg(feature = "std")]`).
