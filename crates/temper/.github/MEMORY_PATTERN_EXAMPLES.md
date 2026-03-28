# Memory Pattern Usage Examples

This document demonstrates how the memory and pattern awareness system works in practice.

## What is Pattern Memory?

Pattern memory is the agent's ability to recall, apply, and evolve architectural decisions, coding conventions, and mathematical patterns across the entire codebase. It ensures consistency and maintains the project's architectural integrity over time.

---

## Example 1: Creating a New Module with Memory Annotations

### Scenario
You need to create a new module `session.rs` for session lifecycle management.

### Without Memory Awareness ❌
```rust
// session.rs
use std::collections::HashMap;  // Wrong! Not no_std compatible
use std::sync::Mutex;           // Wrong! Not available in no_std

pub struct Session {
    id: String,
    metadata: HashMap<String, String>,  // Non-deterministic!
}
```

### With Memory Awareness ✅
```rust
// session.rs
// Memory: no_std pattern from rust-nostd.instructions.md
use alloc::string::String;
use alloc::collections::BTreeMap;  // Memory: determinism via BTreeMap per copilot-instructions.md
use spin::Mutex;                   // Memory: thread safety pattern from entropy.rs

// Memory: schema versioning pattern from seal.rs — forward compatibility
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub schema_version: u16,  // Always first field
    pub id: String,
    // Memory: BTreeMap for deterministic iteration per Rule 2 in copilot-instructions.md
    pub metadata: BTreeMap<String, String>,
}

// Memory: domain separation pattern from entropy.rs — prevents cross-protocol attacks
const SESSION_ID_DOMAIN: &str = "Temper.Session.ID.v1";
```

**Memory annotations explain:**
- WHERE the pattern comes from (which file or instruction)
- WHY the pattern is important (security, compatibility, etc.)

---

## Example 2: Writing Tests with Memory Patterns

### Scenario
You need to test the new session ID generation for uniqueness.

### Without Memory Awareness ❌
```rust
#[test]
fn test_uniqueness() {
    let id1 = generate_session_id();
    let id2 = generate_session_id();
    assert_ne!(id1, id2);  // Too simple, no statistical rigor
}
```

### With Memory Awareness ✅
```rust
#[test]
fn test_session_id_uniqueness() {
    // Memory: Statistical test pattern from entropy_tests.rs
    // Birthday bound for 256-bit IDs: P(collision in 10⁵ samples) ≈ 10⁻⁶⁷
    
    // -- Setup & Fixtures
    // Memory: three-section test structure per testing.instructions.md
    let mut ids = HashSet::new();
    let sample_size = 100_000;
    
    // -- Exec
    for _ in 0..sample_size {
        let id = generate_session_id();
        ids.insert(id);
    }
    
    // -- Check
    assert_eq!(
        ids.len(),
        sample_size,
        "Expected zero collisions in {} session IDs",
        sample_size
    );
}
```

**Memory annotations explain:**
- Test structure (Setup/Exec/Check) from testing.instructions.md
- Statistical basis (birthday bound) from similar tests in entropy_tests.rs
- Why the sample size is meaningful (collision probability)

---

## Example 3: Extending Cryptographic Protocols

### Scenario
You need to add key rotation to the session module.

### Without Memory Awareness ❌
```rust
pub fn rotate_key(&mut self) {
    let new_key = rand::random::<[u8; 32]>();  // Where does randomness come from?
    self.key = new_key;  // Key material not zeroized!
}
```

### With Memory Awareness ✅
```rust
// Memory: re-seed pattern from entropy.rs — trigger after threshold
const KEY_ROTATION_THRESHOLD: u64 = 1_048_576;  // 2²⁰ bytes, same as DRBG re-seed

pub fn rotate_key(&mut self, rng: &mut TemperEntropy) -> Result<()> {
    // Memory: domain separation per entropy.instructions.md
    const KEY_ROTATION_DOMAIN: &str = "Temper.Session.Rotate.v1";
    
    // Generate new key with domain-separated KDF
    let mut hasher = blake3::Hasher::new();
    hasher.update(self.current_key.as_ref());
    let mut new_key = hasher.finalize().as_bytes().clone();
    
    // Memory: zeroization pattern from envelope.rs — forward secrecy
    self.current_key.fill(0);  // Zeroize old key
    
    self.current_key = new_key;
    self.rotation_count += 1;
    
    Ok(())
}

// Memory: Drop pattern from handshake keys — ensure cleanup
impl Drop for Session {
    fn drop(&mut self) {
        self.current_key.fill(0);
    }
}
```

**Memory annotations explain:**
- Re-seed threshold value (2²⁰) from entropy.rs
- Domain separation constant pattern
- Zeroization for forward secrecy
- Drop implementation for cleanup

---

## Example 4: Error Handling with Memory

### Scenario
You need to add new error variants for the session module.

### Without Memory Awareness ❌
```rust
pub enum SessionError {
    InvalidKey,
    Expired,
}

impl std::error::Error for SessionError {}  // Not no_std compatible!
```

### With Memory Awareness ✅
```rust
// Memory: error pattern from error.rs — derive_more for no_std
use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, SessionError>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum SessionError {
    // Memory: #[from] pattern allows automatic conversions
    #[from(String, &String, &str)]
    Custom(String),
    
    InvalidKey { key_id: String },
    Expired { session_id: String, elapsed: u64 },
    
    // Memory: compose with existing error types
    #[from]
    EntropyError(super::entropy::EntropyError),
}

// Memory: feature gate pattern from error.rs — conditional std support
#[cfg(feature = "std")]
impl std::error::Error for SessionError {}
```

**Memory annotations explain:**
- derive_more pattern for no_std compatibility
- #[from] attribute usage from error.rs
- Feature gating for std::error::Error
- Composition with other error types

---

## Example 5: Documenting Mathematical Basis

### Scenario
You need to test the randomness of rotated session keys.

### Without Memory Awareness ❌
```rust
#[test]
fn test_key_randomness() {
    let key1 = rotate_key();
    let key2 = rotate_key();
    assert_ne!(key1, key2);  // Too simple
}
```

### With Memory Awareness ✅
```rust
#[test]
fn test_session_key_rotation_independence() {
    // MATHEMATICAL BASIS:
    // Memory: chi-squared pattern from entropy_tests.rs
    // Testing for independence of rotated keys via Hamming distance
    // H₀: Keys before and after rotation are independent
    // Expected: ~50% bit flips (128 bits for 256-bit keys)
    // Threshold: 128 ± 10 bits (from avalanche test in entropy_tests.rs)
    
    // -- Setup & Fixtures
    let mut session = Session::new()?;
    let trials = 1000;
    let mut bit_flip_counts = Vec::new();
    
    // -- Exec
    for _ in 0..trials {
        let key_before = session.current_key.clone();
        session.rotate_key(&mut rng)?;
        let key_after = session.current_key.clone();
        
        // Memory: hamming_distance helper from entropy_tests.rs
        let flips = hamming_distance(&key_before, &key_after);
        bit_flip_counts.push(flips);
    }
    
    let avg_flips = bit_flip_counts.iter().sum::<usize>() as f64 / trials as f64;
    
    // -- Check
    // Memory: threshold from avalanche test (128 ± 10 for 256-bit)
    assert!(
        avg_flips >= 118.0 && avg_flips <= 138.0,
        "Average bit flips {} not in range [118, 138] — keys may be correlated",
        avg_flips
    );
}
```

**Memory annotations explain:**
- Mathematical basis structure from entropy_tests.rs
- Statistical threshold values from existing tests
- Test helper function reuse (hamming_distance)
- Expected values and their justification

---

## Example 6: Region Comments for Organization

### Scenario
You need to organize the session module with multiple sub-modules.

### Without Memory Awareness ❌
```rust
// session.rs
mod lifecycle;
mod state;
pub use lifecycle::*;
pub use state::*;

const VERSION: u16 = 1;

pub fn create() -> Session { ... }
pub fn destroy() -> () { ... }

#[cfg(test)]
mod tests { ... }
```

### With Memory Awareness ✅
```rust
// session.rs
// Memory: region comment pattern from lib.rs and entropy.rs

// region:    --- Modules

mod lifecycle;
mod state;

// endregion: --- Modules

// region:    --- Re-exports

pub use lifecycle::{SessionLifecycle, LifecyclePhase};
pub use state::{SessionState, StateTransition};

// endregion: --- Re-exports

// region:    --- Constants

// Memory: schema version as constant per seal.rs pattern
const SCHEMA_VERSION: u16 = 1;

// Memory: domain separation per entropy.instructions.md
const SESSION_DOMAIN: &str = "Temper.Session.v1";

// endregion: --- Constants

// region:    --- Public API

pub fn create_session(rng: &mut TemperEntropy) -> Result<Session> {
    // ...
}

pub fn destroy_session(session: Session) -> Result<()> {
    // Memory: zeroization before drop
    // ...
}

// endregion: --- Public API

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    
    // Memory: Setup/Exec/Check pattern
    // ...
}

// endregion: --- Tests
```

**Memory annotations explain:**
- Region comment ordering from lib.rs
- Constant naming and placement patterns
- Re-export organization
- Test organization

---

## Pattern Memory Checklist

When writing new code, ask yourself:

### ✅ Before Implementation
- [ ] Have I scanned `.github/copilot-instructions.md`?
- [ ] Have I read the relevant `.github/instructions/*.instructions.md` file?
- [ ] Have I looked at similar modules for patterns (e.g., entropy.rs, seal.rs)?
- [ ] Do I understand the mathematical/security basis for what I'm implementing?

### ✅ During Implementation
- [ ] Am I using `alloc::*` and `core::*` instead of `std::*`?
- [ ] Am I using `BTreeMap` instead of `HashMap`?
- [ ] Am I using `spin::Mutex` instead of `std::sync::Mutex`?
- [ ] Have I included `schema_version` in serializable structs?
- [ ] Have I defined domain separation constants?
- [ ] Have I added `// Memory:` annotations where patterns are applied?

### ✅ For Tests
- [ ] Does my test follow Setup/Exec/Check structure?
- [ ] Have I documented the mathematical basis?
- [ ] Have I reused statistical thresholds from existing tests?
- [ ] Are my assertions informative (include actual values)?

### ✅ After Implementation
- [ ] Does the code build with `cargo check --no-default-features --features alloc`?
- [ ] Does the code build with `cargo build`?
- [ ] Do all tests pass with `cargo test`?
- [ ] Have I zeroized sensitive key material?

---

## Evolving the Pattern Memory

As the project grows, you may discover new patterns worth documenting:

### When to Update Instruction Files

**Add to `.github/instructions/*.instructions.md` when:**
1. A pattern is used in 3+ places across the codebase
2. The pattern has security/mathematical significance
3. The pattern is non-obvious and easy to forget
4. The pattern solves a specific no_std or determinism challenge

**Example: Adding a New Pattern**

```markdown
### Memory: Session Rotation Pattern
- **Origin**: `session.rs` lines 45-67
- **Pattern**: Rotate keys every 2²⁰ operations with domain-separated KDF
- **Reason**: Forward secrecy with predictable performance impact
```

Add this to `.github/instructions/entropy.instructions.md` or create a new `session.instructions.md` if the module grows.

---

## Common Pitfalls and Memory Solutions

| Pitfall | Memory Solution |
|---------|----------------|
| Used `HashMap` | Recall determinism rule → Use `BTreeMap` |
| Used `std::sync::Mutex` | Recall no_std pattern → Use `spin::Mutex` |
| Forgot `schema_version` | Recall seal.rs pattern → Add as first field |
| No domain separation | Recall entropy pattern → Define constant `"Temper.<Module>.<Op>.v1"` |
| Test without math docs | Recall testing.instructions.md → Add statistical basis |
| No zeroization | Recall envelope.rs pattern → Implement `Drop` with `.fill(0)` |

---

**Remember:** Pattern memory is not about rigid rules. It's about consistency, maintainability, and ensuring that the cryptographic and architectural rigor of the project persists over time.
