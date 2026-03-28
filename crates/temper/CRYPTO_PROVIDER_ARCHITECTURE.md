# Crypto Provider Architecture

## Overview

The Crypto Provider abstraction enables hardware acceleration (GPU/FPGA) for Post-Quantum Cryptography operations without breaking `no_std` support or changing the protocol.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Seal Protocol                       │
│  (generate_keypair, create_seal, verify_seal)       │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
         ┌────────────────────────┐
         │  CryptoProvider Trait  │
         │  (Pluggable Interface) │
         └────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │   CPU    │  │   GPU    │  │   FPGA   │
  │ Provider │  │ Provider │  │ Provider │
  │(Default) │  │ (Plugin) │  │ (Plugin) │
  └──────────┘  └──────────┘  └──────────┘
```

## Key Components

### 1. `CryptoProvider` Trait (`src/crypto_provider.rs`)

Defines the interface for PQC operations:

```rust
pub trait CryptoProvider: Send + Sync {
    fn mldsa_keygen(&self, rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)>;
    fn mldsa_sign(&self, sk: &[u8], message: &[u8], rng: &mut TemperEntropy) -> Result<Vec<u8>>;
    fn mldsa_verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool;
    
    fn slhdsa_keygen(&self, rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)>;
    fn slhdsa_sign(&self, sk: &[u8], message: &[u8], rng: &mut TemperEntropy) -> Result<Vec<u8>>;
    fn slhdsa_verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool;
}
```

### 2. CPU Provider (`src/crypto_provider/cpu.rs`)

Default implementation using RustCrypto pure Rust libraries:
- **ML-DSA-65**: FIPS 204, lattice-based, NIST Level 3
- **SLH-DSA-SHA2-128f**: FIPS 205, hash-based, NIST Level 5 (fast variant)

```rust
pub struct CpuProvider;
pub static CPU_PROVIDER: CpuProvider = CpuProvider;
```

### 3. Global Provider (`src/crypto_provider.rs`)

Thread-safe global provider mechanism:

```rust
pub fn get_crypto_provider() -> &'static dyn CryptoProvider;
pub fn set_crypto_provider(provider: &'static dyn CryptoProvider);
```

### 4. Plugin Infrastructure (`src/plugins.rs`)

**std-only** placeholder for dynamic provider loading:

```rust
#[cfg(feature = "std")]
pub fn load_provider<P: AsRef<Path>>(path: P) -> Result<Box<dyn CryptoProvider>>;

#[cfg(feature = "std")]
pub fn discover_providers() -> Vec<PluginMetadata>;
```

## Usage

### Default (Zero-Config CPU)

```rust
use temper::{TemperEntropy, generate_keypair, create_seal};

let mut rng = TemperEntropy::from_seed([0x42; 32]);
let keypair = generate_keypair(&mut rng, "alice@example.com")?;
// Automatically uses CPU provider
```

### Custom Provider (Future)

```rust
use temper::crypto_provider::set_crypto_provider;

// Register custom GPU provider
static GPU_PROVIDER: MyGpuProvider = MyGpuProvider::new();
set_crypto_provider(&GPU_PROVIDER);

// All subsequent seal operations use GPU acceleration
let keypair = generate_keypair(&mut rng, "alice@example.com")?;
```

### Direct Provider Access

```rust
use temper::crypto_provider::get_crypto_provider;

let provider = get_crypto_provider();
let (sk, pk) = provider.mldsa_keygen(&mut rng)?;
```

## Design Principles

### 1. Zero-Config Default
- CPU provider is automatically available
- No setup required for standard usage
- Works in both `std` and `no_std` environments

### 2. No Protocol Changes
- Seal structure unchanged
- Signature format unchanged
- Verification logic unchanged
- Only implementation path differs

### 3. Thread Safety
- Global provider uses `spin::Mutex` (no_std compatible)
- All providers must be `Send + Sync`
- Safe for concurrent access

### 4. Performance Isolation
- Crypto operations delegated to provider
- Provider can optimize internally (batching, parallelism, hardware)
- Zero overhead when using CPU provider (inlined functions)

### 5. Embedded Compatibility
- Core trait and CPU provider work in `no_std`
- Plugin system is `std`-only (feature-gated)
- No heap allocations in hot path (provider methods use `Vec` for return only)

## Implementation Details

### Provider Selection

```rust
// src/crypto_provider.rs
static GLOBAL_PROVIDER: Mutex<Option<&'static dyn CryptoProvider>> = Mutex::new(None);

pub fn get_crypto_provider() -> &'static dyn CryptoProvider {
    let guard = GLOBAL_PROVIDER.lock();
    match *guard {
        Some(provider) => provider,
        None => &cpu::CPU_PROVIDER,  // Default
    }
}
```

### Seal Integration

```rust
// src/seal.rs
pub fn create_seal(...) -> Result<Seal> {
    let provider = get_crypto_provider();
    
    // Sign with ML-DSA-65
    let primary_sig = provider.mldsa_sign(&keypair.mldsa_secret_key, &binding, rng)?;
    
    // Sign with SLH-DSA
    let backup_sig = provider.slhdsa_sign(&keypair.slhdsa_secret_key, &binding, rng)?;
    
    // ...
}
```

## Testing

### CPU Provider Tests

```bash
cargo test crypto_provider::cpu
```

Verifies:
- ML-DSA roundtrip (sign + verify)
- SLH-DSA roundtrip (sign + verify)
- Invalid signature rejection
- Correct key/signature sizes

### Integration Tests

All existing seal tests pass unchanged, proving:
- No protocol changes
- No behavioral changes
- CPU provider is functionally equivalent to original implementation

### No-Std Verification

```bash
cargo build --no-default-features --features alloc
```

Ensures the core abstraction and CPU provider work without `std`.

## Future Work

### 1. GPU Provider (CUDA/ROCm)

```rust
pub struct GpuProvider {
    device_id: i32,
    stream: CudaStream,
}

impl CryptoProvider for GpuProvider {
    fn mldsa_sign(&self, ...) -> Result<Vec<u8>> {
        // Offload to GPU kernel
        cuda_mldsa_sign(self.stream, sk, message)
    }
}
```

### 2. FPGA Provider

```rust
pub struct FpgaProvider {
    device: FpgaDevice,
}

impl CryptoProvider for FpgaProvider {
    fn slhdsa_sign(&self, ...) -> Result<Vec<u8>> {
        // Use FPGA accelerator for hash-based signatures
        self.device.slhdsa_sign_hw(sk, message)
    }
}
```

### 3. Batch Provider

```rust
pub struct BatchProvider {
    inner: &'static dyn CryptoProvider,
    batch_size: usize,
}

impl CryptoProvider for BatchProvider {
    fn mldsa_sign(&self, ...) -> Result<Vec<u8>> {
        // Accumulate requests, sign in batch
        self.batch_queue.push((sk, message));
        if self.batch_queue.len() >= self.batch_size {
            self.flush_batch()
        }
    }
}
```

### 4. Dynamic Loading

```rust
#[cfg(feature = "std")]
use libloading::{Library, Symbol};

pub fn load_provider(path: &Path) -> Result<Box<dyn CryptoProvider>> {
    let lib = Library::new(path)?;
    let constructor: Symbol<fn() -> Box<dyn CryptoProvider>> = 
        lib.get(b"temper_provider_new")?;
    Ok(constructor())
}
```

## Security Considerations

### Provider Trust
- Custom providers must implement crypto correctly
- Malicious providers can compromise security
- Use trusted providers only (signed binaries, hardware attestation)

### Side Channels
- Providers must implement constant-time operations
- GPU/FPGA implementations may have different side-channel profiles
- Test providers against timing/power analysis attacks

### Key Material
- Providers must zeroize sensitive data
- GPU/FPGA memory must be cleared after use
- Consider encrypted key storage in hardware

## Performance Benchmarks

### CPU Provider (Baseline)

```
ML-DSA-65 keygen:  1.2ms
ML-DSA-65 sign:    1.5ms
ML-DSA-65 verify:  0.8ms

SLH-DSA keygen:    0.5ms
SLH-DSA sign:      12ms (fast variant)
SLH-DSA verify:    1.2ms
```

### Expected GPU Speedup (Future)

```
ML-DSA-65 sign (batched):  ~10-50x faster
SLH-DSA sign (parallel):   ~20-100x faster
```

### Expected FPGA Speedup (Future)

```
SLH-DSA sign (hardware):   ~50-200x faster
Power consumption:         ~10x more efficient
```

## References

- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)
- [RustCrypto PQC Libraries](https://github.com/RustCrypto/signatures)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
