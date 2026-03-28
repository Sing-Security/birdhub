# Binary Size Analysis Guide

This document provides guidance on analyzing and optimizing binary size for embedded deployments of the Temper crate.

## Quick Start

Install cargo-bloat:
```bash
cargo install cargo-bloat
```

## Basic Analysis

### Check Current Binary Size

```bash
# Build optimized release binary
cargo build --release --no-default-features --features alloc

# Analyze top functions by size
cargo bloat --release --no-default-features --features alloc -n 50
```

### Example Output

```
File  .text     Size Crate
0.7%  17.2%   9.8KiB ml_dsa
0.5%  12.1%   6.9KiB slh_dsa
0.3%   7.8%   4.4KiB blake3
0.2%   5.2%   3.0KiB temper
...
```

## Feature-Specific Analysis

### Compare Feature Combinations

```bash
# Minimal build (no_std + alloc only)
cargo bloat --release --no-default-features --features alloc

# With std feature
cargo bloat --release --features std

# With SIMD acceleration
cargo bloat --release --features std,blake3_simd

# With parallel hashing
cargo bloat --release --features std,blake3_parallel
```

### Expected Size Increases

| Feature Set | Binary Size (Approximate) | Notes |
|-------------|---------------------------|-------|
| `alloc` only | ~120 KB | Minimal, embedded-ready |
| `std` | ~150 KB | +30 KB for std library support |
| `blake3_simd` | ~160 KB | +10 KB for SIMD intrinsics |
| `blake3_parallel` | ~200 KB | +50 KB for Rayon runtime |
| `hardware_example` | ~122 KB | +2 KB for example code |

## Target-Specific Analysis

### ARM Cortex-M (Embedded)

```bash
# Install ARM toolchain
rustup target add thumbv7em-none-eabihf

# Build for Cortex-M4F
cargo build --release \
  --no-default-features \
  --features alloc \
  --target thumbv7em-none-eabihf

# Analyze
cargo bloat --release \
  --no-default-features \
  --features alloc \
  --target thumbv7em-none-eabihf
```

### RISC-V

```bash
# Install RISC-V toolchain
rustup target add riscv32imac-unknown-none-elf

# Build for RISC-V
cargo build --release \
  --no-default-features \
  --features alloc \
  --target riscv32imac-unknown-none-elf

# Analyze
cargo bloat --release \
  --no-default-features \
  --features alloc \
  --target riscv32imac-unknown-none-elf
```

## Advanced Analysis

### Function-Level Analysis

```bash
# Show all functions (not just top N)
cargo bloat --release --no-default-features --features alloc -n 0

# Filter by crate
cargo bloat --release --no-default-features --features alloc --filter temper

# Show specific function details
cargo bloat --release --no-default-features --features alloc --filter create_seal
```

### Section Analysis

```bash
# Analyze by ELF section
cargo bloat --release --no-default-features --features alloc --sections
```

Example output:
```
 Section  Size
   .text  85.2KiB  (executable code)
  .rodata 18.4KiB  (read-only data)
   .data   1.2KiB  (initialized data)
    .bss   0.8KiB  (uninitialized data)
```

## Optimization Strategies

### 1. Link-Time Optimization (LTO)

Already enabled in `[profile.release]`:
```toml
lto = true
```

For even more aggressive optimization:
```toml
lto = "fat"  # Full cross-crate LTO
```

**Trade-off**: Slower build times, smaller binaries

### 2. Codegen Units

Already optimized in `[profile.release]`:
```toml
codegen-units = 1
```

**Effect**: Better optimization at cost of parallel compilation

### 3. Panic Strategy

Already configured in `[profile.release]`:
```toml
panic = "abort"
```

**Savings**: ~10 KB by removing unwinding machinery

### 4. Strip Symbols

Already enabled in `[profile.release]`:
```toml
strip = true
```

**Savings**: ~20-30% size reduction

### 5. Optimize for Size

```toml
opt-level = "z"  # Even more aggressive than "s"
```

**Trade-off**: May hurt performance, saves 5-10 KB

## CI Integration

### GitHub Actions Example

```yaml
name: Size Check

on: [pull_request]

jobs:
  size-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Install cargo-bloat
        run: cargo install cargo-bloat
      
      - name: Check binary size
        run: |
          cargo bloat --release \
            --no-default-features \
            --features alloc \
            -n 20 > bloat-report.txt
          
          cat bloat-report.txt
      
      - name: Upload size report
        uses: actions/upload-artifact@v3
        with:
          name: bloat-report
          path: bloat-report.txt
```

### Size Regression Detection

```bash
#!/bin/bash
# check-size-regression.sh

BASELINE_SIZE=122880  # 120 KB in bytes

cargo build --release --no-default-features --features alloc

BINARY_SIZE=$(stat -c%s target/release/libtemper.rlib 2>/dev/null || \
              stat -f%z target/release/libtemper.rlib 2>/dev/null)

INCREASE=$((BINARY_SIZE - BASELINE_SIZE))
PERCENT=$((INCREASE * 100 / BASELINE_SIZE))

if [ $INCREASE -gt 10240 ]; then  # 10 KB threshold
    echo "❌ Binary size increased by ${INCREASE} bytes (${PERCENT}%)"
    echo "Current: ${BINARY_SIZE} bytes, Baseline: ${BASELINE_SIZE} bytes"
    exit 1
else
    echo "✅ Binary size within acceptable range"
    echo "Current: ${BINARY_SIZE} bytes, Baseline: ${BASELINE_SIZE} bytes"
fi
```

## Interpreting Results

### What to Look For

1. **Large crypto primitives**: ML-DSA and SLH-DSA signatures are inherently large (expected)
2. **BLAKE3**: Should be 4-5 KB without SIMD, 8-10 KB with SIMD
3. **Signature wrappers**: Should be minimal (< 500 bytes each)
4. **Generic instantiations**: Multiple instantiations of generic functions indicate optimization opportunities

### Red Flags

- Temper-specific code > 10 KB (investigate inefficiencies)
- Duplicate symbol instantiations (may need `#[inline]` hints)
- Unexpectedly large helper functions (may need refactoring)

## Example Workflow

```bash
# 1. Baseline measurement
cargo bloat --release --no-default-features --features alloc > before.txt

# 2. Make changes
# ... edit code ...

# 3. Measure after changes
cargo bloat --release --no-default-features --features alloc > after.txt

# 4. Compare
diff before.txt after.txt
```

## Additional Tools

### cargo-size

Alternative to cargo-bloat with different visualizations:

```bash
cargo install cargo-size
cargo size --release --no-default-features --features alloc
```

### binutils size

Traditional size analysis:

```bash
# After building
size target/release/libtemper.rlib

# Or for binaries
size target/thumbv7em-none-eabihf/release/examples/seal_demo
```

## Target Memory Constraints

### Recommended Targets

| MCU | Flash | RAM | Temper Fit |
|-----|-------|-----|------------|
| STM32F103 | 64 KB | 20 KB | ❌ Too small |
| STM32F407 | 256 KB | 64 KB | ✅ Minimal features |
| STM32F767 | 1 MB | 256 KB | ✅ Full features |
| ESP32-S3 | 8 MB | 512 KB | ✅ Full features |
| nRF52840 | 1 MB | 256 KB | ✅ Full features |

### Flash Usage Breakdown

- **ML-DSA**: ~40 KB
- **SLH-DSA**: ~30 KB
- **BLAKE3**: ~5 KB (no SIMD), ~10 KB (with SIMD)
- **ChaCha20**: ~3 KB
- **Temper glue code**: ~5 KB
- **Runtime/allocator**: ~10-20 KB
- **Total (minimal)**: ~120 KB

## Further Reading

- [Cargo Book: Profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [Embedded Rust Book: Optimizations](https://docs.rust-embedded.org/book/unsorted/speed-vs-size.html)
- [cargo-bloat README](https://github.com/RazrFalcon/cargo-bloat)
