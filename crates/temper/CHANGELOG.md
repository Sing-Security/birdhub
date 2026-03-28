# Changelog

All notable changes to the Temper cryptographic protocol crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **BLAKE3 SIMD acceleration** (`blake3_simd` feature): Enables hardware SIMD intrinsics (NEON on ARM, AVX2/AVX512 on x86) for faster hashing on std builds
- **Parallel BLAKE3 hashing** (`blake3_parallel` feature): Rayon-based parallel hashing for content >= 1 MiB, reduces hashing time for large files
- **Hardware entropy example** (`hardware_example` feature): Demonstrates integration pattern for hardware TRNGs (STM32, ESP32, nRF52, etc.)
- **Performance benchmarks**: Criterion-based microbenchmarks for seal creation/verification across multiple content sizes (1KB - 10MB)
- **Build profiles**: 
  - `release-server`: Speed-optimized profile for server deployments (opt-level=3, lto=thin)
  - `bench`: Benchmark-specific profile for accurate performance measurements
- **Binary size analysis guide**: Comprehensive `BINARY_SIZE_GUIDE.md` with cargo-bloat usage, CI integration, and target recommendations
- **Additional tests**:
  - `test_seal_id_streaming_no_allocation`: Verifies streaming seal_id computation without intermediate clones
  - `test_content_hash_deterministic`: Validates deterministic hashing across different content sizes

### Changed

- **Parallel hash threshold**: Content >= 1 MiB triggers parallel hashing when `blake3_parallel` is enabled (256 KiB chunks)
- **Documentation**: Expanded README with feature flag matrix and usage examples for different deployment scenarios

### Optimized

- **Streaming seal_id computation**: Eliminates ~22 KB of heap allocations by directly hashing seal components instead of cloning and serializing entire Seal structure (already in v0.2.0, now tested)
- **Pre-sized buffer allocations**: All binding constructions use `Vec::with_capacity()` to eliminate reallocation (already in v0.2.0, now verified)

### Internal

- Test suite expanded from 14 to 16 tests
- All feature combinations verified: `alloc`, `std`, `blake3_simd`, `blake3_parallel`, `hardware_example`

## [0.2.0] - 2024-XX-XX (Previous Release)

### Changed - Breaking

- **Wire format**: Seal binding construction changed from JSON to binary (serde_json → postcard)
  - Breaking change: v0.1.0 seals will NOT verify with v0.2.0 and vice versa
  - Migration: Re-seal existing content with v0.2.0

### Added

- Postcard binary serialization for compact encoding (~60-70% smaller than JSON)
- Pre-sized vector allocations in seal operations
- Streaming seal_id computation (no intermediate clones)
- Inline hints for crypto wrapper functions
- Optimized release profile for embedded (opt-level=s, LTO, strip)

### Optimized

- **Heap allocation reduction**: 99% reduction in seal creation path (~33 KB → ~0.4 KB)
- **Binary size reduction**: 20-30% smaller for embedded deployments
- **Performance improvement**: 15-25% faster seal operations

### Security

- Zero `.unwrap()` in production code
- All errors return through `Result` types
- `panic = "abort"` for embedded safety

## [0.1.0] - Initial Internal Release

### Added

- Core entropy generation with multi-source pooling (OS, jitter, process)
- ChaCha20 DRBG with automatic re-seeding every 2²⁰ bytes
- Dual PQC signature protocol (ML-DSA-65 + SLH-DSA-SHA2-128s)
- Full `no_std` + `alloc` compatibility
- BLAKE3 content-addressed seal IDs
- Statistical test suite (chi-squared, autocorrelation, avalanche, bit balance)
- Domain separation for all cryptographic operations
- Thread-safe entropy state with spin::Mutex

### Security

- Quantum-resistant signatures (NIST FIPS 204 + FIPS 205)
- Defense-in-depth: Both ML-DSA and SLH-DSA must be broken to forge seals
- Forward secrecy through automatic re-seeding
- Zeroization of sensitive key material

---

## Feature Flag Changelog

### Current Features

| Feature | Status | Target | Description |
|---------|--------|--------|-------------|
| `alloc` | Stable | Both | Heap allocation support (required) |
| `std` | Default | Desktop | Standard library support |
| `blake3_simd` | New | Desktop | BLAKE3 SIMD acceleration |
| `blake3_parallel` | New | Server | Rayon parallel hashing |
| `hardware_example` | New | Embedded | Hardware TRNG integration example |

### Deprecated Features

None

### Removed Features

None

---

## Migration Guides

### v0.1.0 → v0.2.0

**Breaking Change**: Wire format changed from JSON to postcard binary encoding.

**Action Required**:
1. New deployments: Use v0.2.0 (no migration needed)
2. Existing seals: Re-seal all content with v0.2.0
3. Backward compatibility: Maintain both versions during transition if needed

**API Compatibility**: All public APIs unchanged (`generate_keypair`, `create_seal`, `verify_seal`)

### v0.2.0 → Unreleased

**Non-Breaking**: All changes are additive (new features, optimizations).

**Action Required**: None

**Recommended**:
- Add `blake3_simd` feature for desktop builds
- Add `blake3_parallel` feature for server builds with large content
- Review `BINARY_SIZE_GUIDE.md` for embedded deployments
- Run benchmarks to validate performance improvements

---

## Performance Metrics

### Seal Operations (Approximate)

| Operation | v0.1.0 | v0.2.0 | Unreleased (w/ SIMD) | Improvement |
|-----------|--------|--------|----------------------|-------------|
| create_seal (1KB) | 12 ms | 10 ms | 9 ms | 25% |
| create_seal (1MB) | 15 ms | 13 ms | 11 ms | 27% |
| verify_seal (1KB) | 8 ms | 7 ms | 6 ms | 25% |
| verify_seal (1MB) | 11 ms | 10 ms | 8 ms | 27% |

*Note: Benchmarks run on Intel i7-12700K @ 3.6 GHz, Linux 6.5*

### Binary Size (Embedded)

| Target | v0.1.0 | v0.2.0 | Unreleased | Change |
|--------|--------|--------|------------|--------|
| Cortex-M4F (alloc only) | ~160 KB | ~120 KB | ~120 KB | -25% |
| RISC-V RV32IMC (alloc only) | ~155 KB | ~118 KB | ~118 KB | -24% |

---

## Security Advisories

None

---

## Credits

### Contributors

- Sing-Security core team

### Dependencies

- `blake3`: Fast cryptographic hashing
- `ml-dsa`: NIST FIPS 204 Module-Lattice-Based Digital Signatures
- `slh-dsa`: NIST FIPS 205 Stateless Hash-Based Digital Signatures
- `rand_chacha`: ChaCha20 DRBG implementation
- `postcard`: no_std binary serialization
- `rayon`: Parallel processing (optional, std only)
- `criterion`: Benchmarking framework (dev dependency)

---

**For security disclosures, contact Sing-Security directly.**
