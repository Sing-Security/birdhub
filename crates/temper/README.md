# Temper — Quantum-Safe Cryptographic Protocol

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

**Temper** is a Rust cryptographic protocol library for quantum-safe, embedded, and
server environments. It is `#![no_std]` throughout — `alloc` is required, `std` is
optional — and every primitive is chosen for post-quantum resistance.

## Overview

- **Hardened entropy** — a multi-source pool (OS, hardware, jitter, process) is mixed
  through BLAKE3 into a ChaCha20 DRBG that reseeds automatically.
- **Dual PQC signatures** — a seal is valid only if both an ML-DSA-65 and an
  SLH-DSA-SHA2-128f signature verify. The two rest on unrelated hardness assumptions,
  so breaking one is not enough.
- **Hybrid key encapsulation** — ML-KEM-1024 combined with X25519, so an envelope stays
  confidential unless *both* are broken.
- **Deterministic identifiers** — content and structural IDs are BLAKE3-derived, not
  random, so structures are reproducible from their inputs.

## Modules

| Module | Feature | What it does |
|---|---|---|
| `entropy` / `entropy_source` | always | Multi-source entropy pool and ChaCha20 DRBG |
| `seal` | `signatures` | Dual-signature seal: `create_seal`, `verify_seal` |
| `ca` | `signatures` | Certificate authority over the seal primitives |
| `crypto_provider` | `signatures` | Pluggable backend; CPU implementation by default |
| `envelope` | `envelope` | ML-KEM-1024 + X25519 hybrid KEM with ChaCha20-Poly1305 |
| `handshake` | `envelope` | Ephemeral two-party key agreement |
| `record` | `session` | Directional AEAD record keys: counter nonces, stream and datagram modes, rekey ratchet, opt-in length padding |
| `replay` | `session` | Responder-side anti-replay window for `session_id` |
| `session` | `session` | Three-flight mutually authenticated session protocol: concealed identities, blinded handshake ids, optional anti-DoS cookie ([`PROTOCOL.md`](PROTOCOL.md)) |
| `session_cookie` | `session` | Stateless anti-DoS cookie for the session handshake |
| `transport` | `transport` | Length-prefixed framing over tokio; encrypted TCP client/server sessions |
| `keychain` | `keychain` | Derived-key hierarchy for a host OS (see below) |
| `hardware_example` | `hardware_example` | Template for wiring a hardware TRNG |

## Algorithms

| Primitive | Parameter set | NIST category | Sizes |
|---|---|---|---|
| ML-DSA-65 | FIPS 204 | Category 3 | sig 3309 B, pk 1952 B |
| SLH-DSA-SHA2-128f | FIPS 205 | Category 1 | sig 17088 B, pk 32 B |
| ML-KEM-1024 | FIPS 203 | Category 5 | ct 1568 B |
| X25519 | RFC 7748 | — | 32 B |
| ChaCha20-Poly1305 | RFC 8439 | — | AEAD |
| BLAKE3 | — | — | 256-bit digest |

The SLH-DSA category follows the parameter *number*, not the variant: 128 is
Category 1, 192 is Category 3, 256 is Category 5. Temper uses the fast (`f`) variant,
which trades larger signatures (17 KB) for signing speed (~50x faster than `s`).

## Protocol Architecture

### Entropy

```
Entropy Sources (OS, Jitter, HW, PID)
    ↓
 BLAKE3 Entropy Pool (domain-separated)
    ↓
 ChaCha20 DRBG (reseeds every 1 MiB)
    ↓
 Random Output / Key Material
```

### Seal construction

```
message ─BLAKE3→ content hash
             ↓
     binding = hex(hash) || postcard(context)
             ↓
      [ML-DSA-65 signature]
      [SLH-DSA-SHA2-128f signature]
Both must verify for a seal to be valid
```

## Usage

The crate publishes as **`temper-rs`** (the `temper` name on crates.io is
taken); the library it provides — and everything in these examples — is
`temper`:

```toml
# Minimal embedded (Cortex-M, RISC-V)
temper-rs = { version = "0.5", default-features = false, features = ["alloc"] }

# Embedded with hybrid envelope encryption
temper-rs = { version = "0.5", default-features = false, features = ["alloc", "envelope"] }

# Server with SIMD-accelerated hashing
temper-rs = { version = "0.5", features = ["std", "blake3_simd"] }

# Encrypted TCP sessions (tokio): three-flight handshake + AEAD records
temper-rs = { version = "0.5", default-features = false, features = ["transport"] }
```

```rust
use temper::{TemperEntropy, create_seal, generate_keypair, verify_seal};

let mut rng = TemperEntropy::new();
let keypair = generate_keypair(&mut rng)?;
let seal = create_seal(&mut rng, b"payload", &keypair, b"my-domain")?;

let result = verify_seal(b"payload", &seal, &mldsa_pk, &slhdsa_pk)?;
assert!(result.is_valid());
```

## Feature Flags

- **`alloc`** — heap support (Vec, String, BTreeMap). Required by everything.
- **`std`** *(default)* — standard library, OS entropy sources, convenience APIs.
- **`envelope`** *(default)* — ML-KEM-1024 + X25519 hybrid KEM. Implies `signatures`.
- **`session`** — the authenticated session protocol: three postcard flights over any carrier,
  dual PQC transcript signatures, confirm MACs, and directional record keys with a rekey
  ratchet and opt-in length padding. Both identities are concealed — the initiator's is
  sealed to the responder's long-term concealment key, the responder's under a key derived
  from the session secret — and the handshake ids are blinded with fresh randomness rather
  than a deterministic identity digest. A responder can add an optional stateless cookie so
  it refuses an unvalidated peer for the price of two BLAKE3 hashes instead of a flight 2,
  and a `SessionReplayGuard` to refuse a repeated `session_id`. Client authentication is
  mandatory. See [`PROTOCOL.md`](PROTOCOL.md) for the wire format, key schedule, and threat
  model. Implies `envelope`.

  Concealment is against a non-participant observer, not the peer, and flight 1's seal is
  not forward-secret. Read
  [*What the protocol does not do*](PROTOCOL.md#what-the-protocol-does-not-do) before
  relying on it.
- **`transport`** *(std only)* — framed messages (`[u32 LE length][postcard payload]`) over
  tokio, with a TCP client/server that runs the three session flights and then moves one
  encrypted record per frame. `connect` and `Listener::accept` run the handshake; the
  responder's identity, certificate, policy, and optional cookie live in a `ResponderConfig`.
  Implies `std` and `session`; there is no plaintext mode.
- **`signatures`** — ML-DSA-65 and SLH-DSA seal construction and verification.
- **`keychain`** — derived-key hierarchy. Requires only BLAKE3.
- **`compression`** — DEFLATE for seals and envelopes. Implied by `std`.
- **`hardware_example`** — hardware TRNG integration template. Works with or without `std`.
- **`blake3_simd`** *(std only)* — BLAKE3 SIMD intrinsics (NEON, SSE2, AVX2, AVX-512).
- **`blake3_parallel`** *(std only)* — Rayon-based parallel hashing for content ≥ 1 MiB.
  Implies `blake3_simd`.
- **`crucible-user-getrandom`** — host-platform entropy hook. See below.

With `signatures` disabled, the seal API compiles to stubs so that downstream code
still builds: `verify_seal` returns `Ok(valid: true)` unconditionally. **Do not rely
on seal verification without the `signatures` feature** — the feature is on by default
and is implied by `envelope`.

## Platform Integration

Two features exist for a specific host, not as general-purpose API.

**`crucible-user-getrandom`** routes `getrandom` to a host syscall instead of the
zero-fill fallback used on bare metal. Without it, a `no_std` build that calls
`TemperEntropy::new()` seeds its DRBG deterministically, which silently produces
predictable keys. Enable it on any `no_std` target that has an OS underneath it.

**`keychain`** provides a derived-key hierarchy seeded from a process root key. Its
BLAKE3 domain strings are fixed cryptographic separators — changing them would change
every derived key, so treat them as a wire format.

## Testing

```sh
cargo test                                    # default features
cargo test --all-features                     # 160 tests
cargo test --no-default-features --features alloc
cargo clippy --all-features -- -D warnings
cargo fmt --all --check
```

The entropy test suite checks statistical properties: byte distribution (chi-squared,
255 df at p=0.001), bit balance, autocorrelation (|r| < 0.019), avalanche/SAC, and
collision-freedom over 1M u64 samples. These are probabilistic — a rare failure is not
automatically a bug, and loosening a bound to make a run go green is not a fix.

## Build Profiles

- **`release`** — size-first (`opt-level = "s"`, fat LTO, `panic = "abort"`, stripped).
  For embedded targets with limited flash.
- **`release-server`** — speed-first (`opt-level = 3`, thin LTO, unwinding enabled).
  Roughly 15–25% faster than `release`.

```sh
cargo build --profile release-server --features "std,blake3_simd,blake3_parallel,envelope"
```

Cargo reads profiles only from the workspace root, so when Temper is built as a path
dependency these are ignored in favour of the consuming workspace's settings.

## Benchmarking

```sh
cargo bench --bench seal_bench
open target/criterion/report/index.html
```

The suite covers seal creation and verification from 1 KB to 10 MB.

## Binary Size

```sh
cargo install cargo-bloat
cargo bloat --release --no-default-features --features alloc -n 20
```

Rough embedded `release` figures: ~110 KB with `alloc` alone, ~205 KB with `envelope`.
See [`BINARY_SIZE_GUIDE.md`](BINARY_SIZE_GUIDE.md) for the full breakdown and tuning
options.

## Security

Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md). Three properties are
deliberate and documented rather than bugs: `handshake` is unauthenticated key agreement
(its authenticated wrapper is the `session` protocol — see [`PROTOCOL.md`](PROTOCOL.md) for
what that does and does not protect against), handshake flights travel in cleartext inside
the carrier, and the host-integration features above are not general-purpose API.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: keep `no_std` compatibility,
build the full feature matrix, and do not change a serialized type or a BLAKE3 domain
string.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
