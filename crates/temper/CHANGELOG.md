# Changelog

Notable changes to Temper. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions before 0.5.0 were internal and were never published. Their entries are kept
below for lineage; treat them as history, not as release notes for anything you can
depend on.

## [Unreleased]

### Added

- **Session protocol** (`session` feature) — the three flights with both peers'
  identities concealed from a non-participant observer, the bare handshake's
  `local_id` blinded with fresh randomness instead of a deterministic identity
  digest, and an optional stateless anti-DoS cookie. Specified in `PROTOCOL.md`,
  including what the protocol does **not** provide.
- **`session`** — `initiate` / `accept` / `finalize_initiator` /
  `finalize_responder`, the `SessionInit` / `SessionAccept` wire types, and the
  `SessionChallenge` flight-0 type. The initiator's identity is sealed to the
  responder's concealment key; the responder's is sealed under a key derived
  from the session secret and the transcript through the acceptance.
- **`session_cookie`** (`session` feature) — `SessionCookie`, a stateless
  `BLAKE3.keyed_hash(server_secret, peer_tag || time_bucket)` cookie issuer and
  verifier that accepts the current and previous bucket. Separate from
  `session` for the same reason `replay` is: it needs a carrier-supplied peer
  tag and a clock, and the handshake is a pure state machine with neither.
- **`envelope::ConcealmentKeypair` / `ConcealmentPublicKey`** — the long-term
  key an initiator seals to. Only the public half is serializable, so the
  secret cannot reach the wire through the type that names it. Plus
  `envelope::aead_seal` / `aead_open`, a raw-key ChaCha20-Poly1305 with AAD and
  a single-use all-zero nonce, for sealing an identity under a key both sides
  already hold.
- **`session::peek_version`** — read the version field a flight 1 declares,
  decoding a `u16` rather than assuming a raw byte.
- **`transport`** — `Session::initiate` / `Session::accept`,
  `Listener::accept`, `connect`, `ResponderConfig`, and `peer_tag_from_addr`.
  The client handles the cookie challenge internally, restarting flight 1
  with the cookie and permitting exactly one such round.

### Changed

- **`ca`** — certificate content schema 2: a `TemperCertificate` now also signs
  the subject's **concealment public key** (`ConcealmentBinding`), and its wire
  encoding changes accordingly. The concealment key is what an initiator
  KEM-encapsulates flight 1 to, so certifying it is what makes a first contact
  authenticated end to end — a schema-1 certificate leaves the initiator taking
  that key on faith, and a substituted key opens the sealed identity without
  completing the handshake. Schema-1 certificates do not verify under this
  build (domain `Temper.CA.Cert.v2`); none were ever issued outside tests.
  `issue_certificate` now takes the subject's keys as one `SubjectKeys` value
  rather than as separate arguments.

### Security

- The flight-1 seal is **not forward-secret**: it is sealed to the responder's
  static concealment key, so an adversary who records flight 1 and later
  compromises that key recovers the initiator's identity. The responder's side
  is forward-secret.
- The version field is not authenticated, so it selects a code path rather than
  a trust level. This build speaks one version and rejects any other; a future
  breaking change would be negotiated through it, and a responder answering
  more than one version would reintroduce a downgrade surface. Stated in
  `PROTOCOL.md` rather than mitigated.

## [0.5.0] — 2026-10-09

First public release. Everything below the `0.1.0` heading existed before this, in
various internal states; this is the first snapshot published as a crate.

### Added

- **`handshake`** — ephemeral two-party key agreement over ML-KEM-1024 + X25519,
  deriving a shared 32-byte session key via `BLAKE3.derive_key("Temper.Handshake.v1", …)`.
  Provides forward secrecy; unauthenticated on its own — the `session` protocol
  below is the authenticated wrapper.
- **`session`** — a mutually authenticated session protocol on top of `handshake`
  (`session` feature): three postcard flights, dual ML-DSA-65 + SLH-DSA transcript
  signatures on both sides, keyed confirm MACs proving both parties derived the
  shared secret, mandatory client authentication, and peer policy (accept-any,
  pinning, or CA certificates). Directional record keys and the wire format, key
  schedule, and threat model are specified in `PROTOCOL.md`.
- **`record`** (`session` feature) — directional AEAD record keys over
  ChaCha20-Poly1305: counter nonces with the sequence never on the wire, strict
  ordering for streams, and an explicit-sequence pair (`seal_at`/`open_at`) for
  datagram carriers that window on their own. Keys ratchet every 2²⁰ records on
  a one-way BLAKE3 chain, so a key recovered from memory decrypts neither the
  records before it nor the records after it. `seal_padded`/`open_padded` add
  opt-in length quantization.
- **`replay`** (`session` feature) — `SessionReplayGuard`, a bounded
  time-windowed record of accepted `session_id`s, for the responder half of the
  protocol. `transport::Listener` owns one and consults it before computing
  flight 2.
- **`transport`** — length-prefixed framing over tokio with a TCP client/server
  that runs the three session flights and then moves one encrypted record per
  frame. A pre-release plaintext `Session` (with its `session_key()` accessor)
  was replaced rather than shipped.
- **`keychain`** — BLAKE3-derived key hierarchy seeded from a process root key.
  Host-platform integration, not general-purpose API.
- **`crypto_provider`** — pluggable backend for the PQC primitives, with a CPU
  implementation registered by default and `set_crypto_provider` to replace it.
- **`ca`** — certificate authority built on the seal primitives, with
  `TemperCertificate::check_validity` for both ends of the validity window.
- **`envelope`** — ML-KEM-1024 + X25519 hybrid KEM with ChaCha20-Poly1305 AEAD.
- **`blake3_simd`**, **`blake3_parallel`** — SIMD and Rayon-backed hashing (std only).
- **`hardware_example`** — hardware TRNG integration template.
- **`crucible-user-getrandom`** — routes `getrandom` to a host syscall instead of the
  zero-fill bare-metal fallback.
- **`release-server` and `bench` build profiles**, plus a size-first `release` profile.
- **`BINARY_SIZE_GUIDE.md`**, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `NOTICE`.
- **CI** covering the full feature matrix, `cargo fmt --check`, and `clippy -D warnings`.

### Changed

- Version aligned to **0.5.0**. The manifest said `0.1.0` while the README and
  internal documents described the crate as v0.5 — the manifest was the outlier.
- Crate renamed `forgecore-temper` → `temper`, matching the repository and the brand.
- README rewritten for external readers: current module surface, an accurate
  algorithm table, a deduplicated feature-flag section, and an integration section
  for the host-specific features.

### Fixed

- **Corrected the SLH-DSA claims.** The source comments and every document named
  `SLH-DSA-SHA2-128s` and advertised **NIST Level 5**. The implementation has always
  used `Sha2_128f`, which is **Category 1** — the category follows the parameter
  number (128/192/256 → 1/3/5), not the variant. Signatures are 17,088 bytes, not the
  ~7,856 bytes the `s` variant would give. The public documentation overstated the
  security level of one of the two signatures.
- **Reconciled the stated test count.** README claimed 27 tests, the CHANGELOG
  claimed 16; both numbers were invented, and the real suite was several times
  either figure at the audit (it is larger still after the additions above —
  see the CI matrix for the per-feature counts).
- **Declared the build profiles.** README, CHANGELOG and `BINARY_SIZE_GUIDE.md` all
  documented `[profile.release-server]` and `[profile.bench]`, and cited benchmark
  numbers produced under them, but no `[profile.*]` section existed — the documented
  `cargo build --profile release-server` command failed.

### Removed

- **`plugins`.** A module named for dynamically loading crypto providers from
  shared libraries, whose `load_provider` returned an error unconditionally and
  whose `discover_providers` returned an empty vector — with two tests whose only
  job was to pin that inaction. A public symbol named `load_provider` that can
  never load a provider reads as a capability and is not one. Static providers via
  `set_crypto_provider` remain the supported path.
- **`encrypt` and `decrypt`.** Two public functions at the crate root that returned
  their input unchanged. Nothing called them and nothing documented them; a
  cryptography crate must not export a function named `encrypt` that hands back
  plaintext. Use the `envelope` API.
- Internal work-log documents (`IMPLEMENTATION_SUMMARY.md`,
  `INTEGRATION_SUMMARY.md`, `PERFORMANCE_OPTIMIZATIONS.md`,
  `CRYPTO_PROVIDER_ARCHITECTURE.md`) and the `.github/` AI-assistant instruction
  files. All were stale — several described the PQC primitives as unimplemented
  `todo!()` stubs, invented a file tree that does not exist, and named algorithms the
  code does not use.

## [0.2.0] — date not recorded

### Changed — Breaking

- **Wire format**: seal binding construction moved from JSON to postcard binary.
  Seals created by 0.1.0 do not verify under 0.2.0, or vice versa. Migration:
  re-seal existing content.

### Added

- Postcard binary serialization (~60–70% smaller than JSON).
- Pre-sized vector allocations in seal operations.
- Streaming `seal_id` computation, eliminating intermediate clones.

### Optimized

- Heap allocation in the seal creation path reduced from ~33 KB to ~0.4 KB.
- Binary size reduced 20–30% for embedded targets.

## [0.1.0] — initial internal release

### Added

- Multi-source entropy pooling (OS, jitter, process) mixed through BLAKE3.
- ChaCha20 DRBG with automatic reseeding.
- Dual PQC signature protocol (ML-DSA-65 + SLH-DSA).
- `no_std` + `alloc` support throughout.
- BLAKE3 content-addressed seal IDs and domain separation for all operations.
- Statistical entropy test suite — chi-squared, autocorrelation, avalanche, bit balance.

### Security

- Quantum-resistant signatures (FIPS 204 + FIPS 205); both must be broken to forge
  a seal.
- Forward secrecy through automatic reseeding.
- Zeroization of key material.
