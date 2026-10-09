#![no_std]
#![doc = "Temper — Quantum-safe cryptographic protocol with hardened entropy and dual PQC signatures."]

#[cfg(feature = "alloc")]
extern crate alloc;

// When std is enabled, make std available
#[cfg(feature = "std")]
extern crate std;

// When std is enabled, alloc is implicitly available
#[cfg(all(feature = "std", not(feature = "alloc")))]
extern crate alloc;

// region:    --- Modules

pub mod crypto_provider;
pub mod entropy;
pub mod entropy_source;
pub mod error;

#[cfg(feature = "keychain")]
pub mod keychain;

#[cfg(feature = "signatures")]
pub mod seal;

#[cfg(feature = "signatures")]
pub mod ca;

#[cfg(feature = "envelope")]
pub mod envelope;

#[cfg(feature = "envelope")]
pub mod handshake;

// The record layer for the authenticated session protocol. `session`
// implies `envelope`, so the AEAD underneath is always present when this
// compiles; the handshake protocol itself lands with the `session` module.
#[cfg(feature = "session")]
pub mod record;

// The three-flight authenticated session protocol: transcript-signed mutual
// authentication over the bare handshake with both peers' identities concealed,
// peer policies, and an optional stateless anti-DoS cookie.
#[cfg(feature = "session")]
pub mod session;

// Stateless anti-DoS cookie for the session handshake. Separate from `session` for
// the same reason `replay` is: it needs a carrier-supplied peer tag and a
// clock, neither of which belongs in a pure state machine.
#[cfg(feature = "session")]
pub mod session_cookie;

// Responder-side anti-replay state for flight 1. Lives beside `session`
// because it is the piece of that state machine the module deliberately does
// not keep: the handshake itself is stateless between calls, so the memory
// a responder needs to refuse a repeat is the caller's, and this is a shape
// for it.
#[cfg(feature = "session")]
pub mod replay;

// std + tokio only; `transport` implies both. The framing and client/server
// complete the handshake above, so the module sits next to it.
#[cfg(feature = "transport")]
pub mod transport;

// There was a `plugins` module here. It was a placeholder for dynamically
// loading `CryptoProvider` implementations from shared libraries, and it was
// entirely inert: `load_provider` returned an error unconditionally and
// `discover_providers` returned an empty vector, with two tests whose only
// job was to pin that inaction. A published symbol named `load_provider`
// that can never load a provider reads as a capability and is not one, so
// it is gone until something implements it. Static providers via
// `set_crypto_provider` remain the supported path.

#[cfg(feature = "hardware_example")]
pub mod hardware_example;

// Private: stub surface for feature-gated-out modules, re-exported below at
// the crate-root paths it occupied before the move.
mod stubs;

// Private: no_std getrandom registration. The cfg matches the item-level cfgs
// inside, so `std` builds carry no module and no registration at all.
#[cfg(not(feature = "std"))]
mod getrandom_custom;

// The statistical suites report their results, which only means something with
// a stdout. Under no_std these expand to a no-op so the assertions — the part
// that can actually fail — still run. Declared before the modules below, since
// `macro_rules!` scoping is textual.
#[cfg(all(test, not(feature = "std")))]
macro_rules! println {
	($($arg:tt)*) => {
		let _ = format_args!($($arg)*);
	};
}

#[cfg(all(test, feature = "alloc"))]
#[path = "entropy_tests.rs"]
mod entropy_tests;

#[cfg(all(test, feature = "signatures"))]
#[path = "seal_tests.rs"]
mod seal_tests;

#[cfg(all(test, feature = "signatures"))]
#[path = "ca_tests.rs"]
mod ca_tests;

#[cfg(all(test, feature = "envelope"))]
#[path = "envelope_tests.rs"]
mod envelope_tests;

// Functional tests for the flights: round trips, concealment, the cookie
// gate, version dispatch, and a tamper case per field.
#[cfg(all(test, feature = "session"))]
#[path = "session_tests.rs"]
mod session_tests;

// Conformance: every transcript/KDF/seal recomputed from PROTOCOL.md's
// formulas with raw primitives, both protocol roles played by the test against
// the real implementation, plus a negative control per plausible mis-reading
// (a seal key folded into H2, a seal key lacking the secret, H2 over the
// plaintext, a signature by another identity).
#[cfg(all(test, feature = "session"))]
#[path = "session_math_tests.rs"]
mod session_math_tests;

// Golden bytes + property round-trips for the six frozen serialization types.
// Declared under `signatures` (the base of the envelope stack); the envelope
// types inside are feature-gated individually.
#[cfg(all(test, feature = "signatures"))]
#[path = "frozen_tests.rs"]
mod frozen_tests;

pub use entropy::{EntropyHealth, TemperEntropy};
pub use entropy_source::{EntropyError, EntropySource};
pub use error::{Error, Result};

#[cfg(feature = "signatures")]
pub use crypto_provider::{CryptoProvider, get_crypto_provider, set_crypto_provider};

#[cfg(feature = "signatures")]
pub use seal::{Seal, SealContext, SignatureBlock, TemperKeypair, VerifyResult};
#[cfg(feature = "signatures")]
pub use seal::{create_seal, generate_keypair, verify_seal};

#[cfg(feature = "signatures")]
pub use ca::verify_certificate as verify_cert_with_keys;
#[cfg(feature = "signatures")]
pub use ca::{ConcealmentBinding, SubjectKeys, TemperCa, TemperCertificate};

// Stub types for when signatures feature is disabled
#[cfg(not(feature = "signatures"))]
pub use stubs::{Seal, SealContext, SignatureBlock, TemperKeypair, VerifyResult};
#[cfg(not(feature = "signatures"))]
pub use stubs::{create_seal, generate_keypair, verify_seal};

#[cfg(feature = "hardware_example")]
pub use hardware_example::HardwareTrng;

#[cfg(feature = "envelope")]
pub use envelope::{ConcealmentKeypair, ConcealmentPublicKey};
#[cfg(feature = "envelope")]
pub use envelope::{Envelope, EnvelopeKeypair, KernelChainEnvelope};
#[cfg(feature = "envelope")]
pub use envelope::{authenticated_decapsulate, authenticated_encapsulate};
#[cfg(feature = "envelope")]
pub use envelope::{decapsulate, encapsulate, generate_envelope_keypair};
#[cfg(feature = "envelope")]
pub use envelope::{kernel_chain_decapsulate, kernel_chain_encapsulate, kernel_chain_extract_secret};

#[cfg(feature = "session")]
pub use record::RecordKeys;
#[cfg(feature = "session")]
pub use replay::{DEFAULT_REPLAY_CAPACITY, SessionReplayGuard};
#[cfg(feature = "session")]
pub use session::{CertValidity, PROTOCOL_VERSION, PeerIdentity, PeerPolicy, SessionSecrets};
#[cfg(feature = "session")]
pub use session::{
	CookieContext, SessionAccept, SessionAcceptBody, SessionChallenge, SessionInit, accept as session_accept,
	finalize_initiator as session_finalize_initiator, finalize_responder as session_finalize_responder,
	initiate as session_initiate, peek_version,
};
#[cfg(feature = "session")]
pub use session_cookie::SessionCookie;

// Stub types for when envelope feature is disabled
#[cfg(not(feature = "envelope"))]
pub use stubs::{Envelope, EnvelopeKeypair, KernelChainEnvelope};
#[cfg(all(not(feature = "envelope"), feature = "alloc"))]
pub use stubs::{
	authenticated_decapsulate, authenticated_encapsulate, decapsulate, encapsulate, generate_envelope_keypair,
	kernel_chain_decapsulate, kernel_chain_encapsulate, kernel_chain_extract_secret,
};

// `encrypt` / `decrypt` used to live here as public no-ops returning their input
// unchanged. Removed 2026-10-08 — a crypto crate must not export a function
// named `encrypt` that hands back plaintext. Use the envelope API.

// endregion: --- Modules
