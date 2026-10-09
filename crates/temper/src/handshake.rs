//! # Generic Hybrid-KEM Session Handshake
//!
//! Two-party ephemeral handshake using ML-KEM-1024 + X25519, producing a
//! shared 32-byte session key both sides derive independently. This is the
//! same protocol shape as `temper-cbl`'s cross-node `session.rs` (that one
//! stays as-is — it registers keys with the kernel session table and is
//! wired into IPC), generalized here so any `envelope`-feature consumer of
//! this crate can reuse the exact same reviewed KEM/DH/KDF logic without
//! re-deriving it — notably a browser-side WASM client, which cannot depend
//! on a CrucibleOS kernel-target crate like `temper-cbl` at all.
//!
//! # Protocol
//!
//! 1. **Initiator**: [`initiate`] → `(HandshakeProposal, InitiatorState)`.
//!    Sends the proposal (its ephemeral public keys) to the responder.
//! 2. **Responder**: [`accept`] → `(HandshakeAcceptance, ResponderState)`.
//!    Encapsulates a shared secret to the initiator's ML-KEM public key.
//!    Sends the acceptance back.
//! 3. **Initiator**: [`finalize_initiator`] → 32-byte session key.
//! 4. **Responder**: [`finalize_responder`] → the same 32-byte session key.
//!
//! ```text
//! session_key = BLAKE3.derive_key(
//!     "Temper.Handshake.v1",
//!     mlkem_ss || x25519_ss || min(id_a, id_b) || max(id_a, id_b)
//! )
//! ```
//!
//! This is a bare key-agreement primitive — it provides forward secrecy
//! (fully ephemeral on both sides) but, on its own, no protection against an
//! active man-in-the-middle: neither side authenticates the other's identity
//! key against anything pinned in advance. Callers that need that guarantee
//! must layer it on top (e.g. TLS termination in front, or an
//! out-of-band-verified `local_id`).

#![cfg(feature = "envelope")]

use alloc::vec::Vec;

use ml_kem::{
	Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
	kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroize;

use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};

const DOMAIN_HANDSHAKE: &str = "Temper.Handshake.v1";

/// High bit forced on every session id, which pins it to postcard's 9-byte
/// varint band.
///
/// postcard varint-encodes a `u64`, so the encoded length of a uniformly
/// random id depends on the draw: below 2^56 it takes 8 bytes, at or above
/// it takes 9. That makes every flight's length vary by one byte with a
/// value nothing controls — a golden vector, a buffer size, or an MTU
/// calculation that is right for one handshake is off by one for the next
/// (this was observed in practice: the pinned flights of the demo, 3698 and
/// 24131 bytes, came out 3697 and 24130 on a live run).
///
/// Setting the high bit makes the length fixed for a fixed field. It costs
/// one bit of a random identifier whose only requirement is that a server
/// never sees the same one twice; the remaining 63 bits are far past any
/// session table that could exist.
const SESSION_ID_MARKER: u64 = 1 << 63;

/// Proposal sent from the initiator to the responder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakeProposal {
	/// Session identifier chosen by the initiator (random).
	pub session_id: u64,
	/// Initiator's identity tag (opaque to this module — e.g. a BLAKE3 hash
	/// of a longer-lived identity, or all-zero if the caller has none).
	pub initiator_id: [u8; 32],
	/// Initiator's ephemeral X25519 public key.
	pub ephemeral_x25519_pub: [u8; 32],
	/// Initiator's ephemeral ML-KEM-1024 encapsulation key (1568 bytes).
	pub mlkem_public_key: Vec<u8>,
}

/// Acceptance sent from the responder back to the initiator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakeAcceptance {
	/// Session identifier, echoed from the proposal.
	pub session_id: u64,
	/// Responder's identity tag (same convention as `initiator_id`).
	pub responder_id: [u8; 32],
	/// Responder's ephemeral X25519 public key.
	pub ephemeral_x25519_pub: [u8; 32],
	/// ML-KEM-1024 ciphertext encapsulated to the initiator's public key.
	pub mlkem_ciphertext: Vec<u8>,
}

/// Initiator's ephemeral secret state, held between [`initiate`] and
/// [`finalize_initiator`]. Zeroized on drop.
#[derive(Clone)]
pub struct InitiatorState {
	x25519_sk: [u8; 32],
	mlkem_sk: Vec<u8>,
}

impl Drop for InitiatorState {
	fn drop(&mut self) {
		self.x25519_sk.zeroize();
		self.mlkem_sk.zeroize();
	}
}

/// Responder's ephemeral secret state, held between [`accept`] and
/// [`finalize_responder`]. Zeroized on drop.
#[derive(Clone)]
pub struct ResponderState {
	x25519_sk: [u8; 32],
	mlkem_ss: [u8; 32],
}

impl Drop for ResponderState {
	fn drop(&mut self) {
		self.x25519_sk.zeroize();
		self.mlkem_ss.zeroize();
	}
}

/// Begin a handshake as the initiator: generate fresh ephemeral ML-KEM-1024
/// and X25519 keypairs and package the public halves into a proposal.
pub fn initiate(rng: &mut TemperEntropy, local_id: &[u8; 32]) -> Result<(HandshakeProposal, InitiatorState)> {
	let mut sid_bytes = [0u8; 8];
	rng.fill_bytes(&mut sid_bytes);
	let session_id = u64::from_le_bytes(sid_bytes) | SESSION_ID_MARKER;

	let mut x25519_sk_bytes = [0u8; 32];
	rng.fill_bytes(&mut x25519_sk_bytes);
	let x25519_sk = X25519SecretKey::from(x25519_sk_bytes);
	let x25519_pk = X25519PublicKey::from(&x25519_sk);

	let (mlkem_dk, mlkem_ek) = MlKem1024::generate(rng);
	let mlkem_ek_bytes: Vec<u8> = mlkem_ek.as_bytes().to_vec();
	let mlkem_sk_bytes: Vec<u8> = mlkem_dk.as_bytes().to_vec();

	let proposal = HandshakeProposal {
		session_id,
		initiator_id: *local_id,
		ephemeral_x25519_pub: *x25519_pk.as_bytes(),
		mlkem_public_key: mlkem_ek_bytes,
	};

	let state = InitiatorState {
		x25519_sk: x25519_sk.to_bytes(),
		mlkem_sk: mlkem_sk_bytes,
	};

	Ok((proposal, state))
}

/// Accept a handshake as the responder: encapsulate a shared secret to the
/// initiator's ML-KEM public key and generate an ephemeral X25519 keypair.
pub fn accept(
	rng: &mut TemperEntropy,
	proposal: &HandshakeProposal,
	local_id: &[u8; 32],
) -> Result<(HandshakeAcceptance, ResponderState)> {
	let mut x25519_sk_bytes = [0u8; 32];
	rng.fill_bytes(&mut x25519_sk_bytes);
	let x25519_sk = X25519SecretKey::from(x25519_sk_bytes);
	let x25519_pk = X25519PublicKey::from(&x25519_sk);

	if proposal.mlkem_public_key.len() != 1568 {
		return Err(Error::CryptoError(
			"accept: invalid mlkem_public_key length (expected 1568 bytes)".into(),
		));
	}
	let ek_encoded: &Encoded<EncapsulationKey<MlKem1024Params>> = proposal
		.mlkem_public_key
		.as_slice()
		.try_into()
		.map_err(|_| Error::CryptoError("accept: invalid mlkem_public_key encoding".into()))?;
	let mlkem_ek = EncapsulationKey::<MlKem1024Params>::from_bytes(ek_encoded);

	let (mlkem_ct, mlkem_ss_raw) = mlkem_ek
		.encapsulate(rng)
		.map_err(|_| Error::CryptoError("accept: ML-KEM encapsulation failed".into()))?;

	let mlkem_ss_slice: &[u8] = mlkem_ss_raw.as_ref();
	let mlkem_ss: [u8; 32] = mlkem_ss_slice
		.try_into()
		.map_err(|_| Error::CryptoError("accept: ML-KEM shared secret wrong size".into()))?;

	let ct_slice: &[u8] = mlkem_ct.as_ref();
	let acceptance = HandshakeAcceptance {
		session_id: proposal.session_id,
		responder_id: *local_id,
		ephemeral_x25519_pub: *x25519_pk.as_bytes(),
		mlkem_ciphertext: ct_slice.to_vec(),
	};

	let state = ResponderState {
		x25519_sk: x25519_sk.to_bytes(),
		mlkem_ss,
	};

	Ok((acceptance, state))
}

/// Derive the shared session key — initiator side. Decapsulates the
/// responder's ML-KEM ciphertext and performs X25519 DH against the
/// responder's ephemeral public key.
pub fn finalize_initiator(
	proposal: &HandshakeProposal,
	acceptance: &HandshakeAcceptance,
	state: &InitiatorState,
) -> Result<[u8; 32]> {
	let dk_encoded: &Encoded<DecapsulationKey<MlKem1024Params>> = state
		.mlkem_sk
		.as_slice()
		.try_into()
		.map_err(|_| Error::CryptoError("finalize_initiator: invalid mlkem_sk length".into()))?;
	let mlkem_dk = DecapsulationKey::<MlKem1024Params>::from_bytes(dk_encoded);

	let ct: &Ciphertext<MlKem1024> = acceptance.mlkem_ciphertext.as_slice().try_into().map_err(|_| {
		Error::CryptoError("finalize_initiator: invalid mlkem_ciphertext length (expected 1568 bytes)".into())
	})?;

	let mlkem_ss_raw = mlkem_dk
		.decapsulate(ct)
		.map_err(|_| Error::CryptoError("finalize_initiator: ML-KEM decapsulation failed".into()))?;
	let mlkem_ss_slice: &[u8] = mlkem_ss_raw.as_ref();
	let mlkem_ss: [u8; 32] = mlkem_ss_slice
		.try_into()
		.map_err(|_| Error::CryptoError("finalize_initiator: ML-KEM shared secret wrong size".into()))?;

	let x25519_sk = X25519SecretKey::from(state.x25519_sk);
	let x25519_pk = X25519PublicKey::from(acceptance.ephemeral_x25519_pub);
	let x25519_ss = x25519_sk.diffie_hellman(&x25519_pk);

	Ok(derive_session_key(
		&mlkem_ss,
		x25519_ss.as_bytes(),
		&proposal.initiator_id,
		&acceptance.responder_id,
	))
}

/// Derive the shared session key — responder side. The ML-KEM shared secret
/// was already computed during [`accept`]; only the X25519 DH step remains.
pub fn finalize_responder(
	proposal: &HandshakeProposal,
	acceptance: &HandshakeAcceptance,
	state: &ResponderState,
) -> [u8; 32] {
	let x25519_sk = X25519SecretKey::from(state.x25519_sk);
	let x25519_pk = X25519PublicKey::from(proposal.ephemeral_x25519_pub);
	let x25519_ss = x25519_sk.diffie_hellman(&x25519_pk);

	derive_session_key(
		&state.mlkem_ss,
		x25519_ss.as_bytes(),
		&proposal.initiator_id,
		&acceptance.responder_id,
	)
}

/// `input = mlkem_ss || x25519_ss || min(id_a, id_b) || max(id_a, id_b)`,
/// sorted so both parties derive the same key regardless of which side
/// calls this function first.
fn derive_session_key(
	mlkem_ss: &[u8; 32],
	x25519_ss: &[u8; 32],
	initiator_id: &[u8; 32],
	responder_id: &[u8; 32],
) -> [u8; 32] {
	let (id_a, id_b) = if initiator_id <= responder_id {
		(initiator_id, responder_id)
	} else {
		(responder_id, initiator_id)
	};

	let mut hasher = blake3::Hasher::new_derive_key(DOMAIN_HANDSHAKE);
	hasher.update(mlkem_ss);
	hasher.update(x25519_ss);
	hasher.update(id_a);
	hasher.update(id_b);
	*hasher.finalize().as_bytes()
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::boxed::Box;

	type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

	#[test]
	fn test_handshake_round_trip_same_key() -> Result<()> {
		// -- Setup & Fixtures
		let mut rng = make_rng()?;

		// -- Exec
		let (proposal, i_state) = initiate(&mut rng, &id(0xAA))?;
		let (acceptance, r_state) = accept(&mut rng, &proposal, &id(0xBB))?;
		let i_key = finalize_initiator(&proposal, &acceptance, &i_state)?;
		let r_key = finalize_responder(&proposal, &acceptance, &r_state);

		// -- Check
		assert_eq!(i_key, r_key);
		assert_ne!(i_key, [0u8; 32]);
		Ok(())
	}

	#[test]
	fn test_handshake_different_sessions_different_keys() -> Result<()> {
		// -- Setup & Fixtures
		let mut rng = make_rng()?;

		// -- Exec
		let (p1, i1) = initiate(&mut rng, &id(1))?;
		let (a1, _) = accept(&mut rng, &p1, &id(2))?;
		let k1 = finalize_initiator(&p1, &a1, &i1)?;

		let (p2, i2) = initiate(&mut rng, &id(1))?;
		let (a2, _) = accept(&mut rng, &p2, &id(2))?;
		let k2 = finalize_initiator(&p2, &a2, &i2)?;

		// -- Check
		assert_ne!(k1, k2);
		Ok(())
	}

	// region:    --- Support

	fn id(seed: u8) -> [u8; 32] {
		[seed; 32]
	}

	fn make_rng() -> Result<TemperEntropy> {
		Ok(TemperEntropy::new()?)
	}

	// endregion: --- Support
}

// endregion: --- Tests
