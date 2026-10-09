// region:    --- CapKeychain

//! Cryptographic capability key hierarchy for CrucibleOS.
//!
//! # Overview
//!
//! Every process seeds a [`CapKeychain`] from its one-time process root key
//! (obtained via `libcrucible_syscall::process_get_root_key`).  All derived
//! keys use BLAKE3 KDF with named domains so derivations are one-way and
//! domain-separated.
//!
//! ## Domain strings
//!
//! | Domain | Purpose |
//! |--------|---------|
//! | `"CrucibleOS.CapKey.v1"` | Per-capability subkey |
//! | `"CrucibleOS.OpToken.v1"` | Per-opcode operation token |
//! | `"CrucibleOS.DelegationKey.v1"` | Delegation proof MAC key |

use zerocopy::{Immutable, IntoBytes};

/// A process's cryptographic key hierarchy.
///
/// Seed once at process startup with `from_root(process_get_root_key())`.
/// All derived keys are deterministic and zero-copy.
pub struct CapKeychain {
	root_key: [u8; 32],
}

impl CapKeychain {
	/// Construct a keychain from a process root key.
	#[inline]
	pub fn from_root(root_key: [u8; 32]) -> Self {
		Self { root_key }
	}

	/// Derive a capability-scoped subkey for `(cap_id, permissions)`.
	///
	/// Domain: `"CrucibleOS.CapKey.v1"`
	/// Material: `root_key || cap_id (4 bytes LE) || permissions (4 bytes LE)`
	pub fn cap_key(&self, cap_id: u32, permissions: u32) -> [u8; 32] {
		let mut m = [0u8; 40];
		m[..32].copy_from_slice(&self.root_key);
		m[32..36].copy_from_slice(&cap_id.to_le_bytes());
		m[36..40].copy_from_slice(&permissions.to_le_bytes());
		blake3::derive_key("CrucibleOS.CapKey.v1", &m)
	}

	/// Derive an operation token for a specific `(service_id, opcode)` pair.
	///
	/// The token proves the holder is permitted to invoke `opcode` on
	/// `service_id` using the given capability.
	///
	/// Domain: `"CrucibleOS.OpToken.v1"`
	/// Material: `cap_key || service_id (2 bytes LE) || opcode (4 bytes LE)`
	pub fn op_token(&self, cap_id: u32, permissions: u32, service_id: u16, opcode: u32) -> [u8; 32] {
		let cap_k = self.cap_key(cap_id, permissions);
		let mut m = [0u8; 38];
		m[..32].copy_from_slice(&cap_k);
		m[32..34].copy_from_slice(&service_id.to_le_bytes());
		m[34..38].copy_from_slice(&opcode.to_le_bytes());
		blake3::derive_key("CrucibleOS.OpToken.v1", &m)
	}

	/// Derive a delegation MAC key for granting a scoped sub-capability.
	///
	/// Domain: `"CrucibleOS.DelegationKey.v1"`
	/// Material: `cap_key || grantee_pid (4 bytes LE) || delegated_perms (4 bytes LE)`
	pub fn delegation_key(&self, cap_id: u32, permissions: u32, grantee_pid: u32, delegated_perms: u32) -> [u8; 32] {
		let cap_k = self.cap_key(cap_id, permissions);
		let mut m = [0u8; 40];
		m[..32].copy_from_slice(&cap_k);
		m[32..36].copy_from_slice(&grantee_pid.to_le_bytes());
		m[36..40].copy_from_slice(&delegated_perms.to_le_bytes());
		blake3::derive_key("CrucibleOS.DelegationKey.v1", &m)
	}
}

// endregion: --- CapKeychain

// region:    --- DelegationToken

/// 64-byte delegation proof signed by the delegator.
///
/// Verified by the kernel in `handle_cap_delegate` before a sub-capability
/// is minted.  The MAC covers all fields except `mac` itself, keyed with
/// the BLAKE3-derived `delegation_key`.
///
/// Wire layout (`repr(C)`, 64 bytes total):
/// ```text
/// [ 0.. 4)  delegator_pid:   u32
/// [ 4.. 8)  grantee_pid:     u32
/// [ 8..12)  source_cap:      u32
/// [12..16)  delegated_perms: u32
/// [16..18)  service_scope:   u16
/// [18..24)  _pad:            [u8; 6]
/// [24..32)  nonce:           u64
/// [32..64)  mac:             [u8; 32]
/// ```
#[repr(C)]
// `IntoBytes` requires a padding-free type; the explicit `_pad` field makes
// the layout in the doc comment above padding-free by construction, and the
// derive fails to compile if a future field change ever introduces padding.
#[derive(Immutable, IntoBytes)]
pub struct DelegationToken {
	pub delegator_pid: u32,
	pub grantee_pid: u32,
	pub source_cap: u32,
	pub delegated_perms: u32,
	pub service_scope: u16,
	pub _pad: [u8; 6],
	pub nonce: u64,
	pub mac: [u8; 32],
}

impl DelegationToken {
	/// Byte length of the MAC preimage: every field before `mac`.
	///
	/// `offset_of!` states exactly that — unlike `size_of - 32`, it stays
	/// correct-by-construction if a field is ever added before `mac` (the
	/// frozen-layout asserts pin it to 32 anyway).
	const SIGNED_LEN: usize = core::mem::offset_of!(DelegationToken, mac);

	/// Build and sign a delegation token.
	///
	/// `keychain` must belong to the delegating process; `source_perms` is the
	/// permission set the delegator holds on `source_cap`.
	// One argument per MAC-covered token field, in layout order. Bundling them
	// into a struct would just move the same list one level down.
	#[allow(clippy::too_many_arguments)]
	pub fn sign(
		keychain: &CapKeychain,
		source_cap: u32,
		source_perms: u32,
		grantee_pid: u32,
		delegated_perms: u32,
		service_scope: u16,
		nonce: u64,
		delegator_pid: u32,
	) -> Self {
		let dk = keychain.delegation_key(source_cap, source_perms, grantee_pid, delegated_perms);
		let mut token = DelegationToken {
			delegator_pid,
			grantee_pid,
			source_cap,
			delegated_perms,
			service_scope,
			_pad: [0u8; 6],
			nonce,
			mac: [0u8; 32],
		};
		token.mac = *blake3::keyed_hash(&dk, token.signed_bytes()).as_bytes();
		token
	}

	/// Verify the token's MAC using `keychain` (the delegator's keychain, or
	/// one re-derived by the kernel from the master key + delegator PID).
	///
	/// `source_perms` must be the delegator's permission set for `source_cap`.
	pub fn verify(&self, keychain: &CapKeychain, source_perms: u32) -> bool {
		let dk = keychain.delegation_key(self.source_cap, source_perms, self.grantee_pid, self.delegated_perms);
		let expected = blake3::keyed_hash(&dk, self.signed_bytes());
		expected.as_bytes() == &self.mac
	}

	/// Return the byte slice that is covered by the MAC (all fields except `mac`).
	///
	/// `IntoBytes` is derived on the `repr(C)` struct, so zerocopy has already
	/// proven the struct is padding-free: every byte of the object
	/// representation, explicit `_pad` included, is initialized and therefore
	/// safe to expose as the wire format.
	fn signed_bytes(&self) -> &[u8] {
		&self.as_bytes()[..Self::SIGNED_LEN]
	}
}

// endregion: --- DelegationToken

// region:    --- Tests

#[cfg(test)]
mod tests {
	use static_assertions::{assert_eq_align, assert_eq_size, const_assert_eq};

	use super::*;

	/// The kernel copies exactly `size_of::<DelegationToken>()` bytes from
	/// userspace and transmutes them into this type (syscall/handlers.rs), so
	/// every value below is ABI, not implementation detail.
	#[test]
	fn test_keychain_delegation_token_layout_frozen() {
		// -- Setup & Fixtures
		assert_eq_size!(DelegationToken, [u8; 64]);
		assert_eq_align!(DelegationToken, u64);

		const_assert_eq!(DelegationToken::SIGNED_LEN, 32);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, delegator_pid), 0);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, grantee_pid), 4);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, source_cap), 8);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, delegated_perms), 12);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, service_scope), 16);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, _pad), 18);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, nonce), 24);
		const_assert_eq!(core::mem::offset_of!(DelegationToken, mac), 32);

		// -- Exec
		let (_, token) = fixture_token();

		// -- Check
		assert_eq!(token.delegator_pid, 0xdead_beef);
		assert_eq!(token.grantee_pid, 0x5566_7788);
		assert_eq!(token.source_cap, 0x1122_3344);
		assert_eq!(token.delegated_perms, 0x0000_0003);
		assert_eq!(token.service_scope, 0xabcd);
		assert_eq!(token.nonce, 0x0123_4567_89ab_cdef);
	}

	/// Direct byte comparison against the layout spelled out in the struct
	/// doc — not a sign/verify round-trip, which would pass under any
	/// self-consistent byte order.
	#[test]
	fn test_keychain_delegation_token_signed_bytes_matches_layout() {
		// -- Setup & Fixtures
		let (_, token) = fixture_token();

		let mut expected = [0u8; 32];
		expected[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes()); // delegator_pid
		expected[4..8].copy_from_slice(&0x5566_7788u32.to_le_bytes()); // grantee_pid
		expected[8..12].copy_from_slice(&0x1122_3344u32.to_le_bytes()); // source_cap
		expected[12..16].copy_from_slice(&0x0000_0003u32.to_le_bytes()); // delegated_perms
		expected[16..18].copy_from_slice(&0xabcdu16.to_le_bytes()); // service_scope
		// [18..24) is `_pad`, zero by construction
		expected[24..32].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes()); // nonce

		// -- Exec
		let bytes = token.signed_bytes();

		// -- Check
		assert_eq!(bytes, expected, "MAC preimage must match the documented wire layout");
	}

	/// Golden vector captured from the pre-zerocopy implementation: the MAC
	/// preimage is byte-identical across the rewrite.
	#[test]
	fn test_keychain_delegation_token_signed_bytes_golden() {
		// -- Setup & Fixtures
		let (_, token) = fixture_token();

		// -- Exec
		let hex = hex::encode(token.signed_bytes());

		// -- Check
		assert_eq!(hex, GOLDEN_SIGNED_HEX);
	}

	/// The MAC is the BLAKE3 keyed hash of the preimage; pinning it also pins
	/// the derived delegation key, so a byte-order or domain drift fails here.
	#[test]
	fn test_keychain_delegation_token_mac_golden() {
		// -- Setup & Fixtures
		let (_, token) = fixture_token();

		// -- Exec
		let hex = hex::encode(token.mac);

		// -- Check
		assert_eq!(hex, GOLDEN_MAC_HEX);
	}

	#[test]
	fn test_keychain_delegation_token_verify_accepts_matching() {
		// -- Setup & Fixtures
		let (keychain, token) = fixture_token();

		// -- Exec
		let valid = token.verify(&keychain, 0x0000_000f);

		// -- Check
		assert!(valid, "token must verify under its own keychain");
	}

	#[test]
	fn test_keychain_delegation_token_verify_rejects_tampered_field() {
		// -- Setup & Fixtures
		let (keychain, mut token) = fixture_token();

		// -- Exec
		token.source_cap ^= 0x0000_0001;
		let valid = token.verify(&keychain, 0x0000_000f);

		// -- Check
		assert!(!valid, "a single flipped bit outside `mac` must fail verification");
	}

	// region:    --- Support

	/// Captured from the hand-written `signed_bytes` before the zerocopy
	/// rewrite (2026-10-08); values are LE bytes of the fixed fixture below.
	const GOLDEN_SIGNED_HEX: &str = "efbeadde887766554433221103000000cdab000000000000efcdab8967452301";
	const GOLDEN_MAC_HEX: &str = "06aa8839346570377b956eaa36292333dfba55e01c49cc4df9010ba8ffb60d13";

	fn fixture_token() -> (CapKeychain, DelegationToken) {
		let keychain = CapKeychain::from_root([0x42; 32]);
		let token = DelegationToken::sign(
			&keychain,
			0x1122_3344,           // source_cap
			0x0000_000f,           // source_perms
			0x5566_7788,           // grantee_pid
			0x0000_0003,           // delegated_perms
			0xabcd,                // service_scope
			0x0123_4567_89ab_cdef, // nonce
			0xdead_beef,           // delegator_pid
		);
		(keychain, token)
	}

	// endregion: --- Support
}

// endregion: --- Tests
