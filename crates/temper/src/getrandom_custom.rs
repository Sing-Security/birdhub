//! `getrandom` wiring for no_std builds.
//!
//! Exactly one of the two implementations below is compiled (their cfgs are
//! complementary), and `register_custom_getrandom!` wires whichever one that
//! is into `getrandom`.

/// Custom getrandom for CrucibleOS *userspace* builds (no_std CBLs).
///
/// Fills the buffer from the kernel CSPRNG via the `GetRandom` (80) syscall —
/// the same source `std`'s PAL uses. Without this, no_std CBLs fell through
/// to the zero-fill stub below, which made `TemperEntropy::new()` (the
/// alloc-only constructor) seed its DRBG deterministically — every temper-cbl
/// service keypair was derived from an all-zero seed.
///
/// Gated behind an explicit feature (NOT `target_os = "crucible"`) because the
/// kernel itself also links this crate with the same `target_os` — executing a
/// ring-3 `syscall`/`svc` instruction in ring 0 / EL1 must be impossible by
/// construction, so only userspace crates may enable `crucible-user-getrandom`.
#[cfg(all(not(feature = "std"), feature = "crucible-user-getrandom"))]
// `unsafe_code = "deny"` (Cargo.toml): the GetRandom syscall cannot be issued
// from safe Rust, and this is the crate's only irreducible `unsafe` once
// `DelegationToken::signed_bytes` moves to `zerocopy`.
#[allow(unsafe_code)]
fn custom_getrandom(buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
	const SYSCALL_GET_RANDOM: u64 = 80;
	let err = || {
		// SAFETY: CUSTOM_START is a nonzero constant per getrandom's contract.
		getrandom::Error::from(unsafe { core::num::NonZeroU32::new_unchecked(getrandom::Error::CUSTOM_START + 1) })
	};
	let mut remaining: &mut [u8] = buf;
	while !remaining.is_empty() {
		let ret: i64;
		#[cfg(target_arch = "x86_64")]
		// SAFETY: GetRandom validates the pointer/length and writes at most
		// `len` bytes; clobbers match the kernel's syscall ABI.
		unsafe {
			core::arch::asm!(
				"syscall",
				in("rax") SYSCALL_GET_RANDOM,
				in("rdi") remaining.as_mut_ptr() as u64,
				in("rsi") remaining.len() as u64,
				in("rdx") 0u64,
				lateout("rax") ret,
				lateout("rcx") _,
				lateout("r11") _,
				options(nostack),
			);
		}
		#[cfg(target_arch = "aarch64")]
		// SAFETY: same contract as x86_64 above, via SVC.
		unsafe {
			let out: u64;
			core::arch::asm!(
				"svc #0",
				in("x8") SYSCALL_GET_RANDOM,
				inout("x0") remaining.as_mut_ptr() as u64 => out,
				in("x1") remaining.len() as u64,
				in("x2") 0u64,
				options(nostack),
			);
			ret = out as i64;
		}
		#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
		{
			ret = -1;
		}
		if ret <= 0 {
			// Honest failure — never fabricate entropy here.
			return Err(err());
		}
		let n = (ret as usize).min(remaining.len());
		remaining = &mut remaining[n..];
	}
	Ok(())
}

/// Custom getrandom for bare-metal no_std targets (e.g. the kernel itself).
///
/// **WARNING**: This returns zeros! It should only be used when:
/// 1. The target has no OS to provide entropy
/// 2. The caller provides custom entropy sources via `TemperEntropy::from_sources()`
///
/// Userspace CBLs must enable the `crucible-user-getrandom` feature instead
/// (see above) so they get real kernel entropy.
#[cfg(all(not(feature = "std"), not(feature = "crucible-user-getrandom")))]
fn custom_getrandom(buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
	// Zero-fill the buffer
	// This is safe because:
	// 1. On bare metal (no OS), there's no system entropy source anyway
	// 2. Users of bare metal must provide custom entropy via from_sources()
	// 3. The entropy pool mixes this with actual entropy from hardware sources
	for byte in buf.iter_mut() {
		*byte = 0;
	}
	Ok(())
}

#[cfg(not(feature = "std"))]
getrandom::register_custom_getrandom!(custom_getrandom);
