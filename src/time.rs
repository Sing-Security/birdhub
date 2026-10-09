// ============================================================================
// TIME MODULE: wall-clock seconds for cookies, replay, and certificates
// ============================================================================
//
// One reader, in one place, because the clock now decides more than cookie
// rotation: it is what a `PeerPolicy::Cert` validity window is checked
// against, on both ends. A node whose clock is off by more than the window
// tolerance fails closed — the handshake refuses with "certificate expired"
// or "not valid until" — and that error should have exactly one place to
// look at.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the epoch, or 0 if the clock is before it.
///
/// A clock reading, not a monotonic counter: certificates are issued against
/// Unix time on one machine and checked against it on another, so a
/// monotonic instant would not compare. An unset clock reads as 0, which
/// makes every not-yet-valid check fail and is the safe direction to be
/// wrong in.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
