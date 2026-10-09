//! A stateless anti-DoS cookie for the session handshake.
//!
//! Flight 2 is the most expensive message in the protocol — two SLH-DSA
//! signatures, roughly 17 KiB of signature per signing — and a responder
//! produces it before the initiator has proved anything. A
//! [`SessionReplayGuard`](crate::replay::SessionReplayGuard) refuses a *known*
//! session id cheaply, but an attacker sending fresh ids still buys a flight 2
//! per packet. The cookie closes that: the responder hands out a value it can
//! re-derive at will, and refuses any flight 1 that does not carry it back,
//! without keeping per-client state.
//!
//! # Construction
//!
//! ```text
//! cookie = BLAKE3.keyed_hash(server_secret, peer_tag || time_bucket)
//! time_bucket = now_secs / ttl_secs
//! ```
//!
//! The responder needs only `server_secret` to verify — no table, no memory
//! proportional to the number of clients. `peer_tag` binds the cookie to the
//! peer (typically its address bytes) so a value issued to one client cannot
//! be replayed by another; `time_bucket` rotates it so a captured cookie stops
//! working.
//!
//! [`verify`](SessionCookie::verify) accepts the **current and previous**
//! bucket: a client that receives a cookie a moment before a rollover must not
//! be rejected for arriving a moment after one, and the cost of the extra
//! acceptance is that a cookie lives up to `2 * ttl_secs`.
//!
//! # Why it lives here, not in `session`
//!
//! [`crate::session`] is a pure state machine with no I/O and no notion of
//! addresses — which is exactly what lets it run on any carrier. A cookie
//! needs the peer's identity *as the carrier sees it* and a clock, neither of
//! which belongs in that module. This is the same reason
//! [`crate::replay`](crate::replay) is separate: the caller owns the address
//! and the time.
//!
//! # What it is not
//!
//! A cookie is only as strong as the `peer_tag`'s integrity. On a carrier that
//! cannot supply a trustworthy tag — a pipe has no address, and a header a
//! peer can spoof is no better — the check is worthless, because the attacker
//! simply presents its own tag. Do not enable cookies on such a carrier; fail
//! closed rather than pretending.
//!
//! The cookie stops blind fresh floods. It does **not** stop a captured flight
//! 1 being replayed within its bucket, which is why
//! [`SessionReplayGuard`](crate::replay::SessionReplayGuard) stays: different
//! attacks, both needed.

use crate::session::ct_eq;

// region:    --- SessionCookie

/// Stateless cookie issuer and verifier. See the module documentation.
pub struct SessionCookie {
	server_secret: [u8; 32],
	ttl_secs: u64,
}

impl core::fmt::Debug for SessionCookie {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		// The secret is what makes a cookie unforgeable; never print it.
		f.debug_struct("SessionCookie")
			.field("server_secret", &"<REDACTED>")
			.field("ttl_secs", &self.ttl_secs)
			.finish()
	}
}

impl SessionCookie {
	/// Create a cookie state under `server_secret` whose buckets are
	/// `ttl_secs` long.
	///
	/// `server_secret` must be a stable, secret, per-responder value; rotating
	/// it invalidates every outstanding cookie. `ttl_secs` is clamped to at
	/// least one second, because a zero period cannot define a bucket and
	/// would divide by zero — a cookie with no rotation is not a cookie.
	pub fn new(server_secret: [u8; 32], ttl_secs: u64) -> Self {
		Self {
			server_secret,
			ttl_secs: ttl_secs.max(1),
		}
	}

	/// Issue a cookie for `peer_tag` at `now_secs` (flight 0).
	pub fn issue(&self, peer_tag: &[u8; 32], now_secs: u64) -> [u8; 32] {
		self.cookie_for(peer_tag, self.bucket(now_secs))
	}

	/// Whether `cookie` is a valid, unexpired value for `peer_tag`.
	///
	/// Accepts the current and previous bucket so a client that obtained a
	/// cookie just before a rollover is not rejected just after one.
	pub fn verify(&self, cookie: &[u8; 32], peer_tag: &[u8; 32], now_secs: u64) -> bool {
		let bucket = self.bucket(now_secs);
		if ct_eq(cookie, &self.cookie_for(peer_tag, bucket)) {
			return true;
		}
		bucket > 0 && ct_eq(cookie, &self.cookie_for(peer_tag, bucket - 1))
	}

	/// The bucket `now_secs` falls in.
	fn bucket(&self, now_secs: u64) -> u64 {
		now_secs / self.ttl_secs
	}

	/// `keyed_hash(server_secret, peer_tag || bucket_le)`.
	fn cookie_for(&self, peer_tag: &[u8; 32], bucket: u64) -> [u8; 32] {
		let mut hasher = blake3::Hasher::new_keyed(&self.server_secret);
		hasher.update(peer_tag);
		hasher.update(&bucket.to_le_bytes());
		*hasher.finalize().as_bytes()
	}
}

// endregion: --- SessionCookie

// region:    --- Tests

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::boxed::Box;

	type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

	fn cookie() -> SessionCookie {
		SessionCookie::new([0x5A; 32], 60)
	}

	#[test]
	fn test_cookie_round_trips_within_its_bucket() -> Result<()> {
		// -- Setup & Fixtures
		let state = cookie();
		let tag = [0x11; 32];

		// -- Exec
		let value = state.issue(&tag, 1000);

		// -- Check
		assert!(state.verify(&value, &tag, 1000));
		assert!(state.verify(&value, &tag, 1059), "still the same bucket");
		Ok(())
	}

	#[test]
	fn test_cookie_survives_a_single_rollover() -> Result<()> {
		// -- Setup & Fixtures: issued in bucket 16 (t=1000, ttl=60).
		let state = cookie();
		let tag = [0x22; 32];
		let value = state.issue(&tag, 1000);

		// -- Exec & Check: the next bucket still accepts it (a client that got
		// it just before the rollover), the one after does not.
		assert!(state.verify(&value, &tag, 1060), "previous bucket must be accepted");
		assert!(!state.verify(&value, &tag, 1120), "two buckets later must not");
		Ok(())
	}

	#[test]
	fn test_cookie_is_bound_to_the_peer_tag() -> Result<()> {
		// -- Setup & Fixtures
		let state = cookie();
		let value = state.issue(&[0x01; 32], 500);

		// -- Check: a value issued to one tag does not verify for another —
		// which is what stops one client redeeming another's cookie.
		assert!(!state.verify(&value, &[0x02; 32], 500));
		Ok(())
	}

	#[test]
	fn test_cookie_is_bound_to_the_server_secret() -> Result<()> {
		// -- Setup & Fixtures
		let value = cookie().issue(&[0x33; 32], 500);
		let other = SessionCookie::new([0x99; 32], 60);

		// -- Check
		assert!(!other.verify(&value, &[0x33; 32], 500));
		Ok(())
	}

	#[test]
	fn test_cookie_rejects_a_zero_value_never_issued() -> Result<()> {
		// The value a client sends when no responder asked for a cookie must
		// not accidentally verify.
		let state = cookie();
		assert!(!state.verify(&[0u8; 32], &[0x44; 32], 500));
		Ok(())
	}

	#[test]
	fn test_cookie_zero_ttl_does_not_panic() -> Result<()> {
		// -- Setup & Fixtures: a degenerate TTL is clamped, not divided by.
		let state = SessionCookie::new([0x77; 32], 0);
		let value = state.issue(&[0x55; 32], 7);

		// -- Check: it behaves as a one-second bucket.
		assert!(state.verify(&value, &[0x55; 32], 7));
		assert!(!state.verify(&value, &[0x55; 32], 9));
		Ok(())
	}
}

// endregion: --- Tests
