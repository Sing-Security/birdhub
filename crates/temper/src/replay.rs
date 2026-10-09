//! A bounded, time-limited record of the session ids a responder has already
//! accepted, so a replayed flight 1 is refused before it is answered.
//!
//! # What the handshake does and does not already stop
//!
//! A replayed *transcript* does not establish a session, and it is worth
//! being precise about why, because it bounds what this module is for. Every
//! flight is bound into a transcript hash that includes both sides' fresh
//! ephemeral keys: the responder signs `H2`, which contains the initiator's
//! ML-KEM encapsulation key *and* the responder's own new ephemeral, and the
//! secret is agreed against those. Replaying a recorded `init` makes the
//! responder derive a *different* secret, so a recorded `confirm` — whose
//! MAC was taken over the old transcript — cannot complete it, and the
//! responder's own recorded `accept` cannot be replayed at a client whose
//! `H1` differs. Neither side has to do anything for that to hold.
//!
//! What is *not* stopped is the responder accepting the same `session_id`
//! twice, and that has two real consequences:
//!
//! - **A caller that indexes session state by id loses the live entry.**
//!   This is the ordinary shape — a server keeps `session_id -> keys` — and
//!   a replayed flight 1 arrives with a genuine, correctly-signed identity
//!   and the same id, so the table is simply overwritten. The victim's next
//!   record then fails to open. The attacker cannot read anything, but it
//!   can destroy a session it cannot break, silently, for the cost of
//!   replaying one captured packet. The guard turns that into a refusal.
//! - **Every accepted flight 1 costs the responder two SLH-DSA signatures.**
//!   Flight 2 is the most expensive message in the protocol — roughly 17 KiB
//!   of signature per SLH-DSA-SHA2-128f signing, twice — and it is produced
//!   before the initiator has proved anything. Refusing a *known* id costs a
//!   set lookup. This is a mitigation, not a defence: an attacker sending
//!   fresh ids still gets a flight 2 for each one, and the answer to that is
//!   a stateless cookie or a proof of work in flight 1, which is a wire
//!   change and is not in this version. See `PROTOCOL.md`'s threat model.
//!
//! It cannot live inside [`session::accept`](crate::session::accept): that
//! function is a pure state machine with no memory between calls, which is
//! what lets it run on any carrier. So it lives here, in a shape a responder
//! holds for as long as its replay window.
//!
//! Only the responder needs one. The initiator picks the id, and re-running
//! its own handshake is not an attack.
//!
//! # Choosing the two parameters
//!
//! `ttl_secs` is how long a captured flight stays worth replaying. It does
//! not need to be long: the interesting window is one in which the responder
//! still holds the original session's state, which is bounded by the
//! session's own lifetime. A minute is generous for a connection-oriented
//! protocol; hours are not wrong for a long-lived one.
//!
//! `capacity` is the memory bound. The guard never grows past it, so the
//! only question is whether it can hold every session a responder admits
//! within `ttl_secs`. If it cannot, the oldest entry is dropped to make
//! room, and the guarantee weakens for exactly that entry. Size it to the
//! peak arrival rate times the TTL.
//!
//! # Example
//!
//! ```ignore
//! let mut guard = SessionReplayGuard::new(60, 4096)?;
//!
//! // Per inbound flight 1, before running the handshake:
//! guard.admit(init.proposal.session_id, unix_now)?;
//! ```

use alloc::collections::{BTreeSet, VecDeque};

use crate::error::{Error, Result};

// region:    --- Constants

/// How many session ids a guard remembers by default.
///
/// 4096 ids is 32 KiB of key material in the two collections, which is
/// cheap enough to be the default, and enough to cover a busy responder for
/// the default TTL.
pub const DEFAULT_REPLAY_CAPACITY: usize = 4096;

// endregion: --- Constants

// region:    --- SessionReplayGuard

/// Remembers session ids for a window, so a replayed handshake is refused.
///
/// See the module documentation for what this defends and how to size it.
pub struct SessionReplayGuard {
	seen: BTreeSet<u64>,
	/// `(expires_at, session_id)`, oldest expiry first. Insertion order is
	/// expiry order because `now` only moves forward, so the front is always
	/// the next to expire and pruning is a pop.
	order: VecDeque<(u64, u64)>,
	ttl_secs: u64,
	capacity: usize,
}

impl SessionReplayGuard {
	/// Create a guard that remembers each admitted id for `ttl_secs` and
	/// never holds more than `capacity` of them.
	///
	/// Both arguments are rejected at zero: a zero TTL forgets an id before
	/// it could be replayed (the guard would do nothing), and a zero
	/// capacity cannot admit even the first session. A guard that silently
	/// does nothing is worse than no guard, because the caller believes it
	/// is defended.
	pub fn new(ttl_secs: u64, capacity: usize) -> Result<Self> {
		if ttl_secs == 0 {
			return Err(Error::Protocol("replay guard TTL must be greater than zero".into()));
		}
		if capacity == 0 {
			return Err(Error::Protocol(
				"replay guard capacity must be greater than zero".into(),
			));
		}
		Ok(Self {
			seen: BTreeSet::new(),
			order: VecDeque::new(),
			ttl_secs,
			capacity,
		})
	}

	/// Admit a session id, or refuse it as a replay.
	///
	/// Returns `Err(Error::Protocol)` if this id is already being
	/// remembered. Call this *before* running the handshake, never after:
	/// the point is to not do the work, and to not derive the keys, for a
	/// session that is already open.
	pub fn admit(&mut self, session_id: u64, now_secs: u64) -> Result<()> {
		self.prune(now_secs);

		if self.seen.contains(&session_id) {
			return Err(Error::Protocol(alloc::format!(
				"replayed session id {:016x}: already admitted within the last {}s",
				session_id,
				self.ttl_secs
			)));
		}

		// At capacity with nothing expired: drop the entry closest to
		// expiring. Refusing the new session instead would let an attacker
		// who can fill the table deny service to legitimate clients, which
		// is the failure mode a bounded table exists to avoid.
		if self.seen.len() >= self.capacity
			&& let Some((_, evicted)) = self.order.pop_front()
		{
			self.seen.remove(&evicted);
		}

		self.seen.insert(session_id);
		self.order.push_back((now_secs.saturating_add(self.ttl_secs), session_id));
		Ok(())
	}

	/// Whether this id would be refused right now, without admitting it.
	///
	/// Does not prune — a read that mutates is a surprise, and the answer
	/// for an expired entry is the same either way (it is not a replay).
	pub fn is_replay(&self, session_id: u64) -> bool {
		self.seen.contains(&session_id)
	}

	/// How many ids are currently remembered, including ones that have
	/// expired but not yet been pruned.
	pub fn len(&self) -> usize {
		self.seen.len()
	}

	/// Whether the guard is remembering nothing.
	pub fn is_empty(&self) -> bool {
		self.seen.is_empty()
	}

	/// Drop every entry whose window has closed at `now_secs`.
	fn prune(&mut self, now_secs: u64) {
		while let Some((expires_at, session_id)) = self.order.front().copied() {
			if expires_at > now_secs {
				break;
			}
			self.order.pop_front();
			self.seen.remove(&session_id);
		}
	}
}

// endregion: --- SessionReplayGuard

// region:    --- Tests

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::boxed::Box;

	type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

	#[test]
	fn test_replay_guard_admits_a_new_session_and_remembers_it() -> Result<()> {
		// -- Setup & Fixtures
		let mut guard = SessionReplayGuard::new(60, 16)?;

		// -- Exec
		guard.admit(0xABCD, 1000)?;

		// -- Check
		assert!(guard.is_replay(0xABCD));
		assert!(!guard.is_replay(0xABCE), "an id never admitted is not a replay");
		assert_eq!(guard.len(), 1);
		Ok(())
	}

	#[test]
	fn test_replay_guard_refuses_the_same_id_twice() -> Result<()> {
		// -- Setup & Fixtures
		let mut guard = SessionReplayGuard::new(60, 16)?;
		guard.admit(0x1234, 1000)?;

		// -- Exec: the same flight, replayed one second later.
		let outcome = guard.admit(0x1234, 1001);

		// -- Check
		match outcome {
			Err(Error::Protocol(msg)) => assert!(msg.contains("replayed session id"), "got: {msg}"),
			other => panic!("expected a Protocol replay refusal, got {other:?}"),
		}
		assert_eq!(guard.len(), 1, "a refusal must not add a second entry");
		Ok(())
	}

	#[test]
	fn test_replay_guard_forgets_an_id_once_its_window_closes() -> Result<()> {
		// -- Setup & Fixtures: admitted at t=1000, remembered for 60s.
		let mut guard = SessionReplayGuard::new(60, 16)?;
		guard.admit(0x55, 1000)?;

		// -- Exec & Check: the last second it is still remembered is 1059...
		assert!(guard.admit(0x55, 1059).is_err());

		// ...and the first second it is not is 1060. Pinned because the
		// boundary is what a caller sizing the TTL actually cares about, and
		// an off-by-one here is invisible until a replay lands exactly on it.
		guard.admit(0x55, 1060)?;
		assert_eq!(guard.len(), 1, "the expired entry was pruned, not duplicated");
		Ok(())
	}

	#[test]
	fn test_replay_guard_prunes_without_admitting() -> Result<()> {
		// -- Setup & Fixtures: five ids admitted at t=0.
		let mut guard = SessionReplayGuard::new(10, 16)?;
		for id in 0..5 {
			guard.admit(id, 0)?;
		}
		assert_eq!(guard.len(), 5);

		// -- Exec: a later admit past every window clears them first.
		guard.admit(0xFFFF, 11)?;

		// -- Check: only the new id remains.
		assert_eq!(guard.len(), 1);
		assert!(!guard.is_replay(0), "the pruned ids are no longer replays");
		Ok(())
	}

	#[test]
	fn test_replay_guard_stays_within_capacity_under_fresh_ids() -> Result<()> {
		// -- Setup & Fixtures: nothing expires; the capacity is the only bound.
		let mut guard = SessionReplayGuard::new(60, 8)?;

		// -- Exec: far more distinct ids than the guard can hold.
		for id in 0..1000u64 {
			guard.admit(id, 0)?;
		}

		// -- Check: bounded, and the recent ids are the ones kept.
		assert_eq!(guard.len(), 8);
		assert!(guard.is_replay(999), "the newest admission is remembered");
		assert!(!guard.is_replay(0), "the oldest was evicted to make room");
		Ok(())
	}

	#[test]
	fn test_replay_guard_eviction_does_not_leave_a_stale_membership() -> Result<()> {
		// The set and the ordering deque are two structures kept in step by
		// hand. If eviction removed from one and not the other, the guard
		// would refuse ids it no longer remembers — a self-inflicted denial
		// of service that only shows up after exactly `capacity` admissions.
		let mut guard = SessionReplayGuard::new(60, 2)?;
		guard.admit(1, 0)?;
		guard.admit(2, 0)?;
		guard.admit(3, 0)?;

		// -- Exec & Check: the evicted id is admissible again.
		guard.admit(1, 0)?;
		assert_eq!(guard.len(), 2);
		Ok(())
	}

	#[test]
	fn test_replay_guard_rejects_degenerate_parameters() {
		// -- Exec & Check: both zeroes are errors, not silently useless guards.
		assert!(SessionReplayGuard::new(0, 16).is_err(), "a zero TTL checks nothing");
		assert!(
			SessionReplayGuard::new(60, 0).is_err(),
			"a zero capacity admits nothing"
		);
	}
}

// endregion: --- Tests
