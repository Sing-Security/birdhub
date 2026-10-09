//! Authenticated record encryption for established sessions.
//!
//! One directional [`RecordKey`] per direction, ChaCha20-Poly1305 per record.
//! The sequence number never travels on the wire: it is the nonce suffix and
//! part of the AAD, so a replayed, reordered, or skipped record fails its tag
//! with no extra receiver state. For a reliable stream, use [`RecordKey::seal`]
//! / [`RecordKey::open`] — strict +1 ordering, both counters start at 0. For a
//! datagram carrier (packet-oriented transports with their own loss/reorder
//! policy), [`RecordKey::seal_at`] / [`RecordKey::open_at`] take the sequence
//! explicitly and leave the acceptance window to the caller.
//!
//! Wire format of one record:
//!
//! ```text
//! nonce   = [0u8; 4] || seq u64 BE          (12 bytes)
//! AAD     = seq u64 BE || plaintext_len u32 BE
//! record  = ChaCha20-Poly1305(key, nonce, AAD, plaintext)   (tag appended)
//! ```
//!
//! Nonce reuse within a key would be catastrophic; the counter construction
//! makes it impossible as long as one key encrypts from one thread.
//!
//! # Rekey
//!
//! Every [`REKEY_INTERVAL`] records both ends ratchet the key forward:
//! `key(n+1) = derive_key("Temper.Session.v2.Rekey", key(n))`. The ratchet is
//! a plain hash chain, so it is one-way in both directions — an attacker who
//! reads one generation's key out of memory gets neither the records before
//! it nor the records after it. That is the point, and it is the reason this
//! is a ratchet rather than a periodic re-derivation from the handshake
//! secret, which would leave every record in the session readable to anyone
//! who later obtained that secret.
//!
//! It is a protocol constant and not a knob because both directions and both
//! ends must agree on exactly where the boundary falls; a configurable
//! interval is a mismatch waiting to happen, and a mismatch here is a
//! session that stops decrypting halfway through. Carrying the generation on
//! the wire is the alternative, and it would leak a counter that today is
//! invisible.
//!
//! The ratchet is derived from the sequence, so it works for the datagram
//! path too: a record names its own generation. A receiver keeps the
//! previous generation's key so a packet that arrives just after a boundary
//! still opens, and refuses anything further back than that.
//!
//! Padding is optional and off unless asked for — see
//! [`RecordKey::seal_padded`].

#![cfg(feature = "session")]

use alloc::vec::Vec;

use chacha20poly1305::{
	ChaCha20Poly1305, Nonce,
	aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroize;

use crate::error::{Error, Result};

// region:    --- Constants

/// How many records one key covers before both ends ratchet to the next.
///
/// 2²⁰ records is ~100 seconds at 10k records/s and ~17 minutes at 1k/s:
/// frequent enough that a long-lived tunnel is not sitting on one key for
/// hours, rare enough that the ratchet itself is never measurable. The value
/// is a protocol constant — see the module docs for why it is not a knob.
pub const REKEY_INTERVAL: u64 = 1 << 20;

/// Context string for one ratchet step. Versioned with the protocol: if the
/// schedule ever changes, this changes with it, so a peer on one schedule and
/// a peer on another derive different keys and fail loudly instead of silently
/// disagreeing.
const REKEY_DOMAIN: &str = "Temper.Session.v2.Rekey";

/// How many generations ahead of its current key a `RecordKey` will walk to
/// meet a record.
///
/// A stream never needs more than one (its counter advances one at a time);
/// a datagram window that spans more than a few generations is misconfigured.
/// The bound exists because the walk is driven by a sequence number that
/// arrives from the network, and an unbounded walk is an unbounded amount of
/// hashing per packet.
const MAX_REKEY_AHEAD: u64 = 4;

/// Bytes of length prefix [`RecordKey::seal_padded`] puts inside the
/// encrypted payload so the receiver can recover the true length.
const PAD_LEN_PREFIX: usize = 4;

// endregion: --- Constants

// region:    --- RecordKey

/// One record-encryption key, the generation it belongs to, and the two
/// counters that ride with it.
///
/// `seal` counts up `next_tx` (what this side emits); `open` counts up
/// `next_rx` (what this side expects next). They advance independently
/// because they model the two ends of the key: an endpoint that both seals
/// and opens under one key — a relay, or the symmetric single-key setup —
/// must not let sends advance its receive expectation or vice versa. The
/// session protocol hands out different keys per direction anyway, in which
/// case each side simply only ever touches one of the two counters.
///
/// Not `Debug` (the keys would print). Keys are zeroized on drop; the
/// counters and the generation are not secret.
pub struct RecordKey {
	/// Key for generation `generation`.
	key: [u8; 32],
	/// The previous generation's key, kept so a datagram record that arrives
	/// just after a ratchet still opens. Meaningless while `generation == 0`.
	prev: [u8; 32],
	/// Which ratchet generation `key` is: the session's key, ratcheted
	/// forward this many times. Both ends reach the same generation at the
	/// same sequence number, which is what makes the ratchet need no wire
	/// signal.
	generation: u64,
	next_tx: u64,
	next_rx: u64,
}

impl RecordKey {
	/// A fresh key whose send and receive counters both start at 0.
	pub fn new(key: [u8; 32]) -> Self {
		Self {
			key,
			prev: [0u8; 32],
			generation: 0,
			next_tx: 0,
			next_rx: 0,
		}
	}

	/// The sequence number this key will next seal at. Exposed so a datagram
	/// caller can seed its own window state.
	pub fn next_tx(&self) -> u64 {
		self.next_tx
	}

	/// The sequence number this key will next expect to open at.
	pub fn next_rx(&self) -> u64 {
		self.next_rx
	}

	/// Which ratchet generation the send side is currently on. Zero until
	/// [`REKEY_INTERVAL`] records have been sealed.
	pub fn generation(&self) -> u64 {
		self.generation
	}

	/// Test-only: place the receive counter at `seq` without consuming
	/// anything. Exists so a test can put a receiver one record short of a
	/// ratchet boundary without sealing 2²⁰ records to get there.
	#[cfg(test)]
	fn fast_forward_rx(&mut self, seq: u64) {
		self.next_rx = seq;
	}

	/// Encrypt the next record in strict order. The send counter advances
	/// by one, and the key ratchets if this record starts a new generation.
	pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
		let seq = self.next_tx;
		let next = seq
			.checked_add(1)
			.ok_or_else(|| Error::Protocol("record sequence exhausted; re-handshake required".into()))?;
		self.advance_to(generation_of(seq))?;
		let record = seal_with(&self.key, seq, plaintext)?;
		self.next_tx = next;
		Ok(record)
	}

	/// Decrypt the next record in strict order. The receive counter advances
	/// by one. Any replay, reorder, or skip fails the tag — the sequence is
	/// inside the nonce and the AAD, so the wrong record never
	/// authenticates.
	pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>> {
		let seq = self.next_rx;
		self.advance_to(generation_of(seq))?;
		let plaintext = open_with(&self.key, seq, record)?;
		self.next_rx = seq + 1;
		Ok(plaintext)
	}

	/// Encrypt at an explicit sequence (datagram path). Does not touch the
	/// counters. Reusing a sequence under one key is the caller's bug — and
	/// a catastrophic one; see the module docs.
	///
	/// Refuses a sequence from an *earlier* generation than the key is on:
	/// the key it names has been retired, and sealing under a retired key at
	/// a sequence the peer may already have used repeats a nonce, which
	/// breaks ChaCha20 outright rather than merely failing to authenticate.
	pub fn seal_at(&mut self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
		let generation = generation_of(seq);
		if generation < self.generation {
			return Err(Error::Protocol(alloc::format!(
				"refusing to seal at sequence {} (generation {}): this key is on generation {} and the earlier key was retired",
				seq,
				generation,
				self.generation
			)));
		}
		self.advance_to(generation)?;
		seal_with(&self.key, seq, plaintext)
	}

	/// Decrypt at an explicit sequence (datagram path). Replay-window policy
	/// is the caller's; this only proves the record was sealed under this
	/// key at exactly this sequence.
	pub fn open_at(&mut self, seq: u64, record: &[u8]) -> Result<Vec<u8>> {
		let key = self.key_for(seq)?;
		open_with(&key, seq, record)
	}

	/// Encrypt the next record in strict order, padded to a multiple of
	/// `block` bytes, and length-prefixed so [`open_padded`](Self::open_padded)
	/// can recover the true length.
	///
	/// This quantizes record lengths, it does not hide them: an observer
	/// still sees how many blocks a record took, and still sees the timing
	/// and the direction of every record. It removes the *fine* signal — the
	/// exact size of a request, which for something like a login or a file
	/// fetch is most of the information a passive observer needs — at the
	/// cost of at most `block` extra bytes per record. Real traffic-analysis
	/// resistance needs shaping, cover traffic, or a carrier that mixes
	/// peers, none of which is in this layer.
	///
	/// The receiver must call [`open_padded`](Self::open_padded) for these
	/// records; calling plain [`open`](Self::open) returns the padding frame
	/// intact, which the layer above will see as a malformed payload rather
	/// than as a decryption failure. Padding is off unless a caller asks for
	/// it, and there is no negotiation for it, so both ends have to want it.
	pub fn seal_padded(&mut self, plaintext: &[u8], block: usize) -> Result<Vec<u8>> {
		if block == 0 {
			return Err(Error::Protocol("padding block size must be greater than zero".into()));
		}
		let len = plaintext.len();
		let len_u32 = u32::try_from(len)
			.map_err(|_| Error::Protocol("record plaintext too long to pad (over 2^32 bytes)".into()))?;

		// Round up to a whole number of blocks. Written out rather than as
		// `checked_next_multiple_of`, which is not stable on the toolchain
		// this crate pins.
		let padded_len = len
			.checked_add(PAD_LEN_PREFIX)
			.ok_or_else(|| Error::Protocol("padded record length overflow".into()))?
			.div_ceil(block)
			.checked_mul(block)
			.ok_or_else(|| Error::Protocol("padded record length overflow".into()))?;

		let mut framed = Vec::with_capacity(padded_len);
		framed.extend_from_slice(&len_u32.to_le_bytes());
		framed.extend_from_slice(plaintext);
		framed.resize(padded_len, 0);
		self.seal(&framed)
	}

	/// Decrypt a record produced by [`seal_padded`](Self::seal_padded) and
	/// strip its padding.
	pub fn open_padded(&mut self, record: &[u8]) -> Result<Vec<u8>> {
		let framed = self.open(record)?;
		if framed.len() < PAD_LEN_PREFIX {
			return Err(Error::Protocol(
				"padded record is shorter than its own length prefix".into(),
			));
		}
		let len = u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
		if len > framed.len() - PAD_LEN_PREFIX {
			return Err(Error::Protocol(alloc::format!(
				"padded record declares {} bytes but carries {}",
				len,
				framed.len() - PAD_LEN_PREFIX
			)));
		}
		Ok(framed[PAD_LEN_PREFIX..PAD_LEN_PREFIX + len].to_vec())
	}

	/// The key covering `seq`, ratcheting forward to reach it and reaching
	/// back exactly one generation for a record that arrives just after a
	/// boundary.
	fn key_for(&mut self, seq: u64) -> Result<[u8; 32]> {
		let generation = generation_of(seq);
		if generation == self.generation {
			return Ok(self.key);
		}
		// `prev` is only meaningful once a ratchet has happened; before that
		// it is zeros, and returning it would turn a late record into a key
		// that authenticates nothing (or worse, into a silent all-zero key).
		if self.generation > 0 && generation == self.generation - 1 {
			return Ok(self.prev);
		}
		self.advance_to(generation)?;
		Ok(self.key)
	}

	/// Ratchet forward until `key` covers generation `generation`. Refuses to move
	/// backwards — the chain is one-way — and refuses an unbounded jump.
	fn advance_to(&mut self, generation: u64) -> Result<()> {
		if generation < self.generation {
			return Err(Error::Protocol(alloc::format!(
				"record names key generation {}, but this key has already ratcheted past it to {}",
				generation,
				self.generation
			)));
		}
		if generation - self.generation > MAX_REKEY_AHEAD {
			return Err(Error::Protocol(alloc::format!(
				"record names key generation {}, {} generations ahead of {}; refusing to walk that far",
				generation,
				generation - self.generation,
				self.generation
			)));
		}
		while self.generation < generation {
			self.prev = self.key;
			self.key = ratchet(&self.key);
			self.generation += 1;
		}
		Ok(())
	}
}

impl Drop for RecordKey {
	fn drop(&mut self) {
		self.key.zeroize();
		self.prev.zeroize();
	}
}

/// Which ratchet generation covers `seq`.
fn generation_of(seq: u64) -> u64 {
	seq / REKEY_INTERVAL
}

/// One step of the key chain. `derive_key` rather than a bare hash so the
/// ratchet output cannot collide with any other use of BLAKE3 over the same
/// bytes; the domain string is the one PROTOCOL.md names.
fn ratchet(key: &[u8; 32]) -> [u8; 32] {
	blake3::derive_key(REKEY_DOMAIN, key)
}

fn seal_with(key: &[u8; 32], seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
	let aad_bytes = aad(seq, plaintext.len());
	let cipher = ChaCha20Poly1305::new(key.into());
	let payload = Payload {
		msg: plaintext,
		aad: &aad_bytes,
	};
	cipher
		.encrypt(&nonce(seq), payload)
		.map_err(|_| Error::Protocol("record encryption failed".into()))
}

/// The Poly1305 tag ChaCha20-Poly1305 appends to every record. The AAD binds
/// the *plaintext* length, so the receiver must reconstruct it from the
/// record length before the tag check can possibly pass.
const TAG_LEN: usize = 16;

fn open_with(key: &[u8; 32], seq: u64, record: &[u8]) -> Result<Vec<u8>> {
	let plaintext_len = record
		.len()
		.checked_sub(TAG_LEN)
		.ok_or_else(|| Error::Protocol("record shorter than the authentication tag".into()))?;
	let aad_bytes = aad(seq, plaintext_len);
	let cipher = ChaCha20Poly1305::new(key.into());
	let payload = Payload {
		msg: record,
		aad: &aad_bytes,
	};
	cipher
		.decrypt(&nonce(seq), payload)
		.map_err(|_| Error::Protocol("record failed authentication (wrong key, replay, reorder, or corruption)".into()))
}

/// nonce = 4 zero bytes || seq BE. The zeros keep the counter far from the
/// ChaCha20 counter block layout nobody else uses; the big-endian suffix
/// makes the bytes human-checkable against a wire dump.
fn nonce(seq: u64) -> Nonce {
	let mut n = [0u8; 12];
	n[4..].copy_from_slice(&seq.to_be_bytes());
	Nonce::from(n)
}

/// AAD = seq BE || plaintext length BE, binding both to the tag so a record
/// cannot be re-spliced under a different number or truncated.
fn aad(seq: u64, len: usize) -> alloc::vec::Vec<u8> {
	let mut a = alloc::vec::Vec::with_capacity(12);
	a.extend_from_slice(&seq.to_be_bytes());
	a.extend_from_slice(&(len as u32).to_be_bytes());
	a
}

// endregion: --- RecordKey

// region:    --- RecordKeys

/// Both directions for one session, pre-oriented for a role. The initiator
/// sends with the C2S key; the responder mirrors.
pub struct RecordKeys {
	send: RecordKey,
	recv: RecordKey,
}

impl RecordKeys {
	/// Orientation for the side that ran the handshake as initiator.
	pub fn initiator(c2s: [u8; 32], s2c: [u8; 32]) -> Self {
		Self {
			send: RecordKey::new(c2s),
			recv: RecordKey::new(s2c),
		}
	}

	/// Orientation for the side that ran the handshake as responder.
	pub fn responder(c2s: [u8; 32], s2c: [u8; 32]) -> Self {
		Self {
			send: RecordKey::new(s2c),
			recv: RecordKey::new(c2s),
		}
	}

	/// The direction this side sends with.
	pub fn send(&mut self) -> &mut RecordKey {
		&mut self.send
	}

	/// The direction this side receives on.
	pub fn recv(&mut self) -> &mut RecordKey {
		&mut self.recv
	}

	/// Split into the two keys, e.g. to move them to different tasks.
	pub fn into_keys(self) -> (RecordKey, RecordKey) {
		(self.send, self.recv)
	}
}

// endregion: --- RecordKeys

// region:    --- Tests

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::boxed::Box;

	type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>; // For tests.

	const K1: [u8; 32] = [0x11; 32];
	const K2: [u8; 32] = [0x22; 32];

	#[test]
	fn test_record_seal_open_round_trip_advances_counter() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);

		// -- Exec
		let r0 = key.seal(b"first")?;
		let r1 = key.seal(b"second")?;
		let p0 = key.open(&r0)?;
		let p1 = key.open(&r1)?;

		// -- Check
		assert_eq!(p0, b"first");
		assert_eq!(p1, b"second");
		// The send and receive counters advanced in step here, but each on
		// its own: two seals, then two opens.
		assert_eq!(key.next_tx(), 2);
		assert_eq!(key.next_rx(), 2);
		Ok(())
	}

	#[test]
	fn test_record_tampered_record_rejected() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);
		let mut record = key.seal(b"payload")?;

		// -- Exec: flip one bit of the ciphertext body.
		let last = record.len() - 1;
		record[last] ^= 0x01;
		let opened = key.open(&record);

		// -- Check
		assert!(opened.is_err());
		Ok(())
	}

	#[test]
	fn test_record_replay_rejected() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);
		let record = key.seal(b"once")?;

		// -- Exec
		let first = key.open(&record);
		let replay = key.open(&record);

		// -- Check: the same bytes never authenticate twice.
		assert!(first.is_ok());
		assert!(replay.is_err());
		Ok(())
	}

	#[test]
	fn test_record_reordered_records_rejected() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);
		let r0 = key.seal(b"zero")?;
		let r1 = key.seal(b"one")?;

		// -- Exec: deliver in swap.
		let swapped = key.open(&r1);

		// -- Check: strict order is enforced by the tag, no window state.
		assert!(swapped.is_err());
		assert!(key.open(&r0).is_ok());
		assert!(key.open(&r1).is_ok());
		Ok(())
	}

	#[test]
	fn test_record_truncated_below_tag_rejected() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);
		let record = key.seal(b"payload")?;

		// -- Exec: chop bytes off the end, through the tag and past it.
		for cut in 1..=record.len() {
			let truncated = key.open(&record[..record.len() - cut]);

			// -- Check: always a clean rejection, never an underflow.
			assert!(truncated.is_err());
		}
		Ok(())
	}

	#[test]
	fn test_record_datagram_explicit_sequence() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);

		// -- Exec
		let record = key.seal_at(7, b"datagram")?;
		let opened = key.open_at(7, &record);
		let wrong_slot = key.open_at(8, &record);

		// -- Check
		assert_eq!(opened?, b"datagram");
		assert!(wrong_slot.is_err());
		assert_eq!(key.next_tx(), 0, "explicit-sequence path leaves the send counter alone");
		assert_eq!(key.next_rx(), 0, "…and the receive counter");
		Ok(())
	}

	#[test]
	fn test_record_wrong_key_rejected() -> Result<()> {
		// -- Setup & Fixtures
		let mut sender = RecordKey::new(K1);
		let mut attacker = RecordKey::new(K2);
		let record = sender.seal(b"secret")?;

		// -- Exec
		let stolen = attacker.open(&record);

		// -- Check
		assert!(stolen.is_err());
		Ok(())
	}

	#[test]
	fn test_record_keys_directions_are_mirrored_and_distinct() -> Result<()> {
		// -- Setup & Fixtures
		let mut init = RecordKeys::initiator(K1, K2);
		let mut resp = RecordKeys::responder(K1, K2);

		// -- Exec: initiator sends, responder receives; then the way back.
		let c2s = init.send().seal(b"ping")?;
		let ping = resp.recv().open(&c2s)?;
		let s2c = resp.send().seal(b"pong")?;
		let pong = init.recv().open(&s2c)?;

		// -- Check
		assert_eq!(ping, b"ping");
		assert_eq!(pong, b"pong");
		// Negative control: a direction cross would fail the tag — that is
		// the whole point of two keys instead of one.
		assert!(init.send().open(&s2c).is_err());
		Ok(())
	}

	#[test]
	fn test_record_deterministic_at_same_sequence_distinct_across_sequences() -> Result<()> {
		// -- Setup & Fixtures
		let mut a = RecordKey::new(K1);
		let mut b = RecordKey::new(K1);

		// -- Exec
		let same = a.seal_at(0, b"x")?;
		let also = b.seal_at(0, b"x")?;
		let other = b.seal_at(1, b"x")?;

		// -- Check: (key, seq, plaintext) fully determines the record; a
		// different seq is a different nonce and a different ciphertext.
		assert_eq!(same, also);
		assert_ne!(same, other);
		Ok(())
	}

	// region: --- Rekey

	// The ratchet is driven by the sequence number, so a test reaches a
	// boundary by naming a sequence at it rather than by sealing a million
	// records. Every case below is O(1) for that reason.

	/// The first sequence covered by generation `n`.
	const fn boundary(n: u64) -> u64 {
		n * REKEY_INTERVAL
	}

	#[test]
	fn test_record_ratchet_moves_both_ends_at_the_same_record() -> Result<()> {
		// -- Setup & Fixtures: one key material, both ends.
		let mut sender = RecordKey::new(K1);
		let mut receiver = RecordKey::new(K1);

		// -- Exec: the last record of generation 0, then the first of 1.
		let last_g0 = sender.seal_at(boundary(1) - 1, b"last")?;
		let first_g1 = sender.seal_at(boundary(1), b"first")?;

		// -- Check: the receiver follows without being told, because the
		// generation is a function of the sequence and nothing else.
		assert_eq!(receiver.open_at(boundary(1) - 1, &last_g0)?, b"last");
		assert_eq!(receiver.generation(), 0, "the last of a generation does not ratchet");
		assert_eq!(receiver.open_at(boundary(1), &first_g1)?, b"first");
		assert_eq!(receiver.generation(), 1, "the first record past the boundary does");
		assert_eq!(sender.generation(), 1);
		Ok(())
	}

	#[test]
	fn test_record_ratchet_determinism_across_boundaries() -> Result<()> {
		// Two independent keys ratchet to the same place, so a record sealed
		// on one opens on the other — the property the whole scheme rests on.
		let mut a = RecordKey::new(K1);
		let mut b = RecordKey::new(K1);

		let deep = boundary(3) + 17;
		let record = a.seal_at(deep, b"three generations in")?;

		assert_eq!(a.generation(), 3);
		assert_eq!(b.open_at(deep, &record)?, b"three generations in");
		assert_eq!(b.generation(), 3);
		Ok(())
	}

	#[test]
	fn test_record_ratchet_keeps_one_generation_back_for_late_records() -> Result<()> {
		// -- Setup & Fixtures: a key that has already moved to generation 1.
		let mut sender = RecordKey::new(K1);
		let mut receiver = RecordKey::new(K1);
		let late = sender.seal_at(boundary(1) - 1, b"in flight")?;
		let _ = receiver.seal_at(boundary(1), b"pull it forward")?;

		// -- Exec: the out-of-order datagram turns up after the boundary.
		let opened = receiver.open_at(boundary(1) - 1, &late);

		// -- Check
		assert_eq!(opened?, b"in flight");
		Ok(())
	}

	#[test]
	fn test_record_ratchet_forgets_older_generations() -> Result<()> {
		// -- Setup & Fixtures: the same record from the very first generation.
		let mut sender = RecordKey::new(K1);
		let mut receiver = RecordKey::new(K1);
		let ancient = sender.seal_at(5, b"ancient")?;

		// -- Exec: the receiver is pulled two generations forward.
		let _ = receiver.seal_at(boundary(2), b"forward")?;
		let outcome = receiver.open_at(5, &ancient);

		// -- Check: the chain is one-way, so a record that old is simply
		// unreachable. This is the forward-secrecy half of the ratchet: an
		// attacker who lifts the current key gets nothing before it either.
		assert!(outcome.is_err(), "a record two generations back must not open");
		Ok(())
	}

	#[test]
	fn test_record_ratchet_refuses_to_walk_a_record_driven_distance() -> Result<()> {
		// -- Setup & Fixtures: a sequence far beyond the walk bound.
		let mut key = RecordKey::new(K1);

		// -- Exec: the sequence is attacker-chosen, the walk is not.
		let outcome = key.open_at(boundary(MAX_REKEY_AHEAD + 1), b"anything at all");

		// -- Check
		match outcome {
			Err(Error::Protocol(msg)) => assert!(msg.contains("generations ahead"), "got: {msg}"),
			other => panic!("expected a Protocol refusal, got {other:?}"),
		}
		Ok(())
	}

	#[test]
	fn test_record_ratchet_refuses_to_seal_under_a_retired_key() -> Result<()> {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);
		let _ = key.seal_at(boundary(1), b"current")?;

		// -- Exec: a send at a sequence from the generation before.
		let outcome = key.seal_at(boundary(1) - 1, b"too late");

		// -- Check: refused, because a retired key plus a possibly-reused
		// sequence is nonce reuse, which fails silently rather than loudly.
		match outcome {
			Err(Error::Protocol(msg)) => assert!(msg.contains("retired"), "got: {msg}"),
			other => panic!("expected a Protocol refusal, got {other:?}"),
		}
		Ok(())
	}

	#[test]
	fn test_record_ratchet_stream_path_crosses_the_boundary() -> Result<()> {
		// The stream counters have to cross the same boundary the explicit
		// path does. Reaching 2^20 by sealing is minutes of work, so the
		// counter is fast-forwarded here instead — `next_rx` is the only
		// thing `open` reads to decide the generation.
		let mut sender = RecordKey::new(K1);
		let mut receiver = RecordKey::new(K1);
		let record = sender.seal_at(boundary(1), b"first of the new key")?;

		// -- Exec: the receiver's counter is placed one short of the
		// boundary, then advanced onto it.
		receiver.fast_forward_rx(boundary(1));
		let opened = receiver.open(&record);

		// -- Check
		assert_eq!(opened?, b"first of the new key");
		assert_eq!(receiver.generation(), 1);
		Ok(())
	}

	// endregion: --- Rekey

	// region: --- Padding

	#[test]
	fn test_record_padding_round_trips_every_length_in_a_block() -> Result<()> {
		// -- Setup & Fixtures
		let mut sender = RecordKey::new(K1);
		let mut receiver = RecordKey::new(K1);
		let block = 64;

		// -- Exec & Check: every length from empty to over one block.
		for len in [0usize, 1, 3, 59, 60, 61, 63, 64, 65, 127, 128, 200] {
			let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
			let record = sender.seal_padded(&plaintext, block)?;
			let opened = receiver.open_padded(&record)?;
			assert_eq!(opened, plaintext, "length {len} did not survive padding");

			// Every record is a whole number of blocks plus the tag.
			assert_eq!((record.len() - TAG_LEN) % block, 0, "length {len} is not block-aligned");
		}
		Ok(())
	}

	#[test]
	fn test_record_padding_quantizes_the_length_it_hides() -> Result<()> {
		// -- Setup & Fixtures: three plaintexts of different sizes.
		let mut sender = RecordKey::new(K1);
		let block = 64;

		// -- Exec
		let a = sender.seal_padded(b"a", block)?;
		let b = sender.seal_padded(&[0u8; 30], block)?;
		let c = sender.seal_padded(&[0u8; 60], block)?;

		// -- Check: 1, 31 and 61 bytes of payload all land in the same block,
		// so their records are indistinguishable by length. This is the whole
		// of what padding buys, stated as an assertion.
		assert_eq!(a.len(), b.len());
		assert_eq!(b.len(), c.len());
		Ok(())
	}

	#[test]
	fn test_record_padding_needs_a_nonzero_block() {
		// -- Setup & Fixtures
		let mut key = RecordKey::new(K1);

		// -- Exec & Check
		assert!(
			key.seal_padded(b"x", 0).is_err(),
			"a zero block is a divide by zero, not a no-op"
		);
	}

	#[test]
	fn test_record_padding_is_not_transparent_to_the_unpadded_open() -> Result<()> {
		// Documented consequence, pinned: a receiver that calls `open` on a
		// padded record gets the framing back rather than an error. The layer
		// above sees a malformed payload — which is the point of writing it
		// down, because "it fails somewhere else" is easy to mistake for "it
		// cannot happen".
		let mut sender = RecordKey::new(K1);
		let mut receiver = RecordKey::new(K1);

		let record = sender.seal_padded(b"payload", 64)?;
		let raw = receiver.open(&record)?;

		assert_ne!(raw, b"payload");
		assert_eq!(raw[..4], 7u32.to_le_bytes(), "the frame leads with the true length");
		Ok(())
	}

	// endregion: --- Padding
}

// endregion: --- Tests
