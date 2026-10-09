# Temper Session Protocol

Wire specification for the authenticated session protocol (`session` feature)
and its record layer. This document is normative: a conforming implementation
produces byte-identical flights and keys. The frozen postcard encodings are
pinned by `frozen_tests.rs` and the flight bytes by `session_tests.rs` goldens.

The protocol has one shape: three flights that turn the bare key agreement in
`crate::handshake` into a mutually authenticated session with concealed
identities, its own record layer, and an optional stateless cookie against
blind floods.

## Overview

Three flights establish a mutually authenticated session with forward secrecy
on top of the bare key agreement in `crate::handshake` (ML-KEM-1024 +
X25519, ephemeral on both sides):

```text
Initiator                          Responder
---------                          ---------
                                   SessionChallenge      [flight 0, only if
                   ◄──────────────   version, cookie       a cookie is required]
SessionInit        ──────────────►                        [flight 1]
  version, proposal, cookie,
  sealed_identity
                   ◄──────────────  SessionAccept         [flight 2]
                                     acceptance, sealed_responder,
                                     responder_confirm, sig(H2)
SessionConfirm     ──────────────►                        [flight 3]
  initiator_confirm, sig(H3)

both sides derive C2S/S2C record keys
```

Client authentication is mandatory: the responder refuses to derive a session
until flight 3 verifies. All messages are postcard-encoded structs; the
framing that carries them (length prefix, stream) belongs to the carrier. The
`transport` feature ships one such carrier — `[u32 little-endian length]
[payload]` frames over TCP, the flights as plaintext frames, then one record
per frame for the life of the session.

Neither identity travels in the clear. Each peer's `PeerIdentity` is sealed —
flight 1's to the responder's static concealment key, flight 2's to a key
derived from the shared secret — and the bare handshake's identity tags are
freshly randomised per session, so no value on the wire repeats between two
sessions of the same peers.

## Message shapes

```text
SessionChallenge {
    version: u16                      = 2 (PROTOCOL_VERSION)
    cookie: [u8; 32]
}

SessionInit {
    version: u16                      = 2 (PROTOCOL_VERSION)
    proposal: HandshakeProposal       bare handshake flight 1 (unchanged bytes)
    cookie: [u8; 32]                  flight 0's value, or all-zero
    sealed_identity: Envelope         encapsulate(rng, postcard(PeerIdentity_I),
                                                 responder concealment key)
}

SessionAccept {
    body: SessionAcceptBody {
        acceptance: HandshakeAcceptance   bare handshake flight 2
        sealed_responder: Vec<u8>         AEAD seal of postcard(PeerIdentity_R)
        responder_confirm: [u8; 32]
    }
    mldsa_sig: Vec<u8>                ML-DSA-65 over H2
    slhdsa_sig: Vec<u8>               SLH-DSA-SHA2-128f over H2
}

SessionConfirm {
    body: SessionConfirmBody {
        initiator_confirm: [u8; 32]
    }
    mldsa_sig: Vec<u8>                ML-DSA-65 over H3
    slhdsa_sig: Vec<u8>               SLH-DSA-SHA2-128f over H3
}

PeerIdentity {
    mldsa_pk: Vec<u8>                 1952 bytes
    slhdsa_pk: Vec<u8>                32 bytes
    key_id: String                    hex(BLAKE3(mldsa_pk || slhdsa_pk))
    certificate: Option<Box<TemperCertificate>>
}
```

The bare handshake's opaque `local_id` inputs are a **fresh random** value per
flight, not a digest of the peer's identity: a deterministic blinding would
itself be a stable pseudonym that links every session of the same peer, which
is the property concealment exists to remove. Both roles blind it. The
identities themselves are concealed in the seals, and the transcript still
binds both sides' public keys through those seals.

`proposal.session_id` is a random 64-bit value with its top bit forced set.
postcard varint-encodes a `u64`, so an unrestricted draw would make flight 1
one byte longer or shorter depending on the value; the fixed top bit pins the
encoded width, which is what makes every flight a fixed length. It costs one
bit of a random identifier, and the other 63 are far past any session table.

## Transcript chain

`H(x)` is plain BLAKE3; `postcard(x)` is the canonical postcard encoding.

```text
H1 = H("Temper.Session.v2" || postcard(SessionInit))
H2 = H(H1 || postcard(acceptance) || postcard(sealed_responder))
H3 = H(H2 || postcard(initiator_confirm))
```

Details that matter:

- The responder signs H2; the initiator signs H3. Both signatures are dual
  (ML-DSA-65 **and** SLH-DSA-SHA2-128f) and must verify against the public
  keys in the signer's own `PeerIdentity`.
- H2 covers the accept flight's payload but **not** its confirm MAC or its
  signatures. A MAC cannot cover its own bytes (as in TLS 1.3 Finished), and
  the signatures are *over* H2 rather than inside it — they need no cover
  from themselves. Tampering with either is caught by the MAC check or the
  signature check respectively.
- H2 covers the responder's identity **ciphertext**, not its plaintext: the
  `|| sealed_responder` above is the postcard encoding of a `Vec<u8>`. The
  responder signs H2; the initiator decrypts first and only then verifies the
  signature under the decrypted keys. The signature proves a holder of the
  responder's key endorsed a blob — and that blob decrypts only for a session
  participant.
- The initiator's identity is covered once, inside SessionInit (H1). H3
  binds the initiator's confirm flight to that identity through the chain.

## Key schedule

```text
secret            = handshake shared secret   (bare handshake output, unchanged)
K_server          = BLAKE3.derive_key("Temper.Session.v2.ServerConfirm", secret || H2)
K_client          = BLAKE3.derive_key("Temper.Session.v2.ClientConfirm", secret || H2)
responder_confirm = BLAKE3.keyed_hash(K_server, H2)
initiator_confirm = BLAKE3.keyed_hash(K_client, H2)
C2S               = BLAKE3.derive_key("Temper.Session.v2.C2S", secret || H3)
S2C               = BLAKE3.derive_key("Temper.Session.v2.S2C", secret || H3)
H3                = H(H2 || postcard(initiator_confirm))
```

`||` is concatenation. The confirm MACs prove each side derived `secret`
before any record flows; the traffic keys additionally bind H3, so they
inherit every signature and MAC above them. The initiator sends with C2S and
receives on S2C; the responder mirrors. Confirm MAC comparisons are
constant-time.

Every domain string is distinct, so no value derived for one purpose can be
mistaken for another's — a confirm MAC cannot serve as a record key, and one
direction's keys cannot stand in for the other's.

## Record layer

One ChaCha20-Poly1305 key per direction. The sequence number never travels
on the wire:

```text
nonce   = [0u8; 4] || seq u64 big-endian            (12 bytes)
AAD     = seq u64 big-endian || plaintext_len u32 big-endian
record  = ciphertext || Poly1305 tag (16 bytes)
```

- **Stream mode** (`RecordKey::seal`/`open`): strict +1 counters, both
  starting at 0. A replayed, reordered, or dropped record fails its tag with
  no receiver-side window state. Each key carries independent send/receive
  counters so an endpoint that seals and opens under one key cannot desync.
- **Datagram mode** (`RecordKey::seal_at`/`open_at`): the sequence is an
  explicit argument; replay-window policy is the caller's. This is what a
  packet-oriented carrier windows over before calling `open_at`.
- Nonce reuse within a key is catastrophic. The counter construction makes
  it impossible provided one key encrypts from one owner; do not share a
  key across encrypting threads.

### Rekey

Both ends ratchet the key every `REKEY_INTERVAL` = 2²⁰ records:

```text
key(0)   = C2S or S2C, as derived above
key(n+1) = BLAKE3.derive_key("Temper.Session.v2.Rekey", key(n))
generation(seq) = seq / REKEY_INTERVAL
```

- The generation is a function of the sequence number, so it needs no wire
  signal and cannot be desynchronized by configuration: both ends move at the
  same record or not at all.
- The chain is one-way. An attacker who obtains one generation's key gets
  neither the records before it nor the records after it — which is the whole
  point, and is why this is a ratchet rather than a periodic re-derivation
  from `secret`, which would leave the entire session readable to anyone who
  later obtained that secret.
- Datagram mode: a record names its own generation. A receiver keeps the
  previous generation's key so a record that arrives just after a boundary
  still opens, refuses anything older, and refuses to walk more than 4
  generations forward — the walk is driven by a sequence number that arrives
  from the network, and an unbounded walk is unbounded work per packet.
- Sealing at a sequence from a retired generation is refused: the key is
  gone and the nonce may already have been used, which breaks ChaCha20
  outright rather than merely failing to authenticate.

### Padding (opt-in, per record)

`seal_padded(plaintext, block)` frames the plaintext as
`[true_len u32 LE][payload][zeros]` and pads to a whole number of `block`
bytes; `open_padded` reverses it.

- This **quantizes** lengths, it does not hide them: an observer still sees
  how many blocks a record took, and still sees the timing, direction and
  count of every record. It removes the fine signal — the exact size of a
  request — at a cost of at most `block` bytes per record.
- There is no negotiation, so both ends must choose it. A receiver that
  calls plain `open` on a padded record gets the framing back rather than a
  decryption failure, and the layer above sees a malformed payload.

## Identity and policy

`PeerPolicy` decides which `PeerIdentity` may hold the other end. Every
variant still requires the flight signatures to verify — the policy only
chooses *whose* identities are acceptable:

- `AcceptAny` — any verified identity; the authenticated identity is
  returned in `SessionSecrets::peer` (trust-on-first-use style).
- `Pin(identity)` — both public keys must match byte for byte.
- `Cert { ca_mldsa_pk, ca_slhdsa_pk, validity }` — the flight must carry a
  certificate that verifies under the CA keys, and the certificate's subject
  signing keys must equal the flight identity's keys.

A `TemperCertificate` (content schema 2, domain `Temper.CA.Cert.v2`) signs the
subject id, the validity window, the subject's ML-DSA-65 and SLH-DSA public
keys, and its **concealment public key**. Certifying the concealment key is
what makes a first contact authenticated end to end: it is the key the
initiator KEM-encapsulates flight 1 to, and if it is not the certified one an
impostor who supplies its own key opens the sealed identity — exactly what
concealment exists to prevent — without ever completing the handshake. The
signing-key equality check above covers what flight 1 presents; the
concealment binding covers what flight 1 is sealed *to*. A schema-1
certificate does not verify under this build.

The validity window is governed by `validity`:

- `CertValidity::At(now_secs)` enforces `not_before <= now <= not_after`
  against a caller-supplied Unix time. The check runs *after* the seal
  verifies — before that, `not_after` is an attacker-controlled field.
- `CertValidity::NotChecked` is for a build with no clock and skips the
  window entirely: an expired or not-yet-valid certificate is accepted as
  long as its seal chains to the trusted CA.

This is a required field and not a default, deliberately. A silently skipped
expiry check is a check that passes for the wrong reason, and nothing else in
the handshake notices a certificate that expired — the seal verifies
perfectly. `not_before` matters for the same reason in the other direction:
a certificate issued for a future window can be presented early, and only the
window check catches it.

## Concealment

The initiator's identity is KEM-encapsulated to the responder's **concealment
public key** — a long-term key published before the session starts, and
certified (see *Identity and policy*): an uncertified concealment key is an
impostor's key, because the encapsulation opens to whoever holds its secret.
The responder's identity is sealed under a key derived from the session
secret, so only a participant can read either.

```text
seal_key_R = BLAKE3.derive_key("Temper.Session.v2.ResponderSeal",
                               secret || H1 || postcard(acceptance))
sealed_responder = ChaCha20-Poly1305(seal_key_R, nonce = 0,
                                     aad = "Temper.Session.v2.ResponderSeal",
                                     postcard(PeerIdentity_R))
```

Details that matter:

- `seal_key_R` covers exactly what exists **before** the ciphertext it
  protects: `secret`, `H1`, and the acceptance — the TLS 1.3
  EncryptedExtensions pattern. Folding H2 in would be circular, because H2
  contains this ciphertext.
- The all-zero nonce is safe only because the key is provably used once: it is
  derived per session from a fresh secret, and one acceptance is sealed under
  it. It is not a general-purpose AEAD construction and is not exported as
  one.
- H2 covers the **ciphertext**, not the plaintext identity:
  `H2 = H(H1 || postcard(acceptance) || sealed_responder)`. The `||` is the
  postcard encoding of a `Vec<u8>`. So the signature proves a holder of the
  responder's key endorsed a blob — and that blob decrypts only for a
  participant.

### Forward secrecy of the seals

`sealed_responder` is sealed under a key derived from the bare handshake's
shared `secret`, which only the two parties can compute, so a recorded flight 2
does not open later even if the responder's long-term keys leak.

`sealed_identity` in flight 1 is sealed to the responder's **static**
concealment key, not to a session secret — the responder has not yet
contributed anything. That seal is therefore not forward-secret: a recorded
flight 1 opens once the concealment key leaks, fleet-wide and
retrospectively. Rotate concealment keys per epoch.

## Ordering

The order of operations is part of the specification, not an implementation
detail.

Responder, in `accept`:

1. version check;
2. cookie verification, when one is configured — **before** the concealment
   decapsulation and before any signing;
3. concealment decapsulation, and a consistency check that the decrypted
   identity's `key_id` equals `hex(BLAKE3(mldsa_pk || slhdsa_pk))`;
4. the peer policy;
5. only then the bare handshake and the two SLH-DSA signatures.

Initiator, in `finalize_initiator`: decrypt the responder's identity,
verify **both** signatures over H2 under the decrypted keys, check the confirm
MAC, then apply the policy — and never branch on, log, or `Debug`-print the
plaintext identity before the signature step. A caller cannot opt out, because
there is no point at which the identity is observable before it has been
authenticated.

## Anti-DoS cookie (optional)

```text
cookie      = BLAKE3.keyed_hash(server_secret, peer_tag || time_bucket_le)
time_bucket = now_secs / ttl_secs
```

The responder needs only `server_secret` to verify: no table, no memory
proportional to the number of clients. `verify` accepts the current **and
previous** bucket, so a client that received a cookie just before a rollover
is not refused just after one; the cost is that a cookie lives up to
`2 * ttl_secs`.

`peer_tag` binds the cookie to the peer as the carrier sees it — over TCP,
`BLAKE3("Temper.Transport.PeerTag" || ip_family || ip || port_le)`. A cookie
is worth exactly as much as that tag's integrity. On a carrier where the peer
can choose its own tag (anything spoofable) the attacker simply presents its
own, so **a responder configured with a cookie but no trustworthy tag fails
closed** rather than issuing a value anyone can mint.

A responder that requires a cookie and receives flight 1 without a valid one
answers with a `SessionChallenge` and stops — one hash and 33 bytes, in place
of the decapsulation and two SLH-DSA signatures flight 2 costs. The client
discards the first, unauthenticated flight entirely and starts a fresh one
carrying the cookie (fresh ephemerals and a fresh blinded id, because the
first flight's are already on the wire) and permits exactly one such round. A
responder that challenges twice is refused rather than looped on.

The cookie stops blind floods of fresh ids. It does **not** stop a captured
flight 1 being replayed within its bucket, which is why `SessionReplayGuard`
stays: different attacks, both needed.

## What the protocol does not do

Stated plainly, because each is easy to mistake for a property the protocol
provides:

- **Not anonymous to the peer.** Each side learns the other's full
  `PeerIdentity`, certificates included. Concealment is against a
  non-participant observer.
- **Not anonymous to an observer who later obtains the session secret, or to
  a participant's log.** Whoever holds `secret` can open `sealed_responder`;
  whoever holds the responder's concealment private key can open every
  `sealed_identity` ever sent to it.
- **Flight 1's seal is not forward-secret.** `sealed_identity` is sealed to the
  responder's *static* concealment key, so an adversary who records flight 1
  and later compromises that key recovers the initiator's identity. Only the
  responder's side of the concealment is forward-secret.
- **Not resistant to traffic analysis.** Record and flight lengths, timings,
  directions and counts remain visible; the protocol changes none of that. See
  [Padding](#padding-opt-in-per-record), which quantizes lengths only.
- **The version field is not authenticated.** It is the first field of flight
  1, which carries no signature, so it selects a code path rather than a trust
  level. This build speaks one version: `accept` rejects any other before any
  key agreement, so there is no alternate path to steer a peer onto. A future
  breaking change would be negotiated through this field, and a responder that
  answered more than one version would reintroduce a downgrade surface; a
  deployment that needs concealment would then answer only the version it
  supports.

## Versioning

`version` is the first postcard field of flight 1 (`SessionInit`), and a
responder reads it before anything else. `session::peek_version` reads it with
`postcard::take_from_bytes::<u16>`, so a conforming reader decodes a `u16`
rather than assuming a single raw byte, and asserts the decoded value equals
the one it dispatched on.

`accept` requires `version == PROTOCOL_VERSION` (2) and rejects anything else
with the same wording, before any key agreement. An unknown version is a
protocol error, never a fallback.

`PROTOCOL_VERSION` is **2** because an earlier shape of this protocol used 1:
that shape carried both identities in cleartext and had no cookie field, so its
flight bytes are incompatible with these. This build speaks only 2, and the
number, together with the `.v2` in the domain strings, is what makes the
incompatibility surface as a clear rejection rather than a mis-decode — a peer
still speaking 1 stops at the version check with "unsupported session protocol
version 1 (this build speaks 2)". The version field itself exists so a future
breaking change can be negotiated rather than guessed at.

The wire types are frozen on publish — any change to field order, types, or
the transcript/key-schedule recipes is a version bump, not an edit. The types
are pinned by goldens in `frozen_tests.rs`.

## Threat model

Protected:

- **Confidentiality and integrity** of every record, and of the handshake's
  key agreement (hybrid ML-KEM-1024 + X25519, forward secret).
- **Mutual authentication** — both flights carry dual PQC signatures over a
  transcript that chains the full handshake; an active relay of two
  independent handshakes fails signature and MAC verification.
- **Concealment of both identities** from a non-participant passive observer,
  with no value on the wire repeating between two sessions of the same peers.
- **Record replay/reorder** (stream mode) — rejected by construction.
- **Key-compromise impersonation is limited to the stolen key's side**;
  forward secrecy keeps past sessions safe if a static key leaks later.
- **Forward secrecy within a session**, via the rekey ratchet: a key
  recovered from memory at record *n* does not decrypt the records before it
  or after it.
- **Transcript replay** — a captured flight 1/2/3 sequence cannot be
  replayed to completion. Both sides contribute fresh ephemerals that are
  bound into the transcript hash, so a replayed flight 1 makes the responder
  derive a different secret and a replayed flight 3 fails its confirm MAC.
  This holds without any caller action.
- **A repeated `session_id`**, when the responder holds a
  `SessionReplayGuard`. This is not the same property: the same id
  establishing twice is what overwrites a server's session table, and it is
  also the cheapest thing to refuse before the responder spends two SLH-DSA
  signatures on flight 2. `transport::Listener` owns a guard and consults it
  before computing flight 2.
- **Blind floods of fresh ids**, when a cookie is configured: the responder
  refuses an unvalidated peer for the price of two BLAKE3 hashes instead of a
  flight 2. What that does *not* buy is enumerated under
  [What the protocol does not do](#what-the-protocol-does-not-do); read it
  before treating concealment as anonymity.

Not protected (caller's responsibility, or out of scope):

- **Anonymity from a participant.** Mutual authentication requires each side
  to learn who it talks to, so a responder that logs the client it decrypted
  deanonymises it to itself, and an on-path MITM that completes a session is a
  participant.
- **DoS without a cookie configured.** Flight 1 carries no proof of work, so a
  flood of *fresh* ids costs the responder a flight 2 each (two SLH-DSA
  signatures, the most expensive operation in the protocol). A replay guard
  refuses repeats of a known id but cannot help with fresh ones. The optional
  cookie closes this when the carrier supplies a trustworthy peer tag; without
  one the mitigations are outside the protocol — rate-limit at the carrier, or
  require a cheaper pre-flight.
- **Traffic analysis** — lengths, timing, direction and record counts are
  visible regardless of padding. Padding quantizes lengths at block
  granularity only; shaping, cover traffic, or a mixing carrier are not in
  this layer.
- **Confidentiality against a later compromise of the responder's concealment
  key** — flight 1's seal is not forward-secret, as above.
- **Certificate validity windows** — enforced only when the caller supplies
  `CertValidity::At(now)`; see above.
- **Denial of service against an established session** — an attacker who can
  drop packets can stall a stream, since stream mode has no gap tolerance.
  A datagram carrier with its own window is the answer, not this layer.
