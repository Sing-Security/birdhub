# birdhub

A relay whose two ends know each other by **Temper** certificate.

One binary, two roles: a **hub** terminates sessions and, per client, either
dials the targets its grants allow or pairs it with another node; a **node**
(the client role) keeps one session to the hub, carries every local
connection it accepts to a fixed destination, and may serve named services to
other nodes. The same container image runs both — the roles share all of the
crypto and differ only in which end of the session they drive.

```sh
docker compose up --build
curl -s localhost:1080/
```

## Identity is a certificate, not an address

Each node generates a long-term Temper identity on first start — ML-DSA-65 and
SLH-DSA signing keys plus a concealment key — and keeps it at `identity.key`
with owner-only permissions. The identity is then **certified** by the fleet's
CA: a `TemperCertificate` that signs the node's name, all three of its public
keys, and a validity window.

A node needs exactly two files it did not generate itself — `ca.pub`, the CA's
public keys, and its own certificate. The CA key never leaves the machine that
issued the certificates. Nothing about a network address participates: that is
what lets the same configuration work over a container bridge, a WAN, or
loopback.

## Enrolling a fleet

```sh
# Once, for the fleet. ca.key is the fleet; keep it off every node.
birdhub ca init --key ca.key --pub ca.pub

# On the new node. Generates identity.key if it does not exist yet.
birdhub identity export --key identity.key --pub node.pub --name node.example

# Back on the CA machine.
birdhub ca issue --ca ca.key --identity node.pub --days 365 --out node.cert
```

The node then keeps `ca.pub` and `node.cert`; a client also keeps the hub's
`hub.cert`. Both roles check their own papers at startup — the certificate
must certify exactly the keys on disk, chain to the configured CA, and be
inside its validity window — and the client checks the hub presented
byte-for-byte the certificate it pinned. Any of those failures is reported on
the machine holding the problem, not as an anonymous refusal on the other.

## The session protocol

Every tunnel is one TCP connection carrying one Temper session, and the
session is established once and kept: each connection the client accepts
becomes a **stream** on it rather than its own handshake. Three flights, with
an optional stateless cookie first:

```text
Initiator                                Responder
                                   ◄───  SessionChallenge   (flight 0, if a
         ───────────────────────────►        SessionInit     cookie is required)
                                         SessionAccept
         ───────────────────────────►    SessionConfirm
```

- **Key agreement** — ML-KEM-1024 + X25519, ephemeral on both sides.
- **Signatures** — ML-DSA-65 and SLH-DSA-SHA2-128f, both, over the transcript.
- **Records** — ChaCha20-Poly1305, keys derived with BLAKE3.
- **Certificates** — a peer's identity is accepted only if it presents a
  certificate that verifies under `ca.pub`, whose subject keys equal the keys
  in the flight, and whose window covers the responder's clock.
- **Client authentication is mandatory**: the responder derives no session keys
  until the third flight verifies.

**Neither identity travels in the clear.** The initiator seals its
`PeerIdentity` to the responder's static concealment key — taken from the
hub's *certificate*, so it is authenticated before the first flight — in
flight 1; the responder seals its own under a key derived from the shared
secret in flight 2. The bare handshake's identity tags are re-randomised per
session, so no value on the wire repeats between two sessions of the same two
peers.

### One session, many streams

A stream is opened by name (`Open { stream, target }`), answered or refused
with a reason, carries opaque `Data`, and half-closes and resets exactly as
TCP does. The hub serves each stream in its own task, so a slow conversation
cannot queue the next one behind it, and the handshake — two post-quantum
signatures per side plus a cookie round trip — is paid once rather than on
the critical path of every request. Both sides may open streams; ids are
assigned by parity, so a hub-initiated connection needs no protocol change.
When a session dies it fails every stream on it, and the next connection
re-establishes it.

`crates/temper/PROTOCOL.md` is the normative wire specification. `crates/temper`
is vendored from the CrucibleOS tree — see [Vendoring](#vendoring).

## Node to node

A node can reach a service on another node, and the hub's part in it stops
after the introduction:

```text
node-a ── @cert/node-b ──► hub          "b's certificate, from the CA"
node-a ── @peer/node-b ──► hub ─────┐
                                    │  hub opens one stream on each session
node-a ◄═════ byte pipe (carrier) ══╧═► node-b
node-a ─── nested Temper session ──────► node-b   ← the hub has no keys for this
node-a ─── "web" stream on it ─────────► node-b ── dials 127.0.0.1:8080
```

- The **directory** (`@cert/<subject>`) hands back the certificate that node
  presented at its handshake — to peers whose grants name it, and to no one
  else. The requester verifies it against `ca.pub` and checks the subject, so
  the hub vouches for nothing; a lie earns a failed handshake.
- The **carrier** (`@peer/<subject>`) is a byte pipe the hub splices between
  two of its sessions. The peers then run their own Temper session inside it,
  which is why nothing the hub relays is readable to it: the hub is a meeting
  point and a fallback path, never a party to the conversation.
- **Presence is the session.** A node appears in the directory exactly while
  its supervisor keeps a session up — connected at startup, reconnected with
  backoff when it drops — so a node with no traffic is still reachable.
- **Services** are named on the inner session. The serving node checks the
  peer's certificate subject against its `[[services]] clients` before
  dialing anything, and refusals name both the peer and the service:
  `'node-b.example' does not permit 'node-a.example' to use 'db'`.

## Configuration

Two files, one per role, both baked into the image at `/etc/birdhub/`.

A **hub** reads `[app]`, `[identity]`, `[ca]`, `[hub_server]`, and one
`[[grants]]` entry per client:

```toml
[app]
mode = "hub"

[identity]
key_file = "/etc/birdhub/keys/hub.key"
name = "hub.example"
certificate = "/etc/birdhub/keys/hub.cert"   # issued by the CA for hub.key

[ca]
public = "/etc/birdhub/keys/ca.pub"          # the fleet's trust anchor

[hub_server]
data_address = "0.0.0.0:8388"                # the only listener
require_cookie = true

[[grants]]
client = "laptop.example"                    # certificate subject, proved by the handshake
targets = ["origin:80"]                      # exact host:port — or "@peer/<subject>" to pair
                                             # this client with another node
```

A **client** reads `[app]`, `[identity]`, `[ca]`, `[peer]`, one
`[[transports]]` entry per tunnel, and optionally one `[[services]]` entry per
service it serves to peers:

```toml
[app]
mode = "client"

[identity]
key_file = "/etc/birdhub/keys/client.key"
name = "laptop.example"
certificate = "/etc/birdhub/keys/client.cert"

[ca]
public = "/etc/birdhub/keys/ca.pub"

[peer]
address = "hub:8388"                         # the one hub this node connects to
hub_cert = "/etc/birdhub/keys/hub.cert"      # …and the one it will accept

[[transports]]
name = "web"
local_address = "0.0.0.0:1080"
forward_to = "origin:80"                     # what the hub dials on this tunnel's behalf,
                                             # or "<subject>/<service>" to reach a peer

[[services]]                                 # optional: what this node serves to peers
name = "web"
target = "127.0.0.1:8080"                    # what *this* node dials
clients = ["build-box.example"]              # certificate subjects allowed; empty is an error
```

A tunnel carries exactly one fixed destination. No SOCKS parsing, no
per-connection negotiation: two destinations are two `[[transports]]` entries.

`<subject>/<service>` destinations go peer to peer: the hub pairs the two
nodes and relays what they say, but the two run their own Temper session
inside that pairing, so what the hub carries is ciphertext it holds no keys
for. The serving node checks the dialing peer's certificate against its
`clients` list — proved by that inner handshake, not by anything the hub said.

A section belonging to the other role is a startup error, not a no-op — the
first version ignored misplaced keys, and "I set it and nothing happened" is a
configuration bug worth catching at parse time.

## Authorization

Two questions, answered in two places, both after authentication:

- **Who may connect?** The handshake. `[[grants]]` is keyed by the
  certificate's subject id and is also the fleet roster; a client with no row
  is dropped before it can name a target. With no `[[grants]]` at all, the
  hub serves nobody — the default, and the safe direction. A node that only
  serves peers gets a row with `targets = []`: admitted, present to peers,
  permitted to ask for nothing.
- **What may they dial?** `relay::serve_stream` checks each stream's target
  against that client's exact target list *before* dialing, so a refused
  target is never connected and cannot be probed. Targets are exact strings:
  no wildcards, no ranges, no DNS-dependent matching.
- **What may they reach in a peer?** Two answers, at the two ends. The hub's
  `@peer/<subject>` grant decides which pairs may meet (it is also the grant
  that lets a node fetch the peer's certificate at all); the serving node's
  `[[services]] clients` then decides, per service, which certificate
  subjects may use it. A node that asks for a service it may not use is
  refused with a reason, and nothing is dialed on its behalf.

Beyond authentication, the client also pins the hub byte-for-byte: "a member
of the fleet" and "our hub" are different questions, and the second one
deserves an exact answer.

## Running it

Release tarballs carry the binary (the desktop console ships in the
x86_64 GNU one), both sample configs, and the license — unpack, and the two
configs run as-is against their own keys directory:

```sh
tar -xzf birdhub-v*-x86_64-unknown-linux-musl.tar.gz
cd birdhub-v*-x86_64-unknown-linux-musl
./bin/birdhub hub-config.toml
```

From source, `cargo install --path .` puts the headless binary on your PATH;
the console is `cargo install --path console`.

```sh
docker compose up --build
```

Four containers on a private bridge: a one-shot `init` that enrolls the fleet
(CA, two identities, two certificates — the whole flow above, collapsed into
one volume), then the hub, the client, and a busybox origin to tunnel to. No
`cap_add`, no `privileged`, no `/dev/net/tun`; the same compose file works on
Linux, macOS and Windows.

```sh
curl -s localhost:1080/
```

goes host → client → Temper session → hub → origin:80, and back, and returns
the origin's page (`hello through the tunnel`). The hub logs each session with
the certificate subject it accepted, so the tunnel's authorization is visible:

```text
Hub: serving as 'hub.example' cert=… valid …..
Hub: grant 'laptop.example' → origin:80
Hub: grant 'desktop.example' → @peer/laptop.example
Hub: session … with 'laptop.example' (key_id=…)
```

That session line appears once per client, however many requests you make —
the requests are streams on it.

One row there — `desktop.example` — names a node that is not in the compose
file, because a roster lists the whole fleet and not just the members running
beside the hub. [`scripts/fleet-demo.sh`](scripts/fleet-demo.sh) joins it to
this same hub as a plain process on this machine, from the release binary:
nothing about the node changes for being outside a container — same binary,
same certificates, same config shape — only `[peer] address` is the published
port instead of a compose service name. [TESTING.md](TESTING.md), Method 4,
has the whole run.

## The console and the control API

The headless binary is not the only surface. With `[control] address` in the
config (the compose hub ships with it, published to the host's loopback as
port 8399), the hub serves a local JSON API — fleet state, the roster, the
event log, and the actions: `PUT /grants`, `POST /grants/reload`, and the
session kick. The same functions back the desktop frontend:

```sh
cargo run -p birdhub-console -- hub-config.toml    # or a node's config
```

`birdhub-console` embeds the core — hub or node, chosen by the config's
mode — in the same one-process shape the other desktop tools use: core on
its own tokio thread, egui on the main thread, buttons and API calling one
implementation. Fleet, Roster (editable, with Save/Reload), Events (the log
as data), Config and About for a hub; Status, Transports, Services and Peers
for a node. The screenshots in `shots/` come from the test harness rendering
the real views (`cargo test -p birdhub-console`). [TESTING.md](TESTING.md),
Method 5, walks the API and the revocation loop through it.

Delete the `birdhub-keys` volume to start a new fleet. [TESTING.md](TESTING.md)
has the manual, non-Docker flow plus the negative cases — un-certified client,
non-granted target, wrong CA, expired certificate — each with the exact log
line it must produce.

## Vendoring

`crates/temper` is a copy of `crucible/runtime/temper` from CrucibleOS, so the
Docker build context is this repository alone and a change to temper cannot
silently change what the container builds.

```sh
scripts/sync-temper.sh --from /path/to/CrucibleOS   # refresh
scripts/sync-temper.sh --check                      # fail if drifted
```

`--check` compares hashes of the tracked files, which is the form CI wants:
a vendored copy that has drifted is a bug whether or not it compiles.

## Licensing

See [ATTRIBUTION](ATTRIBUTION) and [LICENSE](LICENSE).
