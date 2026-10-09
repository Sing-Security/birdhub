# Testing birdhub

Three ways in: the suite, the containers, and two plain processes. The
negative cases at the end are the point — a relay that accepts everything
passes every positive test.

## Method 0 — the suite

```sh
cargo test
```

69 tests, none of them needing a network: config shapes (every misplaced
section is a parse-time error, the control API is opt-in and validated), the
CA flow end to end (init → export → issue → verify, with the tamper and
expiry cases), the identity/certificate match checks, the stream multiplexer
(both sides may open, ids never collide, half-close stays directional, a
reset does not disturb its neighbours, an unanswered stream is refused rather
than hung, a session's death ends every stream on it, and the operator's
shutdown ends it the same way), the target grammar, the relay's grant
enforcement — including that a refused target reaches the dialer *never*,
proven by handing
the dialer a closure that panics.

The peer path is covered end to end without a network too: directory fetches
gated by the peer grant, the registry's reconnect race, a hub pairing two
in-memory sessions with bytes spliced through, and one full exchange where
the nested Temper handshake, the service allow-list, the inner mux and a real
loopback echo server are all live at once — allowed, not-permitted and
unknown-service are three opens on that one nested session.

## Method 1 — Docker Compose

Requires only a container runtime. No root, no capabilities, no tun device.

```sh
docker compose up --build
```

Four containers: `init` (runs once, enrolls the fleet into the shared
volume), `hub`, `client`, and `origin` (busybox httpd, the thing the tunnel
dials). Watch the logs for the lines that matter:

```text
init    | enroll: done — hub.example and laptop.example certified by demo-ca
hub     | Hub: serving as 'hub.example' cert=<hex> valid …..
hub     | Hub: grant 'laptop.example' → origin:80
hub     | Hub: grant 'desktop.example' → @peer/laptop.example
hub     | Hub: data plane on 0.0.0.0:8388
client  | Node: hub 'hub.example' cert=<hex> concealment_id=<hex> at hub:8388
client  | Node: 'web' listening on 0.0.0.0:1080 -> origin:80
```

The second grant row names a node that is not in the compose file — a roster
lists the whole fleet, not just the members running beside the hub — and
Method 4 below is that node joining this same fleet from outside the
containers.

Then send traffic through the tunnel:

```sh
curl -s localhost:1080/
```

This goes host → client → Temper session → hub → origin:80, and back, and
returns the origin's page (`hello through the tunnel`). The hub's next line
names the certificate subject the session was accepted under:

```text
hub     | Hub: session <id> with 'laptop.example' (key_id=<hex>)
```

### What to check

**The identity was concealed.** That key_id appears nowhere in the bytes on
the wire. Capture the handshake and look:

```sh
sudo tcpdump -i any -X port 8388
```

You will see a length-prefixed postcard flight, then ChaCha20-Poly1305
records. You will not see a public key in the clear, and you will not see the
client's name.

**The cookie is doing its job.** With `require_cookie = true` the hub sends
`SessionChallenge` before it spends two SLH-DSA signatures on a caller. In the
capture, the first flight on the wire comes *from* the hub. Set it to `false`
and the first flight comes from the client — one fewer round trip and one more
signature per connection attempt.

**Identity survives a restart.** `docker compose restart client` must not
change the client's key_id or its certificate. Both read the same files from
the volume; a node that regenerated its identity on restart would need
re-enrolling.

**The session is shared.** Send several requests at once, then count the
hub's session lines:

```sh
for i in 1 2 3; do curl -s localhost:1080/ >/dev/null & done; wait
docker compose logs hub | grep -c "session .* with 'laptop.example'"
```

One, however many requests you make: each request is a stream on that one
session. The handshake is paid once, and a slow request cannot hold up the
next one.

## Method 2 — Two processes, no containers

```sh
cargo build --release --locked
mkdir -p /tmp/birdhub-keys
cd /tmp/birdhub-keys
```

Enroll the fleet (this is `scripts/enroll-demo.sh` with local paths):

```sh
BIN=/path/to/birdhub/target/release/birdhub
$BIN ca init --key ca.key --pub ca.pub --id local-ca
$BIN identity export --key hub.key    --pub hub.pub    --name hub.example
$BIN identity export --key client.key --pub client.pub --name laptop.example
$BIN ca issue --ca ca.key --identity hub.pub    --days 365 --out hub.cert
$BIN ca issue --ca ca.key --identity client.pub --days 365 --out client.cert
```

Write a hub config and a client config differing from
[`hub-config.toml`](hub-config.toml) and [`client-config.toml`](client-config.toml)
only in the paths and host names:

| shipped | local |
| --- | --- |
| `/etc/birdhub/keys/…` | `/tmp/birdhub-keys/…` |
| `hub:8388` | `127.0.0.1:8388` |
| `origin:80` | `127.0.0.1:8000` |

`origin` can be any local listener — `python3 -m http.server 8000` will do.

Then, in two terminals:

```sh
$BIN hub.toml
$BIN client.toml
```

and from a third:

```sh
curl -s localhost:1080/
```

This is the same thing the containers do, without the container layer — useful
when a failure could be either the config or the packaging.

## Method 3 — the peer path, three processes

Same fleet as Method 2, plus one more node. Enroll `node-b.example` and give
it a certificate; it gets no transports, only services:

```toml
# node-b.toml — [app], [identity], [ca], [peer] as above, then:
[[services]]
name = "web"
target = "127.0.0.1:8000"
clients = ["laptop.example"]

[[services]]
name = "db"
target = "127.0.0.1:8000"
clients = ["someone-else.example"]
```

The hub needs a second roster row for it — admitted, asking for nothing — and
the laptop's row needs a peer grant:

```toml
[[grants]]
client = "laptop.example"
targets = ["127.0.0.1:8000", "@peer/node-b.example"]

[[grants]]
client = "node-b.example"
targets = []
```

The laptop then adds a transport with a peer destination:

```toml
[[transports]]
name = "webpeer"
local_address = "127.0.0.1:1090"
forward_to = "node-b.example/web"
```

Run all three, wait for each node's session line, then:

```sh
curl -s localhost:1090/
```

The body comes back through the whole path — laptop → hub pairing → node-b →
its local `8000` — and three logs each show their own half:

```text
hub  | Hub: pairing 'laptop.example' with 'node-b.example'
hub  | Hub: session <id> with 'node-b.example' (key_id=<hex>)       ← registered the moment it connected
laptop | Node: peer session <id> with 'node-b.example'             ← the nested handshake
node-b | Node: peer session <id> with 'laptop.example'
node-b | Node: serving 'web' to 'laptop.example'
```

Everything after the pairing is ciphertext to the hub: it spliced streams, it
did not read them. The peer session ids on both nodes are the same session.

## Method 4 — a mixed fleet: a native node joins the containers

Membership is a certificate, not a location. `scripts/fleet-demo.sh` adds one
more node to the *same* fleet the compose file runs — `desktop.example`, a
plain process on this machine running `target/release/birdhub`, no container:

```sh
docker compose up --build -d
scripts/fleet-demo.sh
```

The script copies the fleet's CA material out of the compose volume (in a
real deployment only the certificate would travel; the CA key stays on the CA
machine), enrolls `desktop.example` with the same three commands every node
uses, and writes a config of the same shape as any other node's. The only
line that knows anything about containers is the hub's address:

```toml
[peer]
address = "127.0.0.1:8388"                    # the published port, not a service name
hub_cert = "/tmp/birdhub-fleet/keys/hub.cert"
```

`desktop` serves nothing and asks the hub for exactly one thing — a pairing
with `laptop.example`, which is the roster row quoted in Method 1:

```toml
[[transports]]
name = "webpeer"
local_address = "127.0.0.1:1090"
forward_to = "laptop.example/web"
```

`laptop`'s `web` service dials `origin:80` — resolvable only inside the
compose network, which neither the hub nor `desktop` can see or needs to.
Then:

```sh
curl -s localhost:1090/
hello through the tunnel
```

The three logs each show their half:

```text
hub-1     | Hub: pairing 'desktop.example' with 'laptop.example'
desktop   | Node: peer session <id> with 'laptop.example'
client-1  | Node: serving 'web' to 'desktop.example'
```

This is the point of the whole design: a node's environment — container, bare
metal, another OS — never enters its identity, its certificate, or its
authorization. Moving a node between environments changes `[peer] address`
and a handful of file paths, nothing else.

## Method 5 — the console and the control API

The headless binary is not the only surface. The hub (and each node) can
serve a **local JSON API** — `src/control.rs` — which is the same surface the
console's buttons call, so the two can never disagree. It is off unless the
config writes it down:

```toml
[control]
address = "127.0.0.1:8399"
```

The compose hub has this on, published to the host's loopback. With the
fleet up (Method 1), the API answers:

```sh
curl -s http://127.0.0.1:8399/status        # who the hub is
curl -s http://127.0.0.1:8399/fleet         # live sessions, oldest first
curl -s http://127.0.0.1:8399/grants        # the roster as applied
curl -s 'http://127.0.0.1:8399/events?after=0&filter=session&limit=10'
```

Actions go through it too, and each one logs an event first. The kick —
end one session; the client reconnects and is subject to whatever the
roster says *now*:

```sh
curl -s -X POST http://127.0.0.1:8399/sessions/<id>/disconnect   # {"ok":true}
```

and the full revocation loop, which is the one that matters: `PUT /grants`
with the client's row removed, then the kick — the hub's next lines are

```text
Hub: grants applied (1 rows)
Hub: session <id> with 'laptop.example' disconnected by operator
Hub: refusing 'laptop.example' (key_id=<hex>) — no grant names it …
```

`PUT /grants` rewrites the config file (comments are lost — the price of a
save button); `POST /grants/reload` re-reads a hand-edited file instead.

The **console** embeds the same core and renders it — the same shell and GPU
backend as the other desktop tools, one process, core on its own tokio
thread:

```sh
cargo run -p birdhub-console -- hub-config.toml     # or a node's config
```

Pages: Fleet (sessions + inspector + Disconnect), Roster (editor + Save /
Reload), Events (the log as data, with chips and search), Config, About —
and the node's Status / Transports / Services / Peers. The screenshots in
`shots/` are rendered by the test harness off fixture data (`cargo test -p
birdhub-console`), so a page can be looked at without a fleet.

## The negative cases

Each of these must fail, with the named line in the log. A green run of the
positive flow says nothing about any of them.

**An un-certified client is dropped.** Enroll a second identity but do not add
a grant for it, point a client at the hub with it, and watch the hub:

```text
Hub: refusing 'stranger.example' (key_id=…) — no grant names it (a node that only serves still needs an entry, with no targets)
```

Nothing is dialed, and the client learns only that its session closed. The
line appears twice in the hub log — once per session — because the client
re-establishes the session once after finding it dead, then reports what it
saw; that retry is bounded, and the report names the real cause:

```text
Node: connection from … ended: hub refused origin:80: session closed while opening the stream
```

**A non-granted target is refused before dialing.** Change the client's
`forward_to` to anything not in its grant — say `origin:81` — and both ends
name the target:

```text
Hub: origin:81 is not granted to this client
Node: connection from … ended: hub refused origin:81: origin:81 is not granted to this client
```

Set `forward_to` to a host that does not resolve at all and the same refusal
comes back: proof the grant check happens before the dial, not as a
consequence of it.

The peer-shaped refusals each name their own fix. A service the serving node
does not serve to this peer is refused after the nested handshake, before
anything is dialed there:

```text
node-b | Node: 'node-b.example' does not permit 'laptop.example' to use 'db'
laptop | Node: connection from … ended: peer 'node-b.example' refused 'db': 'node-b.example' does not permit 'laptop.example' to use 'db'
```

A peer that is granted but not connected — and a peer nobody was granted:

```text
laptop | Node: connection from … ended: directory lookup for 'ghost.example': peer 'ghost.example' is not connected
laptop | Node: connection from … ended: directory lookup for 'other.example': no grant names peer 'other.example' (reaching it is granted as "@peer/other.example")
```

The second message is the one an ungranted request produces, and it is the
only thing the requester learns: presence is told to nodes whose grants
already name the peer, never to nodes probing for one.

**A wrong CA is rejected at startup.** Point the client's `[ca] public` at a
`ca.pub` from a different fleet:

```text
certificate for 'laptop.example' is not signed by CA 'other-ca'
```

**An expired certificate is rejected.** Reissue with `--days 0`, hand it to
the client, restart:

```text
certificate expired at …, presented at …
```

Temper certificates are not revocable individually yet, so expiry plus the
hub's grant table are the whole of revocation.

**A substituted hub is rejected — twice over.** Point the client's
`[peer] hub_cert` at another fleet member's certificate and the handshake
itself dies before the substitute learns anything:

```text
Hub: handshake refused: CryptoError("ChaCha20-Poly1305 decryption failed (authentication tag mismatch)")
Node: hub session: handshake with <address> failed: Io(Custom { kind: UnexpectedEof, error: "peer closed during the session handshake" })
```

The client seals its identity to the concealment key *inside the pinned
certificate*, so a hub holding different keys cannot open flight 1 at all —
it drops the connection, and the client's next read is that EOF.

Reissue the hub's own certificate (`ca issue` again, same `hub.pub`, a
different `--days`) and the handshake succeeds — one identity, one concealment
key — but the client still refuses, on the byte-exact pin:

```text
hub presented certificate <hex> ('hub.example') but [peer] hub_cert is <hex>
```

A renewed certificate is a new file the operator has to carry to every client.
That is the cost of pinning, and this is what not paying it looks like.

**A mismatched certificate is caught at home.** Swap `client.cert` with the
hub's, or with any file the CA issued for other keys:

```text
certificate '<hex>' (for 'hub.example') does not certify this identity's ML-DSA signing key, SLH-DSA signing key, concealment key — re-export the identity and re-issue the certificate
```

All three halves are named, so fixing one file reveals the rest of the
mismatch rather than asking for another round trip.

## What is not covered

- **Direct paths between peers.** Peers reach each other and run their own
  session end to end, but the bytes still travel through the hub: there is no
  candidate exchange, no hole punching, no NAT traversal yet. The hub is the
  meeting point and the fallback path, and today it is also the only path.
- **Admission is not automatic revocation.** Dropping a `[[grants]]` row
  refuses the next session; a session already up keeps its list until the
  operator kicks it (Method 5) — the kick plus the edit is full revocation,
  but nothing tears the session down by itself.
- **A freshly connected node can be reported offline.** The hub registers a
  peer when its handshake finishes verifying; a request that arrives in that
  window is told "not connected" even though the node's own log already says
  it is up. One handshake's worth of time, and a retry clears it.
- **Denial of service.** The cookie forces a round trip per attempt, the
  replay guard bounds memory, and a serving node bounds concurrent carrier
  handshakes — but that bound is not per-peer, and a flooded hub still
  answers.
- **Remote administration.** The control API is unauthenticated and bound
  only to the address the config writes (loopback in the samples); an
  authenticated remote admin — a Temper session like every other — is not
  built yet, and until it is the API must not be published beyond the
  loopback.
- **Anything about the payload.** The tunnel carries bytes; TLS inside it is
  the caller's business and is not terminated here.
- **Operating systems other than Linux.** The source type-checks for
  `x86_64-pc-windows-gnu` (`cargo check --target x86_64-pc-windows-gnu` —
  the unix-only file-mode code is `#[cfg(unix)]`-gated), and the container
  flow runs anywhere Docker does. Nothing has been built, packaged (service
  manager, install paths), or run on Windows or macOS natively.
