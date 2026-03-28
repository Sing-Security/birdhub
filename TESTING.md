# VISP Architecture: End-to-End Testing Guide

This guide outlines how to fully test the VISP (Virtual ISP) architecture using the **Temper** cryptographic transport protocol. We provide two methods: a local **Docker Compose** environment (recommended for development) and a manual **Multi-Node** deployment.

## Prerequisites

- **Linux** with root privileges (required for `nftables` and `iproute2`).
- **Rust Nightly** toolchain (Edition 2024 is required for the `temper` crate).
- **NetBird** (Identity Provider & Mesh).
- **Unbound** (For DNS split-horizon routing).

---

## Method 1: Docker Compose (Recommended)

The project includes a pre-configured Docker environment that simulates a Hub and a Client in a private 100.64.0.0/16 mesh network.

### 1. Build and Start
```bash
docker-compose build
docker-compose up
```

### 2. Verify Handshake
Watch the logs for the following sequence:
- `hub-test  | Hub: NetBird identity verified - IP: 100.64.0.1`
- `client-test | Handshake with hub-test:8388 successful. Session established.`

### 3. Test the Tunnel
In a separate terminal on your host machine, send data through the client's local listener (Port 1080):
```bash
echo "Temper Protocol Test" | nc localhost 1080
```
**Expected Result:** The Hub will receive the encrypted packet, decrypt it, and echo the plaintext back through the tunnel to your terminal.

---

## Method 2: Manual Multi-Node Deployment

### Phase 1: Running the Hub (Server)

The Hub acts as the secure exit node. It performs PQC handshakes and rotates master keys hourly.

#### 1. Hub `config.toml`
```toml
[app]
mode = "hub"

[hub_server]
bind_address = "0.0.0.0:8080"
server_port = 8388
```

#### 2. Start the Hub
```bash
cargo +nightly run --release
```

---

### Phase 2: Running the Client

#### 1. Client `config.toml`
```toml
[app]
mode = "client"

[exit]
mode = "manual"
primary = "my-hub"

[[transports]]
name = "my-hub"
server_address = "100.64.x.x" # Fedora Hub's NetBird IP
server_port = 8388
local_port = 1080
mark = 101
```

#### 2. Start the Client
```bash
sudo ./target/release/birdhub
```

---

## Phase 3: Verifying Security & Routing

### Test 1: Post-Quantum Handshake Audit
Verify that the `HubIdentitySeal` is correctly parsed. If the signature is invalid or the PQC `Envelope` fails to decapsulate, the agent will log `HandshakeFailed` and drop the connection.

### Test 2: Obfuscation & DPI Evasion
Every packet sent between the nodes should have a varying size even if the payload is constant. This is due to the randomized **Obfuscation Header** (16-64 bytes). Use `tcpdump` to verify:
```bash
sudo tcpdump -i wt0 -X port 8388
```

### Test 3: Replay Protection
The Temper protocol uses a sliding window bitmask. You can attempt to replay a captured packet using a tool like `tcpreplay`.
**Expected Result:** The receiver should log `ReplayDetected` and discard the packet without attempting decryption.

### Test 4: Split-Horizon DNS
Verify that internal mesh names resolve locally while public names resolve through the tunnel:
```bash
# Mesh Resolution
dig @127.0.0.1 some-peer.netbird.cloud
# Public Resolution (via Hub)
curl --socks5-hostname localhost:1080 https://ifconfig.me
```

---

## Self-Healing Tests

1. **Master Key Rotation**: Leave the Hub running for >1 hour. The Hub will log `Hub: Rotating master key...`. New connections will automatically use the new key version.
2. **Watchdog Recovery**: Kill the `birdhub` process on the client and restart it. The `NftManager` will re-apply the base rules and kill-switch, ensuring no cleartext leaks occur during the transition.
```bash