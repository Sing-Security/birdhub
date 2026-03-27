# VISP Architecture: End-to-End Testing Guide

This guide outlines how to fully test the VISP (Virtual ISP) architecture in a real-world or simulated local environment. The system operates in two distinct modes: **Hub** and **Client**.

## Prerequisites

Ensure the following dependencies are installed on your test machines:
- **Linux** with root privileges (required for `nftables` and `iproute2`)
- **NetBird** (Identity Provider & Mesh)
- **Shadowsocks-libev** (`ss-server` and `ss-local` binaries in your PATH)
- **I2Pd** (For anonymous transparent routing)

---

## Phase 1: Running the Hub

The Hub acts as the secure exit node and identity-gated control plane. It automatically generates in-memory Shadowsocks passwords, rotates them hourly, and serves them to authorized NetBird peers.

### 1. Hub `config.toml`

Create a `config.toml` on the machine acting as the Hub (e.g., a VPS or a dedicated local node):

```toml
[app]
mode = "hub"
```

### 2. Start the Hub

```bash
cargo build --release
sudo ./target/release/birdhub
```

**Expected Output:**
- The agent detects `mode = "hub"`.
- Generates a secure atomic password.
- Spawns `ss-server` securely in the background.
- Axum HTTP server binds to `0.0.0.0:8080` (or the configured NetBird IP).
- You will see logs indicating the Key Rotation loop has started (rotates every 3600 seconds).

---

## Phase 2: Running the Client

The Client connects to the Hub's control plane via the NetBird mesh, fetches the dynamic password, and configures the local OS to route traffic transparently.

### 1. Client `config.toml`

Create a `config.toml` on your client machine (laptop/desktop):

```toml
[app]
mode = "client"

[exit]
mode = "manual"
primary = "us"

[watchdog]
check_interval_secs = 30

[i2p]
enabled = true
router_ip = "127.0.0.1"
http_proxy_port = 4444
socks_proxy_port = 4446
dns_port = 4447

[[transports]]
name = "us-exit"
server_address = "100.64.0.1" # The NetBird IP of your Hub
server_port = 8388
method = "aes-256-gcm"
local_port = 1080
mark = 101
```

### 2. Start the Client

```bash
sudo ./target/release/birdhub
```

**Expected Output:**
- The agent detects `mode = "client"`.
- Authenticates via NetBird API.
- Flushes routing tables and sets up `nftables` kill switches.
- Hits `http://100.64.0.1:8080/auth` to fetch the dynamic `ss-server` password.
- Spawns `ss-local` securely using environment variables.
- Starts the embedded DNS Split-Horizon Proxy on `127.0.2.53:53`.

---

## Phase 3: Verifying Network Flows

With the Client agent running, open a new terminal and test the transparent routing capabilities.

### Test 1: Public Internet (Exit via Hub)
Verify that your IP has changed to the Hub's public IP:
```bash
curl -I https://cloudflare.com
curl ifconfig.me
```
*Traffic flows through the local `ss-local` tunnel, exiting at the Hub.*

### Test 2: Internal Mesh (Split-Horizon DNS)
Verify that internal `.netbird.cloud` domains bypass the Shadowsocks tunnel:
```bash
ping some-peer.netbird.cloud
```
*The embedded DNS proxy catches `.netbird.cloud`, resolves it via the mesh, and `iproute2` routes it directly over the `wt0` interface.*

### Test 3: I2P Transparent Proxy
Ensure you have `i2pd` running (`sudo systemctl start i2pd`).
```bash
curl -I http://stats.i2p
```
*The DNS proxy catches `.i2p`, fetches a fake IP from `i2pd:4447`, and `nftables` intercepts the TCP connection, redirecting it to `i2pd:4444`. No browser configuration required!*

---

## Phase 4: Self-Healing & Teardown

### Testing Key Rotation
Leave the system running for over an hour. You will see the Hub log: `Hub: Rotating Shadowsocks Password...`. 
The Client's Watchdog will detect the connection drop, automatically query the `/auth` endpoint for the new password, and restart `ss-local` without manual intervention.

### Teardown
When you are done testing, stop the Client agent (`Ctrl+C`). Clean up the kernel modifications:
```bash
# Flush policy routing
sudo ip rule del fwmark 101 table 101 2>/dev/null
sudo ip route flush table 101

# Flush firewall
sudo nft flush ruleset

# Kill stray processes
sudo killall ss-local ss-server
```
