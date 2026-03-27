# VISP (Virtual ISP) - Birdhub

![Rust](https://img.shields.io/badge/rust-stable-orange.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)
![Status](https://img.shields.io/badge/status-Active%20Development-brightgreen.svg)

## Overview

VISP (Virtual ISP) is a Zero-Trust overlay network architecture engineered for secure, segmented routing. It is built by combining **NetBird**, which acts as the Identity Provider (IdP) and Mesh network, with **Shadowsocks**, which serves as the Encrypted Transport Layer. This unified architecture ensures identity-verified, deeply encrypted network tunnels.

## Dual-Mode Operation

The architecture operates in two distinct modes to facilitate secure connectivity:

- **Hub Mode**: Acts as the Control Plane for the network. It handles incoming connections, enforces identity via NetBird, and manages **Atomic hourly password rotation** for Shadowsocks. This ensures forward secrecy and severely limits the window of opportunity for any compromised credentials.
- **Client Mode**: Operates as a transparent OS router. It seamlessly captures and directs outbound traffic through the Shadowsocks encrypted transport layer without requiring complex manual OS network configuration from the end user.

## Embedded DNS Split-Horizon Proxy

To ensure traffic is intelligently and securely routed, VISP features an embedded DNS Split-Horizon Proxy. It transparently intercepts and categorizes DNS queries at the network layer based on their target TLD:

- **`.netbird.cloud` / `.orbit.lfam.us`**: Queries are routed directly to the Hubs over the secure NetBird mesh.
- **Public Internet**: Standard queries are resolved and routed securely out through the Shadowsocks tunnel to prevent local ISP snooping and geo-leaks.
- **`.i2p`**: Queries are intercepted and directed to local or remote I2P routers, enabling seamless, native access to anonymous network resources.

## I2P Integration & Configuration

VISP places a strong emphasis on network flexibility and anonymity, particularly for `.i2p` traffic. In your `config.toml`, the `[i2p]` block explicitly supports specifying a `router_ip`. 

This fully supports using a **remote I2P node** rather than forcing a local instance on every client. By configuring a remote I2P node (e.g., pointing `router_ip` to a dedicated Hub on the mesh), administrators can build sophisticated network segments, offloading I2P routing to dedicated, isolated hardware while transparently providing `.i2p` access to all clients on the VISP network.

## Quick Start & Setup

1. **Dependencies**: Ensure you have `netbird`, `nftables`, `iproute2`, and optionally `i2pd` installed on your host system.
2. **Configure**: Adjust your `config.toml` in the project root. Ensure you set the correct `mode` (`hub` or `client`), configure your NetBird credentials, and define your `[i2p]` network settings.
3. **Build & Run**: 
   ```bash
   cargo build --release
   sudo ./target/release/birdhub
   ```
   *(Note: The agent must be run as root to manipulate `nftables` and `iproute2` for transparent routing.)*
4. **Test**: Refer to `TESTING.md` for a complete guide on validating the deployment. This includes instructions on testing Hub-to-Client connectivity, verifying the atomic hourly password rotations, and auditing the DNS Split-Horizon routing behavior.

## License

PROPRIETARY AND CONFIDENTIAL. All rights reserved pending formal consultation with a legal agent. See the `LICENSE` file for full details.