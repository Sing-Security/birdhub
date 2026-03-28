# VISP (Virtual ISP) - Birdhub

![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)
![Status](https://img.shields.io/badge/status-Active%20Development-brightgreen.svg)

## Overview

VISP (Virtual ISP) is a Zero-Trust overlay network architecture engineered for secure, segmented routing. It is built on the **Golden Rule of VISP**:

*   **Identity** = NetBird (Mesh & Peer Verification)
*   **Transport** = Temper (Cryptographic Tunneling)
*   **Brain** = Birdhub Agent (Routing & Policy Enforcement)

By combining NetBird's mesh identity with the **Temper** cryptographic protocol, VISP ensures identity-verified, post-quantum resilient network tunnels with high-performance streaming encryption.

## The Temper Transport Protocol

Birdhub has transitioned from traditional proxy protocols to **Temper**, a custom cryptographic transport designed for the VISP architecture. 

-   **3-Phase Handshake**: Uses Post-Quantum Cryptography (PQC) with **Seals** (Signatures) and **Envelopes** (KEM) to establish forward-secure session keys.
-   **Lock-Free Rotation**: Utilizes `ArcSwap` for hourly master key rotations with zero throughput impact.
-   **Streaming Encryption**: Optimized ChaCha20-Poly1305 authenticated encryption for low-latency data transfer.
-   **DPI Evasion**: Every packet includes a randomized obfuscation header (16-64 bytes) to frustrate Deep Packet Inspection and traffic analysis.
-   **Replay Protection**: Built-in sliding window bitmask to prevent packet injection and replay attacks.

## Dual-Mode Operation

The architecture operates in two distinct modes:

-   **Hub Mode**: Acts as the network's Control and Data Plane. It listens for authenticated NetBird peers, performs the Temper handshake, and routes traffic to the destination. Hubs rotate their master key material hourly to ensure long-term security.
-   **Client Mode**: Operates as a transparent OS router. It initiates handshakes with Hubs and captures local traffic via `nftables` and `iproute2`, tunneling it securely through Temper without requiring manual browser or app configuration.

## Embedded DNS Split-Horizon Proxy

VISP features a built-in DNS proxy that ensures requests match the physical exit of the transport tunnel, preventing geo-leaks:

-   **Internal Mesh**: `.netbird.cloud` queries are resolved directly via the NetBird mesh.
-   **Public Internet**: Standard queries are resolved via the active Hub's DNS exit.
-   **`.i2p`**: Queries are intercepted and directed to local or remote I2P routers for native anonymous browsing.

## I2P Integration

VISP supports military-grade anonymity by integrating I2P. You can specify a `router_ip` in the `config.toml`, allowing clients to use a **remote I2P node** on the mesh rather than running a I2P router locally on every device.

## Quick Start & Setup

1.  **Dependencies**: Install `netbird`, `nftables`, `iproute2`, and `unbound`.
2.  **Toolchain**: This project requires **Rust Nightly** (for Edition 2024 support in the `temper` crate).
3.  **Configure**: Create a `config.toml`. Set `mode = "hub"` for servers or `mode = "client"` for end-users.
4.  **Build & Run**:
    ```bash
    cargo +nightly build --release
    sudo ./target/release/birdhub
    ```
    *(Note: Root privileges are required to manage networking tables and firewall rules.)*

## Testing

Refer to `TESTING.md` for a complete guide on validating the deployment, including instructions for the provided **Docker Compose** local test environment.

## License

PROPRIETARY AND CONFIDENTIAL. All rights reserved. See the `LICENSE` file for full details.
