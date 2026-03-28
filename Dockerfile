# ==============================================================================
# Build Stage
# ==============================================================================
FROM rustlang/rust:nightly-bookworm-slim AS builder

# Install system build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/birdhub

# Copy the entire project context at once to ensure workspace members
# and their relative paths (like crates/temper) are correctly resolved
COPY . .

# Build the release binary
RUN cargo build --release

# ==============================================================================
# Runtime Stage
# ==============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies:
# - nftables: Required for NftManager to apply firewall rules
# - iproute2: Required for RouteManager to manipulate routing tables
# - ca-certificates: Required for secure connections to NetBird/Hub APIs
# - procps: For general process management/debugging
RUN apt-get update && apt-get install -y \
    nftables \
    iproute2 \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories for the agent's operations
# src/dns.rs expects /etc/unbound/unbound.conf.d/ to exist for writing configs
RUN mkdir -p /etc/unbound/unbound.conf.d/ /etc/birdhub

# Copy the binary from the builder stage
COPY --from=builder /usr/src/birdhub/target/release/birdhub /usr/local/bin/birdhub

# Set up the multi-call mock script for system binaries.
# This intercepts calls to netbird, systemctl, nft, and ip to allow
# running the agent in lightweight containers without real systemd/unbound.
COPY mock-netbird.sh /usr/local/bin/mock-system
RUN chmod +x /usr/local/bin/mock-system && \
    ln -s /usr/local/bin/mock-system /usr/local/bin/netbird && \
    ln -s /usr/local/bin/mock-system /usr/local/bin/systemctl && \
    ln -s /usr/local/bin/mock-system /usr/local/bin/nft && \
    ln -s /usr/local/bin/mock-system /usr/local/bin/ip

# Ensure /usr/local/bin is at the front of PATH so mocks are preferred
ENV PATH="/usr/local/bin:${PATH}"

WORKDIR /etc/birdhub

# Labels for the image
LABEL org.opencontainers.image.source="https://github.com/visp-network/birdhub"
LABEL org.opencontainers.image.description="VISP Network Agent - Identity, Transport, and Routing Controller"

# Set the entrypoint to the birdhub binary
ENTRYPOINT ["birdhub"]
