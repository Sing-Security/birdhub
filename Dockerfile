# ==============================================================================
# birdhub — one image, two roles
# ==============================================================================
#
# There is one image and two containers (`docker compose up`): a hub and a
# client. They are the same binary reading different configs, because the two
# roles share every part of the crypto and differ only in which end of the
# session they drive.
#
# The image needs nothing from the host. No `NET_ADMIN`, no `/dev/net/tun`, no
# nftables, no routing table surgery — the tunnel is a TCP connection carrying
# one Temper session, and the destination is named inside it. That is what
# makes the same compose file work on Linux, macOS and Windows: it never asks
# Docker for a capability those platforms grant differently.

# ------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------
FROM rustlang/rust:nightly-bookworm-slim AS builder

WORKDIR /usr/src/birdhub

# The workspace is one package plus the vendored `crates/temper`, and
# `Cargo.lock` is committed, so `--locked` is meaningful: the image either
# builds the exact dependency tree that was tested, or it fails loudly.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

# temper is edition 2024 with RustCrypto prereleases; the pinned nightly is the
# toolchain it is developed against, and the image tracks it deliberately.
RUN cargo build --release --locked --bin birdhub

# ------------------------------------------------------------------------------
# Runtime
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim

# Env features only — nothing here links a C library, so there is no runtime
# dependency beyond libc and no package to install.

# Unprivileged, and a fixed uid so a bind-mounted key directory keeps working
# across hosts.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin birdhub \
    && mkdir -p /etc/birdhub/keys \
    && chown -R birdhub:birdhub /etc/birdhub

COPY --from=builder /usr/src/birdhub/target/release/birdhub /usr/local/bin/birdhub

# Both role configs are baked in; compose selects one with `command:`. Nothing
# is bind-mounted from the host, which is the part that differs most between
# Docker Desktop on Windows, macOS and Linux.
COPY --chown=birdhub:birdhub hub-config.toml client-config.toml /etc/birdhub/

# The demo's enrollment flow, run once by the `init` service. Ships in the
# image rather than the compose file so `docker compose up` stays a single
# readable command.
COPY --chown=birdhub:birdhub scripts/enroll-demo.sh /usr/local/share/birdhub/enroll-demo.sh

# The key directory is the one thing that must outlive the container: a node's
# identity is its keypair, and regenerating it changes who the node is.
VOLUME ["/etc/birdhub/keys"]

USER birdhub
WORKDIR /etc/birdhub
ENTRYPOINT ["birdhub"]
CMD ["/etc/birdhub/hub-config.toml"]
