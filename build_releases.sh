#!/bin/bash
set -e

# birdhub multi-architecture release build.
# Requirements: rust, tar, sha256sum; `cross` for the foreign targets.
#
# Each artifact is a directory tarball: the binaries plus the configs,
# LICENSE and README a new operator needs. The desktop console rides in the
# native GNU tarball — the headless binary is what servers get.

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
OUTPUT_DIR="releases/v$VERSION"
PACKAGE_NAME="birdhub"

# x86_64-unknown-linux-gnu:   standard Linux (Fedora, Arch, Debian) — the
#                             console ships here, where a GPU and a desktop
#                             session are a fair assumption
# x86_64-unknown-linux-musl:  static, for Alpine and scratch containers
# aarch64-unknown-linux-musl: ARM64 servers and routers, static
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
)

echo "Building birdhub v$VERSION..."
mkdir -p "$OUTPUT_DIR"

for TARGET in "${TARGETS[@]}"; do
    echo "=================================================="
    echo "Building for target: $TARGET"
    echo "=================================================="

    # Native cargo for the host, cross for foreign architectures and libc.
    if [ "$TARGET" == "x86_64-unknown-linux-gnu" ]; then
        cargo build --release --locked --target "$TARGET"
        cargo build --release --locked --target "$TARGET" -p birdhub-console
    else
        if ! command -v cross &> /dev/null; then
            echo "cross is not installed. Installing via cargo..."
            cargo install cross --git https://github.com/cross-rs/cross
        fi
        cross build --release --locked --target "$TARGET"
    fi

    STAGE="$OUTPUT_DIR/${PACKAGE_NAME}-v$VERSION-$TARGET"
    rm -rf "$STAGE"
    mkdir -p "$STAGE/bin"

    cp "target/$TARGET/release/$PACKAGE_NAME" "$STAGE/bin/"
    if [ -f "target/$TARGET/release/birdhub-console" ]; then
        cp "target/$TARGET/release/birdhub-console" "$STAGE/bin/"
    fi
    cp LICENSE README.md "$STAGE/"
    cp hub-config.toml client-config.toml "$STAGE/"

    TAR_NAME="$PACKAGE_NAME-v$VERSION-$TARGET.tar.gz"
    echo "Packaging $TAR_NAME..."
    tar -czf "$OUTPUT_DIR/$TAR_NAME" -C "$OUTPUT_DIR" "$(basename "$STAGE")"

    echo "Generating checksum for $TAR_NAME..."
    (cd "$OUTPUT_DIR" && sha256sum "$TAR_NAME" > "$TAR_NAME.sha256")

    rm -rf "$STAGE"
    echo "Successfully packaged $TARGET."
done

echo "=================================================="
echo "All builds complete! Artifacts located in $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR"
echo "=================================================="
