#!/bin/bash
set -e

# VISP Multi-Architecture Build Script for Local Releases
# Requirements: rust, cargo, cross, tar, sha256sum

VERSION="0.1.0"
OUTPUT_DIR="releases/v$VERSION"
PACKAGE_NAME="birdhub"

# Define the targets we want to build
# x86_64-unknown-linux-gnu: Standard Linux (Fedora, Arch, Ubuntu)
# x86_64-unknown-linux-musl: Alpine Linux (static glibc)
# aarch64-unknown-linux-musl: Alpine ARM64 (static glibc)
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
)

# Aarch64 GNU target explicitly requires advanced GCC/Clang setups for rocksdb.
# Since musl handles static linkage perfectly for ARM64 servers/routers,
# we bypass aarch64-unknown-linux-gnu to avoid libclang/rocksdb C-binding nightmares.

echo "Starting local release build for VISP $VERSION..."
mkdir -p "$OUTPUT_DIR"

for TARGET in "${TARGETS[@]}"; do
    echo "=================================================="
    echo "Building for target: $TARGET"
    echo "=================================================="

    # Use cross for foreign architectures/libc, cargo for native
    if [ "$TARGET" == "x86_64-unknown-linux-gnu" ]; then
        cargo build --release --locked --target "$TARGET"
    else
        # Ensure cross is installed
        if ! command -v cross &> /dev/null; then
            echo "cross is not installed. Installing via cargo..."
            cargo install cross --git https://github.com/cross-rs/cross
        fi
        cross build --release --locked --target "$TARGET"
    fi

    # Package the binary
    BIN_PATH="target/$TARGET/release/$PACKAGE_NAME"
    TAR_NAME="$PACKAGE_NAME-v$VERSION-$TARGET.tar.gz"
    TAR_PATH="$OUTPUT_DIR/$TAR_NAME"

    echo "Packaging $TAR_NAME..."
    tar -czvf "$TAR_PATH" -C "target/$TARGET/release" "$PACKAGE_NAME"

    # Generate SHA256 checksum
    echo "Generating checksum for $TAR_NAME..."
    cd "$OUTPUT_DIR"
    sha256sum "$TAR_NAME" > "$TAR_NAME.sha256"
    cd - > /dev/null

    echo "Successfully packaged $TARGET."
done

echo "=================================================="
echo "All builds complete! Artifacts located in $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR"
echo "=================================================="
