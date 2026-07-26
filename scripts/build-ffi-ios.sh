#!/usr/bin/env bash
# Build vault-ffi for iOS and package it as VaultFFI.xcframework.
#
# The macOS targets link a single static lib because they only ever run on one
# architecture. iOS needs two slices — the device and the simulator are different
# platforms, not different architectures of one — and an .xcframework is the only
# container Xcode accepts for that. Linking the two .a files directly instead
# fails at the *second* one with a duplicate-symbol error.
#
# Run from anywhere; the Xcode pre-build phase in apps/ios/project.yml calls it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/apps/ios/libs"
XCFRAMEWORK="$OUT/VaultFFI.xcframework"

# arm64 only, matching apps/macos (which builds aarch64-apple-darwin): an Intel
# Mac cannot run this simulator slice. Add x86_64-apple-ios here if that changes.
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET="aarch64-apple-ios-sim"

echo "==> Rust targets"
rustup target add "$DEVICE_TARGET" "$SIM_TARGET"

echo "==> cargo build ($DEVICE_TARGET, $SIM_TARGET)"
cd "$ROOT"
cargo build -p vault-ffi --release --target "$DEVICE_TARGET"
cargo build -p vault-ffi --release --target "$SIM_TARGET"

# The header ships inside the xcframework so the package is self-describing.
# apps/ios/project.yml also points HEADER_SEARCH_PATHS at the crate's include
# directory, which is what actually resolves the bridging header's #import.
HEADERS="$OUT/include"
rm -rf "$HEADERS"
mkdir -p "$HEADERS"
cp "$ROOT/crates/vault-ffi/include/vault_ffi.h" "$HEADERS/"

echo "==> xcframework"
# -create-xcframework refuses to overwrite, so clear it first.
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
    -library "$ROOT/target/$DEVICE_TARGET/release/libvault_ffi.a" -headers "$HEADERS" \
    -library "$ROOT/target/$SIM_TARGET/release/libvault_ffi.a" -headers "$HEADERS" \
    -output "$XCFRAMEWORK"

echo "==> $XCFRAMEWORK"
