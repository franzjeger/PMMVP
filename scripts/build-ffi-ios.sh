#!/usr/bin/env bash
# Build vault-ffi for iOS and stage the static libs where the linker looks.
#
# One .a per platform in its own directory, picked by the SDK-conditional
# LIBRARY_SEARCH_PATHS in apps/ios/project.yml. Two are needed because device
# and simulator are different *platforms*, not two architectures of one.
#
# NOT an xcframework, though docs/IOS.md originally asked for one and the first
# cut of this script built one. Xcode resolves a framework dependency when it
# sets the target up — before any pre-build script runs — so an xcframework this
# project builds itself can never exist in time:
#
#   error: There is no XCFramework found at '.../libs/VaultFFI.xcframework'
#   note: Run script build phase 'Build vault-ffi (Rust xcframework)' will be run
#         during every build
#
# Library search paths are resolved at LINK time, after this script has run,
# which is also exactly how apps/macos links the same library. An xcframework is
# the right packaging for a binary shipped to someone else; for a library built
# from source in the same repo it only breaks a clean checkout.
#
# Run from anywhere; the Xcode pre-build phase in apps/ios/project.yml calls it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/apps/ios/libs"

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

# Separate directories, not separate filenames: the linker is given one search
# path per SDK and asks for -lvault_ffi in both.
echo "==> staging into $OUT"
mkdir -p "$OUT/device" "$OUT/simulator"
cp -f "$ROOT/target/$DEVICE_TARGET/release/libvault_ffi.a" "$OUT/device/libvault_ffi.a"
cp -f "$ROOT/target/$SIM_TARGET/release/libvault_ffi.a" "$OUT/simulator/libvault_ffi.a"

echo "==> device:    $OUT/device/libvault_ffi.a"
echo "==> simulator: $OUT/simulator/libvault_ffi.a"
