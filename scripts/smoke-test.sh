#!/usr/bin/env bash
#
# Pre-install smoke test — run BEFORE installing any build over the working app.
#
#   scripts/smoke-test.sh          # hermetic: Rust tests + frontend typecheck/build
#   scripts/smoke-test.sh --full   # + OS-keychain regression tests (macOS desktop,
#                                  #   may touch the real keychain with test-only
#                                  #   service names) + live bridge round-trip if
#                                  #   the app is running
#
# Exists because we shipped builds that passed partial checks while the real
# user flow (quick unlock, autofill) was broken. Rule: no install without a
# green smoke run; never claim a flow works without exercising THAT flow.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
FULL="${1:-}"

step() { printf '\n==> %s\n' "$1"; }

step "Rust: hermetic workspace tests"
cargo test --quiet

step "Rust: desktop app compiles"
cargo build --quiet -p vault-desktop

step "Frontend: typecheck + build"
(cd apps/desktop && npm run --silent build)

if [ "$FULL" = "--full" ]; then
  if [ "$(uname)" = "Darwin" ]; then
    step "Keychain regression tests (quick-unlock drift heal)"
    cargo test --quiet -p vault-store -- --ignored
  fi

  step "Live bridge round-trip (only if the app is running)"
  BRIDGE="$HOME/Library/Application Support/no.sybr.vault/native-bridge.json"
  if [ -f "$BRIDGE" ] && [ -x target/release/vault-native-host ]; then
    python3 - <<'PY'
import json, struct, subprocess, sys
msg = json.dumps({"type": "hello", "version": "smoke"}).encode()
p = subprocess.run(["target/release/vault-native-host"],
                   input=struct.pack("<I", len(msg)) + msg,
                   capture_output=True, timeout=10)
out = p.stdout
if len(out) < 4:
    sys.exit("native host gave no response")
n = struct.unpack("<I", out[:4])[0]
resp = json.loads(out[4:4 + n])
print(f"   native host reachable; app_connected={resp.get('app_connected')}")
PY
  else
    echo "   (skipped: app not running or native host not built)"
  fi
fi

printf '\nSMOKE OK\n'
