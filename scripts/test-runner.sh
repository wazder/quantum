#!/usr/bin/env bash
# Cargo custom test runner. Re-signs the test binary with the JIT
# entitlement before exec'ing it so MAP_JIT pages can be flipped to RX
# at runtime. Configured via .cargo/config.toml.
#
# Pure-Rust binaries that don't touch MAP_JIT also pass through — the
# extra codesign call is harmless and fast.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <test-binary> [args...]" >&2
    exit 64
fi

BIN="$1"
shift

SIGN_IDENTITY="${QUANTUM_SIGN_IDENTITY:-Apple Development: tatarhasan09@gmail.com (FD43D54MNN)}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENTITLEMENTS="$REPO_ROOT/build/jit.entitlements"

if [[ ! -f "$ENTITLEMENTS" ]]; then
    echo "missing entitlements file: $ENTITLEMENTS" >&2
    exit 1
fi

# Re-sign even if already signed; --force makes it idempotent.
codesign --force --sign "$SIGN_IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --options runtime \
    "$BIN" >/dev/null 2>&1 || {
    echo "codesign failed for $BIN with identity '$SIGN_IDENTITY'" >&2
    echo "fallback: ad-hoc sign (works for local JIT but not Gatekeeper-distributable)" >&2
    codesign --force --sign - --entitlements "$ENTITLEMENTS" "$BIN"
}

exec "$BIN" "$@"
