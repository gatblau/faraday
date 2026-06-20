#!/usr/bin/env bash
# Build the macOS service installer (.pkg) for faradayd (ADR-031).
#
# Signing + notarization are OPTIONAL and OFF by default — an UNSIGNED .pkg is produced
# unless you opt in (no certificates are required to build/test). To sign + notarize:
#   PYS_CODESIGN_IDENTITY="Developer ID Installer: <Name> (TEAMID)"   # enables --sign
#   PYS_NOTARY_PROFILE="<notarytool keychain profile>"               # enables notarize+staple
#
# Usage: build-pkg.sh [path-to-release-binary]   (default: target/release/faradayd)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_BIN="${1:-$ROOT/target/release/faradayd}"
VERSION="${PYS_VERSION:-0.1.0}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
IDENTIFIER="dev.faraday.faradayd"
PKG="$OUT_DIR/faradayd-$VERSION.pkg"

if [ ! -x "$TARGET_BIN" ]; then
  echo "error: binary not found at $TARGET_BIN (run: cargo build --release)" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/payload/usr/local/bin" "$STAGE/scripts"
cp "$TARGET_BIN" "$STAGE/payload/usr/local/bin/faradayd"
chmod 755 "$STAGE/payload/usr/local/bin/faradayd"
cp "$ROOT/packaging/macos/scripts/postinstall" "$STAGE/scripts/postinstall"
chmod 755 "$STAGE/scripts/postinstall"

mkdir -p "$OUT_DIR"
# Conditional invocation (no array) keeps this portable to macOS's bash 3.2 under `set -u`.
if [ -n "${PYS_CODESIGN_IDENTITY:-}" ]; then
  echo "signing with: $PYS_CODESIGN_IDENTITY"
  pkgbuild --root "$STAGE/payload" --scripts "$STAGE/scripts" \
    --identifier "$IDENTIFIER" --version "$VERSION" --install-location / \
    --sign "$PYS_CODESIGN_IDENTITY" "$PKG"
else
  echo "building UNSIGNED (set PYS_CODESIGN_IDENTITY to sign) — Gatekeeper will warn on first run"
  pkgbuild --root "$STAGE/payload" --scripts "$STAGE/scripts" \
    --identifier "$IDENTIFIER" --version "$VERSION" --install-location / \
    "$PKG"
fi
echo "built $PKG"

if [ -n "${PYS_NOTARY_PROFILE:-}" ]; then
  echo "notarizing via profile: $PYS_NOTARY_PROFILE"
  xcrun notarytool submit "$PKG" --keychain-profile "$PYS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$PKG"
fi
