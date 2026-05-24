#!/usr/bin/env bash
# update-nxc.sh — install or update the official NetExec (`nxc`) binary.
#
# NetExec publishes PyInstaller-built standalone binaries on its GitHub
# Releases page (`nxc-ubuntu-latest.zip`, `nxc-macOS-latest.zip`,
# `nxc-windows-latest.zip`). Some releases ship no asset at all, so this
# script walks recent releases until it finds one with an asset matching
# your platform.
#
# By default it installs to $HOME/.local/bin/nxc (no sudo required).
# Idempotent: if the installed version matches the latest release tag, no
# download happens unless --force is passed.
#
# Usage:
#   ./scripts/update-nxc.sh                 # detect platform, install/update
#   ./scripts/update-nxc.sh --prefix /usr/local/bin    # custom install dir
#   ./scripts/update-nxc.sh --tag v1.5.0    # pin to a specific release tag
#   ./scripts/update-nxc.sh --check         # dry-run: show what would happen
#   ./scripts/update-nxc.sh --force         # reinstall even if version matches
#
# Env knobs (same effect as the flags):
#   PREFIX=/usr/local/bin TAG=v1.5.0 FORCE=1 CHECK=1 ./scripts/update-nxc.sh

set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local/bin}"
TAG="${TAG:-}"
FORCE="${FORCE:-0}"
CHECK="${CHECK:-0}"
GH_REPO="Pennyw0rth/NetExec"
RELEASES_PAGE_SIZE=10        # how far back to walk when latest has no assets

# ---- arg parsing ----
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --tag)    TAG="$2"; shift 2 ;;
        --force)  FORCE=1; shift ;;
        --check)  CHECK=1; shift ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

# ---- helpers ----
color() { printf "\033[1;36m==> %s\033[0m\n" "$*"; }
warn()  { printf "\033[1;33m!! %s\033[0m\n"  "$*" >&2; }
fail()  { printf "\033[1;31mXX %s\033[0m\n"  "$*" >&2; exit 1; }
need()  { command -v "$1" >/dev/null || fail "$1 is required but not in PATH"; }

need curl
need unzip
need python3

# ---- platform detection → asset filename pattern ----
UNAME_S="$(uname -s)"
case "$UNAME_S" in
    Linux)   ASSET="nxc-ubuntu-latest.zip" ;;
    Darwin)  ASSET="nxc-macOS-latest.zip" ;;
    MINGW*|MSYS*|CYGWIN*) ASSET="nxc-windows-latest.zip" ;;
    *) fail "unsupported platform: $UNAME_S (use pip install netexec instead)" ;;
esac
color "platform: $UNAME_S → asset $ASSET"

# ---- discover the release + asset URL ----
if [ -n "$TAG" ]; then
    color "pinned to tag $TAG"
    API_URL="https://api.github.com/repos/$GH_REPO/releases/tags/$TAG"
else
    API_URL="https://api.github.com/repos/$GH_REPO/releases?per_page=$RELEASES_PAGE_SIZE"
fi

RELEASE_JSON="$(curl -fsSL "$API_URL")"

read -r RELEASE_TAG ASSET_URL < <(printf "%s" "$RELEASE_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
releases = [data] if isinstance(data, dict) else data
asset = '$ASSET'
for r in releases:
    for a in r.get('assets', []) or []:
        if a.get('name') == asset:
            print(r['tag_name'], a['browser_download_url'])
            sys.exit(0)
sys.exit(1)
") || fail "no recent release exposes $ASSET — try --tag <known-tag> or pip install netexec"

color "latest release with this asset: $RELEASE_TAG"

# ---- compare against installed version ----
INSTALLED_TAG=""
if command -v nxc >/dev/null; then
    # `nxc --version` prints something like "NetExec Version : 1.5.0 (deadbeef)"
    INSTALLED_TAG="v$(nxc --version 2>/dev/null | grep -Eio 'version[[:space:]:]+[0-9]+\.[0-9]+\.[0-9]+' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [ "$INSTALLED_TAG" = "v" ] && INSTALLED_TAG=""
fi

if [ -n "$INSTALLED_TAG" ]; then
    color "currently installed: $INSTALLED_TAG (at $(command -v nxc))"
else
    color "no existing nxc detected in PATH"
fi

if [ "$INSTALLED_TAG" = "$RELEASE_TAG" ] && [ "$FORCE" = "0" ]; then
    color "already up-to-date — pass --force to reinstall"
    exit 0
fi

[ "$CHECK" = "1" ] && { color "(--check) would download $ASSET_URL and install to $PREFIX/nxc"; exit 0; }

# ---- download + extract + install ----
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

color "downloading $ASSET_URL"
curl -fsSL -o "$TMP/$ASSET" "$ASSET_URL"

color "extracting"
unzip -q -o "$TMP/$ASSET" -d "$TMP/extracted"
# The zip typically contains a single 'nxc' (Linux/Mac) or 'nxc.exe' (Windows) binary
BIN_NAME="nxc"
[ "$UNAME_S" = "MINGW"* ] || [ "$UNAME_S" = "MSYS"* ] || [ "$UNAME_S" = "CYGWIN"* ] && BIN_NAME="nxc.exe"
BIN_PATH="$(find "$TMP/extracted" -type f \( -name "$BIN_NAME" -o -name 'nxc*' \) | head -1)"
[ -z "$BIN_PATH" ] && fail "binary not found inside zip — contents: $(ls "$TMP/extracted")"

mkdir -p "$PREFIX"
DEST="$PREFIX/$BIN_NAME"
cp "$BIN_PATH" "$DEST"
chmod +x "$DEST"

# macOS: strip the quarantine attribute so Gatekeeper doesn't block first run
if [ "$UNAME_S" = "Darwin" ] && command -v xattr >/dev/null; then
    xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
fi

SHA="$(shasum -a 256 "$DEST" | awk '{print $1}')"
color "installed: $DEST ($RELEASE_TAG, sha256 $SHA)"

# Helpful PATH hint if the install dir isn't already in PATH
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) warn "$PREFIX is not in your PATH — add this to your shell rc:"
       echo "    export PATH=\"$PREFIX:\$PATH\"" ;;
esac

# Sanity check
if "$DEST" --version >/dev/null 2>&1; then
    color "binary runs: $($DEST --version 2>&1 | head -1)"
else
    warn "the binary did not respond to --version; it may need extra libs at runtime"
fi
