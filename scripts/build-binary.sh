#!/usr/bin/env bash
# build-binary.sh — produce a standalone `nxa` binary via PyInstaller.
#
# Useful when the target host has no Python (or a too-old one) — the
# resulting binary embeds the interpreter and is ~50 MB. Output ends up
# in dist/nxa (single-file executable).
#
# Usage:
#   ./scripts/build-binary.sh                       # builds dist/nxa
#   ./scripts/build-binary.sh --install /usr/local/bin   # also copy to PREFIX

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

color() { printf "\033[1;36m==> %s\033[0m\n" "$*"; }
fail()  { printf "\033[1;31mXX %s\033[0m\n"  "$*" >&2; exit 1; }

INSTALL_PREFIX=""
for arg in "$@"; do
    case "$arg" in
        --install) shift; INSTALL_PREFIX="${1:-}"; shift || true ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    esac
done

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || fail "$PY not found in PATH"

# Install PyInstaller in an isolated venv to avoid touching system Python.
VENV="$ROOT/.pyinstaller-venv"
if [ ! -d "$VENV" ]; then
    color "creating build venv at $VENV"
    "$PY" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip pyinstaller
fi

color "building standalone binary with PyInstaller"
cd "$ROOT"
"$VENV/bin/pyinstaller" \
    --onefile \
    --name nxa \
    --distpath "$ROOT/dist" \
    --workpath "$ROOT/.pyinstaller-build" \
    --specpath "$ROOT/.pyinstaller-build" \
    --add-data "scripts/update-nxc.sh:_scripts" \
    --hidden-import netexec_automator \
    --hidden-import netexec_automator.cli \
    "$ROOT/netexec-automator.py"

BIN="$ROOT/dist/nxa"
[ -x "$BIN" ] || fail "build failed — $BIN not produced"
SIZE="$(du -sh "$BIN" | awk '{print $1}')"
SHA="$(shasum -a 256 "$BIN" | awk '{print $1}')"
color "built: $BIN  ($SIZE, sha256 $SHA)"

if [ -n "$INSTALL_PREFIX" ]; then
    mkdir -p "$INSTALL_PREFIX"
    cp "$BIN" "$INSTALL_PREFIX/nxa"
    ln -sf "$INSTALL_PREFIX/nxa" "$INSTALL_PREFIX/netexec-automator"
    color "installed to $INSTALL_PREFIX/nxa (with symlink netexec-automator → nxa)"
fi
