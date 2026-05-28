#!/usr/bin/env bash
# install.sh — opinionated installer for Kali / Debian / Ubuntu / macOS.
#
# Picks the best install method available on the current system, in order:
#   1. pipx install .            (preferred — isolated venv, shortcut in PATH)
#   2. pip install --user .      (PEP 668 hosts may need --break-system-packages)
#
# After install you get two shortcuts in ~/.local/bin:
#   netexec-automator    # full name
#   nxa                  # short alias
#
# Usage:
#   ./scripts/install.sh                  # auto-detect, install from current repo
#   ./scripts/install.sh --uninstall      # remove the install
#   ./scripts/install.sh --force-pip      # skip pipx even if available

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

color() { printf "\033[1;36m==> %s\033[0m\n" "$*"; }
warn()  { printf "\033[1;33m!! %s\033[0m\n"  "$*" >&2; }
fail()  { printf "\033[1;31mXX %s\033[0m\n"  "$*" >&2; exit 1; }

UNINSTALL=0
FORCE_PIP=0
for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=1 ;;
        --force-pip) FORCE_PIP=1 ;;
        -h|--help)
            sed -n '2,16p' "$0"; exit 0 ;;
        *) fail "unknown flag: $arg" ;;
    esac
done

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || fail "$PY not found"

PY_VER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="$(echo "$PY_VER" | cut -d. -f1)"
PY_MINOR="$(echo "$PY_VER" | cut -d. -f2)"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    fail "Python 3.10+ required, found $PY_VER"
fi

# ---- uninstall ---------------------------------------------------------

if [ "$UNINSTALL" = "1" ]; then
    color "uninstalling netexec-automator"
    if command -v pipx >/dev/null && pipx list 2>/dev/null | grep -q netexec-automator; then
        pipx uninstall netexec-automator
    elif "$PY" -m pip show netexec-automator >/dev/null 2>&1; then
        "$PY" -m pip uninstall -y netexec-automator
    else
        warn "no netexec-automator install detected (pipx or pip)"
    fi
    color "done"
    exit 0
fi

# ---- install -----------------------------------------------------------

cd "$ROOT"

if [ "$FORCE_PIP" = "0" ] && command -v pipx >/dev/null; then
    color "installing via pipx (preferred)"
    # --force lets the script be re-run idempotently
    pipx install --force "$ROOT"
    INSTALL_METHOD="pipx"
else
    if command -v pipx >/dev/null; then
        color "skipping pipx (--force-pip passed)"
    else
        color "pipx not found, falling back to pip --user"
    fi

    PIP_FLAGS=(--user --upgrade)
    # PEP 668: Debian/Kali block system pip installs by default; --user
    # generally avoids the message but newer apt distros may need the override.
    if "$PY" -m pip install --user --upgrade --help 2>&1 | grep -q break-system-packages; then
        PIP_FLAGS+=(--break-system-packages)
    fi
    "$PY" -m pip install "${PIP_FLAGS[@]}" "$ROOT"
    INSTALL_METHOD="pip --user"
fi

# ---- PATH hint ---------------------------------------------------------

LOCAL_BIN="$HOME/.local/bin"
case ":$PATH:" in
    *":$LOCAL_BIN:"*) ;;
    *)
        warn "$LOCAL_BIN is not in your PATH. Add this to your shell rc:"
        echo "    export PATH=\"$LOCAL_BIN:\$PATH\""
        ;;
esac

color "installed via $INSTALL_METHOD"

# ---- sanity check ------------------------------------------------------

if command -v nxa >/dev/null; then
    color "shortcut 'nxa' available at $(command -v nxa)"
    nxa --help | head -3 || true
elif [ -x "$LOCAL_BIN/nxa" ]; then
    color "shortcut 'nxa' installed at $LOCAL_BIN/nxa (add to PATH to use directly)"
else
    warn "'nxa' shortcut not found in PATH; pipx/pip may have installed elsewhere"
fi
