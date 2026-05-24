#!/usr/bin/env bash
# Build a self-contained bundle for air-gapped deployment.
#
# Output: dist/netexec-automator-airgapped-<YYYYMMDD>.tar.gz containing:
#   - netexec-automator.py + README + LICENSE
#   - wheels/        Python wheels for netexec + bloodhound (+ all transitive deps)
#   - bin/nxc        (optional) latest pre-built NetExec linux-x64 binary from GitHub
#   - install-offline.sh    one-shot installer for the target host
#   - BUNDLE_README.md
#
# On the target air-gapped machine:
#   tar xzf netexec-automator-airgapped-*.tar.gz
#   cd netexec-automator-airgapped-*
#   ./install-offline.sh           # installs wheels into a venv, optionally drops nxc binary in /usr/local/bin
#
# Runs entirely with bash + standard *nix tools + python3 + pip + curl/tar.
# Network access required ONLY on the build machine.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STAMP="$(date +%Y%m%d)"
DIST_DIR="$ROOT/dist"
BUNDLE_NAME="netexec-automator-airgapped-$STAMP"
STAGING="$DIST_DIR/$BUNDLE_NAME"
WHEELS_DIR="$STAGING/wheels"
BIN_DIR="$STAGING/bin"

# --- Optional knobs (env vars) ---
PYTHON="${PYTHON:-python3}"
SKIP_NXC_BINARY="${SKIP_NXC_BINARY:-0}"     # set to 1 to skip the GitHub binary fetch
INCLUDE_BLOODHOUND="${INCLUDE_BLOODHOUND:-1}"
PIP_PLATFORM="${PIP_PLATFORM:-}"            # e.g. manylinux2014_x86_64 to cross-bundle wheels

color() { printf "\033[1;36m==> %s\033[0m\n" "$*"; }
warn()  { printf "\033[1;33m!! %s\033[0m\n"  "$*"; }
fail()  { printf "\033[1;31mXX %s\033[0m\n"  "$*"; exit 1; }

command -v "$PYTHON" >/dev/null || fail "python3 not found in PATH"
"$PYTHON" -m pip --version >/dev/null || fail "pip not available for $PYTHON"
command -v curl >/dev/null || fail "curl required to fetch NetExec binary"
command -v tar >/dev/null || fail "tar required"

color "cleaning $STAGING"
rm -rf "$STAGING"
mkdir -p "$WHEELS_DIR" "$BIN_DIR"

color "copying tool sources"
cp "$ROOT/netexec-automator.py" "$STAGING/"
cp "$ROOT/README.md"            "$STAGING/"
cp "$ROOT/LICENSE"              "$STAGING/"

color "downloading Python wheels for netexec$( [ "$INCLUDE_BLOODHOUND" = "1" ] && echo " + bloodhound" )"
PIP_PKGS=("netexec")
[ "$INCLUDE_BLOODHOUND" = "1" ] && PIP_PKGS+=("bloodhound")
PIP_DOWNLOAD_ARGS=(-d "$WHEELS_DIR" --no-cache-dir)
[ -n "$PIP_PLATFORM" ] && PIP_DOWNLOAD_ARGS+=(--platform "$PIP_PLATFORM" --only-binary=:all:)
"$PYTHON" -m pip download "${PIP_DOWNLOAD_ARGS[@]}" "${PIP_PKGS[@]}" || \
    warn "pip download failed for some packages — bundle may be incomplete"

# NetExec pre-built binary (Linux x64). Optional — script keeps going if unavailable.
if [ "$SKIP_NXC_BINARY" = "0" ]; then
    color "fetching NetExec latest binary (Linux x64) from GitHub releases"
    RELEASE_JSON="$(curl -fsSL https://api.github.com/repos/Pennyw0rth/NetExec/releases/latest || true)"
    BINARY_URL="$(printf "%s" "$RELEASE_JSON" | \
        grep -Eio 'https://[^"]+/nxc(-linux[^"]*|_linux[^"]*|-ubuntu[^"]*)?' | head -1 || true)"
    if [ -n "$BINARY_URL" ]; then
        curl -fsSL -o "$BIN_DIR/nxc" "$BINARY_URL" && chmod +x "$BIN_DIR/nxc"
        color "  → bin/nxc (sha256: $(shasum -a 256 "$BIN_DIR/nxc" | awk '{print $1}'))"
    else
        warn "no pre-built nxc binary found in latest release — wheels fallback will be used"
        rmdir "$BIN_DIR" 2>/dev/null || true
    fi
else
    color "skipping NetExec binary (SKIP_NXC_BINARY=1)"
    rmdir "$BIN_DIR" 2>/dev/null || true
fi

cat > "$STAGING/install-offline.sh" <<'INSTALL_EOF'
#!/usr/bin/env bash
# Offline installer for the netexec-automator air-gapped bundle.
# Creates a venv, installs the included wheels, optionally drops the nxc binary
# into /usr/local/bin (if present in bin/).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-$HOME/.local/share/netexec-automator/venv}"
PROFILE_LINE="export PATH=\"$VENV_DIR/bin:\$PATH\""

echo "==> using python: $($PYTHON --version)"
echo "==> creating venv at $VENV_DIR"
mkdir -p "$(dirname "$VENV_DIR")"
"$PYTHON" -m venv "$VENV_DIR"

echo "==> installing wheels offline"
"$VENV_DIR/bin/pip" install --no-index --find-links "$HERE/wheels" \
    netexec $( [ -d "$HERE/wheels" ] && ls "$HERE/wheels" | grep -qi bloodhound && echo bloodhound )

if [ -x "$HERE/bin/nxc" ]; then
    if [ -w /usr/local/bin ]; then
        cp "$HERE/bin/nxc" /usr/local/bin/nxc
        echo "==> installed bin/nxc → /usr/local/bin/nxc"
    else
        echo "!! /usr/local/bin not writable; manually:  sudo cp $HERE/bin/nxc /usr/local/bin/"
    fi
fi

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/share/netexec-automator}"
mkdir -p "$INSTALL_DIR"
cp "$HERE/netexec-automator.py" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/netexec-automator.py"
ln -sf "$INSTALL_DIR/netexec-automator.py" "$VENV_DIR/bin/netexec-automator"

cat <<MSG

============================================================
  netexec-automator installed offline.

  Activate the venv with:
      source "$VENV_DIR/bin/activate"

  Or add this line to ~/.bashrc / ~/.zshrc:
      $PROFILE_LINE

  Then run:
      netexec-automator --help

  Tool source: $INSTALL_DIR/netexec-automator.py
============================================================
MSG
INSTALL_EOF
chmod +x "$STAGING/install-offline.sh"

cat > "$STAGING/BUNDLE_README.md" <<EOF
# NetExec Automator — Air-gapped Bundle ($STAMP)

This tarball is a self-contained deployment artifact for offline / air-gapped
systems. It contains everything needed to run \`netexec-automator\` against
internal targets without ever touching the public internet.

## Contents

- \`netexec-automator.py\` — the tool itself (pure stdlib, no extra deps).
- \`wheels/\` — pip wheels for NetExec ($([ "$INCLUDE_BLOODHOUND" = "1" ] && echo "and bloodhound-python ")and all transitive dependencies).
- \`bin/nxc\` — optional pre-built NetExec Linux x64 binary (if available in the latest GitHub release).
- \`install-offline.sh\` — installer that creates a venv, installs the wheels with \`--no-index\`, and links a \`netexec-automator\` shortcut.

## Install on the target host

\`\`\`bash
tar xzf $BUNDLE_NAME.tar.gz
cd $BUNDLE_NAME
./install-offline.sh
\`\`\`

Requirements on the target: \`python3\` ≥ 3.10, \`pip\`, and (recommended) \`nmap\`.
\`bloodhound-python\` is included if the bundle was built with \`INCLUDE_BLOODHOUND=1\` (default).

## Run

\`\`\`bash
source ~/.local/share/netexec-automator/venv/bin/activate
netexec-automator -t 10.10.10.0/24 --combo loot.txt --nmap --low-power
\`\`\`

## Build a fresh bundle

On a build host *with* internet, from the repo root:

\`\`\`bash
./scripts/bundle-airgapped.sh
# or cross-platform wheels:
PIP_PLATFORM=manylinux2014_x86_64 ./scripts/bundle-airgapped.sh
# or wheels only, no binary:
SKIP_NXC_BINARY=1 ./scripts/bundle-airgapped.sh
\`\`\`
EOF

color "creating tarball"
( cd "$DIST_DIR" && tar czf "$BUNDLE_NAME.tar.gz" "$BUNDLE_NAME" )
SIZE="$(du -sh "$DIST_DIR/$BUNDLE_NAME.tar.gz" | awk '{print $1}')"
SHA="$(shasum -a 256 "$DIST_DIR/$BUNDLE_NAME.tar.gz" | awk '{print $1}')"
color "done"
printf "\n  Bundle  : %s\n  Size    : %s\n  SHA-256 : %s\n\n" \
    "$DIST_DIR/$BUNDLE_NAME.tar.gz" "$SIZE" "$SHA"
