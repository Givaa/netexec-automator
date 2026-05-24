#!/usr/bin/env bash
# record-demo.sh — refresh assets/netexec-automator-demo.gif reproducibly.
#
# Workflow:
#   1. asciinema  records a terminal session into a .cast file
#   2. agg        renders the .cast into an animated .gif
#
# Both tools are available via pip / cargo / brew. The script will install
# pointers if either is missing.
#
# Usage:
#   ./scripts/record-demo.sh                       # record interactively, then render
#   ./scripts/record-demo.sh --cast existing.cast  # re-render an existing recording

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ASSETS="$ROOT/assets"
CAST="$ASSETS/demo.cast"
GIF="$ASSETS/netexec-automator-demo.gif"
EXISTING_CAST=""

# ---- arg parse ----
while [ $# -gt 0 ]; do
    case "$1" in
        --cast) EXISTING_CAST="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

color() { printf "\033[1;36m==> %s\033[0m\n" "$*"; }
fail()  { printf "\033[1;31mXX %s\033[0m\n" "$*" >&2; exit 1; }

mkdir -p "$ASSETS"

if ! command -v asciinema >/dev/null; then
    fail "asciinema is required. Install with: pipx install asciinema  (or brew install asciinema)"
fi
if ! command -v agg >/dev/null; then
    fail "agg is required. Install with: cargo install --git https://github.com/asciinema/agg  (or brew install agg)"
fi

if [ -n "$EXISTING_CAST" ]; then
    CAST="$EXISTING_CAST"
    [ -f "$CAST" ] || fail "cast file not found: $CAST"
else
    color "starting asciinema recording → $CAST"
    cat <<MSG

  Suggested demo script (open another terminal to copy-paste these):

    clear
    python3 netexec-automator.py --help | head -30
    clear
    python3 netexec-automator.py -t 10.10.10.0/24 --combo loot.txt \\
        --nmap --null-session --enum --bloodhound -v
    # let it run until you see the summary
    cat commands-*.log | head -20
    ls loot/

  Press Ctrl-D (or 'exit') to stop the recording.
MSG
    asciinema rec --overwrite "$CAST"
fi

color "rendering $CAST → $GIF"
# Pick a sensible width/height for README rendering; tweak --speed if needed.
agg --theme monokai --font-size 14 --speed 1.5 --idle-time-limit 2 "$CAST" "$GIF"

color "done: $GIF ($(du -sh "$GIF" | awk '{print $1}'))"
echo "  Commit & push to refresh README:"
echo "      git add $GIF && git commit -m 'Refresh demo GIF'"
