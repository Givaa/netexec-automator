"""Startup banner: NXA ASCII art + credits + a random quote.

Disable with --no-banner. The quote is picked at random from a small
curated pool of one-liners that nod at the multi-protocol nature of the
tool (LOTR, Hackers, WarGames, …). Cheap dopamine for the operator."""

import random

from .constants import (BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW)


# Curated quote pool. Two rules: (1) each one captures the 'why pick one
# when you can have them all' essence of multi-protocol spraying, and
# (2) each is short enough to fit on one terminal line at any sane width.
QUOTES: list[tuple[str, str]] = [
    ("One spray to rule them all.",                        "— adapted from J.R.R. Tolkien"),
    ("Why settle for one, when you can have them all?",    "— anonymous pentester"),
    ("Gotta catch 'em all.",                                "— Pokémon"),
    ("Hack the planet.",                                    "— Hackers (1995)"),
    ("Shall we play a game?",                               "— WarGames (1983)"),
    ("There is no spoon, only (Pwn3d!).",                  "— adapted from The Matrix"),
    ("I'm in.",                                             "— every hacker movie, ever"),
    ("Trying does not work here. Do, or do not.",          "— adapted from Yoda"),
    ("This is the way... across ten protocols at once.",   "— adapted from The Mandalorian"),
]


# Block-letter "NXA" (sliver-style). 6 rows × ~30 cols. Compatible with
# any terminal ≥ 70 cols; gracefully degraded by the rest of the banner.
NXA_BLOCK = [
    "███╗   ██╗██╗  ██╗ █████╗",
    "████╗  ██║╚██╗██╔╝██╔══██╗",
    "██╔██╗ ██║ ╚███╔╝ ███████║",
    "██║╚██╗██║ ██╔██╗ ██╔══██║",
    "██║ ╚████║██╔╝ ██╗██║  ██║",
    "╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝",
]


def render_startup_banner(width: int = 70) -> str:
    """Return the full multi-line startup banner as a single string.

    Layout:
      ┌─────────────────────────────────────────────────────────────────┐
      │                                                                 │
      │   <NXA block letters>    ⚡ NetExec Automator                    │
      │                            auto-pwn AD in one command           │
      │                                                                 │
      │                            by Giovanni Rapa (@Givaa)            │
      │                            github.com/Givaa/netexec-automator   │
      │                                                                 │
      │   "<quote>"                                                     │
      │       <attribution>                                             │
      │                                                                 │
      └─────────────────────────────────────────────────────────────────┘
    """
    quote, attribution = random.choice(QUOTES)
    inner = width - 2  # space inside the borders
    lines: list[str] = []

    # Top border
    lines.append(f"{DIM}{CYAN}╔{'═' * inner}╗{RESET}")
    lines.append(f"{DIM}{CYAN}║{' ' * inner}║{RESET}")

    # Block letters paired with the meta lines on the right.
    meta_lines = [
        f"{CYAN}{BOLD}⚡ NetExec Automator{RESET}",
        f"{DIM}spray 'em all — auto-pwn AD{RESET}",
        "",
        f"{DIM}by Giovanni Rapa {CYAN}(@Givaa){RESET}",
        f"{DIM}github.com/Givaa/netexec-automator{RESET}",
        "",
    ]
    for i, block_line in enumerate(NXA_BLOCK):
        meta = meta_lines[i] if i < len(meta_lines) else ""
        lines.append(_compose_row(block_line, meta, inner, block_color=RED))

    # Blank line
    lines.append(f"{DIM}{CYAN}║{' ' * inner}║{RESET}")

    # Quote
    quote_line = f'  {YELLOW}"{quote}"{RESET}'
    attr_line = f'        {DIM}{attribution}{RESET}'
    lines.append(_pad_row(quote_line, inner))
    lines.append(_pad_row(attr_line, inner))

    # Bottom border
    lines.append(f"{DIM}{CYAN}║{' ' * inner}║{RESET}")
    lines.append(f"{DIM}{CYAN}╚{'═' * inner}╝{RESET}")

    return "\n".join(lines)


# Emoji we use as status icons or in the banner: terminals render each
# of these as 2 columns wide, but Python's `len()` counts them as 1.
# Listing them explicitly is more reliable than unicodedata for the few
# symbols we actually print (some emoji are EAW='N' in Unicode but still
# wide in every modern terminal).
_FORCE_WIDE = set("⚡💀🩸🧪🔓📋💾⚠⏱")


def _visible_len(s: str) -> int:
    """Length of `s` as the terminal will render it: ANSI escapes contribute
    zero columns, wide emoji contribute two, everything else one."""
    import re
    import unicodedata

    s = re.sub(r"\x1b\[[0-9;]*m", "", s)
    w = 0
    for ch in s:
        if ch in _FORCE_WIDE:
            w += 2
        elif unicodedata.east_asian_width(ch) in ("W", "F"):
            w += 2
        else:
            w += 1
    return w


def _compose_row(block: str, meta: str, inner: int, block_color: str = "") -> str:
    """Render one row: 3-space pad + colored block letters + spacer + meta."""
    block_w = _visible_len(block)
    left = f"   {block_color}{BOLD}{block}{RESET}"
    spacer_w = max(2, 32 - block_w)  # keep meta at col ~33
    middle = " " * spacer_w
    composed = left + middle + meta
    return _pad_row(composed, inner)


def _pad_row(content: str, inner: int) -> str:
    """Wrap `content` inside the cyan border, padding to `inner` visible chars."""
    visible = _visible_len(content)
    pad = max(0, inner - visible)
    return f"{DIM}{CYAN}║{RESET}{content}{' ' * pad}{DIM}{CYAN}║{RESET}"
