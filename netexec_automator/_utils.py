"""Small terminal/path helpers used by the banner and the live progress bar."""

import shutil

from .constants import BANNER_PATH_BUDGET


def _term_width(default: int = 80) -> int:
    """Return the current terminal width, with a safe fallback for non-TTY."""
    try:
        return max(40, shutil.get_terminal_size((default, 24)).columns)
    except OSError:
        return default


def _truncate_path(p, budget: int = BANNER_PATH_BUDGET) -> str:
    """Render a path in <budget> chars max — keep the tail (filename) visible."""
    s = str(p)
    if len(s) <= budget:
        return s
    return "…" + s[-(budget - 1):]


def _truncate_text(s, budget: int) -> str:
    """Truncate `s` (any text, not just a path) to <budget> visible chars,
    appending '…' to signal the cut. Returns the original string when it
    already fits.

    Counts visible columns (emoji wide chars + ANSI-stripped) so banner
    cells with status icons don't slip off-grid."""
    from .banner import _visible_len  # local import to avoid circular at module load
    s = str(s)
    if _visible_len(s) <= budget:
        return s
    # Walk char-by-char accumulating visible width until we'd exceed budget-1
    # (we reserve 1 column for the ellipsis).
    import unicodedata
    _FORCE_WIDE = set("⚡💀🩸🧪🔓📋💾⚠⏱")
    width = 0
    out: list[str] = []
    cap = budget - 1
    for ch in s:
        if ch in _FORCE_WIDE or unicodedata.east_asian_width(ch) in ("W", "F"):
            w = 2
        else:
            w = 1
        if width + w > cap:
            break
        out.append(ch)
        width += w
    return "".join(out) + "…"
