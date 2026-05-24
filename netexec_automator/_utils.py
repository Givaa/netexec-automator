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
