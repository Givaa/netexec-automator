"""Tests for the startup banner module: ASCII art rendering, quote pool,
visible-length math, --no-banner plumbing."""

import re


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def test_banner_renders_to_string(nxa):
    out = nxa.render_startup_banner(width=72)
    assert isinstance(out, str)
    assert "NetExec Automator" in strip_ansi(out)


def test_banner_includes_credits(nxa):
    out = strip_ansi(nxa.render_startup_banner(width=72))
    assert "Giovanni Rapa" in out
    assert "@Givaa" in out
    assert "github.com/Givaa/netexec-automator" in out


def test_banner_picks_a_quote_from_the_pool(nxa):
    """A quote and its attribution must both appear in the rendered banner."""
    plain = strip_ansi(nxa.render_startup_banner(width=72))
    assert any(
        quote in plain and attribution in plain
        for quote, attribution in nxa.QUOTES
    ), "no curated quote/attribution pair found in rendered banner"


def test_banner_uses_box_drawing(nxa):
    out = nxa.render_startup_banner(width=72)
    plain = strip_ansi(out)
    # Top + bottom borders should each appear at least once
    assert "╔" in plain and "╗" in plain
    assert "╚" in plain and "╝" in plain


def test_banner_rows_have_uniform_visible_width(nxa):
    """All rendered rows must have the same *visible* (terminal-rendered)
    width — that's what keeps the right-hand border aligned. Visible width
    is ANSI-stripped AND accounts for wide emoji (⚡ 💀 ...) which Python
    counts as 1 char but the terminal renders as 2 columns."""
    from netexec_automator.banner import _visible_len
    rendered_lines = nxa.render_startup_banner(width=72).splitlines()
    rendered_lines = [l for l in rendered_lines if strip_ansi(l).strip() or "║" in strip_ansi(l)]
    widths = {_visible_len(l) for l in rendered_lines}
    assert len(widths) == 1, (
        f"rows have non-uniform visible widths: {sorted(widths)}\n"
        + "\n".join(rendered_lines)
    )


def test_visible_len_counts_wide_emoji_as_2(nxa):
    """⚡ 💀 🩸 🧪 🔓 📋 are 2 cells wide in terminals; the helper must
    reflect that or the box-drawing borders go off by one per emoji."""
    from netexec_automator.banner import _visible_len
    assert _visible_len("⚡") == 2
    assert _visible_len("💀") == 2
    assert _visible_len("⚡ NetExec") == 2 + 1 + 7  # emoji + space + 'NetExec'


def test_visible_len_strips_ansi(nxa):
    from netexec_automator.banner import _visible_len
    plain = "hello"
    colored = "\x1b[91m\x1b[1mhello\x1b[0m"
    assert _visible_len(plain) == _visible_len(colored) == 5


def test_no_banner_attr_propagates(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    assert a.no_banner is True


def test_no_banner_default_off(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a.no_banner is False


def test_quote_pool_is_non_empty(nxa):
    assert len(nxa.QUOTES) >= 3
    for quote, attribution in nxa.QUOTES:
        assert quote and attribution
        assert quote != attribution
