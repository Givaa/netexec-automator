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
    """All rendered rows must have the same visible (ANSI-stripped) length —
    that's what keeps the right-hand border aligned."""
    plain_lines = strip_ansi(nxa.render_startup_banner(width=72)).splitlines()
    # Skip empty lines (shouldn't be any, but be defensive)
    plain_lines = [l for l in plain_lines if l]
    widths = {len(l) for l in plain_lines}
    assert len(widths) == 1, f"rows have non-uniform widths: {sorted(widths)}\n" + "\n".join(plain_lines)


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
