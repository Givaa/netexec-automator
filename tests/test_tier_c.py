"""Tests for Tier C additions: TOML config loader, DNS SRV DC discovery."""

import tempfile
from pathlib import Path
from unittest import mock


def test_load_toml_config_basic(nxa, tmp_path):
    cfg = tmp_path / "n.toml"
    cfg.write_text(
        "workers = 5\n"
        'modules = "spider_plus,gpp_password"\n'
        "enum = true\n"
        "delay = 1.5\n"
    )
    out = nxa._load_toml_config(str(cfg))
    assert out["workers"] == 5
    assert out["modules"] == "spider_plus,gpp_password"
    assert out["enum"] is True
    assert out["delay"] == 1.5


def test_toml_merge_respects_cli_override(nxa, tmp_path):
    cfg = tmp_path / "n.toml"
    cfg.write_text("workers = 5\nenum = true\n")
    parser = nxa._build_parser()
    # Simulate CLI: -w 10 explicitly, --config also points to TOML with workers=5
    args = parser.parse_args(["-t", "x", "-u", "u", "-p", "p", "-w", "10",
                              "--config", str(cfg)])
    args = nxa._merge_toml_into_args(args, parser)
    # CLI -w 10 must win over TOML workers=5
    assert args.workers == 10
    # TOML enum=true must apply (CLI didn't set it)
    assert args.enum is True


def test_toml_unknown_key_is_warned_not_fatal(nxa, tmp_path, capsys):
    cfg = tmp_path / "n.toml"
    cfg.write_text("garbage_key = 42\nworkers = 3\n")
    parser = nxa._build_parser()
    args = parser.parse_args(["-t", "x", "-u", "u", "-p", "p", "--config", str(cfg)])
    args = nxa._merge_toml_into_args(args, parser)
    assert args.workers == 3
    err = capsys.readouterr().err
    assert "garbage_key" in err


def test_resolve_dc_via_dns_no_tools_returns_empty(nxa):
    # No dig/nslookup installed → should silently return []
    with mock.patch("shutil.which", return_value=None):
        assert nxa.NxcAutomator._resolve_dc_via_dns("corp.local") == []


def test_find_update_nxc_script_in_repo_layout(nxa):
    """When running from a checked-out repo, the script must be locatable
    via the repo-root path (scripts/update-nxc.sh next to the package dir)."""
    from netexec_automator.cli import _find_update_nxc_script
    script = _find_update_nxc_script()
    assert script is not None
    assert script.name == "update-nxc.sh"
    assert script.exists()


def test_resolve_dc_via_dns_parses_dig_output(nxa):
    fake_dig = mock.Mock()
    fake_dig.returncode = 0
    fake_dig.stdout = (
        "0 100 389 dc01.corp.local.\n"
        "0 100 389 dc02.corp.local.\n"
    )
    with mock.patch("shutil.which", side_effect=lambda t: "/usr/bin/dig" if t == "dig" else None), \
         mock.patch("subprocess.run", return_value=fake_dig):
        hosts = nxa.NxcAutomator._resolve_dc_via_dns("corp.local")
    assert hosts == ["dc01.corp.local", "dc02.corp.local"]
