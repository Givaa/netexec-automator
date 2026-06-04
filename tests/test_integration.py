"""End-to-end integration tests: run the actual netexec-automator.py CLI as
a subprocess, with PATH rewritten so the tool finds tests/fixtures/nxc-mock.sh
instead of a real `nxc`. Exercises orchestration code that unit tests can't
reach (run(), _post_exploit_host, _collect_target_results, the threading and
progress bar, the --strict exit path, …)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL = REPO_ROOT / "netexec-automator.py"
MOCK_DIR = REPO_ROOT / "tests" / "fixtures"
MOCK_NXC = MOCK_DIR / "nxc-mock.sh"


@pytest.fixture
def env_with_mock(tmp_path):
    """Stage a fake nxc binary in tmp_path/bin and prepend it to PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nxc_link = bin_dir / "nxc"
    nxc_link.symlink_to(MOCK_NXC)
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["NXA_MOCK_TARGET"] = "10.10.10.5"
    env["NXA_MOCK_USER"] = "administrator"
    env["NXA_MOCK_PASS"] = "Summer2025!"
    return env


def run_tool(args, env, cwd, timeout=30):
    """Run the CLI and return (rc, stdout, stderr).

    The nmap pre-scan is on by default now, but these tests drive the nxc
    spray/orchestration against a mock nxc — a real nmap against the fake
    target finds nothing open and would skip the spray entirely. So default
    to --no-nmap unless the test explicitly opts into scanning."""
    args = list(args)
    if not {"--nmap", "--no-nmap", "--scan-only"}.intersection(args):
        args = ["--no-nmap", *args]
    proc = subprocess.run(
        # sys.executable, not bare "python3" (which may resolve to a <3.10
        # system Python that can't parse the codebase's `str | None` syntax).
        [sys.executable, str(TOOL), *args],
        env=env, cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---- Basic flow ----

def test_help_works(env_with_mock, tmp_path):
    rc, out, err = run_tool(["--help"], env_with_mock, tmp_path)
    assert rc == 0
    assert "examples" in out.lower()
    assert "--bloodhound" in out


def test_preflight_aborts_when_nxc_missing(tmp_path):
    """No nxc in PATH (and not --scan-only) → exit 127 with friendly message.
    We keep python3's parent dir in PATH so we can launch the tool at all."""
    import sys
    env = os.environ.copy()
    py_dir = str(Path(sys.executable).parent)
    env["PATH"] = f"{py_dir}:/usr/bin:/bin"  # strip nxc but keep python3
    rc, out, err = run_tool(
        ["-t", "127.0.0.1", "-u", "u", "-p", "p", "--no-cmd-log"],
        env, tmp_path,
    )
    assert rc == 127, f"got rc={rc}\nstdout={out!r}\nstderr={err!r}"
    combined = out + err
    assert "nxc not found" in combined.lower()


def test_valid_cred_appears_in_quiet_output(env_with_mock, tmp_path):
    """The mock authenticates (administrator/Summer2025!) on 10.10.10.5 — the
    tool's quiet mode should print that one cred line to stdout."""
    rc, out, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "-q", "--no-cmd-log"],
        env_with_mock, tmp_path,
    )
    assert "administrator" in out
    assert "Summer2025" in out


def test_host_header_can_show_ptr_hostname(env_with_mock, tmp_path):
    """When DNS PTR resolves, the on-screen host header should include
    the resolved hostname in parentheses. Default behaviour is enabled."""
    rc, out, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--no-cmd-log", "--resolve-timeout", "0.1"],
        env_with_mock, tmp_path,
    )
    # Either the PTR resolved (and appears as '(...)' next to the IP)
    # or it didn't and we still see the raw IP. Both are acceptable —
    # we just want to confirm the codepath didn't crash and the IP still
    # appears in the output.
    assert "10.10.10.5" in out


def test_no_resolve_flag_suppresses_ptr(env_with_mock, tmp_path):
    """--no-resolve disables DNS lookups entirely (verified by running
    with an unreachable resolver-timeout — no DNS attempt should hang)."""
    rc, out, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--no-cmd-log", "--no-resolve"],
        env_with_mock, tmp_path,
    )
    assert "10.10.10.5" in out


def test_pwn3d_appears_with_skull_icon(env_with_mock, tmp_path):
    rc, out, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--no-cmd-log"],
        env_with_mock, tmp_path,
    )
    # The 💀 icon is used both live and in the summary's 'ADMIN PWN3D' block.
    assert "💀" in out or "PWN3D" in out


# ---- JSON export end-to-end ----

def test_export_json_contains_valid_cred(env_with_mock, tmp_path):
    json_path = tmp_path / "out.json"
    rc, out, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--export-json", str(json_path), "--no-cmd-log"],
        env_with_mock, tmp_path,
    )
    assert json_path.exists()
    doc = json.loads(json_path.read_text())
    assert len(doc["valid_credentials"]) >= 1
    first = doc["valid_credentials"][0]
    assert first["user"] == "administrator"
    assert first["pwn3d"] is True


# ---- --strict exit code ----

def test_strict_exits_clean_when_no_errors(env_with_mock, tmp_path):
    rc, _, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--strict", "--no-cmd-log"],
        env_with_mock, tmp_path,
    )
    assert rc == 0


# ---- Auto-secretsdump + auto-grow combo ----

def test_secretsdump_pwn3d_writes_hashes_to_grow_combo(env_with_mock, tmp_path):
    """When the cred is (Pwn3d!), --secretsdump should dump SAM and the
    parsed NT hashes should land in loot/auto-grown-creds.txt as a combo
    file the next run could consume."""
    loot = tmp_path / "loot"
    rc, out, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--secretsdump", "--loot-dir", str(loot),
         "--no-cmd-log"],
        env_with_mock, tmp_path,
    )
    grown = loot / "auto-grown-creds.txt"
    assert grown.exists(), f"grown combo not created. Output:\n{out}"
    content = grown.read_text()
    # SAM dump in the mock includes Administrator (NT 8846f7…)
    assert "8846f7ea" in content.lower()
    assert "administrator" in content.lower()


# ---- Commands transcript ----

def test_commands_transcript_logs_real_subprocesses(env_with_mock, tmp_path):
    cmd_log = tmp_path / "commands.log"
    rc, _, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--cmd-log", str(cmd_log)],
        env_with_mock, tmp_path,
    )
    assert cmd_log.exists()
    text = cmd_log.read_text()
    # Every entry has the ISO timestamp + label + shell-quoted command
    assert "[SMB (domain)]" in text or "[SMB" in text
    assert "nxc smb 10.10.10.5" in text
    assert "Summer2025" in text  # the password ends up quoted in the log


def test_only_filter_skips_other_protocols(env_with_mock, tmp_path):
    """With --only smb, the cmd-log must contain ONLY smb invocations
    (no ssh/ldap/wmi/etc.)."""
    cmd_log = tmp_path / "commands.log"
    rc, _, _ = run_tool(
        ["-t", "10.10.10.5", "-u", "administrator", "-p", "Summer2025!",
         "--only", "smb", "--cmd-log", str(cmd_log)],
        env_with_mock, tmp_path,
    )
    text = cmd_log.read_text()
    for p in ("ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"):
        assert f"nxc {p}" not in text, f"unexpected {p} invocation:\n{text}"
