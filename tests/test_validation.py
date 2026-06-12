"""Tests for the input-validation layer in cli._validate_args, plus the
logs/ dir defaults, the _truncate_text helper, and the reachability probe."""

import subprocess
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "netexec-automator.py"


def run_tool(args, env=None, cwd=None):
    import os
    py_env = (env or os.environ).copy()
    py_dir = str(Path(sys.executable).parent)
    py_env.setdefault("PATH", f"{py_dir}:/usr/bin:/bin")
    proc = subprocess.run(
        # sys.executable, not bare "python3": the latter can resolve to a
        # system Python older than 3.10 that chokes on the codebase's
        # `str | None` annotations (ImportError → exit 1, not the exit-2 we test).
        [sys.executable, str(TOOL), *args],
        env=py_env, cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, timeout=15,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---- nmap default-on policy ----------------------------------------------

def test_nmap_pre_scan_on_by_default():
    """The nmap pre-scan is on by default; --no-nmap opts out; --scan-only
    (and the deprecated --nmap no-op) keep it on."""
    from netexec_automator.cli import _build_parser, _nmap_enabled
    p = _build_parser()
    base = ["-t", "10.0.0.5", "-u", "u", "-p", "p"]
    assert _nmap_enabled(p.parse_args(base)) is True                       # default ON
    assert _nmap_enabled(p.parse_args(base + ["--no-nmap"])) is False      # opt out
    assert _nmap_enabled(p.parse_args(base + ["--scan-only"])) is True     # forces on
    assert _nmap_enabled(p.parse_args(base + ["--no-nmap", "--scan-only"])) is True  # scan-only wins
    assert _nmap_enabled(p.parse_args(base + ["--nmap"])) is True          # legacy no-op, still on


def test_skip_tried_on_by_default():
    """Incremental spray (remember prior attempts) is on by default;
    --retry-all / --no-skip-tried force a full re-spray."""
    from netexec_automator.cli import _build_parser, _skip_tried_enabled
    p = _build_parser()
    base = ["-t", "10.0.0.5", "-u", "u", "-p", "p"]
    assert _skip_tried_enabled(p.parse_args(base)) is True                      # default ON
    assert _skip_tried_enabled(p.parse_args(base + ["--retry-all"])) is False   # force full re-spray
    assert _skip_tried_enabled(p.parse_args(base + ["--no-skip-tried"])) is False  # alias
    assert _skip_tried_enabled(p.parse_args(base + ["--skip-tried"])) is True   # legacy no-op


# ---- _validate_args: file existence --------------------------------------

def test_combo_missing_file_errors_cleanly(tmp_path):
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "--combo", str(tmp_path / "nope.txt"), "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2  # parser.error exits 2
    assert "--combo" in err and "file not found" in err.lower()


def test_wordlist_missing_file_errors_cleanly(tmp_path):
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p",
         "--crack", "--wordlist", str(tmp_path / "missing-wordlist.txt"),
         "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--wordlist" in err
    assert "file not found" in err.lower()


def test_config_missing_file_errors_cleanly(tmp_path):
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "--config", str(tmp_path / "no.toml"), "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--config" in err


def test_target_with_slash_must_exist(tmp_path):
    """If -t looks like a path (slash in name) it must resolve to a file."""
    rc, _, err = run_tool(
        ["-t", str(tmp_path / "missing-targets.txt"), "-u", "u", "-p", "p",
         "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "-t" in err or "target" in err.lower()


def test_bare_ip_target_does_not_trigger_file_check(tmp_path):
    """'10.0.0.5' shouldn't be treated as a path; the run must proceed to
    the next gate (which exits because nxc isn't in PATH)."""
    import os
    env = os.environ.copy()
    env["PATH"] = f"{Path(sys.executable).parent}:/usr/bin:/bin"
    rc, out, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p", "--no-cmd-log"],
        env=env, cwd=tmp_path,
    )
    combined = out + err
    # We should reach the nxc pre-flight, not the path validator
    assert "nxc not found" in combined.lower() or rc != 2
    assert "file not found" not in combined.lower()


# ---- _validate_args: numeric ranges -------------------------------------

def test_negative_workers_rejected(tmp_path):
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p", "-w", "0", "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--workers" in err
    assert "got 0" in err


def test_negative_delay_rejected(tmp_path):
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p", "--delay", "-1", "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--delay" in err


def test_combo_with_user_is_rejected(tmp_path):
    """--combo carries the user already; -u with --combo is ambiguous."""
    combo = tmp_path / "c.txt"
    combo.write_text("admin:pwd\n")
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "--combo", str(combo), "-u", "admin", "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--combo" in err


# ---- --exam-safe module blocklist ---------------------------------------

def test_exam_safe_refuses_blocked_module(tmp_path):
    """A prohibited module in --modules must abort before any work starts."""
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p", "--exam-safe",
         "--modules", "spider_plus,zerologon", "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--exam-safe" in err
    assert "zerologon" in err.lower()


def test_exam_safe_matches_case_and_hyphen_insensitively(tmp_path):
    """'MS17-010' must match the blocklisted 'ms17-010' / 'ms17_010'."""
    rc, _, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p", "--exam-safe",
         "--modules", "MS17-010", "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc == 2
    assert "--exam-safe" in err
    assert "ms17-010" in err.lower()


def test_exam_safe_allows_enum_modules(tmp_path):
    """Pure enumeration modules must pass validation (rc != 2)."""
    rc, out, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p", "--exam-safe",
         "--modules", "spider_plus,gpp_password", "--no-cmd-log"],
        cwd=tmp_path,
    )
    # Should sail past _validate_args to the nxc preflight, not parser.error.
    assert rc != 2
    assert "--exam-safe" not in (out + err)


def test_blocked_module_allowed_without_exam_safe(tmp_path):
    """Without --exam-safe the blocklist is inert — nothing is refused."""
    rc, out, err = run_tool(
        ["-t", "10.0.0.5", "-u", "u", "-p", "p",
         "--modules", "zerologon", "--no-cmd-log"],
        cwd=tmp_path,
    )
    assert rc != 2
    assert "exam-safe" not in (out + err).lower()


# ---- _truncate_text -----------------------------------------------------

def test_truncate_text_within_budget(nxa):
    from netexec_automator._utils import _truncate_text
    assert _truncate_text("short", 10) == "short"


def test_truncate_text_over_budget_adds_ellipsis(nxa):
    from netexec_automator._utils import _truncate_text
    s = "this is a fairly long config value that won't fit in 20 cols"
    out = _truncate_text(s, 20)
    # End with the ellipsis and be <= 20 visible cols
    from netexec_automator.banner import _visible_len
    assert out.endswith("…")
    assert _visible_len(out) <= 20


def test_truncate_text_counts_wide_emoji(nxa):
    from netexec_automator._utils import _truncate_text
    from netexec_automator.banner import _visible_len
    # Each emoji is 2 cols; '⚡⚡⚡⚡⚡' is 10 visible cols
    out = _truncate_text("⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡", 5)  # budget=5 → 2 emoji + …
    assert _visible_len(out) <= 5


# ---- logs/ default -------------------------------------------------------

def test_default_log_paths_land_in_logs_dir(nxa, tmp_path):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    # Path stored as string; just check the parent directory name
    assert "logs" in a.log_file
    assert a.cmd_log_path is not None
    assert a.cmd_log_path.parent.name == "logs"


def test_no_cmd_log_disables_path(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", cmd_log_disabled=True)
    assert a.cmd_log_path is None


def test_custom_cmd_log_overrides_default(nxa, tmp_path):
    custom = tmp_path / "myrun.log"
    a = nxa.NxcAutomator(target="x", user="u", password="p", cmd_log=str(custom))
    assert a.cmd_log_path == custom


# ---- Reachability TCP probe ---------------------------------------------

def test_is_host_reachable_returns_bool(nxa):
    """Just verify the method runs and returns a bool — the actual
    connectivity outcome depends on the test host's network."""
    result = nxa.NxcAutomator._is_host_reachable("127.0.0.1", ports=(1,), timeout=0.5)
    assert isinstance(result, bool)


def test_is_host_reachable_unreachable_port(nxa):
    """Pick a port that's almost certainly closed on localhost. Should
    return False within the timeout."""
    # Port 1 is reserved and almost never listening; bind() requires root.
    assert nxa.NxcAutomator._is_host_reachable("127.0.0.1", ports=(1,), timeout=0.5) is False


def test_is_host_reachable_true_for_listening_port(nxa):
    """A real listening socket on localhost must be detected as reachable,
    even when mixed with closed ports."""
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert nxa.NxcAutomator._is_host_reachable(
            "127.0.0.1", ports=(1, port, 2), timeout=2.0
        ) is True
    finally:
        srv.close()


def test_is_host_reachable_empty_ports_is_false(nxa):
    """Empty port tuple must return False (not raise), matching the old
    sequential loop's no-op fall-through."""
    assert nxa.NxcAutomator._is_host_reachable("127.0.0.1", ports=(), timeout=0.5) is False


def test_is_host_reachable_probes_all_resolved_addresses(nxa, monkeypatch):
    """Regression: a dual-stack name whose FIRST (IPv6) address is dead but
    whose IPv4 address listens must still be reachable — create_connection
    tried every resolved address, so must we. Guards against pinning to
    getaddrinfo()[0] (which silently dropped live IPv4-only hosts)."""
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    live_port = srv.getsockname()[1]

    real_gai = socket.getaddrinfo

    def fake_gai(host, port, *args, **kwargs):
        if host == "dualstack.test":
            # IPv6 ::1 on a dead port FIRST, then the live IPv4 listener.
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 1, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", live_port)),
            ]
        return real_gai(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    try:
        assert nxa.NxcAutomator._is_host_reachable(
            "dualstack.test", ports=(live_port,), timeout=2.0
        ) is True
    finally:
        srv.close()


def test_is_host_reachable_dead_host_is_parallel(nxa):
    """A dead host with several filtered ports must return False bounded by
    ~one timeout (probes run in parallel), not len(ports) × timeout. Uses an
    RFC5737 TEST-NET-1 address that is never routed. Lenient bound: a
    reversion to sequential per-port waits (~5 × timeout) would blow past it."""
    import time
    import pytest
    ports = (445, 22, 3389, 80, 139)
    timeout = 0.5
    t0 = time.monotonic()
    result = nxa.NxcAutomator._is_host_reachable("192.0.2.1", ports=ports, timeout=timeout)
    elapsed = time.monotonic() - t0
    if result is not False:
        # Some sandboxes / transparent proxies accept outbound connects to any
        # address, so TEST-NET looks "reachable" and there's no dead-host path
        # to time. The parallelism guarantee still holds on real networks / CI.
        pytest.skip("environment accepts outbound connects to TEST-NET — no dead-host path to measure")
    assert elapsed < timeout * 3, f"probe took {elapsed:.2f}s — not running in parallel?"


def test_is_host_reachable_leaves_no_worker_threads(nxa):
    """Regression: the probe must not spawn/leak worker threads. The previous
    ThreadPoolExecutor version left losing connect threads blocked for the
    full timeout (joined by concurrent.futures' atexit hook, stalling exit and
    piling up across the discovery loop). The selector-based probe uses none."""
    import socket
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        before = threading.active_count()
        assert nxa.NxcAutomator._is_host_reachable(
            "127.0.0.1", ports=(port, 1, 2), timeout=2.0
        ) is True
        # No threads created → count is unchanged the instant we return.
        assert threading.active_count() == before
    finally:
        srv.close()


def test_reachability_check_default_on(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a.reachability_check is True


def test_reachability_check_opt_out(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", reachability_check=False)
    assert a.reachability_check is False


# ---- --show / --reset / deprecated flags --------------------------------

def test_show_and_reset_roundtrip(tmp_path):
    """--show lists prior loot (grouped, no secrets); --reset wipes it; --show
    is then empty. All run without -t and exit 0."""
    from netexec_automator.cache import HostCache
    cache_file = tmp_path / "state.db"
    c = HostCache(cache_file, ttl=86400)
    c.record_attempt("10.0.0.5", "smb", False, "administrator", "SECRETHASH_XYZ",
                     "corp.local", "ok", pwn3d=True)
    c.close()

    rc, out, err = run_tool(["--show", "--cache-path", str(cache_file)], cwd=tmp_path)
    blob = out + err
    assert rc == 0
    assert "administrator" in blob and "corp.local" in blob
    assert "SECRETHASH_XYZ" not in blob  # the stored hash must never be surfaced

    rc, out, err = run_tool(["--reset", "--cache-path", str(cache_file)], cwd=tmp_path)
    assert rc == 0
    assert "wiped" in (out + err).lower()

    rc, out, err = run_tool(["--show", "--cache-path", str(cache_file)], cwd=tmp_path)
    assert rc == 0
    assert "no valid credentials on record" in (out + err).lower()


def test_deprecated_flags_are_accepted_as_noops(tmp_path):
    """--nmap and --skip-tried are hidden deprecated no-ops; passing them must
    not error."""
    cache_file = tmp_path / "state.db"
    rc, out, err = run_tool(
        ["--show", "--nmap", "--skip-tried", "--cache-path", str(cache_file)],
        cwd=tmp_path,
    )
    assert rc == 0
    assert "error" not in err.lower()
