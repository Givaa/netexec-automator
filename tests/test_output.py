"""Tests for the redesigned output: outcome classifier, one-line recap,
end-of-run FINAL REPORT, dead-host tracking."""

import re

from unittest import mock


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


# ---- _classify_task_outcome ---------------------------------------------

def test_classify_pwn3d_wins(nxa):
    parsed = [("[+]", "admin:pwd (Pwn3d!)"), ("[-]", "bob:fail")]
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a._classify_task_outcome(parsed) == "pwn3d"


def test_classify_ok_when_no_pwn3d(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a._classify_task_outcome([("[+]", "user:pass")]) == "ok"


def test_classify_timeout_over_fail(nxa):
    """When both [-] and [!] are present, [!] (timeout) is more significant."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a._classify_task_outcome([("[-]", "no"), ("[!]", "skipped")]) == "timeout"


def test_classify_fail_when_only_auth_errors(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a._classify_task_outcome([("[-]", "bob:wrong")]) == "fail"


def test_classify_noop_when_empty(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a._classify_task_outcome([]) == "noop"


# ---- Recap one-line output ----------------------------------------------

def test_recap_groups_by_outcome(nxa, capsys):
    """Default mode (no -v) prints a one-line recap grouped by icon."""
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    results = {
        ("smb", False): ["SMB  h  445  H  [+] dom\\admin:pwd (Pwn3d!)"],
        ("smb", True):  ["SMB  h  445  H  [-] dom\\admin:pwd STATUS_LOGON_FAILURE"],
        ("ssh", False): ["SSH  h  22   H  [!] timed out"],
    }
    tasks = [("smb", False), ("smb", True), ("ssh", False), ("ldap", False)]
    a._print_target_results(results, tasks)
    out = strip_ansi(capsys.readouterr().out)
    assert "💀" in out and "SMB (domain)" in out
    assert "✘" in out and "SMB (local)" in out
    assert "⏱" in out and "SSH (domain)" in out


def test_recap_collapses_no_response(nxa, capsys):
    """If all protocols had no response, say so plainly on one line."""
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    tasks = [("ssh", False), ("ftp", False), ("vnc", False)]
    a._print_target_results({}, tasks)
    out = strip_ansi(capsys.readouterr().out)
    assert "no response" in out.lower()


def test_verbose_mode_shows_full_block(nxa, capsys):
    """-v restores the original per-protocol verbose breakdown."""
    a = nxa.NxcAutomator(target="x", user="u", password="p",
                         verbosity=nxa.V_VERBOSE, no_banner=True)
    results = {
        ("smb", False): ["SMB  h  445  H  [+] dom\\admin:pwd (Pwn3d!)"],
    }
    tasks = [("smb", False)]
    a._print_target_results(results, tasks)
    out = strip_ansi(capsys.readouterr().out)
    assert "Detailed Results" in out
    assert "dom\\admin:pwd" in out


# ---- FINAL REPORT ---------------------------------------------------------

def test_final_report_lists_pwn3d_separately(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    cred = a.credentials[0]
    a.valid_creds = [
        {"host": "10.0.0.5", "protocol": "smb", "local_auth": False,
         "credential": cred, "raw": "corp\\admin:pwd (Pwn3d!)"},
        {"host": "10.0.0.7", "protocol": "smb", "local_auth": False,
         "credential": cred, "raw": "corp\\bob:Welcome1"},
    ]
    a._print_final_report()
    out = strip_ansi(capsys.readouterr().out)
    assert "ADMIN PWN3D (1)" in out
    assert "VALID CREDENTIALS (1)" in out
    assert "10.0.0.5" in out and "10.0.0.7" in out


def test_final_report_lists_harvested_and_cracked(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    a.harvested_hashes = [
        {"host": "10.0.0.5", "source": "sam", "user": "Administrator",
         "lm": "a" * 32, "nt": "b" * 32},
    ]
    a.cracked_creds = [{"user": "Administrator", "password": "Welcome1", "source": "nt-crack"}]
    a._print_final_report()
    out = strip_ansi(capsys.readouterr().out)
    assert "HASHES HARVESTED" in out
    assert "1× NT" in out
    assert "CRACKED PLAINTEXT (1)" in out
    assert "Administrator:Welcome1" in out


def test_final_report_lists_bloodhound_runs(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    a.bloodhound_results = [
        {"domain": "corp.local", "dc_ip": "10.0.0.5", "auth_user": "admin",
         "output_path": "/loot/bh/corp.local/20260524", "success": True, "error": ""},
    ]
    a._print_final_report()
    out = strip_ansi(capsys.readouterr().out)
    assert "BLOODHOUND (1 domain" in out
    assert "corp.local" in out
    assert "10.0.0.5" in out


def test_final_report_lists_dead_hosts(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    a.dead_hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    a._print_final_report()
    out = strip_ansi(capsys.readouterr().out)
    assert "NO RESPONSE (3)" in out
    assert "10.0.0.1" in out and "10.0.0.2" in out


def test_final_report_says_nothing_found_when_empty(nxa, capsys):
    """Run produced literally zero findings → make it explicit."""
    a = nxa.NxcAutomator(target="x", user="u", password="p", no_banner=True)
    a._print_final_report()
    out = strip_ansi(capsys.readouterr().out)
    assert "no valid credentials found" in out.lower()


def test_final_report_suppressed_in_quiet(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p",
                         verbosity=nxa.V_QUIET, no_banner=True)
    a.valid_creds = [{
        "host": "10.0.0.5", "protocol": "smb", "local_auth": False,
        "credential": a.credentials[0], "raw": "admin:pwd (Pwn3d!)",
    }]
    a._print_final_report()
    out = capsys.readouterr().out
    assert out == "", "quiet mode must not emit the FINAL REPORT"


def test_format_host_tag_uses_resolver(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    with mock.patch("socket.gethostbyaddr", return_value=("dc01.corp.local", [], ["10.10.10.5"])):
        tag = a._format_host_tag("10.10.10.5")
    assert "dc01.corp.local" in tag
    assert "10.10.10.5" in tag


def test_format_host_tag_falls_back_to_smb_banner(nxa):
    """When DNS PTR is empty, _format_host_tag should compose name+domain
    from values learned during the spray (host_names + host_domain)."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    # No PTR (gethostbyaddr raises)
    import socket
    a.host_names["10.10.10.5"] = "DC01"
    a.host_domain["10.10.10.5"] = "corp.local"
    with mock.patch("socket.gethostbyaddr", side_effect=socket.herror("no PTR")):
        tag = a._format_host_tag("10.10.10.5")
    assert "DC01.corp.local" in tag
    assert "10.10.10.5" in tag


def test_format_host_tag_uses_just_name_when_no_domain(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.host_names["10.10.10.7"] = "WS01"
    # no host_domain entry
    import socket
    with mock.patch("socket.gethostbyaddr", side_effect=socket.herror("no PTR")):
        tag = a._format_host_tag("10.10.10.7")
    assert "WS01" in tag


def test_detect_dc_extracts_name(nxa):
    """SMB banner parsing should populate host_names alongside host_domain."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    block = "SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:corp.local)"
    results = {("smb", False): [block]}
    a._detect_dc_from_results("10.10.10.5", results, open_ports={445, 389})
    assert a.host_names["10.10.10.5"] == "DC01"
    assert a.host_domain["10.10.10.5"] == "corp.local"
