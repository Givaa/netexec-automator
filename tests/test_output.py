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


def test_probe_smb_banner_populates_host_names(nxa):
    """The pre-spray SMB probe should fill host_names + host_domain so the
    live ► header can show 'IP (DC01.corp.local)' from the very first line."""
    import subprocess as sp
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    banner = (
        "SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 ... "
        "(name:DC01) (domain:corp.local)"
    )
    fake_result = mock.Mock(returncode=0, stdout=banner, stderr="")
    with mock.patch.object(sp, "run", return_value=fake_result):
        a._probe_smb_banner("10.10.10.5")
    assert a.host_names["10.10.10.5"] == "DC01"
    assert a.host_domain["10.10.10.5"] == "corp.local"


def test_probe_smb_banner_skips_when_smb_port_closed(nxa):
    """If nmap pre-scan says SMB ports are closed, the probe shouldn't
    even spawn a subprocess (we'd just get a timeout)."""
    import subprocess as sp
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    with mock.patch.object(sp, "run") as run_mock:
        a._probe_smb_banner("10.10.10.5", open_ports={22, 80})
    run_mock.assert_not_called()


def test_probe_smb_banner_skips_when_already_known(nxa):
    """Cached host_names/host_domain → no probe needed."""
    import subprocess as sp
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.host_names["10.10.10.5"] = "DC01"
    a.host_domain["10.10.10.5"] = "corp.local"
    with mock.patch.object(sp, "run") as run_mock:
        a._probe_smb_banner("10.10.10.5")
    run_mock.assert_not_called()


def test_bulk_probe_runs_when_nmap_off_empty_ports(nxa):
    """Regression: with --nmap off the bulk sweep passes an empty ports set
    per host. It must still probe (open_ports=None), otherwise host_names is
    never populated and the live header loses its '(hostname)' on no-PTR nets."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    seen = {}
    def fake_probe(host, open_ports=None):
        seen[host] = open_ports
        a.host_names[host] = "DC01"
    with mock.patch.object(a, "_probe_smb_banner", side_effect=fake_probe):
        a._bulk_probe_smb_banners({"10.10.10.5": set()})  # nmap-off shape
    assert "10.10.10.5" in seen, "empty-ports host was not probed (regression)"
    assert seen["10.10.10.5"] is None, "empty set must become None so the probe runs"


def test_resolved_hostname_prefers_ptr_over_smb_banner(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.host_names["10.10.10.5"] = "DC01"
    a.host_domain["10.10.10.5"] = "corp.local"
    with mock.patch("socket.gethostbyaddr", return_value=("dc-via-dns.corp.local", [], ["10.10.10.5"])):
        assert a._resolved_hostname("10.10.10.5") == "dc-via-dns.corp.local"


def test_detect_dc_extracts_name(nxa):
    """SMB banner parsing should populate host_names alongside host_domain."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    block = "SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:corp.local)"
    results = {("smb", False): [block]}
    a._detect_dc_from_results("10.10.10.5", results, open_ports={445, 389})
    assert a.host_names["10.10.10.5"] == "DC01"
    assert a.host_domain["10.10.10.5"] == "corp.local"


# ---- auth scope: both local-auth and domain are sprayed -----------------

def test_build_protocol_tasks_covers_both_local_and_domain(nxa):
    """Every local-auth-capable protocol (smb/wmi/winrm/rdp/mssql) must be
    sprayed BOTH as domain auth and as local auth; non-local protocols (ssh,
    ldap, ...) get domain only. Guards the 'try both scopes' guarantee."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    tasks = a._build_protocol_tasks(open_ports=None)  # nmap-off: all protocols
    assert ("smb", False) in tasks and ("smb", True) in tasks      # domain + local
    assert ("ssh", False) in tasks and ("ssh", True) not in tasks  # domain only
    assert ("ldap", False) in tasks and ("ldap", True) not in tasks


# ---- print_loot_on_record (shared by --show + end-of-run reminder) ------

def test_print_loot_on_record_groups_by_domain(nxa, capsys):
    rows = [
        ("10.0.0.5", "smb", False, "administrator", "corp.local", True),
        ("10.0.0.6", "smb", True,  "localadmin",    "corp.local", False),
        ("172.16.0.9", "ssh", False, "root",        None,         False),
    ]
    nxa.NxcAutomator.print_loot_on_record(rows)
    out = strip_ansi(capsys.readouterr().out)
    assert "LOOT ON RECORD (3 valid · 1 Pwn3d)" in out
    assert "corp.local" in out and "(no domain / local)" in out
    assert "administrator@10.0.0.5" in out and "(Pwn3d!)" in out
    assert "[smb/local]" in out  # auth scope shown


def test_print_loot_on_record_empty_says_nothing_on_record(nxa, capsys):
    nxa.NxcAutomator.print_loot_on_record([])
    out = strip_ansi(capsys.readouterr().out)
    assert "no valid credentials on record" in out.lower()


# ---- --null-session is protocol-aware -----------------------------------

def test_null_session_is_protocol_aware(nxa):
    """--null-session tries null/Guest/anonymous:'' on every protocol, plus
    FTP's classic anonymous:anonymous and ftp:ftp ONLY on FTP."""
    a = nxa.NxcAutomator(target="x", null_session=True, no_banner=True)
    ftp = [c.display for c in a.credentials if nxa.NxcAutomator._credential_supported(c, "ftp")]
    smb = [c.display for c in a.credentials if nxa.NxcAutomator._credential_supported(c, "smb")]
    # FTP gets the full set including the FTP-specific combos
    assert "ftp:ftp" in ftp and "anonymous:anonymous" in ftp
    assert "<empty>:<empty>" in ftp
    # Other protocols keep the universal null/Guest/anonymous but NOT ftp noise
    assert "<empty>:<empty>" in smb and "Guest:<empty>" in smb
    assert "ftp:ftp" not in smb and "anonymous:anonymous" not in smb
