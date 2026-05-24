"""Snapshot tests: lock in the expected shape of nxc / nmap output.

These regression tests catch the case where NetExec changes its output
format in a future release and our regex/marker assumptions silently stop
matching (turning every action into ⊘ instead of ✔). Fixtures live in
tests/fixtures/nxc_outputs/ as plain text, captured from realistic runs.

If a fixture starts failing after a NetExec upgrade, you've found a
breaking change in nxc — and the fix is usually a single regex tweak."""

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "nxc_outputs"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


# ---- SMB banner / Pwn3d ----

def test_smb_banner_extracts_domain(nxa):
    blob = load("smb_banner_dc.txt")
    m = nxa.SMB_DOMAIN_RE.search(blob)
    assert m and m.group(1) == "corp.local"


def test_smb_banner_extracts_name(nxa):
    blob = load("smb_banner_dc.txt")
    m = nxa.SMB_NAME_RE.search(blob)
    assert m and m.group(1) == "DC01"


def test_pwn3d_detected_in_real_line(nxa):
    blob = load("smb_banner_dc.txt")
    pwn3d_lines = [l for l in blob.splitlines() if nxa.NxcAutomator._is_pwn3d(l)]
    assert len(pwn3d_lines) == 1
    assert "administrator" in pwn3d_lines[0].lower()


# ---- Shares / enum success markers ----

def test_shares_action_classifies_as_ok(nxa, tmp_path):
    blob = load("smb_shares.txt")
    loot = tmp_path / "shares.txt"
    loot.write_text(blob)
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout=blob, stderr="", loot_path=loot)
    markers = next(a for a in nxa.SMB_ENUM_ACTIONS if a["name"] == "shares")["ok_markers"]
    status, _, _ = nxa.NxcAutomator._classify_action(res, markers)
    assert status == "ok"


def test_pass_pol_lockout_extracted(nxa):
    blob = load("smb_pass_pol.txt")
    m = nxa.LOCKOUT_THRESHOLD_RE.search(blob)
    assert m and int(m.group(1)) == 3
    m = nxa.LOCKOUT_DURATION_RE.search(blob)
    assert m and "30 minutes" in m.group(1)


def test_pass_pol_classifier_says_ok(nxa, tmp_path):
    blob = load("smb_pass_pol.txt")
    loot = tmp_path / "pp.txt"
    loot.write_text(blob)
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout=blob, stderr="", loot_path=loot)
    markers = next(a for a in nxa.SMB_ENUM_ACTIONS if a["name"] == "pass-pol")["ok_markers"]
    status, _, _ = nxa.NxcAutomator._classify_action(res, markers)
    assert status == "ok"


# ---- SAM / secretsdump ----

def test_sam_dump_yields_four_hashes(nxa):
    blob = load("smb_sam.txt")
    hits = list(nxa.HASH_DUMP_LINE_RE.finditer(blob))
    assert len(hits) == 4
    users = [m.group("user") for m in hits]
    assert "Administrator" in users
    assert "Guest" in users


def test_sam_classifier_marks_ok_when_dump_present(nxa, tmp_path):
    blob = load("smb_sam.txt")
    loot = tmp_path / "sam.txt"
    loot.write_text(blob)
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout=blob, stderr="", loot_path=loot)
    markers = next(a for a in nxa.SMB_SECRETS_ACTIONS if a["name"] == "sam")["ok_markers"]
    status, _, _ = nxa.NxcAutomator._classify_action(res, markers)
    assert status == "ok"


# ---- Access-denied / logon-failure (the main 'noop' triggers) ----

def test_access_denied_is_noop_not_ok(nxa, tmp_path):
    """exit code 0 but STATUS_ACCESS_DENIED → must classify as 'noop'."""
    blob = load("smb_access_denied.txt")
    loot = tmp_path / "ad.txt"
    loot.write_text(blob)
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout=blob, stderr="", loot_path=loot)
    markers = next(a for a in nxa.SMB_SECRETS_ACTIONS if a["name"] == "sam")["ok_markers"]
    status, _, note = nxa.NxcAutomator._classify_action(res, markers)
    assert status == "noop"
    assert "access denied" in note.lower()


def test_logon_failure_is_noop_not_ok(nxa, tmp_path):
    blob = load("smb_logon_failure.txt")
    loot = tmp_path / "lf.txt"
    loot.write_text(blob)
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout=blob, stderr="", loot_path=loot)
    markers = next(a for a in nxa.SMB_SECRETS_ACTIONS if a["name"] == "sam")["ok_markers"]
    status, _, _ = nxa.NxcAutomator._classify_action(res, markers)
    assert status == "noop"


# ---- LDAP roasting ----

def test_asreproast_user_extracted(nxa):
    blob = load("ldap_asreproast.txt")
    users = nxa.KRB_AS_REP_USER_RE.findall(blob)
    assert "alice" in users
    assert "svc_legacy" in users


def test_kerberoasting_user_extracted(nxa):
    blob = load("ldap_kerberoasting.txt")
    users = nxa.KRB_TGS_REP_USER_RE.findall(blob)
    assert "svc_mssql" in users
    assert "svc_iis" in users


def test_asreproast_classifier_reads_loot_file(nxa, tmp_path):
    """The action writes hashes to the loot file, not stdout — classifier
    must use extra_text to detect success."""
    blob = load("ldap_asreproast.txt")
    loot = tmp_path / "asrep.txt"
    loot.write_text(blob)
    # Simulate empty stdout (nxc wrote to file, not stdout)
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout="", stderr="", loot_path=loot)
    markers = next(a for a in nxa.LDAP_ENUM_ACTIONS if a["name"] == "asreproast")["ok_markers"]
    status, _, _ = nxa.NxcAutomator._classify_action(res, markers, extra_text=blob)
    assert status == "ok"


# ---- Nmap XML parsing ----

def test_nmap_xml_parser_extracts_open_ports(nxa):
    xml = load("nmap_scan.xml")
    parsed = nxa.NmapScanner._parse_xml(xml)
    assert "10.10.10.5" in parsed
    ports = parsed["10.10.10.5"]
    assert ports[445] == "open"
    assert ports[389] == "open"
    assert 22 not in ports  # SSH wasn't in this fixture
