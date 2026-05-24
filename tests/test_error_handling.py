"""Tests for the error-handling polish pass: classifier, flag-combo warnings,
strict mode, DC heuristic, cracker diagnostics."""

from pathlib import Path


def test_classify_action_ok(nxa):
    res = nxa.NxcActionResult(ok=True, exit_code=0,
                              stdout="Sharename     Permissions  Remark\nADMIN$  READ", stderr="",
                              loot_path=Path("/tmp/x"))
    status, icon, note = nxa.NxcAutomator._classify_action(res, ["Sharename"])
    assert status == "ok"
    assert icon == nxa.ICON_OK


def test_classify_action_noop_when_no_marker(nxa):
    res = nxa.NxcActionResult(ok=True, exit_code=0,
                              stdout="SMB  10.0.0.1  445  HOST  [+] WORKGROUP\\admin:pwd", stderr="",
                              loot_path=Path("/tmp/x"))
    status, icon, _ = nxa.NxcAutomator._classify_action(res, ["Sharename", "Pwn3d"])
    assert status == "noop"
    assert icon == nxa.ICON_NOOP


def test_classify_action_noop_when_access_denied(nxa):
    res = nxa.NxcActionResult(ok=True, exit_code=0,
                              stdout="SMB  10.0.0.1  445  HOST  STATUS_ACCESS_DENIED", stderr="",
                              loot_path=Path("/tmp/x"))
    status, icon, note = nxa.NxcAutomator._classify_action(res, ["Sharename"])
    assert status == "noop"
    assert "access denied" in note.lower()


def test_classify_action_fail_on_exit_code(nxa):
    res = nxa.NxcActionResult(ok=False, exit_code=2, stdout="", stderr="boom",
                              loot_path=Path("/tmp/x"))
    status, icon, _ = nxa.NxcAutomator._classify_action(res, ["whatever"])
    assert status == "fail"
    assert icon == nxa.ICON_FAIL


def test_classify_action_fail_on_timeout(nxa):
    res = nxa.NxcActionResult(ok=False, exit_code=-1, stdout="", stderr="timed out",
                              loot_path=Path("/tmp/x"))
    status, icon, note = nxa.NxcAutomator._classify_action(res, ["whatever"])
    assert status == "fail"
    assert icon == nxa.ICON_TIMEOUT


def test_classify_action_uses_extra_text(nxa, tmp_path):
    """asreproast writes hashes to a file, not stdout — classifier must read it."""
    out_file = tmp_path / "asrep.txt"
    out_file.write_text("$krb5asrep$23$alice@CORP.LOCAL:abcdef...")
    res = nxa.NxcActionResult(ok=True, exit_code=0, stdout="", stderr="", loot_path=out_file)
    status, _, _ = nxa.NxcAutomator._classify_action(res, ["$krb5asrep$"], extra_text=out_file.read_text())
    assert status == "ok"


def test_strict_records_errors(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", strict=True)
    a._record_error("boom1")
    a._record_error("boom2")
    assert len(a.strict_errors) == 2


def test_validate_flag_combinations_crack_without_sources(nxa, capsys):
    # --crack on, but no source of hashes (no secretsdump, no enum)
    a = nxa.NxcAutomator(target="x", user="u", password="p", crack_enabled=True)
    # Disable the cracker so we don't try the binary detection
    a.cracker = None
    a.crack_enabled = True
    a._validate_flag_combinations()
    err = capsys.readouterr().err
    assert "--crack" in err and "hash source" in err


def test_validate_flag_combinations_only_excludes_smb_with_modules(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p",
                         modules="spider_plus", only_protocols="ldap")
    a._validate_flag_combinations()
    err = capsys.readouterr().err
    assert "--modules" in err


def test_validate_flag_combinations_quiet_when_correct(nxa, capsys):
    a = nxa.NxcAutomator(target="x", user="u", password="p",
                         enum_enabled=True, secretsdump=True)
    a._validate_flag_combinations()
    err = capsys.readouterr().err
    assert err == ""


def test_is_likely_dc_when_no_cache(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")  # no --nmap, no cache
    # Without cache data we attempt anyway (return True)
    assert a._is_likely_dc("10.0.0.5") is True


def test_diagnose_zero_cracks_no_hashes_loaded(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot)
    cracker.last_stderr = "ERROR: No hashes loaded"
    hint = cracker.diagnose_zero_cracks()
    assert hint and "no hashes loaded" in hint.lower()


def test_diagnose_zero_cracks_mode_unsupported(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot)
    cracker.last_stderr = "Hash-mode 18200 is not supported in this version"
    hint = cracker.diagnose_zero_cracks()
    assert hint and "mode" in hint.lower()


def test_diagnose_zero_cracks_returns_none_on_empty(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot)
    cracker.last_stderr = ""
    assert cracker.diagnose_zero_cracks() is None
