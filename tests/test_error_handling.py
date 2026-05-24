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


def test_diagnose_zero_cracks_segfault(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot)
    cracker.last_stderr = "hashcat killed by signal 11 (attempt 2/2)"
    hint = cracker.diagnose_zero_cracks()
    assert hint and "segfault" in hint.lower()


def test_diagnose_zero_cracks_oom(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot)
    cracker.last_stderr = "hashcat killed by signal 9"
    hint = cracker.diagnose_zero_cracks()
    assert hint and "oom" in hint.lower()


def test_cache_path_custom(nxa, tmp_path):
    """--cache-path lets the user isolate parallel runs on a custom DB."""
    custom = tmp_path / "isolated.db"
    a = nxa.NxcAutomator(
        target="x", user="u", password="p",
        nmap_enabled=True, cache_path=str(custom),
    )
    assert a.cache is not None
    assert a.cache.path == custom
    assert custom.exists()
    a.cache.close()


def test_streaming_nxc_action_no_capture_output(nxa, tmp_path, monkeypatch):
    """Streaming refactor: stdout goes straight to the loot file, not RAM."""
    import subprocess as sp
    a = nxa.NxcAutomator(target="x", user="u", password="p", loot_dir=str(tmp_path / "loot"))
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        # Verify we are NOT using capture_output (memory-killing for big dumps).
        assert "capture_output" not in kwargs, "must stream stdout to file, not buffer"
        assert kwargs.get("stdout") is not None, "stdout must be a file handle"
        # Write fake nxc output to the streamed file
        kwargs["stdout"].write(b"SMB  10.0.0.1  445  HOST  Sharename     Permissions  Remark\n"
                                b"ADMIN$  READ\n")
        captured["cmd"] = cmd
        return sp.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(sp, "run", fake_run)
    loot_path = tmp_path / "test-out.txt"
    result = a._run_nxc_action(
        "smb", "10.0.0.1", a.credentials[0], local_auth=False,
        extra_args=["--shares"], loot_path=loot_path,
    )
    assert result.ok
    assert "Sharename" in result.stdout  # head read back from file
    assert loot_path.exists() and loot_path.stat().st_size > 0
    # The head should also be re-readable for the classifier
    status, _, _ = nxa.NxcAutomator._classify_action(result, ["Sharename"])
    assert status == "ok"


def test_streaming_nxc_action_permission_error(nxa, tmp_path):
    """If loot dir can't be created, we record an error and return a fail result."""
    # Point loot at an unwriteable parent (file masquerading as dir)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("I am a file")
    a = nxa.NxcAutomator(target="x", user="u", password="p", loot_dir=str(blocker))
    loot_path = blocker / "sub" / "out.txt"
    result = a._run_nxc_action(
        "smb", "10.0.0.1", a.credentials[0], local_auth=False,
        extra_args=["--shares"], loot_path=loot_path,
    )
    assert not result.ok
    assert a.strict_errors  # error was recorded
