"""Tests for the HashCracker class: wordlist discovery, potfile parsing,
command builder, kerberos user extraction."""

import gzip
from pathlib import Path
from unittest import mock

import pytest


def test_detect_cracker_prefers_hashcat(nxa):
    with mock.patch("shutil.which", side_effect=lambda t: f"/usr/bin/{t}"):
        assert nxa.HashCracker.detect_cracker("auto") == "hashcat"


def test_detect_cracker_falls_back_to_john(nxa):
    with mock.patch("shutil.which", side_effect=lambda t: "/usr/bin/john" if t == "john" else None):
        assert nxa.HashCracker.detect_cracker("auto") == "john"


def test_detect_cracker_returns_none_when_missing(nxa):
    with mock.patch("shutil.which", return_value=None):
        assert nxa.HashCracker.detect_cracker("auto") is None


def test_find_wordlist_uses_explicit_arg(nxa, tmp_path):
    wl = tmp_path / "my.txt"
    wl.write_text("password\n123456\n")
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot, wordlist=str(wl))
    assert cracker.find_wordlist() == wl


def test_find_wordlist_decompresses_gz(nxa, tmp_path):
    wl_gz = tmp_path / "rockyou.txt.gz"
    with gzip.open(wl_gz, "wb") as fh:
        fh.write(b"password\n123456\n")
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot, wordlist=str(wl_gz))
    resolved = cracker.find_wordlist()
    assert resolved == wl_gz.with_suffix("")  # .txt sibling
    assert resolved.read_text() == "password\n123456\n"


def test_find_wordlist_returns_none_when_missing(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    # Override the global defaults to point at /nonexistent so the test
    # doesn't accidentally pick up a real rockyou.txt on disk.
    cracker = nxa.HashCracker(loot=loot, wordlist="/definitely/does/not/exist.txt")
    assert cracker.find_wordlist() is None


def test_parse_potfile_nt(nxa):
    text = (
        "8846f7eaee8fb117ad06bdd830b7586c:Password123\n"
        "# comment\n"
        "31d6cfe0d16ae931b73c59d7e0c089c0:\n"  # empty plaintext → skipped
        "  \n"
        "aad3b435b51404eeaad3b435b51404ee:Welcome1\n"
    )
    pairs = nxa.HashCracker._parse_potfile(text)
    assert ("8846f7eaee8fb117ad06bdd830b7586c", "Password123") in pairs
    assert ("aad3b435b51404eeaad3b435b51404ee", "Welcome1") in pairs


def test_parse_potfile_kerberos(nxa):
    text = "$krb5asrep$23$alice@CORP.LOCAL:abcdef:Summer2025!\n"
    pairs = nxa.HashCracker._parse_potfile(text)
    # rpartition splits on the LAST colon, so plaintext is correct even
    # when the hash itself contains colons.
    assert pairs[0][1] == "Summer2025!"
    assert "alice" in pairs[0][0]


def test_belongs_to_filters_correctly(nxa):
    HC = nxa.HashCracker
    nt = "8846f7eaee8fb117ad06bdd830b7586c"
    asrep = "$krb5asrep$23$alice@CORP.LOCAL"
    tgs = "$krb5tgs$23$*svc$CORP.LOCAL$mssql/dc*$..."
    assert HC._belongs_to(nt, "nt")
    assert not HC._belongs_to(asrep, "nt")
    assert HC._belongs_to(asrep, "asrep")
    assert HC._belongs_to(tgs, "tgs")


def test_build_cmd_hashcat_nt(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot, cracker="hashcat")
    cmd = cracker.build_cmd("nt", tmp_path / "h.txt", tmp_path / "wl.txt")
    assert cmd[0] == "hashcat"
    assert "1000" in cmd  # -m 1000 for NT
    assert "-a" in cmd and "0" in cmd
    assert "--potfile-path" in cmd


def test_build_cmd_hashcat_asrep(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot, cracker="hashcat")
    cmd = cracker.build_cmd("asrep", tmp_path / "h.txt", tmp_path / "wl.txt")
    assert "18200" in cmd


def test_build_cmd_with_rules(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot, cracker="hashcat", rules="/etc/rules/best64.rule")
    cmd = cracker.build_cmd("nt", tmp_path / "h.txt", tmp_path / "wl.txt")
    assert "-r" in cmd
    assert "/etc/rules/best64.rule" in cmd


def test_build_cmd_john(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    cracker = nxa.HashCracker(loot=loot, cracker="john")
    cmd = cracker.build_cmd("nt", tmp_path / "h.txt", tmp_path / "wl.txt")
    assert cmd[0] == "john"
    assert any("--format=nt" in a for a in cmd)
    assert any("--wordlist=" in a for a in cmd)


def test_kerberos_user_regex(nxa):
    asrep = "$krb5asrep$23$alice@CORP.LOCAL:abcdef..."
    m = nxa.KRB_AS_REP_USER_RE.search(asrep)
    assert m and m.group(1) == "alice"

    tgs = "$krb5tgs$23$*svc_sql$CORP.LOCAL$mssql/dc01*$abcdef..."
    m = nxa.KRB_TGS_REP_USER_RE.search(tgs)
    assert m and m.group(1) == "svc_sql"


def test_parse_potfile_nt_password_with_colon(nxa):
    """A cracked NT plaintext containing ':' must be kept whole — split on the
    FIRST colon after the 32-hex hash, not truncated by the last colon (which
    used to drop the crack entirely once _belongs_to rejected the bad hash)."""
    text = "8846f7eaee8fb117ad06bdd830b7586c:Sum:mer:2025!\n"
    pairs = nxa.HashCracker._parse_potfile(text)
    assert ("8846f7eaee8fb117ad06bdd830b7586c", "Sum:mer:2025!") in pairs
