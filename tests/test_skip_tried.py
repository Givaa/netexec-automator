"""Tests for the --skip-tried incremental-spray cache."""

import hashlib
from pathlib import Path

import pytest


@pytest.fixture
def cache(nxa, tmp_path):
    c = nxa.HostCache(tmp_path / "state.db", ttl=86400)
    yield c
    c.close()


# ---- HostCache.tried_creds table -----------------------------------------

def test_was_tried_returns_none_when_never_attempted(cache):
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "deadbeef") is None


def test_record_and_lookup_roundtrip(cache):
    cache.record_attempt(
        "10.0.0.5", "smb", False, "admin", "abc123", "corp.local", "fail", pwn3d=False
    )
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "abc123") == "fail"


def test_successes_are_always_skipped_on_rerun(cache):
    cache.record_attempt(
        "10.0.0.5", "smb", False, "admin", "abc", "corp.local", "ok", pwn3d=True
    )
    # Even with rerun_after=1 (i.e. immediately stale), 'ok' is forever-skipped
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "abc", rerun_after=1) == "ok"


def test_stale_failures_are_retried_when_rerun_after_is_set(cache):
    """Failures older than `rerun_after` should report 'None' so the caller
    re-attempts; fresh failures remain skipped."""
    import time
    cache.record_attempt(
        "10.0.0.5", "smb", False, "admin", "xyz", "corp.local", "fail"
    )
    # Backdate the row to look 2 hours old
    cache._conn.execute(
        "UPDATE tried_creds SET attempted_at = ? WHERE user = 'admin' AND secret_hash = 'xyz'",
        (int(time.time()) - 7200,),
    )
    cache._conn.commit()
    # Default (rerun_after=0): still skipped
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "xyz") == "fail"
    # 1h rerun-after → 2h-old row is stale → None (re-attempt)
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "xyz", rerun_after=3600) is None


def test_record_upserts_on_pk(cache):
    """A second record_attempt for the same PK should overwrite, not duplicate."""
    cache.record_attempt("10.0.0.5", "smb", False, "admin", "abc", None, "fail")
    cache.record_attempt("10.0.0.5", "smb", False, "admin", "abc", None, "ok", pwn3d=True)
    assert cache.count_tried() == 1
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "abc") == "ok"


def test_list_valid_returns_successes_pwn3d_first(cache):
    """list_valid returns only ok/pwn3d rows (never failures), Pwn3d first,
    and never leaks the secret hash."""
    cache.record_attempt("10.0.0.5", "smb", False, "bob", "h1", None, "fail")          # excluded
    cache.record_attempt("10.0.0.5", "smb", False, "alice", "h2", None, "ok")          # valid
    cache.record_attempt("10.0.0.6", "smb", True, "admin", "h3", None, "ok", pwn3d=True)  # pwn3d
    rows = cache.list_valid()
    assert len(rows) == 2
    # rows are (target, protocol, local_auth, user, domain, pwn3d, attempted_at)
    assert rows[0][:6] == ("10.0.0.6", "smb", True, "admin", None, True)   # Pwn3d first
    assert isinstance(rows[0][6], int) and rows[0][6] > 0                  # timestamp present
    assert any(r[:6] == ("10.0.0.5", "smb", False, "alice", None, False) for r in rows)
    # secret hashes never appear in the returned tuples
    assert all(h not in str(r) for r in rows for h in ("h1", "h2", "h3"))


def test_clear_tried_cache_reports_count(cache):
    for u in ("a", "b", "c"):
        cache.record_attempt("10.0.0.5", "smb", False, u, "x", None, "fail")
    assert cache.count_tried() == 3
    n = cache.clear_tried_cache()
    assert n == 3
    assert cache.count_tried() == 0


def test_local_auth_is_part_of_the_key(cache):
    """The same user:secret against the same host at domain-auth vs local-auth
    are two distinct attempts."""
    cache.record_attempt("10.0.0.5", "smb", False, "admin", "abc", None, "fail")
    cache.record_attempt("10.0.0.5", "smb", True,  "admin", "abc", None, "ok", pwn3d=True)
    assert cache.was_tried("10.0.0.5", "smb", False, "admin", "abc") == "fail"
    assert cache.was_tried("10.0.0.5", "smb", True,  "admin", "abc") == "ok"


# ---- Credential fingerprint ----------------------------------------------

def test_fingerprint_is_secret_only(nxa):
    """Two different users with the same password must collide on
    fingerprint — the user is a separate PK column."""
    a = nxa.Credential(user="alice", password="Summer2025!")
    b = nxa.Credential(user="bob",   password="Summer2025!")
    assert nxa.NxcAutomator._credential_fingerprint(a) == \
           nxa.NxcAutomator._credential_fingerprint(b)


def test_fingerprint_differs_for_different_secrets(nxa):
    a = nxa.Credential(user="admin", password="Welcome1")
    b = nxa.Credential(user="admin", password="Welcome2")
    assert nxa.NxcAutomator._credential_fingerprint(a) != \
           nxa.NxcAutomator._credential_fingerprint(b)


def test_fingerprint_handles_hash_creds(nxa):
    pwd  = nxa.Credential(user="admin", password="x")
    hsh  = nxa.Credential(user="admin", nthash="8846f7eaee8fb117ad06bdd830b7586c")
    # Should be different because the secret material differs
    assert nxa.NxcAutomator._credential_fingerprint(pwd) != \
           nxa.NxcAutomator._credential_fingerprint(hsh)


def test_fingerprint_no_plaintext_leak(nxa):
    """The fingerprint is SHA1, not the raw secret. We never want
    'Summer2025!' showing up if someone reads the SQLite cache."""
    cred = nxa.Credential(user="admin", password="Summer2025!")
    fp = nxa.NxcAutomator._credential_fingerprint(cred)
    assert "Summer2025" not in fp
    assert len(fp) == 40  # SHA1 hex


# ---- NxcAutomator wiring -------------------------------------------------

def test_skip_tried_opens_cache_even_without_nmap(nxa, tmp_path):
    """--skip-tried alone (no --nmap, no --bloodhound) should still open the cache."""
    a = nxa.NxcAutomator(
        target="x", user="u", password="p",
        skip_tried=True, cache_path=str(tmp_path / "state.db"),
    )
    assert a.cache is not None
    a.cache.close()


def test_skip_tried_default_off(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a.skip_tried is False
    assert a.skipped_already_tried == 0


# ---- reset() (the --reset full wipe) -------------------------------------

def test_reset_wipes_all_tables(cache):
    """--reset must clear every table for a clean new engagement, not just
    tried_creds — port scans, loot, DC discoveries and BloodHound runs."""
    cache.store("10.0.0.5", {445: "open"})
    cache.record_attempt("10.0.0.5", "smb", False, "admin", "h", "corp.local", "ok", pwn3d=True)
    cache.record_dc("corp.local", "10.0.0.5", "smb_banner")
    cache.record_bloodhound("corp.local", "10.0.0.5", "admin", "/tmp/bh", True)

    counts = cache.reset()

    assert counts["host_ports"] >= 1
    assert counts["tried_creds"] == 1
    assert counts["domain_controllers"] == 1
    assert counts["bloodhound_runs"] == 1
    # Everything is gone afterwards.
    assert cache.get_fresh("10.0.0.5") is None
    assert cache.count_tried() == 0
    assert cache.list_valid() == []
    assert cache.get_dcs("corp.local") == []


# ---- scoped reset (--reset DOMAIN / --reset-except DOMAIN) ---------------

def test_reset_domain_scopes_to_one_domain(cache):
    cache.record_attempt("10.0.0.5", "smb", False, "a", "h1", "corp.local", "ok", pwn3d=True)
    cache.record_attempt("10.0.0.9", "smb", False, "b", "h2", "other.local", "ok")
    cache.record_attempt("172.16.0.1", "ssh", False, "root", "h3", None, "ok")  # local
    cache.store("10.0.0.5", {445: "open"})  # port scan must survive a scoped reset
    counts = cache.reset_domain("corp.local")
    assert counts["tried_creds"] == 1
    remaining = {(r[0], r[4]) for r in cache.list_valid()}
    assert ("10.0.0.5", "corp.local") not in remaining
    assert ("10.0.0.9", "other.local") in remaining
    assert ("172.16.0.1", None) in remaining          # local creds untouched
    assert cache.get_fresh("10.0.0.5") is not None     # host_ports untouched


def test_reset_domain_local_targets_null_domain(cache):
    cache.record_attempt("172.16.0.1", "ssh", False, "root", "h1", None, "ok")
    cache.record_attempt("10.0.0.5", "smb", False, "a", "h2", "corp.local", "ok")
    counts = cache.reset_domain("local")
    assert counts["tried_creds"] == 1
    remaining = {(r[0], r[4]) for r in cache.list_valid()}
    assert ("172.16.0.1", None) not in remaining       # the local creds are gone
    assert ("10.0.0.5", "corp.local") in remaining


def test_reset_except_keeps_only_one_domain(cache):
    cache.record_attempt("10.0.0.5", "smb", False, "a", "h1", "corp.local", "ok")
    cache.record_attempt("10.0.0.9", "smb", False, "b", "h2", "other.local", "ok")
    cache.record_attempt("172.16.0.1", "ssh", False, "root", "h3", None, "ok")  # local
    cache.reset_except("corp.local")
    remaining = {(r[0], r[4]) for r in cache.list_valid()}
    assert remaining == {("10.0.0.5", "corp.local")}   # everyone else (incl. local) wiped
