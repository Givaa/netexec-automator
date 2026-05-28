"""Tests for the BloodHound + domain-wide LDAP cred/DC selection logic."""

from unittest import mock


# ---- BloodHoundRunner.build_cmd -----------------------------------------

def test_build_cmd_strips_domain_prefix_from_user(nxa, tmp_path):
    """`bloodhound-python` chokes on 'DOMAIN\\user' — feed it 'user' only."""
    loot = nxa.LootStore(tmp_path / "loot")
    runner = nxa.BloodHoundRunner(cache=None, loot=loot)
    cred = nxa.Credential(user="corp\\administrator", password="Summer2025!")
    cmd = runner.build_cmd("corp.local", "10.10.10.5", cred)
    # The -u value must be 'administrator', not 'corp\administrator'
    u_idx = cmd.index("-u")
    assert cmd[u_idx + 1] == "administrator"


def test_build_cmd_prefers_dc_fqdn_for_dc_param(nxa, tmp_path):
    """-dc should accept the FQDN when provided; -ns is always the IP
    (bloodhound-python uses it as a nameserver, IPs only)."""
    loot = nxa.LootStore(tmp_path / "loot")
    runner = nxa.BloodHoundRunner(cache=None, loot=loot)
    cred = nxa.Credential(user="administrator", password="x")
    cmd = runner.build_cmd("corp.local", "10.10.10.5", cred, dc_host="DC01.corp.local")
    dc_idx = cmd.index("-dc")
    ns_idx = cmd.index("-ns")
    assert cmd[dc_idx + 1] == "DC01.corp.local"
    assert cmd[ns_idx + 1] == "10.10.10.5"


def test_build_cmd_falls_back_to_ip_when_no_fqdn(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    runner = nxa.BloodHoundRunner(cache=None, loot=loot)
    cred = nxa.Credential(user="admin", password="x")
    cmd = runner.build_cmd("corp.local", "10.10.10.5", cred)
    assert cmd[cmd.index("-dc") + 1] == "10.10.10.5"


def test_build_cmd_uses_hashes_when_no_password(nxa, tmp_path):
    loot = nxa.LootStore(tmp_path / "loot")
    runner = nxa.BloodHoundRunner(cache=None, loot=loot)
    cred = nxa.Credential(user="svc", nthash="8846f7eaee8fb117ad06bdd830b7586c")
    cmd = runner.build_cmd("corp.local", "10.10.10.5", cred)
    assert "--hashes" in cmd
    assert ":8846f7eaee8fb117ad06bdd830b7586c" in cmd
    assert "-p" not in cmd


def test_strip_domain_prefix_handles_no_prefix(nxa):
    assert nxa.BloodHoundRunner._strip_domain_prefix("administrator") == "administrator"
    assert nxa.BloodHoundRunner._strip_domain_prefix("CORP\\admin") == "admin"


# ---- NxcAutomator._pick_best_domain_cred --------------------------------

def test_pick_best_domain_cred_prefers_pwn3d(nxa):
    """Two domain creds for the same domain: the (Pwn3d!) one must win
    over the non-admin one. This is the main bug the previous selector had."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    cred_low = nxa.Credential(user="lowpriv", password="pwd")
    cred_high = nxa.Credential(user="admin", password="pwd")
    a.host_domain["10.0.0.5"] = "corp.local"
    a.host_domain["10.0.0.7"] = "corp.local"
    a.valid_creds = [
        # Inserted in 'low first' order to prove the picker doesn't take whatever's first
        {"host": "10.0.0.5", "protocol": "smb", "local_auth": False,
         "credential": cred_low, "raw": "corp\\lowpriv:pwd"},
        {"host": "10.0.0.7", "protocol": "smb", "local_auth": False,
         "credential": cred_high, "raw": "corp\\admin:pwd (Pwn3d!)"},
    ]
    best = a._pick_best_domain_cred("corp.local")
    assert best is not None
    assert best["credential"].user == "admin"
    assert "(Pwn3d!)" in best["raw"]


def test_pick_best_domain_cred_skips_local_auth(nxa):
    """A local-auth cred (--local-auth on SMB) is NOT a domain credential
    and must not be returned even if it's a Pwn3d! one."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    local_admin = nxa.Credential(user="admin", password="local-pwd")
    domain_user = nxa.Credential(user="alice", password="dom-pwd")
    a.host_domain["10.0.0.5"] = "corp.local"
    a.valid_creds = [
        {"host": "10.0.0.5", "protocol": "smb", "local_auth": True,
         "credential": local_admin, "raw": "WS01\\admin:local-pwd (Pwn3d!)"},
        {"host": "10.0.0.5", "protocol": "smb", "local_auth": False,
         "credential": domain_user, "raw": "corp\\alice:dom-pwd"},
    ]
    best = a._pick_best_domain_cred("corp.local")
    assert best["credential"].user == "alice"


def test_pick_best_domain_cred_returns_none_when_no_match(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.valid_creds = []
    assert a._pick_best_domain_cred("corp.local") is None


# ---- NxcAutomator._dc_fqdn_for_domain ------------------------------------

def test_dc_fqdn_uses_smb_banner_name(nxa):
    """When _probe_smb_banner / _detect_dc_from_results captured the NetBIOS
    name, the FQDN helper should compose NAME.domain."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.host_names["10.10.10.5"] = "DC01"
    assert a._dc_fqdn_for_domain("corp.local", "10.10.10.5").lower() == "dc01.corp.local"


def test_dc_fqdn_returns_none_without_smb_banner(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert a._dc_fqdn_for_domain("corp.local", "10.10.10.5") is None


# ---- NxcAutomator._pick_dc_for_domain ------------------------------------

def test_pick_dc_for_domain_prefers_dns_srv(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.domain_hosts["corp.local"] = {"10.10.10.5"}
    with mock.patch.object(nxa.NxcAutomator, "_resolve_dc_via_dns",
                           return_value=["dc-from-dns.corp.local"]):
        dc_ip, source = a._pick_dc_for_domain("corp.local")
    assert dc_ip == "dc-from-dns.corp.local"
    assert source == "dns_srv"


def test_pick_dc_for_domain_falls_back_to_banner_host(nxa):
    """No DNS, no cache → fall back to whatever host advertised the domain."""
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    a.domain_hosts["corp.local"] = {"10.10.10.5"}
    with mock.patch.object(nxa.NxcAutomator, "_resolve_dc_via_dns", return_value=[]):
        dc_ip, source = a._pick_dc_for_domain("corp.local")
    assert dc_ip == "10.10.10.5"
    assert source == "smb_banner"


def test_pick_dc_for_domain_returns_none_when_unknown(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    with mock.patch.object(nxa.NxcAutomator, "_resolve_dc_via_dns", return_value=[]):
        dc_ip, source = a._pick_dc_for_domain("unknown.local")
    assert dc_ip is None
