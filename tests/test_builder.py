"""Tests for the credential matcher, command builder, and protocol filtering."""

import tempfile
from pathlib import Path


def test_match_password_credential(nxa):
    a = nxa.NxcAutomator(target="x", user="administrator", password="S3cret")
    m = a._match_msg_to_credential("corp.local\\administrator:S3cret", "smb")
    assert m and m.user == "administrator"


def test_match_hash_credential(nxa):
    a = nxa.NxcAutomator(target="x", user="svc", nthash="8846f7eaee8fb117ad06bdd830b7586c")
    m = a._match_msg_to_credential("WORKGROUP\\svc:8846f7eaee8fb117ad06bdd830b7586c", "smb")
    assert m and m.nthash


def test_match_null_session_artifact(nxa):
    a = nxa.NxcAutomator(target="x", null_session=True)
    # nxc null-session lines look like 'WORKGROUP\:'
    m = a._match_msg_to_credential("WORKGROUP\\:", "smb")
    assert m is not None


def test_match_guest_user(nxa):
    a = nxa.NxcAutomator(target="x", null_session=True)
    m = a._match_msg_to_credential("WORKGROUP\\Guest:", "smb")
    assert m and m.user.lower() == "guest"


def test_combo_loader_mixed(nxa):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write(
        "# combo\n"
        "admin:Password!\n"
        "svc:8846f7eaee8fb117ad06bdd830b7586c\n"
        "legacy:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
        "guest:\n"
    )
    tmp.close()
    try:
        a = nxa.NxcAutomator(target="x", combo=tmp.name)
        assert len(a.credentials) == 4
        assert any(c.password == "Password!" for c in a.credentials)
        assert any(c.is_hash and c.lmhash is None for c in a.credentials)
        assert any(c.is_hash and c.lmhash for c in a.credentials)
    finally:
        Path(tmp.name).unlink()


def test_protocol_filter_only(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", only_protocols="smb,ldap")
    tasks = a._build_protocol_tasks()
    protos = {p for p, _ in tasks}
    assert protos == {"smb", "ldap"}


def test_protocol_filter_exclude(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p",
                         exclude_protocols="vnc,ftp,nfs")
    tasks = a._build_protocol_tasks()
    protos = {p for p, _ in tasks}
    assert protos == set(nxa.ALL_PROTOCOLS) - {"vnc", "ftp", "nfs"}


def test_protocol_filter_unknown_raises(nxa):
    import pytest
    with pytest.raises(ValueError, match="unknown protocol"):
        nxa.NxcAutomator(target="x", user="u", password="p", only_protocols="smb,banana")


def test_build_nxc_command_adds_domain(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", domain="corp.local")
    cmd = a._build_nxc_command("smb", "10.0.0.1", a.credentials[0], local_auth=False)
    assert "-d" in cmd and "corp.local" in cmd


def test_build_nxc_command_local_auth_drops_domain(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", domain="corp.local")
    cmd = a._build_nxc_command("smb", "10.0.0.1", a.credentials[0], local_auth=True)
    assert "-d" not in cmd
    assert "--local-auth" in cmd


def test_build_nxc_command_kerberos_only_on_supported(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", kerberos=True, domain="corp.local")
    smb_cmd = a._build_nxc_command("smb", "10.0.0.1", a.credentials[0], local_auth=False)
    assert "-k" in smb_cmd  # SMB supports Kerberos
    ssh_cmd = a._build_nxc_command("ssh", "10.0.0.1", a.credentials[0], local_auth=False)
    assert "-k" not in ssh_cmd  # SSH doesn't


def test_credential_supported_hash_skip(nxa):
    cred = nxa.Credential(user="svc", nthash="8846f7eaee8fb117ad06bdd830b7586c")
    assert nxa.NxcAutomator._credential_supported(cred, "smb")
    assert not nxa.NxcAutomator._credential_supported(cred, "ssh")


def test_pick_best_cred_prefers_pwn3d(nxa):
    raw_normal = "corp\\admin:Password"
    raw_pwn3d = "corp\\admin:Password (Pwn3d!)"
    cred = nxa.Credential(user="admin", password="Password")
    entries = [
        {"host": "h", "protocol": "smb", "local_auth": False, "credential": cred, "raw": raw_normal},
        {"host": "h", "protocol": "smb", "local_auth": True,  "credential": cred, "raw": raw_pwn3d},
    ]
    best = nxa.NxcAutomator._pick_best_cred(entries)
    assert best["raw"] == raw_pwn3d
