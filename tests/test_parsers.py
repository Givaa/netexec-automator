"""Parser-level tests — hash detection, combo file, protocol filter, Pwn3d."""

import pytest


def test_parse_hash_nt_only(nxa):
    lm, nt = nxa.NxcAutomator._parse_hash_value("8846f7eaee8fb117ad06bdd830b7586c")
    assert lm is None
    assert nt == "8846f7eaee8fb117ad06bdd830b7586c"


def test_parse_hash_lmnt(nxa):
    lm, nt = nxa.NxcAutomator._parse_hash_value(
        "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    )
    assert lm == "aad3b435b51404eeaad3b435b51404ee"
    assert nt == "8846f7eaee8fb117ad06bdd830b7586c"


def test_parse_hash_invalid(nxa):
    with pytest.raises(ValueError):
        nxa.NxcAutomator._parse_hash_value("notahex")


@pytest.mark.parametrize("line,expected_attr,expected_value", [
    ("admin:Password!", "password", "Password!"),
    ("svc:8846f7eaee8fb117ad06bdd830b7586c", "nthash", "8846f7eaee8fb117ad06bdd830b7586c"),
    ("guest:", "password", ""),
    ("admin:P@ss:w0rd:!", "password", "P@ss:w0rd:!"),
])
def test_combo_line_basic(nxa, line, expected_attr, expected_value):
    cred = nxa.NxcAutomator._parse_combo_line(line)
    assert getattr(cred, expected_attr) == expected_value


def test_combo_line_lmnt(nxa):
    cred = nxa.NxcAutomator._parse_combo_line(
        "user:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    )
    assert cred.lmhash and cred.nthash


def test_combo_line_skips_comments_and_blanks(nxa):
    assert nxa.NxcAutomator._parse_combo_line("") is None
    assert nxa.NxcAutomator._parse_combo_line("# a comment") is None
    assert nxa.NxcAutomator._parse_combo_line("   ") is None


def test_combo_line_malformed_raises(nxa):
    with pytest.raises(ValueError):
        nxa.NxcAutomator._parse_combo_line("no_colon_here")


def test_credential_cli_args_password(nxa):
    cred = nxa.Credential(user="admin", password="P@ss w0rd")
    args = cred.to_cli_args()
    assert args == ["-u", "admin", "-p", "P@ss w0rd"]


def test_credential_cli_args_hash(nxa):
    cred = nxa.Credential(user="svc", nthash="8846f7eaee8fb117ad06bdd830b7586c")
    args = cred.to_cli_args()
    assert "-H" in args and "8846f7eaee8fb117ad06bdd830b7586c" in args
    assert "-p" not in args


def test_credential_cli_args_lmnt(nxa):
    cred = nxa.Credential(
        user="legacy",
        lmhash="aad3b435b51404eeaad3b435b51404ee",
        nthash="31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    args = cred.to_cli_args()
    secret = args[args.index("-H") + 1]
    assert ":" in secret


def test_pwn3d_detection(nxa):
    assert nxa.NxcAutomator._is_pwn3d("corp\\admin:Password (Pwn3d!)")
    assert nxa.NxcAutomator._is_pwn3d("corp\\admin:Password (pwn3d!)")
    assert not nxa.NxcAutomator._is_pwn3d("corp\\admin:Password")


def test_hash_dump_regex(nxa):
    sample = (
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    hits = list(nxa.HASH_DUMP_LINE_RE.finditer(sample))
    assert len(hits) == 3
    assert hits[0].group("user") == "Administrator"


def test_lockout_threshold_regex(nxa):
    sample = "Account Lockout Threshold: 5\nAccount Lockout Duration: 30 minutes"
    m = nxa.LOCKOUT_THRESHOLD_RE.search(sample)
    assert m and m.group(1) == "5"


def test_smb_domain_regex(nxa):
    line = "SMB  10.0.0.1  445  DC01  [*] Windows ... (name:DC01) (domain:corp.local)"
    assert nxa.SMB_DOMAIN_RE.search(line).group(1) == "corp.local"
    assert nxa.SMB_NAME_RE.search(line).group(1) == "DC01"


def test_truncate_path(nxa):
    assert nxa._truncate_path("short.log") == "short.log"
    long = "/a/very/long/path/that/exceeds/the/budget/commands.log"
    out = nxa._truncate_path(long, budget=20)
    assert out.startswith("…") and len(out) == 20


def test_term_width_returns_int(nxa):
    w = nxa._term_width()
    assert isinstance(w, int) and w >= 40
