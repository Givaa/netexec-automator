"""Module-level constants, regex patterns, and small lookup tables.

Kept dependency-free so every other module can import from here without
risk of circularity. ANSI codes / status icons live here too — that way
the CLI, the runner, and the cracker all agree on what ⊘ vs ✘ means."""

import re
from pathlib import Path
from typing import Literal

# ---- ANSI colours --------------------------------------------------------

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ---- Status icons (one meaning per icon, used everywhere) ----------------

ICON_OK         = f"{GREEN}✔{RESET}"         # action produced real, actionable data
ICON_NOOP       = f"{YELLOW}⊘{RESET}"        # ran cleanly but produced nothing (expected, not a bug)
ICON_FAIL       = f"{RED}✘{RESET}"           # real failure: subprocess error, I/O error, parse error
ICON_WARN       = f"{YELLOW}{BOLD}⚠{RESET}"  # warning: degraded/disabled feature, lockout risk
ICON_TIMEOUT    = f"{YELLOW}⏱{RESET}"        # network-level timeout
ICON_SKIP       = f"{DIM}↷{RESET}"           # deliberately skipped (filter, dedup, stop-on-success)
ICON_PWN3D      = f"{RED}{BOLD}💀{RESET}"    # cred grants admin on host
ICON_HARVEST    = f"{GREEN}🧪{RESET}"        # hashes collected
ICON_CRACK      = f"{CYAN}🔓{RESET}"         # cracking activity
ICON_BLOODHOUND = f"{CYAN}🩸{RESET}"         # BloodHound / DC discovery
ICON_FINDING    = f"{GREEN}{BOLD}⚡{RESET}"  # valid credential (live)
ICON_HOST       = f"{GREEN}{BOLD}►{RESET}"   # per-host header
ICON_SUBTASK    = f"{CYAN}{BOLD}▸{RESET}"    # post-exploit phase header

# ---- Protocols -----------------------------------------------------------

ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}
HASH_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql", "ldap"}
KERBEROS_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "ldap", "mssql"}

# Default TCP ports nmap probes during pre-scan; protocol skipped if none open.
PROTOCOL_PORTS: dict[str, list[int]] = {
    "smb":   [445, 139],
    "ssh":   [22],
    "ldap":  [389, 636],
    "ftp":   [21],
    "wmi":   [135],
    "winrm": [5985, 5986],
    "rdp":   [3389],
    "vnc":   [5900],
    "mssql": [1433],
    "nfs":   [2049],
}

# ---- Exam-safe module blocklist ----------------------------------------

# Modules refused at startup under --exam-safe. These are nxc -M modules that
# perform *automated exploitation* of a known vulnerability (CVE exploit or
# authentication-coercion) rather than passive enumeration — exactly the class
# of "automated exploitation tools" forbidden in certification exams such as
# OSCP. Enumeration/collection modules (spider_plus, gpp_password, etc.) are
# intentionally allowed. Comparison is case-insensitive and treats '-' and '_'
# as equivalent (see _normalize_module), so "ms17-010" matches "ms17_010".
EXAM_SAFE_BLOCKLIST: frozenset[str] = frozenset({
    "zerologon",      # CVE-2020-1472
    "nopac",          # CVE-2021-42278 / 42287 (sAMAccountName spoofing)
    "petitpotam",     # CVE-2021-36942 (EFSRPC coercion)
    "printnightmare", # CVE-2021-1675 / 34527 (spooler RCE)
    "ms17-010",       # EternalBlue
    "smbghost",       # CVE-2020-0796 (SMBv3 compression)
    "dfscoerce",      # MS-DFSNM coercion
    "shadowcoerce",   # MS-FSRVP coercion
    "coerce_plus",    # multi-vector auth coercion
})


# ---- Credential patterns / null-session --------------------------------

HASH_NT_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_LMNT_PATTERN = re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$")

# Always-tried anonymous attempts when --null-session is on. Order matters:
# null first (cheapest signal), then Guest, then anonymous (FTP-style).
NULL_SESSION_CREDS: list[tuple[str, str]] = [
    ("", ""),
    ("Guest", ""),
    ("anonymous", ""),
]

# Protocol-specific anonymous logins added on top of NULL_SESSION_CREDS when
# --null-session is on. The universal set above (null / Guest:'' / anonymous:'')
# already covers SMB / LDAP / WinRM / RDP / MSSQL / VNC null sessions; FTP has
# its own classic anonymous combos that the empty-password ones miss. Each is
# tried ONLY on its protocol (see _credential_supported), so SMB etc. don't get
# sprayed with ftp:ftp noise.
PROTOCOL_ANON_CREDS: dict[str, list[tuple[str, str]]] = {
    "ftp": [("anonymous", "anonymous"), ("ftp", "ftp")],
}

# Every username used by a --null-session anonymous attempt (universal +
# per-protocol), lowercased. Used to (a) keep anon logins out of the
# lockout-risk count and (b) label them as "anon" in the banner summary.
ANON_USERNAMES: frozenset[str] = frozenset(
    {u.lower() for u, _ in NULL_SESSION_CREDS}
    | {u.lower() for combos in PROTOCOL_ANON_CREDS.values() for u, _ in combos}
)

# ---- Defaults / timeouts -----------------------------------------------

DEFAULT_WORKERS = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
MAX_RETRY = 3
SUBPROCESS_TIMEOUT = 45
NETEXEC_TIMEOUT = 30
BANNER_WIDTH = 60
# Path-display budget inside the banner before we ellipsize. Keeps long
# cmd-log / loot-dir / log-file paths from wrapping and trashing the layout.
BANNER_PATH_BUDGET = 42

CACHE_DEFAULT_TTL = 86400  # 24h — open-port sets are stable, cache them long.
# Dead/no-open-ports results are *volatile* (a host can come back online any
# minute), so they get a much shorter TTL. The liveness re-probe in
# _discover_target catches a returning host instantly on standard ports; this
# bounds how long a host that returned on a non-standard port stays skipped.
DEAD_CACHE_DEFAULT_TTL = 3600  # 1h
CACHE_DEFAULT_PATH = Path.home() / ".cache" / "netexec-automator" / "state.db"
NMAP_TIMEOUT = 180
# Ranges with up to this many addresses (a /20) are expanded so we can reuse
# per-IP cache entries and only nmap the unknown hosts. Larger ranges are
# scanned as a single nmap invocation (expanding them per-IP isn't worth it).
RANGE_EXPAND_CAP = 4096
BLOODHOUND_TIMEOUT = 600
CRACK_DEFAULT_TIMEOUT = 600  # 10 min per hash-type attack

# ---- Hash cracking -----------------------------------------------------

# Hashcat modes for the hash types we can produce.
HASH_TYPES: dict[str, dict] = {
    "nt":    {"hashcat_mode": "1000",  "john_format": "nt",         "label": "NT (SAM/LSA/NTDS)"},
    "asrep": {"hashcat_mode": "18200", "john_format": "krb5asrep",  "label": "Kerberos AS-REP"},
    "tgs":   {"hashcat_mode": "13100", "john_format": "krb5tgs",    "label": "Kerberos TGS-REP"},
}

# Where to look for a default wordlist (rockyou-style). First hit wins.
# Both decompressed and .gz forms are supported (auto-decompressed on first use).
WORDLIST_DEFAULT_PATHS: list[str] = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.gz",
    str(Path.home() / "wordlists" / "rockyou.txt"),
    str(Path.home() / ".local" / "share" / "wordlists" / "rockyou.txt"),
]
ROCKYOU_DOWNLOAD_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

# Extract username embedded in Kerberos hashes for auto-grow.
KRB_AS_REP_USER_RE = re.compile(r"\$krb5asrep\$\d+\$([^@\$]+)@", re.IGNORECASE)
# Kerberoasting hash format: $krb5tgs$23$*user$DOMAIN$spn*$encrypted_data
KRB_TGS_REP_USER_RE = re.compile(r"\$krb5tgs\$\d+\$\*([^\$]+)\$", re.IGNORECASE)

# ---- Profiles / verbosity ----------------------------------------------

# Profile presets — applied when the corresponding flag is given.
# 'low-power' is intended for VMs / weak hosts: minimal parallelism, longer
# timeouts so we don't hammer the local CPU or network stack.
LOW_POWER_PROFILE = {
    "workers": 3,
    "max_retry": 1,
    "netexec_timeout": 45,
    "subprocess_timeout": 60,
    "delay": 0.5,
}

V_QUIET = -1
V_NORMAL = 0
V_VERBOSE = 1
V_DEBUG = 2

# ---- Action tables -----------------------------------------------------
# Each action: name, nxc args, and the substrings/patterns that prove the
# action *produced data*. If exit code is 0 but none of these markers appear,
# we report a yellow ⊘ ("ran cleanly, nothing to show") instead of a green ✔.

SMB_ENUM_ACTIONS: list[dict] = [
    {"name": "shares",   "args": ["--shares"],         "ok_markers": ["Sharename", "[Type]", "READ", "WRITE", "Pwn3d"]},
    {"name": "users",    "args": ["--users"],          "ok_markers": ["[+]", "Username", "Total of"]},
    {"name": "sessions", "args": ["--sessions"],       "ok_markers": ["Enumerated", "active session", "Username"]},
    {"name": "loggedon", "args": ["--loggedon-users"], "ok_markers": ["[+]", "logged in", "logon time"]},
    {"name": "pass-pol", "args": ["--pass-pol"],       "ok_markers": ["Minimum password", "Lockout", "Maximum password"]},
]

LDAP_ENUM_ACTIONS: list[dict] = [
    {"name": "users",         "args": ["--users"],                       "ok_markers": ["[+]", "samaccountname"]},
    {"name": "admin-count",   "args": ["--admin-count"],                 "ok_markers": ["[+]", "Found"]},
    {"name": "groups",        "args": ["--groups"],                      "ok_markers": ["[+]", "Member"]},
    {"name": "asreproast",    "args": ["--asreproast", "{outfile}"],     "ok_markers": ["$krb5asrep$"]},
    {"name": "kerberoasting", "args": ["--kerberoasting", "{outfile}"],  "ok_markers": ["$krb5tgs$"]},
]

SMB_SECRETS_ACTIONS: list[dict] = [
    {"name": "sam",  "args": ["--sam"],  "requires_dc": False, "ok_markers": [":::"]},
    {"name": "lsa",  "args": ["--lsa"],  "requires_dc": False, "ok_markers": [":::", "DPAPI", "_SC_"]},
    {"name": "ntds", "args": ["--ntds"], "requires_dc": True,  "ok_markers": [":::"]},
]

# ---- Output parsing patterns -------------------------------------------

# Heuristics for harvesting hashes out of nxc dump output.
# SAM:  "Administrator:500:aad3b4...:8846f7ea...:::"
# NTDS: "corp.local\\krbtgt:502:aad3b4...:8846f7ea...:::"
HASH_DUMP_LINE_RE = re.compile(
    r"(?P<user>[A-Za-z0-9._\\$\\\\-]+):\d+:(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::"
)

# Lockout policy parsing from `nxc smb --pass-pol` output.
LOCKOUT_THRESHOLD_RE = re.compile(r"lockout\s+threshold[\s:]+(\d+)", re.IGNORECASE)
LOCKOUT_DURATION_RE  = re.compile(r"lockout\s+duration[\s:]+([\w\d\s,]+?)(?:\n|$)", re.IGNORECASE)

# Patterns we look for in SMB info lines to discover domain/host identity.
SMB_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.IGNORECASE)
SMB_NAME_RE = re.compile(r"\(name:([^)]+)\)", re.IGNORECASE)

# ---- Type aliases ------------------------------------------------------

TaskKey = tuple[str, bool]
ParsedStatus = tuple[str, str]
AttemptClassification = Literal["credential_response", "connectivity_timeout", "ambiguous"]

# ---- nxc output classification patterns ---------------------------------

AUTH_RESPONSE_PATTERNS = (
    "status_logon_failure",
    "status_access_denied",
    "rpc_s_access_denied",
    "access denied",
    "authentication failed",
    "invalid credentials",
    "bad credentials",
    "permission denied",
    "login failed",
    "logon failure",
)

CONNECTIVITY_TIMEOUT_PATTERNS = (
    "timed out",
    "connection timeout",
    "connection refused",
    "connection reset",
    "reset by peer",
    "could not connect",
    "connection error",
    "host is unreachable",
    "no route to host",
    "network is unreachable",
    "netbios connection",
    "name or service not known",
    "temporary failure in name resolution",
    "broken pipe",
    "errno 110",
    "errno 111",
    "errno 113",
)
