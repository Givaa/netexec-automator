"""netexec-automator package.

Backward-compat re-exports: tests, the thin launcher, and any external
consumer can do `import netexec_automator as nxa` and find everything that
used to live at the top of the single-file `netexec-automator.py` script.

This is intentional — the split is an internal refactor, the public surface
(CLI flags + Python attribute names) is unchanged."""

# Constants, regexes, ANSI colours, icons, action tables, type aliases
from .constants import *  # noqa: F401,F403
from .constants import (
    ALL_PROTOCOLS, AUTH_RESPONSE_PATTERNS, BANNER_PATH_BUDGET, BANNER_WIDTH,
    BLOODHOUND_TIMEOUT, BLUE, BOLD, CACHE_DEFAULT_PATH, CACHE_DEFAULT_TTL,
    CONNECTIVITY_TIMEOUT_PATTERNS, CRACK_DEFAULT_TIMEOUT, CYAN, DEFAULT_WORKERS,
    DIM, GREEN, HASH_AUTH_PROTOCOLS, HASH_DUMP_LINE_RE, HASH_LMNT_PATTERN,
    HASH_NT_PATTERN, HASH_TYPES, ICON_BLOODHOUND, ICON_CRACK, ICON_FAIL,
    ICON_FINDING, ICON_HARVEST, ICON_HOST, ICON_NOOP, ICON_OK, ICON_PWN3D,
    ICON_SKIP, ICON_SUBTASK, ICON_TIMEOUT, ICON_WARN, KERBEROS_AUTH_PROTOCOLS,
    KRB_AS_REP_USER_RE, KRB_TGS_REP_USER_RE, LDAP_ENUM_ACTIONS,
    LOCAL_AUTH_PROTOCOLS, LOCKOUT_DURATION_RE, LOCKOUT_THRESHOLD_RE,
    LOW_POWER_PROFILE, MAX_RETRY, NETEXEC_TIMEOUT, NMAP_TIMEOUT,
    NULL_SESSION_CREDS, PROTOCOL_PORTS, RED, RESET, ROCKYOU_DOWNLOAD_URL,
    SMB_DOMAIN_RE, SMB_ENUM_ACTIONS, SMB_NAME_RE, SMB_SECRETS_ACTIONS,
    SUBPROCESS_TIMEOUT, V_DEBUG, V_NORMAL, V_QUIET, V_VERBOSE,
    WORDLIST_DEFAULT_PATHS, YELLOW, AttemptClassification, ParsedStatus, TaskKey,
)

# Small helpers
from ._utils import _term_width, _truncate_path  # noqa: F401

# Data types
from .types import Credential, NxcActionResult  # noqa: F401

# Helper classes
from .bloodhound import BloodHoundRunner  # noqa: F401
from .cache import HostCache  # noqa: F401
from .cracker import HashCracker  # noqa: F401
from .loot import LootStore  # noqa: F401
from .resolver import HostnameResolver  # noqa: F401
from .scanner import NmapScanner  # noqa: F401

# Main runner + CLI
from .automator import NxcAutomator  # noqa: F401
from .cli import (  # noqa: F401
    _apply_low_power_defaults,
    _build_parser,
    _load_toml_config,
    _merge_toml_into_args,
    main,
    parse_mode,
)
