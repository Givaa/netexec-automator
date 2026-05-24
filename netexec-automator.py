#!/usr/bin/env python3

import argparse
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Literal

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}
# Protocols where nxc accepts -H NT hash auth. The rest (ssh/ftp/vnc/nfs) only do passwords.
HASH_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql", "ldap"}
# Protocols that meaningfully accept Kerberos (-k). Others get skipped when --kerberos is on.
KERBEROS_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "ldap", "mssql"}

HASH_NT_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_LMNT_PATTERN = re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$")

# Always-tried anonymous attempts when --null-session is on. Order matters:
# null first (cheapest signal), then Guest, then anonymous (FTP-style).
NULL_SESSION_CREDS: list[tuple[str, str]] = [
    ("", ""),
    ("Guest", ""),
    ("anonymous", ""),
]

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

DEFAULT_WORKERS = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
MAX_RETRY = 3
SUBPROCESS_TIMEOUT = 45
NETEXEC_TIMEOUT = 30
BANNER_WIDTH = 60
PROGRESS_CLEAR_WIDTH = 70

CACHE_DEFAULT_TTL = 86400  # 24h
CACHE_DEFAULT_PATH = Path.home() / ".cache" / "netexec-automator" / "state.db"
NMAP_TIMEOUT = 180
BLOODHOUND_TIMEOUT = 600

# Verbosity levels
V_QUIET = -1
V_NORMAL = 0
V_VERBOSE = 1
V_DEBUG = 2

# Enumeration probes that nxc supports on SMB when --enum is on.
SMB_ENUM_ACTIONS: list[tuple[str, str]] = [
    ("shares", "--shares"),
    ("users", "--users"),
    ("sessions", "--sessions"),
    ("loggedon", "--loggedon-users"),
    ("pass-pol", "--pass-pol"),
]

# Patterns we look for in SMB info lines to discover domain/host identity.
SMB_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.IGNORECASE)
SMB_NAME_RE = re.compile(r"\(name:([^)]+)\)", re.IGNORECASE)

TaskKey = tuple[str, bool]
ParsedStatus = tuple[str, str]
AttemptClassification = Literal["credential_response", "connectivity_timeout", "ambiguous"]

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

@dataclass
class Credential:
    """Single nxc auth attempt. Supports password, NT hash, and LM:NT hash."""
    user: str
    password: str | None = None
    nthash: str | None = None
    lmhash: str | None = None  # optional, paired with nthash as LM:NT

    @property
    def is_hash(self) -> bool:
        return self.nthash is not None

    def to_cli_args(self) -> list[str]:
        args = ["-u", self.user]
        if self.nthash:
            secret = f"{self.lmhash}:{self.nthash}" if self.lmhash else self.nthash
            args.extend(["-H", secret])
        else:
            args.extend(["-p", self.password if self.password is not None else ""])
        return args

    @property
    def display(self) -> str:
        if self.nthash:
            secret = f"{self.lmhash}:{self.nthash}" if self.lmhash else self.nthash
            return f"{self.user or '<empty>'}:[hash]{secret}"
        pwd = self.password if self.password is not None else ""
        return f"{self.user or '<empty>'}:{pwd or '<empty>'}"


class HostCache:
    """SQLite-backed cache for nmap port discovery results."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS host_ports (
        target TEXT NOT NULL,
        port INTEGER NOT NULL,
        state TEXT NOT NULL,
        scanned_at INTEGER NOT NULL,
        PRIMARY KEY (target, port)
    );
    CREATE INDEX IF NOT EXISTS idx_target ON host_ports(target);

    CREATE TABLE IF NOT EXISTS domain_controllers (
        domain TEXT NOT NULL,
        dc_ip TEXT NOT NULL,
        source TEXT NOT NULL,
        discovered_at INTEGER NOT NULL,
        PRIMARY KEY (domain, dc_ip)
    );

    CREATE TABLE IF NOT EXISTS bloodhound_runs (
        domain TEXT PRIMARY KEY,
        dc_ip TEXT,
        auth_user TEXT,
        output_path TEXT,
        ran_at INTEGER NOT NULL,
        success INTEGER NOT NULL
    );
    """

    def __init__(self, path: Path, ttl: int):
        self.path = path
        self.ttl = ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    def get_fresh(self, target: str) -> dict[int, str] | None:
        """Return cached port→state map if scanned within TTL, else None.
        Empty dict means 'scanned and nothing open' (still a cache hit)."""
        cutoff = int(time.time()) - self.ttl
        latest = self._conn.execute(
            "SELECT MAX(scanned_at) FROM host_ports WHERE target = ?", (target,)
        ).fetchone()
        if not latest or latest[0] is None or latest[0] < cutoff:
            # Sentinel row (port=0) lets us record 'scanned but dead' hosts.
            sentinel = self._conn.execute(
                "SELECT scanned_at FROM host_ports WHERE target = ? AND port = 0", (target,)
            ).fetchone()
            if sentinel and sentinel[0] >= cutoff:
                return {}
            return None
        rows = self._conn.execute(
            "SELECT port, state FROM host_ports WHERE target = ? AND port > 0",
            (target,),
        ).fetchall()
        return {port: state for port, state in rows}

    def store(self, target: str, ports: dict[int, str]):
        now = int(time.time())
        self._conn.execute("DELETE FROM host_ports WHERE target = ?", (target,))
        if ports:
            self._conn.executemany(
                "INSERT INTO host_ports (target, port, state, scanned_at) VALUES (?, ?, ?, ?)",
                [(target, port, state, now) for port, state in ports.items()],
            )
        else:
            # Sentinel: record that we scanned this target and found nothing.
            self._conn.execute(
                "INSERT INTO host_ports (target, port, state, scanned_at) VALUES (?, 0, 'none', ?)",
                (target, now),
            )
        self._conn.commit()

    def record_dc(self, domain: str, dc_ip: str, source: str):
        """Upsert a domain controller discovery (idempotent on PK)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO domain_controllers "
            "(domain, dc_ip, source, discovered_at) VALUES (?, ?, ?, ?)",
            (domain.lower(), dc_ip, source, int(time.time())),
        )
        self._conn.commit()

    def get_dcs(self, domain: str) -> list[tuple[str, str]]:
        """Return [(dc_ip, source)] for a domain, most recent first."""
        rows = self._conn.execute(
            "SELECT dc_ip, source FROM domain_controllers WHERE domain = ? "
            "ORDER BY discovered_at DESC",
            (domain.lower(),),
        ).fetchall()
        return list(rows)

    def recent_bloodhound(self, domain: str, ttl: int) -> dict | None:
        cutoff = int(time.time()) - ttl
        row = self._conn.execute(
            "SELECT domain, dc_ip, auth_user, output_path, ran_at, success "
            "FROM bloodhound_runs WHERE domain = ? AND ran_at >= ? AND success = 1",
            (domain.lower(), cutoff),
        ).fetchone()
        if not row:
            return None
        return {
            "domain": row[0], "dc_ip": row[1], "auth_user": row[2],
            "output_path": row[3], "ran_at": row[4], "success": bool(row[5]),
        }

    def record_bloodhound(self, domain: str, dc_ip: str, auth_user: str, output_path: str, success: bool):
        self._conn.execute(
            "INSERT OR REPLACE INTO bloodhound_runs "
            "(domain, dc_ip, auth_user, output_path, ran_at, success) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (domain.lower(), dc_ip, auth_user, output_path, int(time.time()), 1 if success else 0),
        )
        self._conn.commit()

    def close(self):
        self._conn.close()


class NmapScanner:
    """Run nmap port discovery and parse XML output."""

    def __init__(self, ports: list[int], timeout: int = NMAP_TIMEOUT, log_cmd=None):
        self.ports = ports
        self.timeout = timeout
        # Optional callback: (label, cmd, target) → None. Called before each scan.
        self.log_cmd = log_cmd

    @staticmethod
    def is_available() -> bool:
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, target: str) -> dict[str, dict[int, str]]:
        """Run nmap on a target (single host, hostname, or CIDR).
        Returns {ip_or_hostname: {port: state}} only for hosts with at least one open port."""
        port_arg = ",".join(str(p) for p in self.ports)
        cmd = ["nmap", "-Pn", "-n", "--open", "-p", port_arg, "-T4", "-oX", "-", target]
        if self.log_cmd:
            self.log_cmd("nmap", cmd, target)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return {}
        if result.returncode != 0 or not result.stdout:
            return {}
        return self._parse_xml(result.stdout)

    @staticmethod
    def _parse_xml(xml_str: str) -> dict[str, dict[int, str]]:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return {}

        results: dict[str, dict[int, str]] = {}
        for host in root.findall("host"):
            addr_elem = host.find("address[@addrtype='ipv4']") or host.find("address")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr")
            if not ip:
                continue
            ports_dict: dict[int, str] = {}
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    portid = port.get("portid")
                    state_elem = port.find("state")
                    if portid and state_elem is not None:
                        ports_dict[int(portid)] = state_elem.get("state", "unknown")
            results[ip] = ports_dict
        return results


class LootStore:
    """Owns the loot/ directory layout used by enum, modules, and BloodHound."""

    def __init__(self, root: Path):
        self.root = root

    def dir_for(self, *parts: str) -> Path:
        out = self.root.joinpath(*parts)
        out.mkdir(parents=True, exist_ok=True)
        return out

    @staticmethod
    def safe_name(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "unknown"


class BloodHoundRunner:
    """Wraps bloodhound-python invocation, with TTL-based dedup via HostCache."""

    def __init__(
        self,
        cache: HostCache | None,
        loot: LootStore,
        ttl: int = CACHE_DEFAULT_TTL,
        force: bool = False,
        timeout: int = BLOODHOUND_TIMEOUT,
        log_cmd=None,
    ):
        self.cache = cache
        self.loot = loot
        self.ttl = ttl
        self.force = force
        self.timeout = timeout
        # Optional callback: (label, cmd, target) → None
        self.log_cmd = log_cmd

    @staticmethod
    def is_available() -> bool:
        try:
            subprocess.run(
                ["bloodhound-python", "--help"], capture_output=True, timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def already_collected(self, domain: str) -> dict | None:
        if self.force or not self.cache:
            return None
        return self.cache.recent_bloodhound(domain, self.ttl)

    def build_cmd(self, domain: str, dc_ip: str, credential: "Credential") -> list[str]:
        cmd = [
            "bloodhound-python",
            "-c", "All",
            "-u", credential.user,
            "-d", domain,
            "-dc", dc_ip,
            "-ns", dc_ip,
            "--zip",
        ]
        if credential.nthash:
            cmd.extend(["--hashes", f":{credential.nthash}"])
        elif credential.password is not None:
            cmd.extend(["-p", credential.password])
        return cmd

    def collect(
        self, domain: str, dc_ip: str, credential: "Credential"
    ) -> tuple[bool, Path, str]:
        """Run bloodhound-python; returns (success, output_dir, last_stderr_line)."""
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = self.loot.dir_for(
            "bloodhound", LootStore.safe_name(domain), ts
        )
        cmd = self.build_cmd(domain, dc_ip, credential)
        if self.log_cmd:
            self.log_cmd(f"bloodhound {domain}", cmd, dc_ip)
        last_err = ""
        success = False
        try:
            result = subprocess.run(
                cmd,
                cwd=str(out_dir),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            success = result.returncode == 0
            if result.stderr:
                err_lines = [l for l in result.stderr.splitlines() if l.strip()]
                last_err = err_lines[-1] if err_lines else ""
            # Write the raw transcript next to the zip for forensic reference.
            (out_dir / "bloodhound-python.stdout.log").write_text(result.stdout or "")
            (out_dir / "bloodhound-python.stderr.log").write_text(result.stderr or "")
        except subprocess.TimeoutExpired:
            last_err = f"bloodhound-python timed out after {self.timeout}s"
        if self.cache:
            self.cache.record_bloodhound(
                domain, dc_ip, credential.user, str(out_dir), success
            )
        return success, out_dir, last_err


class NxcAutomator:
    """Run nxc across all protocols with combination or linear credential pairing."""

    def __init__(
        self,
        target: str,
        user: str | None = None,
        password: str | None = None,
        nthash: str | None = None,
        combo: str | None = None,
        domain: str | None = None,
        kerberos: bool = False,
        null_session: bool = False,
        output: str | None = None,
        workers: int = DEFAULT_WORKERS,
        mode: str = "combination",
        nmap_enabled: bool = False,
        cache_enabled: bool = True,
        cache_ttl: int = CACHE_DEFAULT_TTL,
        scan_only: bool = False,
        verbosity: int = V_NORMAL,
        enum_enabled: bool = False,
        modules: str | None = None,
        bloodhound_enabled: bool = False,
        bloodhound_force: bool = False,
        bloodhound_ttl: int = CACHE_DEFAULT_TTL,
        loot_dir: str = "loot",
        cmd_log: str | None = None,
        cmd_log_disabled: bool = False,
    ):
        self.targets = self._read_value_or_file(target)
        self.mode = mode.lower()
        self.domain = domain
        self.kerberos = kerberos
        self.null_session = null_session

        self.user_arg = user
        self.password_arg = password
        self.hash_arg = nthash
        self.combo_arg = combo

        # Kept for banner display
        self.users = self._read_value_or_file(user) if user else []
        self.passwords = self._read_value_or_file(password) if password else []
        self.hashes = self._read_value_or_file(nthash) if nthash else []

        self.credentials = self._build_credentials()

        self.workers = workers
        self.lock = Lock()
        self.cmd_log_lock = Lock()
        self.completed = 0
        self.total_tasks = 0
        ts = datetime.now().strftime("%H-%M-%S-%f")[:-3]
        self.log_file = output if output else f"{ts}.txt"
        if cmd_log_disabled:
            self.cmd_log_path: Path | None = None
        else:
            self.cmd_log_path = Path(cmd_log) if cmd_log else Path(f"commands-{ts}.log")
        self._cmd_log_initialized = False

        self.verbosity = verbosity
        self.nmap_enabled = nmap_enabled
        self.scan_only = scan_only
        self.scanner = (
            NmapScanner(ports=self._all_known_ports(), log_cmd=self._log_command)
            if nmap_enabled else None
        )
        # Cache is also useful for DC/bloodhound dedup even without --nmap.
        cache_useful = (nmap_enabled or bloodhound_enabled) and cache_enabled
        self.cache = HostCache(CACHE_DEFAULT_PATH, ttl=cache_ttl) if cache_useful else None

        self.enum_enabled = enum_enabled
        self.modules = [m.strip() for m in modules.split(",") if m.strip()] if modules else []
        self.loot = LootStore(Path(loot_dir))
        self.bloodhound_enabled = bloodhound_enabled
        self.bloodhound_runner = (
            BloodHoundRunner(
                self.cache, self.loot,
                ttl=bloodhound_ttl, force=bloodhound_force,
                log_cmd=self._log_command,
            )
            if bloodhound_enabled else None
        )

        # Cross-host state populated during the run.
        self.valid_creds: list[dict] = []
        self.domain_hosts: dict[str, set[str]] = {}  # domain → {hostnames}
        self.host_domain: dict[str, str] = {}        # host → domain

    @staticmethod
    def _all_known_ports() -> list[int]:
        seen: list[int] = []
        for ports in PROTOCOL_PORTS.values():
            for port in ports:
                if port not in seen:
                    seen.append(port)
        return seen

    def _vprint(self, level: int, msg: str):
        """Emit msg only when current verbosity >= level. Plays nice with the progress bar."""
        if self.verbosity < level:
            return
        with self.lock:
            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()
            print(msg, flush=True)
            self._redraw_progress()

    def _vprint_cmd(self, label: str, cmd: list[str]):
        """Verbose: dump the command line about to be executed."""
        self._vprint(V_VERBOSE, f"  {DIM}$ [{label}] {shlex.join(cmd)}{RESET}")

    def _log_command(self, label: str, cmd: list[str], target: str | None = None):
        """Append a shell-pasteable copy of cmd to commands.log AND emit verbose dump.

        Format is OSCP-report friendly: comment header with timestamp + label,
        followed by the exact command (shell-quoted), one entry per call."""
        self._vprint_cmd(label, cmd)
        if not self.cmd_log_path:
            return
        with self.cmd_log_lock:
            mode = "a" if self._cmd_log_initialized else "w"
            with open(self.cmd_log_path, mode) as fh:
                if not self._cmd_log_initialized:
                    fh.write(
                        "# NetExec Automator — commands transcript\n"
                        f"# Started: {datetime.now().isoformat(timespec='seconds')}\n"
                        "# Each block: '# <iso ts> [label] target=<host>' followed by\n"
                        "# the exact shell-quoted command. Safe to copy-paste into reports.\n\n"
                    )
                    self._cmd_log_initialized = True
                ts_iso = datetime.now().isoformat(timespec="seconds")
                tgt = f" target={target}" if target else ""
                fh.write(f"# {ts_iso} [{label}]{tgt}\n")
                fh.write(shlex.join(cmd) + "\n\n")

    @staticmethod
    def _read_lines(path: str) -> list[str]:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]

    @classmethod
    def _read_value_or_file(cls, source: str) -> list[str]:
        """Return direct value as one-item list, or load non-empty lines from file."""
        return cls._read_lines(source) if os.path.isfile(source) else [source]

    @staticmethod
    def _auth_scope(local_auth: bool) -> str:
        return "local" if local_auth else "domain"

    def _task_label(self, protocol: str, local_auth: bool) -> str:
        """Return standardized display label for protocol/auth scope."""
        return f"{protocol.upper()} ({self._auth_scope(local_auth)})"

    @staticmethod
    def _build_protocol_tasks(open_ports: set[int] | None = None) -> list[TaskKey]:
        """Generate (protocol, local_auth) tasks. If open_ports is given, drop
        protocols whose mapped ports are all closed."""
        tasks: list[TaskKey] = []
        for protocol in ALL_PROTOCOLS:
            if open_ports is not None:
                mapped = PROTOCOL_PORTS.get(protocol, [])
                if not any(p in open_ports for p in mapped):
                    continue
            tasks.append((protocol, False))
            if protocol in LOCAL_AUTH_PROTOCOLS:
                tasks.append((protocol, True))
        return tasks

    @staticmethod
    def _parse_hash_value(value: str) -> tuple[str | None, str]:
        """Return (lmhash, nthash). Raises if format is invalid."""
        v = value.strip()
        if HASH_LMNT_PATTERN.match(v):
            lm, nt = v.split(":", 1)
            return lm, nt
        if HASH_NT_PATTERN.match(v):
            return None, v
        raise ValueError(
            f"Invalid hash {v!r}: expected 32 hex chars (NT) or 32:32 hex (LM:NT)."
        )

    @classmethod
    def _parse_combo_line(cls, line: str) -> Credential | None:
        """Parse one 'user:secret' line. Auto-detects whether secret is NT/LM:NT hash
        or password. Returns None for blank or comment lines."""
        raw = line.rstrip("\n\r")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            return None
        if ":" not in stripped:
            raise ValueError(f"Malformed combo line (missing ':'): {stripped!r}")
        user, _, secret = raw.partition(":")
        user = user.strip()
        # Don't strip the secret — passwords may legitimately have surrounding whitespace.
        if HASH_LMNT_PATTERN.match(secret.strip()):
            lm, nt = secret.strip().split(":", 1)
            return Credential(user=user, lmhash=lm, nthash=nt)
        if HASH_NT_PATTERN.match(secret.strip()):
            return Credential(user=user, nthash=secret.strip())
        return Credential(user=user, password=secret)

    @classmethod
    def _load_combo_file(cls, path: str) -> list[Credential]:
        creds: list[Credential] = []
        with open(path) as fh:
            for lineno, line in enumerate(fh, start=1):
                try:
                    cred = cls._parse_combo_line(line)
                except ValueError as exc:
                    raise ValueError(f"{path}:{lineno}: {exc}") from None
                if cred is not None:
                    creds.append(cred)
        if not creds:
            raise ValueError(f"Combo file {path!r} contained no usable credentials.")
        return creds

    def _build_credentials(self) -> list[Credential]:
        """Compose the credential list from null/guest, combo file, or -u/-p/-H pools."""
        creds: list[Credential] = []

        # Null-session and Guest/anonymous fast-checks go first (cheapest signals).
        if self.null_session:
            creds.extend(Credential(user=u, password=p) for u, p in NULL_SESSION_CREDS)

        if self.combo_arg:
            if self.password_arg or self.hash_arg or self.user_arg:
                raise ValueError("--combo cannot be combined with -u/-p/-H.")
            creds.extend(self._load_combo_file(self.combo_arg))
            return creds

        # If only null-session was requested (no -u), that's a valid configuration.
        if not self.user_arg:
            if creds:
                return creds
            raise ValueError(
                "Provide credentials via -u/-p, -u/-H, --combo, or --null-session."
            )

        if not self.password_arg and not self.hash_arg:
            raise ValueError("With -u you must also provide -p, -H, or use --combo.")

        if self.mode == "combination":
            for u in self.users:
                for p in self.passwords:
                    creds.append(Credential(user=u, password=p))
                for h in self.hashes:
                    lm, nt = self._parse_hash_value(h)
                    creds.append(Credential(user=u, lmhash=lm, nthash=nt))
            return creds

        if self.mode == "linear":
            if self.passwords and self.hashes:
                raise ValueError(
                    "Linear mode accepts -p or -H, not both. Use --combo for mixed lists."
                )
            pool = self.passwords or self.hashes
            if len(self.users) != len(pool):
                raise ValueError(
                    "Linear mode requires user and secret lists to have the same length."
                )
            if self.passwords:
                creds.extend(Credential(user=u, password=p) for u, p in zip(self.users, pool))
            else:
                for u, h in zip(self.users, pool):
                    lm, nt = self._parse_hash_value(h)
                    creds.append(Credential(user=u, lmhash=lm, nthash=nt))
            return creds

        raise ValueError(f"Unsupported mode: {self.mode}")

    def _redraw_progress(self):
        if self.total_tasks > 0:
            bar_len = 20
            filled = int(bar_len * self.completed / self.total_tasks)
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
            pct = int(100 * self.completed / self.total_tasks)
            sys.stderr.write(f"\r  {DIM}{bar} {pct:3d}% ({self.completed}/{self.total_tasks}){RESET}")
            sys.stderr.flush()

    def _update_progress(self):
        with self.lock:
            self.completed += 1
            self._redraw_progress()

    def _skip_progress(self, count: int):
        with self.lock:
            self.completed += count
            self._redraw_progress()

    def _print_live(self, msg: str):
        """Print a finding in real-time, temporarily clearing the progress bar."""
        with self.lock:
            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()
            print(msg, flush=True)
            self._redraw_progress()

    def _build_nxc_command(
        self, protocol: str, target: str, credential: Credential, local_auth: bool
    ) -> list[str]:
        cmd = ["nxc", protocol, target, *credential.to_cli_args()]
        if local_auth:
            cmd.append("--local-auth")
        elif self.domain:
            # -d is only meaningful for domain auth (and gets ignored / rejected with --local-auth)
            cmd.extend(["-d", self.domain])
        if self.kerberos and not local_auth and protocol in KERBEROS_AUTH_PROTOCOLS:
            cmd.append("-k")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
        return cmd

    @staticmethod
    def _credential_supported(credential: Credential, protocol: str) -> bool:
        """Skip hash creds on protocols nxc doesn't expose -H for (ssh/ftp/vnc/nfs)."""
        if credential.is_hash and protocol not in HASH_AUTH_PROTOCOLS:
            return False
        return True

    def _report_success_lines(self, stdout: str, protocol: str, local_auth: bool):
        for raw_line in stdout.split("\n"):
            marker, msg = self._parse_nxc_line(raw_line.strip())
            if marker == "[+]":
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {GREEN}{BOLD}⚡ {label}{RESET} {GREEN}{msg}{RESET}"
                )
            elif marker == "[-]" and self.verbosity >= V_VERBOSE:
                label = self._task_label(protocol, local_auth)
                self._vprint(V_VERBOSE, f"  {DIM}✘ {label} {msg}{RESET}")
            elif marker == "[*]" and self.verbosity >= V_DEBUG:
                label = self._task_label(protocol, local_auth)
                self._vprint(V_DEBUG, f"  {DIM}* {label} {msg}{RESET}")

    @staticmethod
    def _parse_status_blocks(blocks: list[str]) -> list[ParsedStatus]:
        parsed: list[ParsedStatus] = []
        for block in blocks:
            for line in block.split("\n"):
                line = line.strip()
                if not line:
                    continue
                marker, msg = NxcAutomator._parse_nxc_line(line)
                if marker in ("[+]", "[-]", "[!]"):
                    parsed.append((marker, msg))
        return parsed

    @staticmethod
    def _status_icon(parsed: list[ParsedStatus]) -> str:
        has_success = any(marker == "[+]" for marker, _ in parsed)
        has_skip = any(marker == "[!]" for marker, _ in parsed)
        if has_success:
            return f"{GREEN}✔{RESET}"
        if has_skip:
            return f"{YELLOW}⏱{RESET}"
        return f"{RED}✘{RESET}"

    @staticmethod
    def _contains_any_pattern(text: str, patterns: tuple[str, ...]) -> bool:
        return any(pattern in text for pattern in patterns)

    def _classify_attempt_output(self, stdout: str, stderr: str) -> AttemptClassification:
        """Classify one nxc run to decide timeout skip behavior."""
        combined = "\n".join(part for part in (stdout, stderr) if part).lower()
        if not combined:
            return "ambiguous"

        # Credential-related failures mean the service responded, so they should
        # not contribute to consecutive connectivity timeout skips.
        if self._contains_any_pattern(combined, AUTH_RESPONSE_PATTERNS):
            return "credential_response"

        if self._contains_any_pattern(combined, CONNECTIVITY_TIMEOUT_PATTERNS):
            return "connectivity_timeout"

        for raw_line in (stdout + "\n" + stderr).split("\n"):
            marker, _ = self._parse_nxc_line(raw_line.strip())
            if marker in ("[+]", "[-]", "[*]", "[!]"):
                return "credential_response"

        return "ambiguous"

    def _format_stderr_block(self, stderr: str, fallback_marker: str) -> str | None:
        """Convert stderr lines to parseable status lines for result summary."""
        formatted: list[str] = []
        for raw_line in stderr.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            marker, msg = self._parse_nxc_line(line)
            if marker in ("[+]", "[-]", "[!]"):
                formatted.append(f"{marker} {msg}")
            else:
                formatted.append(f"{fallback_marker} {line}")
        return "\n".join(formatted) if formatted else None

    def _run_protocol_task(self, protocol: str, target: str, local_auth: bool = False) -> list[str]:
        """Run all credential pairs for one protocol/auth-type, return captured output."""
        output_lines: list[str] = []
        timeout_count = 0
        total_per_task = len(self.credentials)
        ran = 0
        for credential in self.credentials:
            if not self._credential_supported(credential, protocol):
                # Hash creds aren't usable on ssh/ftp/vnc/nfs — count as done, move on.
                self._vprint(
                    V_VERBOSE,
                    f"  {DIM}↷ skip {self._task_label(protocol, local_auth)} "
                    f"for hash-only cred {credential.user!r}{RESET}",
                )
                ran += 1
                self._update_progress()
                continue
            cmd = self._build_nxc_command(protocol, target, credential, local_auth)
            self._log_command(self._task_label(protocol, local_auth), cmd, target=target)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
                stdout = (result.stdout or "").strip()
                stderr = (result.stderr or "").strip()
                classification = self._classify_attempt_output(stdout, stderr)

                if stdout:
                    output_lines.append(stdout)
                    self._report_success_lines(stdout, protocol, local_auth)

                # stderr often carries connection errors; include it when stdout is empty
                # or when we classified this attempt as a connectivity timeout.
                if stderr and (not stdout or classification == "connectivity_timeout"):
                    marker = "[!]" if classification == "connectivity_timeout" else "[-]"
                    stderr_block = self._format_stderr_block(stderr, marker)
                    if stderr_block:
                        output_lines.append(stderr_block)

                if classification == "connectivity_timeout":
                    timeout_count += 1
                else:
                    timeout_count = 0
            except subprocess.TimeoutExpired:
                timeout_count += 1

            ran += 1
            self._update_progress()

            if timeout_count >= MAX_RETRY:
                # Skip remaining credentials for this protocol after repeated timeouts.
                output_lines.append(f"[!] {MAX_RETRY} consecutive timeouts — skipped")
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {YELLOW}⏱ {label}{RESET} {DIM}{MAX_RETRY} consecutive timeouts — skipping{RESET}"
                )
                remaining = total_per_task - ran
                if remaining > 0:
                    self._skip_progress(remaining)
                break
        return output_lines

    @staticmethod
    def _parse_nxc_line(line: str) -> tuple[str | None, str]:
        """Extract status marker and message from nxc output.

        'SMB  10.x.x.x  445  DC01  [+] dom\\user:pass' -> ('[+]', 'dom\\user:pass')
        """
        for marker in ("[+]", "[-]", "[*]", "[!]"):
            idx = line.find(marker)
            if idx != -1:
                return marker, line[idx + 4:].strip()
        return None, line.strip()

    @staticmethod
    def _extract_target_info(results: dict) -> str | None:
        """Get first [*] info line to display target OS/host details once."""
        for blocks in results.values():
            for block in blocks:
                for line in block.split("\n"):
                    if "[*]" in line:
                        idx = line.find("[*]")
                        return line[idx + 4:].strip()
        return None

    def _credential_summary(self) -> str:
        """Compact one-liner describing credential composition for the banner."""
        null_users = {u for u, _ in NULL_SESSION_CREDS}
        n_pwd = sum(
            1 for c in self.credentials
            if not c.is_hash and c.user not in null_users
        )
        n_hash = sum(1 for c in self.credentials if c.is_hash)
        n_quick = sum(1 for c in self.credentials if c.user in null_users and not c.is_hash)
        parts: list[str] = []
        if n_pwd:
            parts.append(f"{n_pwd} pwd")
        if n_hash:
            parts.append(f"{n_hash} hash")
        if n_quick:
            parts.append(f"{n_quick} anon (null/guest)")
        return " · ".join(parts) if parts else "—"

    def _auth_options_summary(self) -> str:
        parts: list[str] = []
        if self.domain:
            parts.append(f"domain={self.domain}")
        if self.kerberos:
            parts.append("kerberos")
        if self.null_session:
            parts.append("null-session")
        if self.combo_arg:
            parts.append(f"combo={os.path.basename(self.combo_arg)}")
        return " · ".join(parts) if parts else "—"

    def _post_exploit_summary(self) -> str:
        parts: list[str] = []
        if self.enum_enabled:
            parts.append("enum")
        if self.modules:
            parts.append(f"modules={','.join(self.modules)}")
        if self.bloodhound_enabled:
            parts.append("bloodhound")
        return " · ".join(parts) if parts else "—"

    def _print_scan_banner(self, total_attempts: int):
        nmap_status = "ON" if self.nmap_enabled else "OFF"
        cache_status = "ON" if self.cache else ("OFF" if (self.nmap_enabled or self.bloodhound_enabled) else "n/a")
        verbosity_label = {V_DEBUG: "DEBUG", V_VERBOSE: "VERBOSE", V_NORMAL: "NORMAL", V_QUIET: "QUIET"}.get(self.verbosity, "NORMAL")
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ NetExec Automator{RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets Count   {DIM}│{RESET} {BOLD}{len(self.targets):<11}{RESET} Protocols {DIM}│{RESET} {BOLD}{len(ALL_PROTOCOLS)}{RESET} (+ local auth)")
        print(f"  Credentials     {DIM}│{RESET} {BOLD}{len(self.credentials):<11}{RESET} Workers   {DIM}│{RESET} {BOLD}{self.workers}{RESET}")
        print(f"  Composition     {DIM}│{RESET} {BOLD}{self._credential_summary()}{RESET}")
        print(f"  Auth Options    {DIM}│{RESET} {BOLD}{self._auth_options_summary()}{RESET}")
        print(f"  Pairing Mode    {DIM}│{RESET} {BOLD}{self.mode.upper():<11}{RESET} Log File  {DIM}│{RESET} {BOLD}{self.log_file}{RESET}")
        print(f"  Nmap Pre-scan   {DIM}│{RESET} {BOLD}{nmap_status:<11}{RESET} Cache     {DIM}│{RESET} {BOLD}{cache_status}{RESET}")
        print(f"  Post-Exploit    {DIM}│{RESET} {BOLD}{self._post_exploit_summary()}{RESET}")
        print(f"  Verbosity       {DIM}│{RESET} {BOLD}{verbosity_label:<11}{RESET} Loot Dir  {DIM}│{RESET} {BOLD}{self.loot.root}{RESET}")
        cmd_log_str = str(self.cmd_log_path) if self.cmd_log_path else "disabled"
        print(f"  Command Log     {DIM}│{RESET} {BOLD}{cmd_log_str}{RESET}")
        if self.scan_only:
            print(f"  {YELLOW}{BOLD}⚠ scan-only mode — no auth attempts will run{RESET}")
        else:
            print(f"  Total Tasks     {DIM}│{RESET} {BOLD}~{total_attempts}{RESET} {DIM}(upper bound, filtered by nmap){RESET}" if self.nmap_enabled else f"  Total Tasks     {DIM}│{RESET} {BOLD}{total_attempts}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _collect_target_results(self, target: str, tasks: list[TaskKey], pair_count: int) -> dict[TaskKey, list[str]]:
        self.completed = 0
        self.total_tasks = len(tasks) * pair_count
        results: dict[TaskKey, list[str]] = {}

        # Each future handles one protocol/auth scope task and runs all credentials sequentially.
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures: dict = {}
            for protocol, local_auth in tasks:
                fut = pool.submit(self._run_protocol_task, protocol, target, local_auth)
                futures[fut] = (protocol, local_auth)

            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    results[key] = [f"[!] Error: {exc}"]
        return results

    def _print_target_results(self, results: dict[TaskKey, list[str]], tasks: list[TaskKey]):
        target_info = self._extract_target_info(results)

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {CYAN}{BOLD}📋 NetExec Automator Results{RESET}")
        print(f"{'─' * BANNER_WIDTH}")

        if target_info:
            print(f"    {DIM}{target_info}{RESET}")
        print()

        successes: list[tuple[str, str]] = []
        # Track no-response by protocol name so domain/local variants collapse into one line.
        no_output_protos: set[str] = set()

        for protocol, local_auth in tasks:
            key = (protocol, local_auth)
            label = self._task_label(protocol, local_auth)
            blocks = results.get(key, [])

            if not blocks:
                no_output_protos.add(protocol.upper())
                continue

            # Keep only user-facing status lines from raw nxc output.
            parsed = self._parse_status_blocks(blocks)

            if not parsed:
                no_output_protos.add(protocol.upper())
                continue

            icon = self._status_icon(parsed)

            for i, (marker, msg) in enumerate(parsed):
                if i == 0:
                    prefix = f"  {icon} {BOLD}{label:<20}{RESET}"
                else:
                    prefix = f"      {'':<20}"

                if marker == "[+]":
                    print(f"{prefix} {GREEN}{msg}{RESET}")
                    successes.append((label, msg))
                elif marker == "[-]":
                    print(f"{prefix} {DIM}{msg}{RESET}")
                elif marker == "[!]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")

        if no_output_protos:
            ordered = [p for p in ALL_PROTOCOLS if p.upper() in no_output_protos]
            names = ", ".join(p.upper() for p in ordered)
            print(f"\n  {DIM}── No response: {names}{RESET}")

        print(f"\n{'─' * BANNER_WIDTH}")

        if successes:
            print(f"\n  {GREEN}{BOLD}✓ VALID CREDENTIALS{RESET}\n")
            for label, msg in successes:
                print(f"    {GREEN}►{RESET} {BOLD}{label:<20}{RESET} {DIM}│{RESET} {msg}")
            print()
        else:
            print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}\n")

        print(f"{'═' * BANNER_WIDTH}\n")

    # ---------------------------------------------------------------
    # Post-exploitation: DC detection, enum/modules, BloodHound
    # ---------------------------------------------------------------

    def _detect_dc_from_results(
        self,
        host: str,
        results: dict[TaskKey, list[str]],
        open_ports: set[int] | None,
    ):
        """Scan SMB output blocks for (domain:...) info and combine with nmap port
        signals to identify whether `host` is a Domain Controller."""
        domain_found: str | None = None
        for (protocol, _local), blocks in results.items():
            if protocol != "smb":
                continue
            for block in blocks:
                m = SMB_DOMAIN_RE.search(block)
                if m:
                    domain_found = m.group(1).strip()
                    break
            if domain_found:
                break

        if not domain_found:
            return

        domain_lc = domain_found.lower()
        self.host_domain[host] = domain_lc
        self.domain_hosts.setdefault(domain_lc, set()).add(host)

        # Signal B: LDAP (389/636) AND SMB (445) open → very likely a DC
        looks_like_dc = False
        source = "smb_banner"
        if open_ports is not None:
            has_ldap = 389 in open_ports or 636 in open_ports
            has_smb = 445 in open_ports
            if has_ldap and has_smb:
                looks_like_dc = True
                source = "nmap_ldap_smb"

        # If we can't validate via nmap (--nmap off), fall back to the SMB banner
        # signal alone — the host advertised a domain, so it speaks AD.
        if not looks_like_dc and open_ports is None:
            looks_like_dc = True

        if looks_like_dc:
            if self.cache:
                self.cache.record_dc(domain_lc, host, source)
            self._vprint(
                V_VERBOSE,
                f"  {CYAN}🩸 DC candidate{RESET} {DIM}{host} → domain={domain_lc} (source={source}){RESET}",
            )

    def _extract_valid_creds_from_results(
        self, host: str, results: dict[TaskKey, list[str]]
    ) -> list[dict]:
        """Return [{host, protocol, local_auth, credential, raw}] for each [+] line."""
        valid: list[dict] = []
        for (protocol, local_auth), blocks in results.items():
            for block in blocks:
                for raw_line in block.split("\n"):
                    marker, msg = self._parse_nxc_line(raw_line.strip())
                    if marker != "[+]":
                        continue
                    cred = self._match_msg_to_credential(msg, protocol)
                    if cred is None:
                        continue
                    valid.append({
                        "host": host,
                        "protocol": protocol,
                        "local_auth": local_auth,
                        "credential": cred,
                        "raw": msg,
                    })
        return valid

    def _match_msg_to_credential(self, msg: str, protocol: str) -> "Credential | None":
        """Best-effort: figure out which Credential produced a [+] line.

        nxc prints `domain\\user:secret` (or hash). We match on the longest
        user/secret pair that appears in the message. Returns None if ambiguous."""
        for cred in self.credentials:
            secret = cred.nthash or (cred.password or "")
            user = cred.user
            # Be lenient: any cred whose user and secret both appear in the msg wins.
            if user and user in msg and (not secret or secret in msg):
                return cred
            if not user and "":
                # null session — match the literal ":" pattern hard to do; skip
                pass
        # Fallback: first credential (works for single-cred runs)
        return self.credentials[0] if len(self.credentials) == 1 else None

    def _run_nxc_action(
        self,
        protocol: str,
        host: str,
        credential: "Credential",
        local_auth: bool,
        extra_args: list[str],
        loot_path: Path,
    ) -> bool:
        """Run a follow-up nxc command (--shares, --users, -M ...) and save output."""
        cmd = self._build_nxc_command(protocol, host, credential, local_auth)
        # Drop the --log clause to keep the post-exploit log separate from main spray.
        if "--log" in cmd:
            i = cmd.index("--log")
            del cmd[i : i + 2]
        cmd.extend(extra_args)
        self._log_command(f"post-ex {' '.join(extra_args)}".strip(), cmd, target=host)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
            loot_path.write_text((result.stdout or "") + ("\n--- stderr ---\n" + result.stderr if result.stderr else ""))
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            loot_path.write_text(f"timed out after {SUBPROCESS_TIMEOUT}s")
            return False

    def _post_exploit_host(self, host: str, host_valid: list[dict]):
        """Run --enum probes and --modules on the strongest valid SMB cred for this host."""
        if not (self.enum_enabled or self.modules):
            return
        # Pick best SMB cred: domain auth first, then local, then anything
        smb_creds = [v for v in host_valid if v["protocol"] == "smb"]
        if not smb_creds:
            return
        smb_creds.sort(key=lambda v: (v["local_auth"], v["credential"].is_hash))
        target = smb_creds[0]
        cred = target["credential"]
        local = target["local_auth"]
        scope = self._auth_scope(local)
        host_dir = self.loot.dir_for(LootStore.safe_name(host), "smb", scope)

        if self.enum_enabled:
            print(f"\n  {CYAN}{BOLD}▸ enum {host}{RESET} {DIM}(SMB {scope} as {cred.user or '<empty>'}){RESET}")
            for name, flag in SMB_ENUM_ACTIONS:
                out = host_dir / f"{name}.txt"
                ok = self._run_nxc_action("smb", host, cred, local, [flag], out)
                icon = f"{GREEN}✔{RESET}" if ok else f"{YELLOW}⏱{RESET}"
                print(f"    {icon} {name:<12} {DIM}→ {out}{RESET}")

        for mod in self.modules:
            print(f"\n  {CYAN}{BOLD}▸ module {host}{RESET} {DIM}(SMB {scope} as {cred.user or '<empty>'}) -M {mod}{RESET}")
            out = host_dir / f"module-{LootStore.safe_name(mod)}.txt"
            ok = self._run_nxc_action("smb", host, cred, local, ["-M", mod], out)
            icon = f"{GREEN}✔{RESET}" if ok else f"{YELLOW}⏱{RESET}"
            print(f"    {icon} {mod:<24} {DIM}→ {out}{RESET}")

    def _pick_bloodhound_cred(self, domain: str) -> "Credential | None":
        """Choose a credential that successfully authenticated against this domain."""
        for entry in self.valid_creds:
            host = entry["host"]
            cred = entry["credential"]
            if entry["local_auth"]:
                continue
            if self.host_domain.get(host) == domain.lower():
                return cred
        return None

    def _run_bloodhound_pass(self):
        """For every discovered domain, run bloodhound-python once (TTL-deduped)."""
        if not self.bloodhound_runner:
            return
        if not self.domain_hosts:
            self._vprint(V_VERBOSE, f"  {DIM}🩸 BloodHound: no domain detected, skipping{RESET}")
            return

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {CYAN}{BOLD}🩸 BloodHound Collection{RESET}")
        print(f"{'─' * BANNER_WIDTH}")

        for domain, hosts in self.domain_hosts.items():
            cached = self.bloodhound_runner.already_collected(domain)
            if cached:
                ran_at = datetime.fromtimestamp(cached["ran_at"]).strftime("%Y-%m-%d %H:%M")
                print(f"  {YELLOW}↷ {domain}{RESET} {DIM}already collected at {ran_at} → skipped{RESET}")
                print(f"     {DIM}→ {cached['output_path']}{RESET}")
                continue

            dcs = [h for h in hosts]  # all hosts that advertised this domain
            if self.cache:
                # Prefer DCs recorded with explicit source
                dc_records = self.cache.get_dcs(domain)
                if dc_records:
                    dcs = [ip for ip, _src in dc_records]

            if not dcs:
                print(f"  {RED}✘ {domain}{RESET} {DIM}no DC candidate identified{RESET}")
                continue

            cred = self._pick_bloodhound_cred(domain)
            if not cred:
                print(f"  {RED}✘ {domain}{RESET} {DIM}no domain credential available{RESET}")
                continue

            dc_ip = dcs[0]
            print(f"  {CYAN}▸ {domain}{RESET} {DIM}via {dc_ip} as {cred.user}{RESET}")
            success, out_dir, err = self.bloodhound_runner.collect(domain, dc_ip, cred)
            if success:
                print(f"    {GREEN}✔ collected{RESET} {DIM}→ {out_dir}{RESET}")
            else:
                print(f"    {RED}✘ failed{RESET} {DIM}{err}{RESET}")
                print(f"    {DIM}→ {out_dir} (see stderr.log){RESET}")

    @staticmethod
    def _is_expandable_spec(target: str) -> bool:
        """True if the target is a CIDR / range that nmap will expand into many hosts."""
        return "/" in target or "-" in target

    def _discover_target(self, target: str) -> dict[str, set[int]]:
        """Resolve a target spec into {host: {open_ports}}.

        Without --nmap, returns {target: set()} (signals 'no filtering').
        With --nmap, runs scan (cache-aware for single hosts) and returns
        only hosts with at least one open port.
        """
        if not self.nmap_enabled or self.scanner is None:
            return {target: set()}

        expandable = self._is_expandable_spec(target)

        if self.cache and not expandable:
            cached = self.cache.get_fresh(target)
            if cached is not None:
                open_set = {p for p, st in cached.items() if st == "open"}
                self._vprint(
                    V_VERBOSE,
                    f"  {DIM}🗎 cache hit {target} → {len(open_set)} open port(s){RESET}",
                )
                return {target: open_set} if open_set else {}
            self._vprint(V_VERBOSE, f"  {DIM}🗎 cache miss {target} → running nmap{RESET}")

        scan_result = self.scanner.scan(target)
        self._vprint(
            V_DEBUG,
            f"  {DIM}🔍 nmap raw: {len(scan_result)} host(s) with open ports{RESET}",
        )

        if self.cache:
            if not expandable:
                # nmap may report results keyed by IP rather than the hostname/IP given.
                ports = scan_result.get(target)
                if ports is None and len(scan_result) == 1:
                    ports = next(iter(scan_result.values()))
                self.cache.store(target, ports or {})
            else:
                for ip, ports in scan_result.items():
                    self.cache.store(ip, ports)

        return {
            host: {p for p, st in ports.items() if st == "open"}
            for host, ports in scan_result.items()
            if any(st == "open" for st in ports.values())
        }

    @staticmethod
    def _format_open_ports(open_ports: set[int]) -> str:
        protos: list[str] = []
        for proto in ALL_PROTOCOLS:
            if any(p in open_ports for p in PROTOCOL_PORTS.get(proto, [])):
                protos.append(proto.upper())
        return ", ".join(protos) if protos else "none"

    def run(self):
        task_count = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
        pair_count = len(self.credentials)
        total_attempts = len(self.targets) * pair_count * task_count

        if self.nmap_enabled and self.scanner is not None and not NmapScanner.is_available():
            print(f"  {YELLOW}{BOLD}⚠ nmap not found in PATH — disabling pre-scan{RESET}\n")
            self.nmap_enabled = False
            self.scanner = None
            if self.scan_only:
                print(f"  {RED}{BOLD}✗ --scan-only requires nmap; aborting.{RESET}\n")
                return

        if self.bloodhound_runner and not BloodHoundRunner.is_available():
            print(f"  {YELLOW}{BOLD}⚠ bloodhound-python not found in PATH — disabling --bloodhound{RESET}\n")
            self.bloodhound_runner = None
            self.bloodhound_enabled = False

        if self.verbosity > V_QUIET:
            self._print_scan_banner(total_attempts)

        try:
            for raw_target in self.targets:
                discovered = self._discover_target(raw_target)

                if not discovered:
                    msg = "no open ports / unreachable" if self.nmap_enabled else "no targets"
                    if self.verbosity > V_QUIET:
                        print(f"  {DIM}► {raw_target} — {msg}{RESET}\n")
                    continue

                for host, open_ports in discovered.items():
                    tasks = self._build_protocol_tasks(open_ports if self.nmap_enabled else None)

                    if self.verbosity > V_QUIET:
                        header = f"  {GREEN}{BOLD}► {host}{RESET}"
                        if self.nmap_enabled:
                            header += f" {DIM}[{self._format_open_ports(open_ports)}]{RESET}"
                        print(header + "\n")

                    if not tasks:
                        if self.verbosity > V_QUIET:
                            print(f"  {DIM}── no testable protocols on this host{RESET}\n")
                        continue

                    if self.scan_only:
                        continue

                    results = self._collect_target_results(host, tasks, pair_count)
                    sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
                    sys.stderr.flush()

                    if self.verbosity > V_QUIET:
                        self._print_target_results(results, tasks)

                    # Post-spray analysis: detect DC, harvest valid creds, run enum/modules
                    self._detect_dc_from_results(host, results, open_ports if self.nmap_enabled else None)
                    host_valid = self._extract_valid_creds_from_results(host, results)
                    if host_valid:
                        self.valid_creds.extend(host_valid)
                        if self.verbosity == V_QUIET:
                            for entry in host_valid:
                                label = self._task_label(entry["protocol"], entry["local_auth"])
                                print(f"  {GREEN}► {host}{RESET} {BOLD}{label:<20}{RESET} {GREEN}{entry['raw']}{RESET}")
                        self._post_exploit_host(host, host_valid)

            if self.bloodhound_enabled:
                self._run_bloodhound_pass()
        finally:
            if self.cache:
                self.cache.close()


def parse_mode(value: str) -> str:
    """Validate accepted mode values."""
    mode = value.lower()
    if mode in ("combination", "linear"):
        return mode
    raise argparse.ArgumentTypeError("Mode must be one of: combination, linear")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run nxc across all protocols with combination or linear credential pairing."
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP/hostname or path to targets.txt")
    parser.add_argument("-u", "--user", help="Username, or path to users.txt")
    parser.add_argument("-p", "--password", help="Password, or path to passwords.txt")
    parser.add_argument("-H", "--hash", dest="nthash",
                        help="NT hash (32 hex), LM:NT (32:32 hex), or path to hashes.txt")
    parser.add_argument("-d", "--domain",
                        help="Active Directory domain — appended to nxc with -d for domain auth")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos auth (-k). Requires a valid ccache (KRB5CCNAME or /tmp/krb5cc_*).")
    parser.add_argument("--combo",
                        help="Path to a user:secret combo file. Auto-detects password vs NT/LM:NT hash per line.")
    parser.add_argument("--null-session", action="store_true",
                        help="Also probe null session, Guest:'', and anonymous:'' as fast quick-wins.")
    parser.add_argument("-o", "--output", help="Custom log file path (default: HH-MM-SS-mmm.txt)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Number of parallel threads (default: {DEFAULT_WORKERS})")
    parser.add_argument(
        "-m", "--mode",
        type=parse_mode,
        default="combination",
        metavar="{combination,linear}",
        help="Credential pairing mode: combination (all combinations) or linear (index-matched pairs).",
    )
    parser.add_argument(
        "--nmap", action="store_true",
        help="Pre-scan target ports with nmap and skip protocols whose ports are closed.",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Bypass the SQLite nmap-result cache (only relevant with --nmap).",
    )
    parser.add_argument(
        "--cache-ttl", type=int, default=CACHE_DEFAULT_TTL,
        help=f"Seconds nmap results remain valid in cache (default: {CACHE_DEFAULT_TTL} = 24h).",
    )
    parser.add_argument(
        "--scan-only", action="store_true",
        help="Run nmap discovery only and print open ports — no nxc auth attempts. Implies --nmap.",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity: -v shows commands + failed auth lines, -vv adds raw nxc/nmap output.",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Only print valid credentials and post-exploit output. Suppresses banner and per-host detail.",
    )
    parser.add_argument(
        "--enum", action="store_true",
        help="On valid SMB cred, run --shares/--users/--sessions/--loggedon-users/--pass-pol into loot/.",
    )
    parser.add_argument(
        "--modules",
        help="Comma-separated nxc -M modules to run on valid SMB creds (e.g. spider_plus,gpp_password).",
    )
    parser.add_argument(
        "--bloodhound", action="store_true",
        help="Auto-collect BloodHound data per discovered AD domain (requires bloodhound-python).",
    )
    parser.add_argument(
        "--bloodhound-force", action="store_true",
        help="Re-collect BloodHound for a domain even if a recent successful run exists.",
    )
    parser.add_argument(
        "--bloodhound-ttl", type=int, default=CACHE_DEFAULT_TTL,
        help=f"Dedup window for BloodHound runs per domain (default: {CACHE_DEFAULT_TTL} = 24h).",
    )
    parser.add_argument(
        "--loot-dir", default="loot",
        help="Directory root for enum/modules/bloodhound output (default: loot/).",
    )
    parser.add_argument(
        "--cmd-log",
        help="Path for the shell-quoted commands transcript (default: commands-HH-MM-SS-mmm.log).",
    )
    parser.add_argument(
        "--no-cmd-log", action="store_true",
        help="Disable the commands transcript file.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    nmap_enabled = args.nmap or args.scan_only
    if args.quiet:
        verbosity = V_QUIET
    else:
        verbosity = min(args.verbose, V_DEBUG)
    try:
        runner = NxcAutomator(
            target=args.target,
            user=args.user,
            password=args.password,
            nthash=args.nthash,
            combo=args.combo,
            domain=args.domain,
            kerberos=args.kerberos,
            null_session=args.null_session,
            output=args.output,
            workers=args.workers,
            mode=args.mode,
            nmap_enabled=nmap_enabled,
            cache_enabled=not args.no_cache,
            cache_ttl=args.cache_ttl,
            scan_only=args.scan_only,
            verbosity=verbosity,
            enum_enabled=args.enum,
            modules=args.modules,
            bloodhound_enabled=args.bloodhound,
            bloodhound_force=args.bloodhound_force,
            bloodhound_ttl=args.bloodhound_ttl,
            loot_dir=args.loot_dir,
            cmd_log=args.cmd_log,
            cmd_log_disabled=args.no_cmd_log,
        )
        runner.run()
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
