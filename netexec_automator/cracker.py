"""HashCracker: hashcat/john wrapper with retry-on-signal, potfile parsing,
auto wordlist discovery (rockyou)."""

import shutil
import subprocess
from pathlib import Path

from .constants import (CRACK_DEFAULT_TIMEOUT, HASH_NT_PATTERN, HASH_TYPES,
                        WORDLIST_DEFAULT_PATHS)
from .loot import LootStore


class HashCracker:
    """Wraps hashcat (preferred) or john for offline cracking of harvested hashes.

    Designed to be opt-in (`--crack`) and incremental: each hash type produced
    by the spray (NT from SAM/LSA/NTDS, AS-REP from --asreproast, TGS from
    --kerberoasting) goes into a separate attack, persisted in a shared
    potfile under loot/cracked/. Newly cracked plaintexts are returned to the
    caller so they can be auto-appended to the grow-combo file."""

    def __init__(
        self,
        loot: LootStore,
        wordlist: str | None = None,
        cracker: str = "auto",
        rules: str | None = None,
        timeout: int = CRACK_DEFAULT_TIMEOUT,
        log_cmd=None,
    ):
        self.loot = loot
        self.wordlist_arg = wordlist
        self.cracker_pref = cracker
        self.rules = rules
        self.timeout = timeout
        self.log_cmd = log_cmd
        self._wordlist_path: Path | None = None  # resolved lazily
        self._cracker: str | None = None         # resolved lazily
        self.last_stderr: str = ""

    # ---- discovery ----

    @staticmethod
    def detect_cracker(pref: str = "auto") -> str | None:
        """Return 'hashcat' or 'john' if available; honors pref when possible."""
        order = (
            ["hashcat", "john"] if pref == "auto"
            else [pref]
        )
        for tool in order:
            if shutil.which(tool):
                return tool
        return None

    def cracker(self) -> str | None:
        if self._cracker is None:
            self._cracker = self.detect_cracker(self.cracker_pref)
        return self._cracker

    def find_wordlist(self) -> Path | None:
        """Locate a usable wordlist. If a .gz is found, decompress to a
        sibling .txt and return that path."""
        if self._wordlist_path is not None:
            return self._wordlist_path
        candidates = [self.wordlist_arg] if self.wordlist_arg else WORDLIST_DEFAULT_PATHS
        for cand in candidates:
            if not cand:
                continue
            p = Path(cand).expanduser()
            if not p.exists():
                continue
            if p.suffix == ".gz":
                decompressed = p.with_suffix("")  # strip .gz
                if not decompressed.exists():
                    try:
                        import gzip
                        with gzip.open(p, "rb") as src, open(decompressed, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                    except OSError:
                        continue
                self._wordlist_path = decompressed
            else:
                self._wordlist_path = p
            return self._wordlist_path
        return None

    # ---- attack ----

    def cracked_dir(self) -> Path:
        return self.loot.dir_for("cracked")

    def build_cmd(self, hash_type: str, hash_file: Path, wordlist: Path) -> list[str]:
        info = HASH_TYPES[hash_type]
        # Honour an explicit --cracker preference even if the binary isn't in
        # PATH; actual crack() will fail gracefully if it isn't there.
        if self.cracker_pref in ("hashcat", "john"):
            cracker = self.cracker_pref
        else:
            cracker = self.cracker() or "hashcat"
        out_dir = self.cracked_dir()
        if cracker == "hashcat":
            cmd = [
                "hashcat",
                "-m", info["hashcat_mode"],
                "-a", "0",
                "--quiet",
                "--potfile-path", str(out_dir / "potfile"),
                "--outfile", str(out_dir / f"cracked-{hash_type}.txt"),
                str(hash_file), str(wordlist),
            ]
            if self.rules:
                cmd.extend(["-r", self.rules])
        else:
            # john --wordlist=... --format=<fmt> hash_file
            cmd = [
                "john",
                f"--wordlist={wordlist}",
                f"--format={info['john_format']}",
                str(hash_file),
            ]
        return cmd

    def crack(self, hash_type: str, hash_file: Path) -> tuple[bool, list[tuple[str, str]]]:
        """Run the cracker for one hash file. Returns (success, [(hash,plain)…]).

        Hashcat occasionally segfaults / gets OOM-killed mid-run, especially
        when the GPU driver is unhappy or the workload profile is too high.
        We detect that (returncode < 0 = killed by signal) and retry once
        with `-w 1` (low workload). The potfile is write-as-you-go so any
        plaintexts cracked before the crash are preserved across attempts.

        last_stderr is always populated for the caller to feed to
        diagnose_zero_cracks()."""
        self.last_stderr = ""
        cracker = self.cracker()
        if not cracker:
            return False, []
        wordlist = self.find_wordlist()
        if not wordlist:
            return False, []
        if not hash_file.exists() or hash_file.stat().st_size == 0:
            return False, []

        base_cmd = self.build_cmd(hash_type, hash_file, wordlist)

        for attempt in range(2):  # 0 = first try, 1 = retry with -w 1
            cmd = base_cmd if attempt == 0 else (base_cmd + ["-w", "1"])
            if self.log_cmd:
                label = f"crack {hash_type}" + (f" retry-w1" if attempt else "")
                self.log_cmd(label, cmd, str(hash_file))
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                self.last_stderr = (res.stderr or "").strip()
                if res.returncode >= 0:
                    # Normal termination (0 = cracks, 1 = no cracks for hashcat — both ok).
                    break
                # Negative returncode = killed by signal (SIGSEGV, SIGKILL via OOM-killer, …)
                self.last_stderr = (
                    f"{cracker} killed by signal {-res.returncode} "
                    f"(attempt {attempt + 1}/2)\n{self.last_stderr}"
                ).strip()
                if attempt == 0 and cracker == "hashcat":
                    continue  # retry with -w 1
                break
            except subprocess.TimeoutExpired:
                self.last_stderr = "timed out"
                break
            except FileNotFoundError as exc:
                self.last_stderr = f"{exc.filename} not found"
                return False, []

        cracked = self._collect_results(cracker, hash_type, hash_file)
        return True, cracked

    def diagnose_zero_cracks(self) -> str | None:
        """Given self.last_stderr, suggest the most likely reason cracking
        produced no plaintexts. Returns None when no specific hint applies."""
        s = (self.last_stderr or "").lower()
        if not s:
            return None
        if "killed by signal 9" in s or "out of memory" in s or "killed (signal: 9)" in s:
            return "hashcat killed by OOM — wordlist too large for available RAM, try a smaller list"
        if "killed by signal 11" in s or "segmentation fault" in s or "segfault" in s:
            return "hashcat segfaulted (GPU driver?) — retried with -w 1 already; falling back to john may help"
        if "killed by signal" in s:
            return "hashcat killed by a signal — see commands.log + system dmesg for details"
        if "no hashes loaded" in s:
            return "no hashes loaded — invalid hash format for this -m mode?"
        if "hash-mode" in s and ("not supported" in s or "unknown" in s):
            return "hashcat version doesn't support this hash mode"
        if "salt-value" in s or "salt-length" in s:
            return "hash format error (salt mismatch)"
        if "exhausted" in s:
            return "wordlist exhausted — try --crack-rules or a bigger wordlist"
        if "timed out" in s:
            return f"timed out after {self.timeout}s — raise --crack-timeout"
        if "device" in s and ("not detected" in s or "no devices" in s):
            return "no GPU detected, hashcat ran on CPU (slow)"
        return None

    def _collect_results(self, cracker: str, hash_type: str, hash_file: Path) -> list[tuple[str, str]]:
        """Read potfile / john.pot to extract (hash, plaintext) pairs."""
        pairs: list[tuple[str, str]] = []
        if cracker == "hashcat":
            pot = self.cracked_dir() / "potfile"
            if pot.exists():
                pairs = self._parse_potfile(pot.read_text(errors="replace"))
        else:
            # john --show prints 'user:password' to stdout
            try:
                shown = subprocess.run(
                    ["john", "--show", f"--format={HASH_TYPES[hash_type]['john_format']}", str(hash_file)],
                    capture_output=True, text=True, timeout=30,
                )
                for line in shown.stdout.splitlines():
                    if ":" in line and not line.startswith(("0 password", "Loaded ")):
                        h, _, p = line.rpartition(":")
                        if h and p:
                            pairs.append((h, p))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        # Keep only pairs whose hash is plausibly related to this attack
        return [(h, p) for h, p in pairs if self._belongs_to(h, hash_type)]

    @staticmethod
    def _belongs_to(hash_str: str, hash_type: str) -> bool:
        if hash_type == "nt":
            return bool(HASH_NT_PATTERN.match(hash_str))
        if hash_type == "asrep":
            return "$krb5asrep$" in hash_str.lower()
        if hash_type == "tgs":
            return "$krb5tgs$" in hash_str.lower()
        return True

    @staticmethod
    def _parse_potfile(text: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # potfile is 'hash:plaintext'. An NT hash is exactly 32 hex with no
            # ':', so the plaintext is everything after the FIRST colon — this
            # preserves colons inside the cracked password (e.g. 'Sum:mer:25').
            # Kerberos hashes embed ':' in the hash itself, so for those fall
            # back to splitting on the last colon.
            head = line.split(":", 1)[0]
            if HASH_NT_PATTERN.match(head):
                h, p = head, line[len(head) + 1:]
            else:
                h, _, p = line.rpartition(":")
            if h and p:
                out.append((h, p))
        return out
