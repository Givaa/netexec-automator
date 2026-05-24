"""bloodhound-python wrapper: pre-flight, dedup, subprocess + logging."""

import subprocess
from datetime import datetime
from pathlib import Path

from .cache import HostCache
from .constants import BLOODHOUND_TIMEOUT, CACHE_DEFAULT_TTL
from .loot import LootStore
from .types import Credential


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

    def build_cmd(self, domain: str, dc_ip: str, credential: Credential) -> list[str]:
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

    def collect(self, domain: str, dc_ip: str, credential: Credential) -> tuple[bool, Path, str]:
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
