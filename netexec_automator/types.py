"""Pure-data types shared across the package."""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class NxcActionResult:
    """Return value of a post-exploit nxc invocation.

    Carries both the raw process state (ok / exit / stdout / stderr) and the
    loot path the output was teed to. Callers use _classify_action() to turn
    this into a (status, note) tuple — the distinction between 'exit 0' and
    'actually produced data' is what kept us from showing misleading ✔ icons."""
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    loot_path: Path

    @property
    def combined(self) -> str:
        return "\n".join(filter(None, (self.stdout, self.stderr)))


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
