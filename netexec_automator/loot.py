"""Loot directory layout used by enum, modules, BloodHound, and the cracker."""

import re
from pathlib import Path


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
