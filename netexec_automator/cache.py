"""SQLite-backed cache: nmap host_ports + domain_controllers + bloodhound_runs."""

import sqlite3
import time
from pathlib import Path


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
        # 30s busy-timeout absorbs concurrent runs / slow disks without
        # the dreaded 'database is locked' crash.
        self._conn = sqlite3.connect(str(self.path), timeout=30)
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
