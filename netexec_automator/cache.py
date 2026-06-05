"""SQLite-backed cache: nmap host_ports + domain_controllers + bloodhound_runs."""

import sqlite3
import time
from pathlib import Path
from threading import Lock


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

    -- Tried credential combinations. Used by --skip-tried so re-runs after
    -- adding new users/passwords to the wordlists only spray the new combos.
    -- We persist only the SHA1 of the secret (never the plaintext) plus the
    -- result so we can optionally retry past failures with --rerun-after.
    CREATE TABLE IF NOT EXISTS tried_creds (
        target TEXT NOT NULL,
        protocol TEXT NOT NULL,
        local_auth INTEGER NOT NULL,
        user TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        domain TEXT,
        result TEXT NOT NULL,     -- 'ok' | 'fail' | 'timeout'
        pwn3d INTEGER NOT NULL DEFAULT 0,
        attempted_at INTEGER NOT NULL,
        PRIMARY KEY (target, protocol, local_auth, user, secret_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_tried_attempted ON tried_creds(attempted_at);
    """

    def __init__(self, path: Path, ttl: int, dead_ttl: int | None = None):
        self.path = path
        self.ttl = ttl
        # Negative results (host scanned, nothing open) expire faster than
        # positive ones — liveness is volatile. Defaults to ttl when unset
        # so existing callers keep their old single-TTL behaviour.
        self.dead_ttl = ttl if dead_ttl is None else dead_ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 30s busy-timeout absorbs concurrent runs / slow disks without
        # the dreaded 'database is locked' crash.
        # check_same_thread=False is required because record_attempt() is
        # called from worker threads in the protocol-spray ThreadPoolExecutor.
        # SQLite itself serializes writes; we add a Python-level lock to keep
        # multi-statement sequences (e.g. clear_tried_cache) atomic.
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        # WAL keeps *separate* connections (e.g. concurrent CLI runs, each with
        # its own HostCache) from blocking each other, and NORMAL sync drops one
        # fsync per commit on a regenerable cache. It does NOT make a single
        # sqlite3 connection object thread-safe, though — and the spray workers
        # share THIS one connection — so every method below serializes its DB
        # access through self._lock. Both PRAGMAs are idempotent and persist.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = Lock()
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    def get_fresh(self, target: str) -> dict[int, str] | None:
        """Return cached port→state map if scanned within TTL, else None.
        Empty dict means 'scanned and nothing open' (still a cache hit).

        Positive results (open ports) are honoured for `ttl`; the negative
        'scanned but dead' sentinel only for the shorter `dead_ttl`, so a host
        that comes back online is re-scanned much sooner than a stable host's
        open-port set is re-discovered."""
        now = int(time.time())
        with self._lock:
            # Positive rows (port > 0): fresh within the long ttl.
            rows = self._conn.execute(
                "SELECT port, state, scanned_at FROM host_ports WHERE target = ? AND port > 0",
                (target,),
            ).fetchall()
            if rows and max(r[2] for r in rows) >= now - self.ttl:
                return {port: state for port, state, _ in rows}
            # Sentinel row (port = 0): 'scanned but dead', fresh within dead_ttl.
            sentinel = self._conn.execute(
                "SELECT scanned_at FROM host_ports WHERE target = ? AND port = 0", (target,)
            ).fetchone()
            if sentinel and sentinel[0] >= now - self.dead_ttl:
                return {}
            return None

    def store(self, target: str, ports: dict[int, str]):
        now = int(time.time())
        with self._lock:
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

    def invalidate(self, target: str):
        """Drop all cached port rows for a target so the next discovery re-scans
        it from scratch. Used by --rescan and by the dead-host liveness re-probe
        when a previously-dead host answers again."""
        with self._lock:
            self._conn.execute("DELETE FROM host_ports WHERE target = ?", (target,))
            self._conn.commit()

    def record_dc(self, domain: str, dc_ip: str, source: str):
        """Upsert a domain controller discovery (idempotent on PK)."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO domain_controllers "
                "(domain, dc_ip, source, discovered_at) VALUES (?, ?, ?, ?)",
                (domain.lower(), dc_ip, source, int(time.time())),
            )
            self._conn.commit()

    def get_dcs(self, domain: str) -> list[tuple[str, str]]:
        """Return [(dc_ip, source)] for a domain, most recent first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT dc_ip, source FROM domain_controllers WHERE domain = ? "
                "ORDER BY discovered_at DESC",
                (domain.lower(),),
            ).fetchall()
        return list(rows)

    def recent_bloodhound(self, domain: str, ttl: int) -> dict | None:
        cutoff = int(time.time()) - ttl
        with self._lock:
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
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO bloodhound_runs "
                "(domain, dc_ip, auth_user, output_path, ran_at, success) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (domain.lower(), dc_ip, auth_user, output_path, int(time.time()), 1 if success else 0),
            )
            self._conn.commit()

    # ---- tried_creds ----------------------------------------------------

    def was_tried(
        self,
        target: str,
        protocol: str,
        local_auth: bool,
        user: str,
        secret_hash: str,
        rerun_after: int = 0,
    ) -> str | None:
        """Return 'ok' / 'fail' / 'timeout' if this combination has been
        attempted before, or None if we should attempt it now.

        rerun_after = 0 means 'never re-attempt' (the default --skip-tried
        behaviour: anything tried before stays skipped). rerun_after = N
        means 'rerun if older than N seconds AND the previous result wasn't ok'.
        Successes (ok / pwn3d) are never re-attempted by default."""
        with self._lock:
            row = self._conn.execute(
                "SELECT result, pwn3d, attempted_at FROM tried_creds "
                "WHERE target = ? AND protocol = ? AND local_auth = ? AND user = ? AND secret_hash = ?",
                (target, protocol, 1 if local_auth else 0, user, secret_hash),
            ).fetchone()
        if not row:
            return None
        result, pwn3d, attempted_at = row
        # Always skip past successes — there's no value in re-spraying a known cred.
        if result == "ok" or pwn3d:
            return result
        if rerun_after > 0 and (int(time.time()) - attempted_at) >= rerun_after:
            return None  # stale failure → caller will retry
        return result

    def record_attempt(
        self,
        target: str,
        protocol: str,
        local_auth: bool,
        user: str,
        secret_hash: str,
        domain: str | None,
        result: str,
        pwn3d: bool = False,
    ):
        """Persist the outcome of a single spray attempt. Upserts on PK.
        Called from worker threads in the spray pool — lock-protected."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tried_creds "
                "(target, protocol, local_auth, user, secret_hash, domain, result, pwn3d, attempted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (target, protocol, 1 if local_auth else 0, user, secret_hash,
                 domain, result, 1 if pwn3d else 0, int(time.time())),
            )
            self._conn.commit()

    def clear_tried_cache(self) -> int:
        """Wipe the tried_creds table. Returns the number of rows deleted."""
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) FROM tried_creds").fetchone()[0]
            self._conn.execute("DELETE FROM tried_creds")
            self._conn.commit()
        return int(count)

    def count_tried(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM tried_creds").fetchone()
        return int(row[0]) if row else 0

    def list_valid(self) -> list[tuple[str, str, bool, str, str | None, bool]]:
        """Return prior *successful* credentials as
        (target, protocol, local_auth, user, domain, pwn3d), Pwn3d first.
        These are the rows where auth worked (result='ok') or granted admin
        (pwn3d=1). Secrets are never returned — only the hash is stored — so
        this is safe to surface in the UI. Valid creds are rare, so callers
        filter to the current targets in Python rather than via SQL."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT target, protocol, local_auth, user, domain, pwn3d FROM tried_creds "
                "WHERE result = 'ok' OR pwn3d = 1 ORDER BY pwn3d DESC, target, user"
            ).fetchall()
        return [(t, p, bool(la), u, d, bool(pw)) for t, p, la, u, d, pw in rows]

    def close(self):
        self._conn.close()
