"""Reverse DNS PTR lookup for nicer 'host (hostname)' headers in the UI.

Pure-stdlib (`socket.gethostbyaddr`) with an in-memory cache and a
configurable per-lookup timeout. Falls back silently to None on any
error so it never blocks the run — purely cosmetic enrichment.

The timeout is applied via socket.setdefaulttimeout() with save/restore
so it doesn't leak into the rest of the process."""

import socket


class HostnameResolver:
    """Best-effort reverse DNS PTR resolver with caching."""

    def __init__(self, timeout: float = 2.0, enabled: bool = True):
        self.timeout = timeout
        self.enabled = enabled
        self._cache: dict[str, str | None] = {}

    def resolve(self, host: str) -> str | None:
        """Return the PTR hostname for `host`, or None if unresolvable.

        If `host` already looks like a hostname (contains a non-numeric
        character that isn't '.'), we just return it — no point in
        doing a forward lookup just to display it back."""
        if not self.enabled:
            return None
        if host in self._cache:
            return self._cache[host]
        if not self._looks_like_ip(host):
            # User passed a hostname directly; keep it as-is, no PTR.
            self._cache[host] = None
            return None

        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            name, _aliases, _addrs = socket.gethostbyaddr(host)
            # Strip trailing dot if any
            if name.endswith("."):
                name = name[:-1]
            self._cache[host] = name
            return name
        except (socket.herror, socket.gaierror, OSError):
            self._cache[host] = None
            return None
        finally:
            socket.setdefaulttimeout(old)

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        """True for IPv4 dotted-quad like '10.0.0.1', false for hostnames."""
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
