"""Phase 2: smart cache — separate dead-sentinel TTL, invalidate(), and the
dead-host liveness re-probe / --rescan in _discover_target."""

from unittest import mock


# ---- HostCache: positive vs negative TTL + invalidate --------------------

def test_dead_sentinel_uses_short_dead_ttl(nxa, tmp_path):
    """A 'scanned but dead' sentinel must expire after dead_ttl, not the long ttl."""
    c = nxa.HostCache(tmp_path / "s.db", ttl=86400, dead_ttl=10)
    c.store("10.0.0.9", {})  # nothing open → sentinel row
    assert c.get_fresh("10.0.0.9") == {}            # fresh dead → cache hit
    # Age it past dead_ttl but far within the 24h ttl.
    c._conn.execute("UPDATE host_ports SET scanned_at = scanned_at - 100 WHERE target = '10.0.0.9'")
    c._conn.commit()
    assert c.get_fresh("10.0.0.9") is None           # expired as dead → re-scan
    c.close()


def test_open_ports_use_long_ttl(nxa, tmp_path):
    """Open-port results are stable: honoured for the full ttl even past dead_ttl."""
    c = nxa.HostCache(tmp_path / "s.db", ttl=86400, dead_ttl=10)
    c.store("10.0.0.10", {445: "open", 22: "open"})
    c._conn.execute("UPDATE host_ports SET scanned_at = scanned_at - 100 WHERE target = '10.0.0.10'")
    c._conn.commit()
    assert c.get_fresh("10.0.0.10") == {445: "open", 22: "open"}
    c.close()


def test_invalidate_clears_entry(nxa, tmp_path):
    c = nxa.HostCache(tmp_path / "s.db", ttl=86400)
    c.store("10.0.0.11", {445: "open"})
    assert c.get_fresh("10.0.0.11") == {445: "open"}
    c.invalidate("10.0.0.11")
    assert c.get_fresh("10.0.0.11") is None
    c.close()


def test_dead_ttl_defaults_to_ttl_when_unset(nxa, tmp_path):
    """Back-compat: callers that don't pass dead_ttl get the old single-TTL behaviour."""
    c = nxa.HostCache(tmp_path / "s.db", ttl=86400)
    assert c.dead_ttl == 86400
    c.close()


# ---- _discover_target: dead-host liveness gate + --rescan ----------------

def _nmap_automator(nxa, tmp_path, **kw):
    return nxa.NxcAutomator(
        target="x", user="u", password="p",
        nmap_enabled=True, cache_path=str(tmp_path / "s.db"), **kw,
    )


def test_dead_cached_but_reachable_triggers_rescan(nxa, tmp_path):
    """A host cached as dead that answers a liveness probe now must be
    re-nmapped, not skipped (the whole point of the reactivity fix)."""
    a = _nmap_automator(nxa, tmp_path)
    a.cache.store("10.0.0.5", {})  # cached dead
    with mock.patch.object(a, "_is_host_reachable", return_value=True), \
         mock.patch.object(a.scanner, "scan", return_value={"10.0.0.5": {445: "open"}}) as scan_mock:
        result = a._discover_target("10.0.0.5")
    scan_mock.assert_called_once()
    assert result == {"10.0.0.5": {445}}


def test_dead_cached_and_still_unreachable_is_skipped(nxa, tmp_path):
    """Still-dead host: trust the cache, no expensive nmap re-scan."""
    a = _nmap_automator(nxa, tmp_path)
    a.cache.store("10.0.0.6", {})
    with mock.patch.object(a, "_is_host_reachable", return_value=False), \
         mock.patch.object(a.scanner, "scan") as scan_mock:
        result = a._discover_target("10.0.0.6")
    scan_mock.assert_not_called()
    assert result == {}


def test_dead_cached_skips_probe_when_reachability_off(nxa, tmp_path):
    """--no-reachability-check: trust the dead sentinel, don't probe or rescan."""
    a = _nmap_automator(nxa, tmp_path, reachability_check=False)
    a.cache.store("10.0.0.6", {})
    with mock.patch.object(a, "_is_host_reachable") as probe, \
         mock.patch.object(a.scanner, "scan") as scan_mock:
        result = a._discover_target("10.0.0.6")
    probe.assert_not_called()
    scan_mock.assert_not_called()
    assert result == {}


def test_rescan_bypasses_cache_hit(nxa, tmp_path):
    """--rescan ignores a perfectly good cached open-port result and re-scans."""
    a = _nmap_automator(nxa, tmp_path, rescan=True)
    a.cache.store("10.0.0.7", {445: "open"})  # would be a cache hit normally
    with mock.patch.object(a.scanner, "scan", return_value={"10.0.0.7": {3389: "open"}}) as scan_mock:
        result = a._discover_target("10.0.0.7")
    scan_mock.assert_called_once()
    assert result == {"10.0.0.7": {3389}}


# ---- Phase 3: per-IP cache reuse for ranges/CIDR -------------------------

def test_expand_cidr_small_range(nxa):
    assert nxa.NxcAutomator._expand_cidr("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_expand_cidr_slash32(nxa):
    assert nxa.NxcAutomator._expand_cidr("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_cidr_too_large_returns_none(nxa):
    assert nxa.NxcAutomator._expand_cidr("10.0.0.0/19") is None  # 8192 > 4096 cap


def test_expand_cidr_non_cidr_returns_none(nxa):
    assert nxa.NxcAutomator._expand_cidr("10.0.0.1-50") is None     # nmap dash-range
    assert nxa.NxcAutomator._expand_cidr("dc01.corp.local") is None  # hostname
    assert nxa.NxcAutomator._expand_cidr("10.0.0.0/33") is None      # invalid


def test_scanner_scan_accepts_list_of_targets(nxa):
    import subprocess as sp
    s = nxa.NmapScanner(ports=[445, 22])
    fake = mock.Mock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")
    with mock.patch.object(sp, "run", return_value=fake) as run_mock:
        s.scan(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    cmd = run_mock.call_args[0][0]
    assert cmd[-3:] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # all targets passed to nmap


def test_range_cache_only_scans_unknown_ips(nxa, tmp_path):
    """A range run reuses cached open/dead IPs and only nmaps the unknowns."""
    a = _nmap_automator(nxa, tmp_path)
    a.cache.store("10.0.0.1", {445: "open"})  # known live
    a.cache.store("10.0.0.2", {})             # known dead (sentinel)
    # 10.0.0.3 not cached
    with mock.patch.object(a.scanner, "scan", return_value={"10.0.0.3": {3389: "open"}}) as scan_mock:
        result = a._discover_range_cached("10.0.0.0/29", ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    scan_mock.assert_called_once_with(["10.0.0.3"])                 # only the unknown
    assert result == {"10.0.0.1": {445}, "10.0.0.3": {3389}}        # dead .2 excluded
    assert a.cache.get_fresh("10.0.0.3") == {3389: "open"}          # newly cached


def test_range_cache_stores_dead_sentinel_for_scanned_empty(nxa, tmp_path):
    """IPs scanned in a range that have nothing open get a dead sentinel so the
    next range run skips them (per-IP memory for dead hosts too)."""
    a = _nmap_automator(nxa, tmp_path)
    with mock.patch.object(a.scanner, "scan", return_value={}):  # nothing open
        result = a._discover_range_cached("10.0.0.0/30", ["10.0.0.1", "10.0.0.2"])
    assert result == {}
    assert a.cache.get_fresh("10.0.0.1") == {}   # sentinel stored
    assert a.cache.get_fresh("10.0.0.2") == {}


def test_discover_target_routes_cidr_through_range_cache(nxa, tmp_path):
    a = _nmap_automator(nxa, tmp_path)
    with mock.patch.object(a, "_discover_range_cached", return_value={"10.0.0.1": {445}}) as rc:
        result = a._discover_target("10.0.0.0/30")
    rc.assert_called_once()
    assert result == {"10.0.0.1": {445}}
