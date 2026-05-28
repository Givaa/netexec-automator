"""Tests for HostnameResolver — reverse DNS PTR with caching."""

from unittest import mock


def test_resolver_disabled_returns_none(nxa):
    r = nxa.HostnameResolver(enabled=False)
    assert r.resolve("1.2.3.4") is None


def test_resolver_passes_through_hostnames(nxa):
    """If the input already looks like a hostname (non-IP), don't bother
    with a PTR — return None and let the caller display the input as-is."""
    r = nxa.HostnameResolver()
    assert r.resolve("dc01.corp.local") is None


def test_resolver_returns_ptr_on_success(nxa):
    r = nxa.HostnameResolver()
    with mock.patch("socket.gethostbyaddr", return_value=("dc01.corp.local", [], ["10.10.10.5"])):
        assert r.resolve("10.10.10.5") == "dc01.corp.local"


def test_resolver_strips_trailing_dot(nxa):
    r = nxa.HostnameResolver()
    with mock.patch("socket.gethostbyaddr", return_value=("dc01.corp.local.", [], ["10.10.10.5"])):
        assert r.resolve("10.10.10.5") == "dc01.corp.local"


def test_resolver_returns_none_on_herror(nxa):
    import socket
    r = nxa.HostnameResolver()
    with mock.patch("socket.gethostbyaddr", side_effect=socket.herror("no PTR")):
        assert r.resolve("10.10.10.5") is None


def test_resolver_returns_none_on_gaierror(nxa):
    import socket
    r = nxa.HostnameResolver()
    with mock.patch("socket.gethostbyaddr", side_effect=socket.gaierror("nope")):
        assert r.resolve("10.10.10.5") is None


def test_resolver_caches_results(nxa):
    r = nxa.HostnameResolver()
    call_count = {"n": 0}

    def fake_resolve(host):
        call_count["n"] += 1
        return ("dc01.corp.local", [], [host])

    with mock.patch("socket.gethostbyaddr", side_effect=fake_resolve):
        r.resolve("10.10.10.5")
        r.resolve("10.10.10.5")
        r.resolve("10.10.10.5")
    assert call_count["n"] == 1, "second lookup should be cached"


def test_resolver_caches_failures(nxa):
    """Cache negative results too — avoids re-querying broken DNS on every host."""
    import socket
    r = nxa.HostnameResolver()
    call_count = {"n": 0}

    def fake_resolve(host):
        call_count["n"] += 1
        raise socket.herror("nope")

    with mock.patch("socket.gethostbyaddr", side_effect=fake_resolve):
        r.resolve("10.10.10.5")
        r.resolve("10.10.10.5")
    assert call_count["n"] == 1


def test_looks_like_ip(nxa):
    assert nxa.HostnameResolver._looks_like_ip("10.0.0.1") is True
    assert nxa.HostnameResolver._looks_like_ip("192.168.1.255") is True
    assert nxa.HostnameResolver._looks_like_ip("dc01.corp.local") is False
    assert nxa.HostnameResolver._looks_like_ip("not.an.ip.really") is False
    assert nxa.HostnameResolver._looks_like_ip("256.1.1.1") is False  # out of range


def test_timeout_is_save_restored(nxa):
    """The default socket timeout must be restored after a lookup so other
    socket code in the process is unaffected."""
    import socket
    r = nxa.HostnameResolver(timeout=2.0)
    socket.setdefaulttimeout(7.0)
    try:
        with mock.patch("socket.gethostbyaddr", return_value=("h", [], ["x"])):
            r.resolve("10.0.0.1")
        assert socket.getdefaulttimeout() == 7.0
    finally:
        socket.setdefaulttimeout(None)


def test_automator_creates_resolver(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p")
    assert hasattr(a, "resolver")
    assert isinstance(a.resolver, nxa.HostnameResolver)


def test_automator_respects_no_resolve(nxa):
    a = nxa.NxcAutomator(target="x", user="u", password="p", resolve_enabled=False)
    assert a.resolver.enabled is False
