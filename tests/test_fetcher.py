"""Tests for reconkit.fetcher. Connections are faked; the conftest guard blocks real ones."""

import http.client
import ssl

import pytest

from conftest import NetworkAccessBlocked
from reconkit import __version__, fetcher
from reconkit.headers import check_findings


class FakeResponse:
    def __init__(self, status, headers):
        self.status = status
        self._headers = headers

    def getheaders(self):
        return list(self._headers.items())

    def read(self):  # pragma: no cover - fetcher must never read the body
        raise AssertionError("fetcher read the response body")


class FakeConnection:
    """Stands in for an http.client connection. `script` gives one outcome per request:
    a (status, headers) tuple, or an exception to raise from getresponse()."""

    def __init__(self, log, outcome, raise_on_request=None):
        self.log = log
        self.outcome = outcome
        self.raise_on_request = raise_on_request
        self.closed = False

    def request(self, method, path, headers=None):
        self.log["requests"].append((method, path, headers))
        if self.raise_on_request:
            raise self.raise_on_request

    def getresponse(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return FakeResponse(*self.outcome)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_net(monkeypatch):
    """Replace fetcher.make_connection. Set log["script"] to the per-request outcomes."""
    log = {"script": [], "requests": [], "connections": [], "factory_calls": [],
           "raise_on_request": None}

    def factory(host, port, scheme, hostname=None, timeout=fetcher.DEFAULT_TIMEOUT):
        log["factory_calls"].append((host, port, scheme, hostname, timeout))
        conn = FakeConnection(log, log["script"].pop(0), log["raise_on_request"])
        log["connections"].append(conn)
        return conn

    monkeypatch.setattr(fetcher, "make_connection", factory)
    return log


# --- request behaviour ---------------------------------------------------------------

def test_sends_one_head_request_and_returns_headers(fake_net):
    fake_net["script"] = [(200, {"Server": "Apache", "X-Frame-Options": "DENY"})]

    result = fetcher.fetch_headers("10.0.0.5", 80, "http")

    assert result == {"status": 200, "headers": {"Server": "Apache", "X-Frame-Options": "DENY"}}
    assert fake_net["factory_calls"] == [("10.0.0.5", 80, "http", None, fetcher.DEFAULT_TIMEOUT)]
    [(method, path, headers)] = fake_net["requests"]
    assert (method, path) == ("HEAD", "/")
    assert headers["Host"] == "10.0.0.5"
    assert headers["User-Agent"] == f"ReconKit/{__version__}"
    assert all(conn.closed for conn in fake_net["connections"])


@pytest.mark.parametrize("host, port, scheme, hostname, expected", [
    ("10.0.0.5", 80, "http", None, "10.0.0.5"),
    ("10.0.0.5", 80, "http", "lab.local", "lab.local"),
    ("10.0.0.5", 8080, "http", "lab.local", "lab.local:8080"),
    ("10.0.0.5", 443, "https", "lab.local", "lab.local"),
    ("10.0.0.5", 8443, "https", None, "10.0.0.5:8443"),
    ("10.0.0.5", 443, "http", None, "10.0.0.5:443"),
])
def test_host_header(fake_net, host, port, scheme, hostname, expected):
    fake_net["script"] = [(200, {})]
    fetcher.fetch_headers(host, port, scheme, hostname)
    assert fake_net["requests"][0][2]["Host"] == expected


@pytest.mark.parametrize("status", [405, 501])
def test_retries_with_get_when_head_not_supported(fake_net, status):
    fake_net["script"] = [(status, {"Allow": "GET"}), (200, {"X-Frame-Options": "DENY"})]

    result = fetcher.fetch_headers("10.0.0.5", 80, "http")

    assert [r[0] for r in fake_net["requests"]] == ["HEAD", "GET"]
    assert result == {"status": 200, "headers": {"X-Frame-Options": "DENY"}}
    assert all(conn.closed for conn in fake_net["connections"])


@pytest.mark.parametrize("status", [200, 301, 403, 404, 500])
def test_no_retry_for_other_statuses(fake_net, status):
    fake_net["script"] = [(status, {"Location": "https://lab.local/"})]
    result = fetcher.fetch_headers("10.0.0.5", 80, "http")
    assert [r[0] for r in fake_net["requests"]] == ["HEAD"]  # redirects are not followed either
    assert result["status"] == status


# --- error handling ---------------------------------------------------------------------

@pytest.mark.parametrize("exc, expected", [
    (TimeoutError("timed out"), "TimeoutError: timed out"),
    (ConnectionRefusedError(111, "Connection refused"),
     "ConnectionRefusedError: [Errno 111] Connection refused"),
    (ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number"),
     "SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number"),
    (http.client.RemoteDisconnected("Remote end closed connection without response"),
     "RemoteDisconnected: Remote end closed connection without response"),
    (http.client.BadStatusLine("HTTP/9.9 ???"), "BadStatusLine: HTTP/9.9 ???"),
    (OSError(), "OSError"),  # empty message falls back to the type name
])
def test_network_and_http_errors_become_error_dicts(fake_net, exc, expected):
    fake_net["script"] = [exc]
    assert fetcher.fetch_headers("10.0.0.5", 80, "http") == {"error": expected}
    assert fake_net["connections"][0].closed


def test_error_during_request_is_handled_and_connection_closed(fake_net):
    fake_net["script"] = [(200, {})]
    fake_net["raise_on_request"] = ConnectionResetError("reset")
    assert fetcher.fetch_headers("10.0.0.5", 80, "http") == {"error": "ConnectionResetError: reset"}
    assert fake_net["connections"][0].closed


def test_error_on_get_retry_is_handled(fake_net):
    fake_net["script"] = [(405, {}), TimeoutError("timed out")]
    assert fetcher.fetch_headers("10.0.0.5", 80, "http") == {"error": "TimeoutError: timed out"}


@pytest.mark.parametrize("exc", [ValueError("bug"), KeyError("bug"), NetworkAccessBlocked("guard")])
def test_other_exceptions_propagate(fake_net, exc):
    fake_net["script"] = [exc]
    with pytest.raises(type(exc)):
        fetcher.fetch_headers("10.0.0.5", 80, "http")


@pytest.mark.parametrize("scheme, port", [("http", 80), ("https", 443)])
def test_real_connection_path_hits_network_guard(scheme, port):
    # No fake: the real make_connection is used, and the conftest guard must surface,
    # not be swallowed into {"error": ...}. 192.0.2.1 is a reserved documentation address.
    with pytest.raises(NetworkAccessBlocked):
        fetcher.fetch_headers("192.0.2.1", port, scheme, "lab.local", timeout=1)


# --- connection setup (constructed, never opened) ---------------------------------------

def test_make_connection_http():
    conn = fetcher.make_connection("10.0.0.5", 8080, "http", "lab.local", timeout=3)
    assert type(conn) is http.client.HTTPConnection
    assert (conn.host, conn.port, conn.timeout) == ("10.0.0.5", 8080, 3)


def test_make_connection_https_skips_cert_verification_and_sets_sni():
    conn = fetcher.make_connection("10.0.0.5", 443, "https", "lab.local", timeout=3)
    assert isinstance(conn, http.client.HTTPSConnection)
    assert (conn.host, conn.port, conn.timeout) == ("10.0.0.5", 443, 3)  # connects to the IP
    assert conn.server_hostname == "lab.local"
    assert conn._context.verify_mode == ssl.CERT_NONE
    assert conn._context.check_hostname is False


def test_make_connection_https_without_hostname_uses_ip_for_sni():
    conn = fetcher.make_connection("10.0.0.5", 443, "https", None)
    assert conn.server_hostname == "10.0.0.5"


def test_https_connect_wraps_socket_with_hostname_for_sni(monkeypatch):
    raw_sock = object()
    monkeypatch.setattr(http.client.HTTPConnection, "connect",
                        lambda self: setattr(self, "sock", raw_sock))
    wrapped = []

    class FakeContext:
        def wrap_socket(self, sock, server_hostname):
            wrapped.append((sock, server_hostname))
            return "tls-socket"

    conn = fetcher.make_connection("10.0.0.5", 443, "https", "lab.local")
    conn._context = FakeContext()
    conn.connect()

    assert wrapped == [(raw_sock, "lab.local")]
    assert conn.sock == "tls-socket"


# --- default fetch in check_findings -------------------------------------------------------

def test_check_findings_uses_fetch_headers_by_default(monkeypatch):
    calls = []

    def stub(host, port, scheme, hostname):
        calls.append((host, port, scheme, hostname))
        return {"status": 200, "headers": {}}

    monkeypatch.setattr(fetcher, "fetch_headers", stub)
    findings = [{"host": "10.0.0.5", "hostname": "-", "port": 80, "proto": "tcp", "state": "open",
                 "service": "http", "version": "-", "extra": "-", "tunnel": ""}]

    check_findings(findings)

    assert calls == [("10.0.0.5", 80, "http", None)]
    assert findings[0]["headers_check"]["status"] == 200
