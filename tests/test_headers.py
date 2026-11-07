"""Tests for reconkit.headers. No network: analysis gets plain dicts, fetching is stubbed."""

import http.client
import socket
from pathlib import Path

import pytest

from conftest import NetworkAccessBlocked
from reconkit.headers import SECURITY_HEADERS, analyze_headers, check_findings, web_target
from reconkit.parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"

ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def finding(service="http", state="open", port=80, tunnel="", host="10.0.0.5", hostname="-"):
    return {"host": host, "hostname": hostname, "port": port, "proto": "tcp", "state": state,
            "service": service, "version": "-", "extra": "-", "tunnel": tunnel}


# --- parser: tunnel key ---------------------------------------------------------

@pytest.mark.parametrize("name", ["scanme.xml", "scanme_filtered.xml"])
def test_parser_adds_empty_tunnel_when_absent(name):
    findings = parse_nmap_xml(FIXTURES / name)
    assert findings and all(f["tunnel"] == "" for f in findings)


# --- analyze_headers ---------------------------------------------------------------

def test_all_headers_present_over_https():
    result = analyze_headers(ALL_HEADERS, "https")
    assert result == {"missing": [], "present": list(SECURITY_HEADERS), "not_applicable": []}


def test_no_headers_over_https():
    result = analyze_headers({}, "https")
    assert result == {"missing": list(SECURITY_HEADERS), "present": [], "not_applicable": []}


def test_hsts_not_applicable_over_http():
    result = analyze_headers({}, "http")
    assert result["not_applicable"] == ["Strict-Transport-Security"]
    assert result["missing"] == [h for h in SECURITY_HEADERS if h != "Strict-Transport-Security"]
    # Even when sent over HTTP, HSTS is N/A rather than "present".
    assert analyze_headers(ALL_HEADERS, "http")["not_applicable"] == ["Strict-Transport-Security"]


def test_header_names_match_case_insensitively():
    mixed = {"content-security-policy": "default-src 'self'", "X-FRAME-OPTIONS": "DENY",
             "x-Content-Type-OPTIONS": "nosniff"}
    result = analyze_headers(mixed, "https")
    assert result["present"] == ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
    assert result["missing"] == ["Strict-Transport-Security", "Referrer-Policy"]


@pytest.mark.parametrize("empty", ["", "   "])
def test_empty_value_counts_as_missing(empty):
    result = analyze_headers({**ALL_HEADERS, "X-Frame-Options": empty}, "https")
    assert result["missing"] == ["X-Frame-Options"]


def test_unrelated_headers_are_ignored():
    result = analyze_headers({"Server": "Apache", "Content-Type": "text/html"}, "https")
    assert result["missing"] == list(SECURITY_HEADERS)


def test_analyze_headers_does_not_modify_input():
    headers = dict(ALL_HEADERS)
    analyze_headers(headers, "http")
    assert headers == ALL_HEADERS


# --- web_target ----------------------------------------------------------------------

@pytest.mark.parametrize("f, expected", [
    (finding("http", port=80), ("http", 80)),
    (finding("http-alt", port=8080), ("http", 8080)),
    (finding("http-proxy", port=3128), ("http", 3128)),
    (finding("https", port=443), ("https", 443)),
    (finding("http", port=8443, tunnel="ssl"), ("https", 8443)),
    (finding("http", state="filtered", port=8008), None),
    (finding("ssh", port=22), None),
    (finding("?", port=1028), None),
])
def test_web_target(f, expected):
    assert web_target(f) == expected


def test_web_target_on_fixture_selects_only_open_port_80():
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    targets = [(f["port"], web_target(f)) for f in findings if web_target(f)]
    assert targets == [(80, ("http", 80))]  # 8008/http is filtered, so skipped


# --- check_findings (stubbed fetch) ------------------------------------------------------

class StubFetch:
    """Records calls and returns canned responses keyed by port."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, host, port, scheme, hostname):
        self.calls.append((host, port, scheme, hostname))
        return self.responses[port]


def test_check_findings_adds_results_to_web_findings_only():
    findings = [finding("ssh", port=22), finding("http", port=80),
                finding("http", port=443, tunnel="ssl", hostname="lab.local")]
    fetch = StubFetch({
        80: {"status": 200, "headers": {"X-Frame-Options": "DENY"}},
        443: {"status": 200, "headers": dict(ALL_HEADERS)},
    })

    returned = check_findings(findings, fetch)

    assert returned is findings
    assert fetch.calls == [("10.0.0.5", 80, "http", None), ("10.0.0.5", 443, "https", "lab.local")]
    assert "headers_check" not in findings[0]

    http_check = findings[1]["headers_check"]
    assert http_check["url"] == "http://10.0.0.5:80/"
    assert http_check["status"] == 200
    assert http_check["error"] is None
    assert http_check["present"] == ["X-Frame-Options"]
    assert http_check["not_applicable"] == ["Strict-Transport-Security"]
    assert http_check["missing"] == ["Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"]

    https_check = findings[2]["headers_check"]
    assert https_check["url"] == "https://lab.local:443/"
    assert https_check["missing"] == []


def test_check_findings_records_redirect_without_following():
    fetch = StubFetch({80: {"status": 301, "headers": {"location": "https://example.test/"}}})
    findings = check_findings([finding("http", port=80)], fetch)

    check = findings[0]["headers_check"]
    assert check["status"] == 301
    assert check["location"] == "https://example.test/"
    assert len(fetch.calls) == 1


def test_check_findings_records_fetch_error():
    fetch = StubFetch({80: {"error": "timed out"}})
    check = check_findings([finding("http", port=80)], fetch)[0]["headers_check"]

    assert check["error"] == "timed out"
    assert check["status"] is None
    assert check["missing"] == check["present"] == check["not_applicable"] == []


def test_check_findings_on_fixture_with_stub():
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    fetch = StubFetch({80: {"status": 200, "headers": {"Server": "Apache/2.4.7 (Ubuntu)"}}})
    check_findings(findings, fetch)

    checked = [f for f in findings if "headers_check" in f]
    assert [f["port"] for f in checked] == [80]
    assert checked[0]["headers_check"]["url"] == "http://scanme.org:80/"
    assert fetch.calls == [("45.33.32.156", 80, "http", "scanme.org")]


# --- network guard (tests/conftest.py) ---------------------------------------------------

def test_network_guard_blocks_connections_and_dns():
    with pytest.raises(NetworkAccessBlocked):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    with pytest.raises(NetworkAccessBlocked):
        socket.getaddrinfo("example.com", 80)
    with socket.socket() as s, pytest.raises(NetworkAccessBlocked):
        s.connect(("192.0.2.1", 80))


def test_network_guard_blocks_http_client():
    conn = http.client.HTTPConnection("192.0.2.1", 80, timeout=1)
    with pytest.raises(NetworkAccessBlocked):
        conn.request("HEAD", "/")
