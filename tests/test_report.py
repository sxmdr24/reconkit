"""Tests for the terminal table, header results and Markdown report."""

from datetime import datetime
from pathlib import Path

import pytest

from reconkit import report
from reconkit.headers import check_findings
from reconkit.parser import parse_nmap_xml
from reconkit.report import TABLE_HEADERS, print_header_results, print_table, write_report

FIXTURES = Path(__file__).parent / "fixtures"


def printed_table(capsys, findings):
    """Run print_table and return (header_line, data_lines)."""
    print_table(findings)
    lines = capsys.readouterr().out.splitlines()
    # Output: blank line, header, separator, one line per finding, blank line, summary.
    header, separator = lines[1], lines[2]
    assert set(separator) == {"-"}
    return header, lines[3:3 + len(findings)]


def test_columns_align_with_long_values(capsys):
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    header, rows = printed_table(capsys, findings)

    # Same columns, same order.
    assert header.split() == list(TABLE_HEADERS)
    starts = [header.index(name) for name in TABLE_HEADERS]

    expected_cells = [
        (f["host"], f"{f['port']}/{f['proto']}", f["state"], f["service"], f["version"], f["extra"])
        for f in findings
    ]
    assert len(rows) == len(expected_cells)

    for row, cells in zip(rows, expected_cells):
        for i, (start, cell) in enumerate(zip(starts, cells)):
            # Every value starts exactly under its header...
            assert row[start:start + len(cell)] == cell, f"{cell!r} misaligned in {row!r}"
            # ...and ends with at least two spaces before the next column.
            if i + 1 < len(starts):
                assert row[start + len(cell):starts[i + 1]].strip() == ""
                assert starts[i + 1] - (start + len(cell)) >= 2, f"{cell!r} too close to next column"


def test_long_values_are_separated(capsys):
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    _, rows = printed_table(capsys, findings)

    row = next(r for r in rows if "snet-sensor-mgmt" in r)
    assert "10000/tcp  " in row
    assert "snet-sensor-mgmt  " in row
    assert "snet-sensor-mgmt-" not in row


# --- security header results (--check-headers) ----------------------------------------

def web_finding(port, service="http", tunnel="", hostname="lab.local"):
    return {"host": "10.0.0.5", "hostname": hostname, "port": port, "proto": "tcp", "state": "open",
            "service": service, "version": "-", "extra": "-", "tunnel": tunnel}


def stub_fetch(responses):
    return lambda host, port, scheme, hostname: responses[port]


@pytest.fixture
def fixed_time(monkeypatch):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 7, 12, 34)

    monkeypatch.setattr(report, "datetime", FixedDatetime)


@pytest.fixture
def checked_findings():
    """http on 80 (missing headers, redirect), https on 443 (all set), http-alt on 8080 (error)."""
    findings = [web_finding(22, service="ssh"), web_finding(80),
                web_finding(443, tunnel="ssl"), web_finding(8080, service="http-alt")]
    return check_findings(findings, stub_fetch({
        80: {"status": 301, "headers": {"Location": "https://lab.local/", "X-Frame-Options": "DENY"}},
        443: {"status": 200, "headers": {
            "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}},
        8080: {"error": "TimeoutError: timed out"},
    }))


def test_print_header_results(capsys, checked_findings):
    print_header_results(checked_findings)
    assert capsys.readouterr().out.splitlines() == [
        "",
        "[*] Security headers (3 web services)",
        "http://lab.local:80/  301",
        "  Missing:  Content-Security-Policy, X-Content-Type-Options, Referrer-Policy",
        "  Redirect: https://lab.local/ (not followed)",
        "  N/A:      Strict-Transport-Security (plain HTTP)",
        "https://lab.local:443/  200",
        "  Missing:  none",
        "  Note:     TLS certificate not verified",
        "http://lab.local:8080/  error: TimeoutError: timed out",
    ]


def test_print_header_results_singular_and_fixture(capsys):
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    check_findings(findings, stub_fetch({80: {"status": 200, "headers": {"Server": "Apache"}}}))
    print_header_results(findings)
    out = capsys.readouterr().out
    assert "[*] Security headers (1 web service)\n" in out
    assert "http://scanme.org:80/  200\n" in out


def test_print_header_results_without_web_services(capsys):
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    findings = [f for f in findings if f["port"] != 80]
    check_findings(findings, stub_fetch({}))
    print_header_results(findings)
    assert capsys.readouterr().out == "\n[-] No open web services to check security headers on.\n"


def test_report_has_security_headers_section(tmp_path, fixed_time, checked_findings):
    md_path = tmp_path / "report.md"
    write_report("lab.local", checked_findings, md_path)
    text = md_path.read_text(encoding="utf-8")

    main_table, section = text.split("\n\n## Security Headers\n\n")
    assert main_table.count("\n| 10.0.0.5 |") == 4  # the port table is unchanged
    assert section.splitlines() == [
        "| URL | Status | Missing | Notes |",
        "|-----|--------|---------|-------|",
        "| http://lab.local:80/ | 301 | Content-Security-Policy, X-Content-Type-Options, Referrer-Policy"
        " | redirects to https://lab.local/ (not followed); Strict-Transport-Security n/a over plain HTTP |",
        "| https://lab.local:443/ | 200 | none | TLS certificate not verified |",
        "| http://lab.local:8080/ | - | - | error: TimeoutError: timed out |",
    ]
    assert text.endswith("|\n")


def test_report_escapes_pipes_in_notes(tmp_path, fixed_time):
    findings = check_findings([web_finding(80)], stub_fetch({80: {"error": "OSError: a|b"}}))
    md_path = tmp_path / "report.md"
    write_report("lab.local", findings, md_path)
    assert "| error: OSError: a\\|b |" in md_path.read_text(encoding="utf-8")


def test_report_without_header_checks_is_unchanged(tmp_path, fixed_time):
    findings = parse_nmap_xml(FIXTURES / "scanme.xml")
    md_path = tmp_path / "report.md"
    write_report("scanme.nmap.org", findings, md_path)
    assert md_path.read_text(encoding="utf-8") == (
        "# Recon Report: scanme.nmap.org\n"
        "Scan time: 2026-11-07 12:34  \n"
        "Total open ports: 2  \n"
        "Total filtered ports: 0\n"
        "\n"
        "| Host | Port | State | Service | Version | Extra |\n"
        "|------|------|-------|---------|---------|-------|\n"
        "| 45.33.32.156 | 22/tcp | open | ssh | OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 | Ubuntu Linux; protocol 2.0 |\n"
        "| 45.33.32.156 | 80/tcp | open | http | Apache httpd 2.4.7 | (Ubuntu) |\n"
    )


def test_port_table_ignores_header_checks(capsys):
    findings = parse_nmap_xml(FIXTURES / "scanme_filtered.xml")
    print_table(findings)
    before = capsys.readouterr().out
    checked =check_findings(findings, stub_fetch({80: {"status": 200, "headers": {}}}))
    print_table(checked)
    assert capsys.readouterr().out == before
