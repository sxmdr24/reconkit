"""End-to-end CLI tests with nmap and HTTP fetching stubbed out (no scans, no network)."""

import shutil
import sys
from pathlib import Path

import pytest

from reconkit import cli, fetcher

FIXTURE = Path(__file__).parent / "fixtures" / "scanme_filtered.xml"


@pytest.fixture
def run_cli(monkeypatch, tmp_path):
    """Run cli.main with the given args; nmap is replaced by copying the fixture."""
    fetch_calls = []

    def fake_run_nmap(target, xml_path, top_ports):
        shutil.copy(FIXTURE, xml_path)

    def fake_fetch(host, port, scheme, hostname):
        fetch_calls.append((host, port, scheme, hostname))
        return {"status": 200, "headers": {"X-Frame-Options": "DENY"}}

    monkeypatch.setattr(cli, "check_nmap", lambda: None)
    monkeypatch.setattr(cli, "run_nmap", fake_run_nmap)
    monkeypatch.setattr(fetcher, "fetch_headers", fake_fetch)

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["reconkit", "scanme.org", "--out", str(tmp_path), *args])
        cli.main()
        return (tmp_path / "scanme.org.md").read_text(encoding="utf-8")

    run.fetch_calls = fetch_calls
    return run


def test_without_flag_no_headers_are_fetched(run_cli, capsys):
    report_text = run_cli()
    out = capsys.readouterr().out
    assert run_cli.fetch_calls == []
    assert "Security headers" not in out
    assert "## Security Headers" not in report_text


def test_check_headers_flag(run_cli, capsys):
    report_text = run_cli("--check-headers")
    out = capsys.readouterr().out
    assert run_cli.fetch_calls == [("45.33.32.156", 80, "http", "scanme.org")]
    assert "[*] Checking security headers on 1 web service(s)\n" in out
    assert "[*] Security headers (1 web service)\n" in out
    # Order: port table summary, then header results, then the report path.
    assert out.index("[+] Open: 2 | Filtered: 16") < out.index("[*] Security headers") < out.index("[+] Report saved")
    assert "## Security Headers" in report_text
    assert "| http://scanme.org:80/ | 200 | Content-Security-Policy, X-Content-Type-Options, Referrer-Policy |" in report_text


def test_help_mentions_flag(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["reconkit", "--help"])
    with pytest.raises(SystemExit):
        cli.main()
    out = capsys.readouterr().out
    assert "--check-headers" in out
    assert "ReconKit v0.3.0" in out
