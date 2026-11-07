"""Unit tests for parse_nmap_xml and count_states, using saved nmap XML fixtures."""

from pathlib import Path

import pytest

from reconkit.parser import count_states, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def scanme():
    return parse_nmap_xml(FIXTURES / "scanme.xml")


@pytest.fixture
def scanme_filtered():
    return parse_nmap_xml(FIXTURES / "scanme_filtered.xml")


def by_port(findings, port):
    matches = [f for f in findings if f["port"] == port]
    assert len(matches) == 1, f"expected exactly one finding for port {port}"
    return matches[0]


@pytest.mark.parametrize(
    "fixture_name, expected_open, expected_filtered",
    [
        ("scanme", 2, 0),
        ("scanme_filtered", 2, 16),
    ],
)
def test_open_and_filtered_counts(request, fixture_name, expected_open, expected_filtered):
    findings = request.getfixturevalue(fixture_name)

    assert count_states(findings) == (expected_open, expected_filtered)
    assert len(findings) == expected_open + expected_filtered
    assert sorted(f["port"] for f in findings if f["state"] == "open") == [22, 80]


def test_count_states_empty():
    assert count_states([]) == (0, 0)


@pytest.mark.parametrize("fixture_name", ["scanme", "scanme_filtered"])
def test_ssh_finding_fields(request, fixture_name):
    ssh = by_port(request.getfixturevalue(fixture_name), 22)

    assert ssh["host"] == "45.33.32.156"
    assert ssh["proto"] == "tcp"
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert ssh["version"] == "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13"
    assert ssh["extra"] == "Ubuntu Linux; protocol 2.0"


def test_hostname_uses_first_hostname_entry(scanme, scanme_filtered):
    assert by_port(scanme, 22)["hostname"] == "scanme.nmap.org"
    assert by_port(scanme_filtered, 22)["hostname"] == "scanme.org"


@pytest.mark.parametrize("port", [1028, 49152, 49156])
def test_port_without_service_element(scanme_filtered, port):
    finding = by_port(scanme_filtered, port)

    assert finding["state"] == "filtered"
    assert finding["service"] == "?"
    assert finding["version"] == "-"
    assert finding["extra"] == "-"


def test_table_guessed_service_has_no_version(scanme_filtered):
    # Filtered ports with a table-guessed <service> keep the name but have no product/version.
    smtp = by_port(scanme_filtered, 25)

    assert smtp["service"] == "smtp"
    assert smtp["version"] == "-"
    assert smtp["extra"] == "-"
