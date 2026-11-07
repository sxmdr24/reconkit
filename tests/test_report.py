"""Tests for the terminal table printed by print_table."""

from pathlib import Path

from reconkit.parser import parse_nmap_xml
from reconkit.report import TABLE_HEADERS, print_table

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
