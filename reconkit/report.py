"""Terminal table and Markdown report output."""

from datetime import datetime

from .parser import count_states

TABLE_HEADERS = ("HOST", "PORT", "STATE", "SERVICE", "VERSION", "EXTRA")
COLUMN_GAP = 2  # minimum spaces between columns


def _table_row(f):
    """The cell values of one finding, in TABLE_HEADERS order."""
    return (f["host"], f"{f['port']}/{f['proto']}", f["state"],
            f["service"], f["version"], f["extra"])


def print_table(findings):
    """Print the results in the terminal, sizing each column to its widest value."""
    if not findings:
        print("[-] No open/filtered ports found.")
        return
    rows = [_table_row(f) for f in findings]
    widths = [max(len(cell) for cell in column) for column in zip(TABLE_HEADERS, *rows)]

    def format_row(cells):
        # Pad every column except the last, so lines have no trailing spaces.
        padded = [cell.ljust(width + COLUMN_GAP) for cell, width in zip(cells[:-1], widths)]
        return "".join(padded) + cells[-1]

    print("\n" + format_row(TABLE_HEADERS))
    print("-" * (sum(widths) + COLUMN_GAP * (len(widths) - 1)))
    for row in rows:
        print(format_row(row))

    open_count, filtered_count = count_states(findings)
    print(f"\n[+] Open: {open_count} | Filtered: {filtered_count}")


def write_report(target, findings, md_path):
    """Save the report in Markdown format."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    open_count, filtered_count = count_states(findings)
    lines = [
        f"# Recon Report: {target}",
        f"Scan time: {timestamp}  ",
        f"Total open ports: {open_count}  ",
        f"Total filtered ports: {filtered_count}",
        "",
        "| Host | Port | State | Service | Version | Extra |",
        "|------|------|-------|---------|---------|-------|",
    ]
    for f in findings:
        lines.append(f"| {f['host']} | {f['port']}/{f['proto']} | {f['state']} | "
                     f"{f['service']} | {f['version']} | {f['extra']} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Report saved to {md_path}")
