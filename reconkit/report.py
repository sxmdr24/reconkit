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


def _header_checks(findings):
    """The headers_check results attached by headers.check_findings, in finding order."""
    return [f["headers_check"] for f in findings if "headers_check" in f]


def _header_notes(check):
    """Short notes about one header check (errors, redirects, N/A headers, TLS)."""
    notes = []
    if check["error"] is not None:
        notes.append(f"error: {check['error']}")
    if check["location"]:
        notes.append(f"redirects to {check['location']} (not followed)")
    if check["not_applicable"]:
        notes.append(f"{', '.join(check['not_applicable'])} n/a over plain HTTP")
    if check["url"].startswith("https://"):
        notes.append("TLS certificate not verified")
    return notes


def print_header_results(findings):
    """Print the security header results added by headers.check_findings."""
    checks = _header_checks(findings)
    if not checks:
        print("\n[-] No open web services to check security headers on.")
        return
    plural = "" if len(checks) == 1 else "s"
    print(f"\n[*] Security headers ({len(checks)} web service{plural})")
    for check in checks:
        if check["error"] is not None:
            print(f"{check['url']}  error: {check['error']}")
            continue
        print(f"{check['url']}  {check['status']}")
        print(f"  Missing:  {', '.join(check['missing']) or 'none'}")
        if check["location"]:
            print(f"  Redirect: {check['location']} (not followed)")
        if check["not_applicable"]:
            print(f"  N/A:      {', '.join(check['not_applicable'])} (plain HTTP)")
        if check["url"].startswith("https://"):
            print("  Note:     TLS certificate not verified")


def _md_cell(text):
    """Escape characters that would break a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _header_report_lines(findings):
    """Markdown lines for the Security Headers section; [] if no checks were run."""
    checks = _header_checks(findings)
    if not checks:
        return []
    lines = [
        "",
        "## Security Headers",
        "",
        "| URL | Status | Missing | Notes |",
        "|-----|--------|---------|-------|",
    ]
    for check in checks:
        if check["error"] is not None:
            status, missing = "-", "-"
        else:
            status, missing = check["status"], ", ".join(check["missing"]) or "none"
        notes = "; ".join(_header_notes(check)) or "-"
        lines.append(f"| {_md_cell(check['url'])} | {status} | {missing} | {_md_cell(notes)} |")
    return lines


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
    lines += _header_report_lines(findings)  # only present when --check-headers ran
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Report saved to {md_path}")
