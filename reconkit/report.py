"""Terminal table and Markdown report output."""

from datetime import datetime

from .parser import count_states


def print_table(findings):
    """Print the results in the terminal."""
    if not findings:
        print("[-] No open/filtered ports found.")
        return
    print(f"\n{'HOST':<16}{'PORT':<10}{'STATE':<10}{'SERVICE':<12}{'VERSION':<36}EXTRA")
    print("-" * 100)
    for f in findings:
        print(f"{f['host']:<16}{str(f['port']) + '/' + f['proto']:<10}"
              f"{f['state']:<10}{f['service']:<12}{f['version']:<36}{f['extra']}")

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
