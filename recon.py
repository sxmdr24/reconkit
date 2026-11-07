#!/usr/bin/env python3
"""
ReconKit v0.1.1 - Simple recon automation (junior level)

Flow:
  1. Run nmap against the target (service/version detection)
  2. Save the XML output
  3. Parse the XML -> list of hosts, ports (open & filtered), services
  4. Print a table in the terminal + save a Markdown report

WARNING: Only scan targets you own or have permission to test
(lab VMs, Metasploitable, localhost, or scanme.nmap.org).
"""

import argparse
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def check_nmap():
    """Make sure nmap is installed."""
    if shutil.which("nmap") is None:
        sys.exit("[!] nmap not found. Install it first: sudo apt install nmap")


def run_nmap(target, xml_path, top_ports):
    """Run nmap and save the results in XML format."""
    cmd = ["nmap", "-sV", "--top-ports", str(top_ports), "-oX", str(xml_path), target]
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"[!] nmap failed:\n{result.stderr}")
    print(f"[+] XML output saved to {xml_path}")


def parse_nmap_xml(xml_path):
    """Turn nmap XML into a list of dicts that is easy to work with."""
    root = ET.parse(xml_path).getroot()
    findings = []

    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status != "up":
            continue

        address = host.find("address").get("addr")
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else "-"

        for port in host.findall("ports/port"):
            state = port.find("state").get("state")
            if state not in ("open", "filtered"):
                continue
            svc = port.find("service")
            findings.append({
                "host": address,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "proto": port.get("protocol"),
                "state": state,
                "service": svc.get("name", "?") if svc is not None else "?",
                "version": " ".join(filter(None, [
                    svc.get("product") if svc is not None else None,
                    svc.get("version") if svc is not None else None,
                ])) or "-",
                "extra": (svc.get("extrainfo") if svc is not None else None) or "-",
            })
    return findings


def count_states(findings):
    """Count the number of open and filtered ports."""
    open_count = sum(1 for f in findings if f["state"] == "open")
    filtered_count = sum(1 for f in findings if f["state"] == "filtered")
    return open_count, filtered_count


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


def main():
    parser = argparse.ArgumentParser(description="ReconKit v0.1.1 - nmap to Markdown report")
    parser.add_argument("target", help="IP / hostname / range, e.g. 192.168.56.101")
    parser.add_argument("--top-ports", type=int, default=100, help="Number of top ports (default 100)")
    parser.add_argument("--out", default="results", help="Output folder (default: results)")
    args = parser.parse_args()

    check_nmap()
    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    name = args.target.replace("/", "_")
    xml_path = out_dir / f"{name}.xml"
    md_path = out_dir / f"{name}.md"

    run_nmap(args.target, xml_path, args.top_ports)
    findings = parse_nmap_xml(xml_path)
    print_table(findings)
    write_report(args.target, findings, md_path)


if __name__ == "__main__":
    main()
