"""Command-line interface: wires scanner -> parser -> (headers) -> report."""

import argparse
from pathlib import Path

from . import __version__
from .headers import check_findings, web_target
from .parser import parse_nmap_xml
from .report import print_header_results, print_table, write_report
from .scanner import check_nmap, run_nmap


def main(prog=None):
    """Run the CLI. `prog` sets the program name in usage/help; None lets argparse use sys.argv[0]."""
    parser = argparse.ArgumentParser(prog=prog, description=f"ReconKit v{__version__} - nmap to Markdown report")
    parser.add_argument("target", help="IP / hostname / range, e.g. 192.168.56.101")
    parser.add_argument("--top-ports", type=int, default=100, help="Number of top ports (default 100)")
    parser.add_argument("--out", default="results", help="Output folder (default: results)")
    parser.add_argument("--check-headers", action="store_true",
                        help="Fetch HTTP headers from open web ports and report missing security headers")
    args = parser.parse_args()

    check_nmap()
    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    name = args.target.replace("/", "_")
    xml_path = out_dir / f"{name}.xml"
    md_path = out_dir / f"{name}.md"

    run_nmap(args.target, xml_path, args.top_ports)
    findings = parse_nmap_xml(xml_path)
    if args.check_headers:
        web_count = sum(1 for f in findings if web_target(f) is not None)
        print(f"[*] Checking security headers on {web_count} web service(s)")
        check_findings(findings)
    print_table(findings)
    if args.check_headers:
        print_header_results(findings)
    write_report(args.target, findings, md_path)
