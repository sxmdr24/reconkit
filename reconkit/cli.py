"""Command-line interface: wires scanner -> parser -> report."""

import argparse
from pathlib import Path

from . import __version__
from .parser import parse_nmap_xml
from .report import print_table, write_report
from .scanner import check_nmap, run_nmap


def main(prog=None):
    """Run the CLI. `prog` sets the program name in usage/help; None lets argparse use sys.argv[0]."""
    parser = argparse.ArgumentParser(prog=prog, description=f"ReconKit v{__version__} - nmap to Markdown report")
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
