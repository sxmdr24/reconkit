"""Running nmap."""

import shutil
import subprocess
import sys


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
