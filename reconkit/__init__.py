"""
ReconKit - Simple recon automation (junior level)

Flow:
  1. Run nmap against the target (service/version detection)   -> scanner
  2. Save the XML output                                         -> scanner
  3. Parse the XML -> list of hosts, ports (open & filtered), services -> parser
  4. Print a table in the terminal + save a Markdown report      -> report

WARNING: Only scan targets you own or have permission to test
(lab VMs, Metasploitable, localhost, or scanme.nmap.org).
"""

__version__ = "0.3.0"
