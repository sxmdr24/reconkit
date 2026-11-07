# ReconKit

[![tests](https://github.com/sxmdr24/reconkit/actions/workflows/tests.yml/badge.svg)](https://github.com/sxmdr24/reconkit/actions/workflows/tests.yml)

A small recon automation tool: runs nmap, parses the results, and writes a readable report.
Built as a learning project after a Junior Penetration Tester (CEH) course.

> [!WARNING]
> **Legal:** use ReconKit **only** on systems you own or have written permission to test. Scanning other systems may be illegal.
> Safe practice targets: your own lab VMs (Metasploitable, DVWA), `localhost`, or `scanme.nmap.org` (provided by Nmap for light testing).

## Why
Raw nmap output is noisy and hard to share. ReconKit turns it into a clean terminal table and a Markdown report you can drop into notes or a write-up, and optionally flags web services that are missing common HTTP security headers.

## Features
- Service/version scan of the top N ports (`nmap -sV`), saved as raw XML
- Open **and** filtered ports, with product, version and extra info
- Terminal table with columns sized to the data, plus a Markdown report
- `--check-headers` (opt-in): for each open web port, reports missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy`
- Python standard library only; tested with pytest on Python 3.10–3.12, with no scans or network access in tests

## Installation (Kali Linux)
Requires Python 3.10+ and nmap.
```bash
sudo apt install nmap
git clone https://github.com/sxmdr24/reconkit.git
cd reconkit
```

## Usage
```bash
python3 -m reconkit scanme.nmap.org
python3 -m reconkit 192.168.56.101 --top-ports 1000 --out lab_results
python3 -m reconkit scanme.nmap.org --check-headers
```
Output goes to `results/<target>.xml` (raw nmap) and `results/<target>.md` (report). `python3 recon.py <target>` also works.

About `--check-headers`: it sends one `HEAD /` request per open web port (falling back to `GET` if `HEAD` is rejected). Redirects are not followed, TLS certificates are not verified (lab targets are often self-signed), and HSTS is shown as n/a on plain HTTP, where browsers ignore it. Without the flag, ReconKit makes no HTTP requests.

## Example output
`python3 -m reconkit scanme.nmap.org --check-headers`:
```
[*] Running: nmap -sV --top-ports 100 -oX results/scanme.nmap.org.xml scanme.nmap.org
[+] XML output saved to results/scanme.nmap.org.xml
[*] Checking security headers on 1 web service(s)

HOST          PORT    STATE  SERVICE  VERSION                             EXTRA
----------------------------------------------------------------------------------------------------
45.33.32.156  22/tcp  open   ssh      OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13  Ubuntu Linux; protocol 2.0
45.33.32.156  80/tcp  open   http     Apache httpd 2.4.7                  (Ubuntu)

[+] Open: 2 | Filtered: 0

[*] Security headers (1 web service)
http://scanme.nmap.org:80/  200
  Missing:  Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
  N/A:      Strict-Transport-Security (plain HTTP)
[+] Report saved to results/scanme.nmap.org.md
```

Excerpt from `results/scanme.nmap.org.md`:
```markdown
| Host | Port | State | Service | Version | Extra |
|------|------|-------|---------|---------|-------|
| 45.33.32.156 | 22/tcp | open | ssh | OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 | Ubuntu Linux; protocol 2.0 |
| 45.33.32.156 | 80/tcp | open | http | Apache httpd 2.4.7 | (Ubuntu) |

## Security Headers

| URL | Status | Missing | Notes |
|-----|--------|---------|-------|
| http://scanme.nmap.org:80/ | 200 | Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | Strict-Transport-Security n/a over plain HTTP |
```

## Project structure
```
reconkit/
  scanner.py   — check for nmap and run it
  parser.py    — parse nmap XML into findings
  headers.py   — pick web ports + analyze security headers (no network code)
  fetcher.py   — fetch HTTP response headers (the only module that makes requests)
  report.py    — terminal table, header results + Markdown report
  cli.py       — command-line entry point
recon.py       — wrapper for backwards compatibility
tests/         — pytest tests + saved nmap XML fixtures
```

## Tests
```bash
pip install pytest
pytest
```
Tests use saved nmap XML and stubbed HTTP. A guard in `tests/conftest.py` blocks any real network access.

## Roadmap
- [x] v0.1 — nmap → XML parsing → table + Markdown report
- [x] v0.2 — Package structure + unit tests (pytest)
- [x] v0.3 — Security header check on open web ports (`--check-headers`)
- [ ] v0.4 — HTML report with templates (Jinja2)
- [ ] v0.5 — Check service versions against a CVE database
- [ ] v0.6 — Parallel scanning of multiple targets + config file
