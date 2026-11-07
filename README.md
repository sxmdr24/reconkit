# ReconKit

A simple recon automation tool: runs nmap, parses the results, and generates a report automatically.
Built as a learning project after a Junior Penetration Tester (CEH) course.

## ⚠️ Legal
Use **only** on systems you own or have written permission to test.
Safe practice targets: your own lab VMs (Metasploitable, DVWA), `localhost`, or `scanme.nmap.org` (officially provided by Nmap for light testing).

## Installation (Kali Linux)
```bash
sudo apt install nmap
git clone <your-repo>
cd reconkit
```

## Usage
```bash
python3 -m reconkit scanme.nmap.org
python3 -m reconkit 192.168.56.101 --top-ports 1000 --out lab_results
```

`python3 recon.py <target>` still works too (it's a thin wrapper around the same CLI).

Output:
- `results/<target>.xml` — raw nmap output
- `results/<target>.md`  — Markdown report

### Security header check (`--check-headers`)
```bash
python3 -m reconkit 192.168.56.101 --check-headers
```
For every **open** `http`/`https`/`http-alt`/`http-proxy` port, ReconKit sends one `HEAD /` request (falling back to `GET` if the server rejects `HEAD`) and reports which of these headers are missing:
`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
Results are printed after the port table and added as a **Security Headers** section in the Markdown report.

- HSTS is shown as *n/a* on plain HTTP (browsers ignore it there).
- Redirects are not followed; the `Location` is shown instead.
- TLS certificates are not verified (lab targets are often self-signed).
- The check is opt-in: without the flag, ReconKit makes no HTTP requests. Like the scan itself, only use it on targets you're allowed to test.

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
tests/         — pytest tests + saved nmap XML fixtures (tests never use the network)
```

## Tests
```bash
pip install pytest
pytest
```

## Roadmap
- [x] v0.1 — nmap → XML parsing → table + Markdown report
- [x] v0.2 — Package structure + unit tests (pytest) for the parser
- [x] v0.3 — Security header check on open web ports (`--check-headers`)
- [ ] v0.4 — HTML report with templates (Jinja2)
- [ ] v0.5 — Check service versions against a CVE database
- [ ] v0.6 — Parallel scanning of multiple targets + config file
