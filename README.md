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
python3 recon.py scanme.nmap.org
python3 recon.py 192.168.56.101 --top-ports 1000 --out lab_results
```

Output:
- `results/<target>.xml` — raw nmap output
- `results/<target>.md`  — Markdown report

## Roadmap
- [x] v0.1 — nmap → XML parsing → table + Markdown report
- [ ] v0.2 — Package structure + unit tests (pytest) for the parser
- [ ] v0.3 — Automatic web enumeration (whatweb / HTTP headers) if port 80/443 is open
- [ ] v0.4 — HTML report with templates (Jinja2)
- [ ] v0.5 — Check service versions against a CVE database
- [ ] v0.6 — Parallel scanning of multiple targets + config file
