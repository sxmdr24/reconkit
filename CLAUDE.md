# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

ReconKit is a learning project (written after a Junior Penetration Tester / CEH course): it runs nmap against a target, parses the XML output, prints a table and writes a Markdown report. The project language is **English**: code identifiers, comments, docstrings, CLI help, printed messages, report text and docs. Keep new code consistent with that. (Commits before the English conversion are in Indonesian.)

**Rule:** Never run nmap or scan any target. For testing, use the XML files in `tests/fixtures/`.

**Rule:** Tests must never touch the network: no sockets, no DNS lookups, no HTTP requests, not even to localhost or `scanme.nmap.org`. Test analysis code by passing plain dicts to pure functions such as `analyze_headers`. Test network code by stubbing it, either by passing a fake `fetch` to `check_findings` or by monkeypatching `http.client` connections. `tests/conftest.py` blocks socket connections for every test; never disable or bypass it. Never run `--check-headers` (or any other command that contacts a target) yourself. Like nmap, only the user runs it.

(The tool itself is meant only for targets the user owns or is authorized to test — lab VMs like Metasploitable/DVWA, `localhost`, `scanme.nmap.org` — but Claude never runs scans, including `python -m reconkit` or `recon.py`, regardless of target. `--help` is safe.)

## Commands

Requires Python 3 (stdlib only, no runtime dependencies) and `nmap` (`sudo apt install nmap`). Tests need `pytest`.

Usage, for reference only (these run nmap, so the user runs them, not Claude):

```bash
python3 -m reconkit scanme.nmap.org
python3 -m reconkit 192.168.56.101 --top-ports 1000 --out lab_results
python3 recon.py scanme.nmap.org   # backwards-compatible wrapper, same CLI
```

Outputs go to `<out>/<target>.xml` (raw nmap) and `<out>/<target>.md` (report); `/` in the target is replaced with `_` in filenames. The default output folder is `results/` (gitignored).

Tests (`pytest.ini` puts the repo root on `sys.path` and sets `testpaths = tests`):

```bash
pytest                                                   # all tests
pytest tests/test_parser.py::test_ssh_finding_fields     # a single test
```

Tests only use saved nmap XML in `tests/fixtures/` (`scanme.xml`: 2 open / 0 filtered; `scanme_filtered.xml`: 2 open / 16 filtered, including ports with no `<service>` element). To test anything that would call nmap, stub `check_nmap`/`run_nmap` (e.g. make `run_nmap` copy a fixture to `xml_path`) instead of scanning. No linter or build step is configured.

## Architecture

The `reconkit/` package is a linear pipeline driven by `cli.main()`. `python -m reconkit` goes through `reconkit/__main__.py`, and `recon.py` at the repo root just imports and calls `reconkit.cli.main`.

1. `scanner.check_nmap()` — exits if nmap isn't on PATH.
2. `scanner.run_nmap()` — runs `nmap -sV --top-ports N -oX <xml> <target>` via `subprocess`; exits on non-zero return.
3. `parser.parse_nmap_xml()` — converts the XML into a flat list of dicts (one per port), with keys `host, hostname, port, proto, state, service, version, extra, tunnel`. Only hosts with state `up` and ports with state `open` or `filtered` are kept; missing values become `"-"`/`"?"` (`tunnel` is `"ssl"` or `""`; nmap reports most HTTPS as `service="http"` + `tunnel="ssl"`).
4. `report.print_table()` / `report.write_report()` — both consume that list of dicts; `parser.count_states()` is shared for open/filtered counts.

The list-of-dicts from `parse_nmap_xml()` is the contract between parsing and output — new output formats (the HTML/Jinja2 report on the roadmap) or enrichment steps (web enumeration, CVE lookup) should consume or extend those dicts rather than re-parse XML. Modules use relative imports within the package; `cli.py` imports the step functions by name, so stub them on `reconkit.cli` when testing `main()`.

The version lives in `reconkit/__init__.py` as `__version__` (used by the CLI description); the README roadmap tracks releases. The roadmap in `README.md` (v0.2–v0.6) is the planned direction for features.
