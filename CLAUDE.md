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
python3 -m reconkit 192.168.56.101 --check-headers   # also sends HTTP requests to open web ports
```

Outputs go to `<out>/<target>.xml` (raw nmap) and `<out>/<target>.md` (report); `/` in the target is replaced with `_` in filenames. The default output folder is `results/` (gitignored).

Tests (`pytest.ini` puts the repo root on `sys.path` and sets `testpaths = tests`):

```bash
pytest                                                   # all tests
pytest tests/test_parser.py::test_ssh_finding_fields     # a single test
```

Tests only use saved nmap XML in `tests/fixtures/` (`scanme.xml`: 2 open / 0 filtered; `scanme_filtered.xml`: 2 open / 16 filtered, including ports with no `<service>` element). To test anything that would call nmap, stub `check_nmap`/`run_nmap` (e.g. make `run_nmap` copy a fixture to `xml_path`) instead of scanning. HTTP stubbing patterns already in use: pass a fake `fetch` to `check_findings` (`tests/test_headers.py`, `tests/test_report.py`); monkeypatch `reconkit.fetcher.make_connection` to return a fake connection (`tests/test_fetcher.py`); monkeypatch `reconkit.fetcher.fetch_headers` to change the default fetch (`tests/test_cli.py`). `tests/test_cli.py` runs `cli.main()` end to end with all of this stubbed. The guard in `tests/conftest.py` raises `NetworkAccessBlocked` (a `RuntimeError`, deliberately not an `OSError`) so the fetcher's error handling can't swallow it. No linter or build step is configured.

## Architecture

The `reconkit/` package is a linear pipeline driven by `cli.main()`. `python -m reconkit` goes through `reconkit/__main__.py`, and `recon.py` at the repo root just imports and calls `reconkit.cli.main`.

1. `scanner.check_nmap()` — exits if nmap isn't on PATH.
2. `scanner.run_nmap()` — runs `nmap -sV --top-ports N -oX <xml> <target>` via `subprocess`; exits on non-zero return.
3. `parser.parse_nmap_xml()` — converts the XML into a flat list of dicts (one per port), with keys `host, hostname, port, proto, state, service, version, extra, tunnel`. Only hosts with state `up` and ports with state `open` or `filtered` are kept; missing values become `"-"`/`"?"` (`tunnel` is `"ssl"` or `""`; nmap reports most HTTPS as `service="http"` + `tunnel="ssl"`).
4. Only with `--check-headers`: `headers.check_findings(findings)` — for each finding where `headers.web_target()` matches (state `open`, service `http`/`https`/`http-alt`/`http-proxy`; scheme `https` if service is `https` or `tunnel == "ssl"`), calls `fetcher.fetch_headers()` and the pure `headers.analyze_headers(headers_dict, scheme)`, and adds `finding["headers_check"] = {url, status, location, missing, present, not_applicable, error}`.
5. `report.print_table()` / `report.write_report()` — both consume that list of dicts; `parser.count_states()` is shared for open/filtered counts. `report.print_header_results()` (called only with the flag) and the `## Security Headers` section of `write_report()` read `headers_check`; without that key the output is exactly the pre-v0.3 output, and the port table never shows header data.

Header check behavior (decided, keep it): HSTS is `not_applicable` over plain HTTP; redirects are not followed (`location` is recorded); TLS certificates are not verified (noted in output); filtered web ports are skipped. `fetcher.py` is the only module with network code: one `HEAD /` (retried as `GET` on 405/501, body never read), connecting to the IP with the nmap hostname as `Host` header and TLS SNI. It turns only `OSError` and `http.client.HTTPException` into `{"error": "<Type>: <message>"}`; never widen that to `Exception`. `headers.py` imports the fetcher lazily so it stays network-free.

The list-of-dicts from `parse_nmap_xml()` is the contract between parsing and output — new output formats (the HTML/Jinja2 report on the roadmap) or enrichment steps (CVE lookup) should consume or extend those dicts rather than re-parse XML. Modules use relative imports within the package; `cli.py` imports the step functions by name, so stub them on `reconkit.cli` when testing `main()`.

The version lives in `reconkit/__init__.py` as `__version__` (used by the CLI description and the fetcher's `User-Agent`); the README roadmap tracks releases. The roadmap in `README.md` (v0.4–v0.6) is the planned direction for features.
