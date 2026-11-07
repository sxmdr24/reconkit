# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

ReconKit is a learning project (written after a Junior Penetration Tester / CEH course): it runs nmap against a target, parses the XML output, prints a table and writes a Markdown report. The project language is **English**: code identifiers, comments, docstrings, CLI help, printed messages, report text and docs. Keep new code consistent with that. (Commits before the English conversion are in Indonesian.)

**Rule:** Never run nmap or scan any target. For testing, use the XML files in `tests/fixtures/`.

(The tool itself is meant only for targets the user owns or is authorized to test — lab VMs like Metasploitable/DVWA, `localhost`, `scanme.nmap.org` — but Claude never runs scans, including `recon.py`, regardless of target.)

## Commands

Requires Python 3 (stdlib only, no dependencies) and `nmap` (`sudo apt install nmap`).

Usage, for reference only (these run nmap, so the user runs them, not Claude):

```bash
python3 recon.py scanme.nmap.org
python3 recon.py 192.168.56.101 --top-ports 1000 --out lab_results
```

Outputs go to `<out>/<target>.xml` (raw nmap) and `<out>/<target>.md` (report); `/` in the target is replaced with `_` in filenames. The default output folder is `results/` (gitignored).

There is no test suite, linter or build step yet (pytest for the parser is planned for v0.2). To exercise the parser, use a fixture in `tests/fixtures/`:

```bash
python3 -c "from recon import parse_nmap_xml; print(parse_nmap_xml('tests/fixtures/scanme.xml'))"
```

## Architecture

Everything lives in the single script `recon.py`, as a linear pipeline driven by `main()`:

1. `check_nmap()` — exits if nmap isn't on PATH.
2. `run_nmap()` — runs `nmap -sV --top-ports N -oX <xml> <target>` via `subprocess`; exits on non-zero return.
3. `parse_nmap_xml()` — converts the XML into a flat list of dicts (one per port), with keys `host, hostname, port, proto, state, service, version, extra`. Only hosts with state `up` and ports with state `open` or `filtered` are kept; missing values become `"-"`/`"?"`.
4. `print_table()` / `write_report()` — both consume that list of dicts; `count_states()` is shared for open/filtered counts.

The list-of-dicts from `parse_nmap_xml()` is the contract between parsing and output — new output formats (the HTML/Jinja2 report on the roadmap) or enrichment steps (web enumeration, CVE lookup) should consume or extend those dicts rather than re-parse XML.

The version string appears in three places (module docstring, argparse `description`, README roadmap); bump them together. The roadmap in `README.md` (v0.2–v0.6) is the planned direction for features.
