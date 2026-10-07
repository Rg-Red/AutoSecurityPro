# AutoSecurityPro (WhiteHat Hacker Suite)

A modular, high-performance Web Security & Attack Surface Assessment Suite
featuring a `rich`-powered terminal interface, passive/active reconnaissance,
WAF evasion, safe Proof-of-Concept vulnerability verification, and automated
JSON reporting.

## Installation

```
pip install -r requirements.txt
```

## Usage

Interactive mode (prompts for a target):

```
python main.py
```

Non-interactive mode:

```
python main.py --target example.com --tor --modules all
```

### Key CLI Flags

- `--target / -t` — Target domain or IP address.
- `--tor` — Route traffic through the local Tor SOCKS5 proxy (`127.0.0.1:9050`).
- `--proxy-file` — Path to a newline-delimited list of proxies.
- `--cookie` / `--jwt` — Credentials for authenticated scanning.
- `--modules` — Comma-separated list: `recon,vuln,dorking,all` (default `all`).
- `--no-dorking` — Disable the Google/DuckDuckGo dorking phase.
- `--output-dir` — Directory for generated JSON reports (default `reports`).

## Design Notes

- All vulnerability checks are strictly **safe, non-destructive Proof-of-Concept**
  verifications (time-based delay checks, benign canary reflections, read-only
  file marker checks). No destructive actions, data exfiltration, or reverse
  shells are ever performed.
- Findings are scored using CVSS v3.1 base metrics and rolled up into an
  overall Security Health Score (0-100).
- A structured `scan_report_<target>_<timestamp>.json` file is written to the
  output directory at the end of every scan.

## Legal Notice

Only run AutoSecurityPro against systems you own or have explicit written
authorization to test. Unauthorized security testing may be illegal in your
jurisdiction.
