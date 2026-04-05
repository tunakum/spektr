# spektr

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/github/license/tunakum/spektr)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)

CVE intelligence CLI. Fetches vulnerabilities from NVD, scores them using CVSS + EPSS + KEV data, and ranks results so you see what actually matters first.

No paid APIs. Runs offline for core features. Built for pentesters and security folks who want fast answers from the terminal.

## Tech stack

Python, Typer, Rich, httpx, SQLite. No heavy frameworks, no cloud dependencies.

## What it does

- Searches NVD for CVEs by software name/version
- Pulls EPSS exploit probability scores (batch, one request)
- Checks CISA KEV catalog for known-exploited vulns
- Combines everything into a single **spektr score** (0-10)
- Caches results in SQLite so repeated queries are instant
- Pretty Rich terminal output with color-coded severity
- Markdown report export (`--output report.md`)
- Persistent config at `~/.config/spektr/config.toml`

## Install

```bash
pip install pipx  # if you don't have pipx yet
pipx install git+https://github.com/tunakum/spektr.git
```

That's it. `spektr` is now available globally, no venv activation needed.

### Development setup

```bash
git clone https://github.com/tunakum/spektr.git
cd spektr
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Needs Python 3.11+.

## Usage

```bash
# search for CVEs
spektr "log4j"
spektr "nginx 1.18.0" --limit 20
spektr "apache struts 2.3" --severity critical

# look up a specific CVE
spektr cve CVE-2021-44228
spektr cve CVE-2021-44228 -o report.md

# sort by different fields
spektr "openssl" --sort epss
spektr "wordpress" --sort cvss

# export results to markdown
spektr "log4j" --output report.md

# skip cache for fresh data
spektr "log4j" --no-cache

# configure defaults
spektr --config                        # show all settings
spektr --config limit 50               # set default limit
spektr --config nvd_api_key YOUR_KEY   # set NVD API key

# clear cached data
spektr clear-cache
```

## Example output

```
+---------------------------------- spektr -----------------------------------+
|                                                                             |
|  log4j                                                                      |
|                                                                             |
+--------------------------- 10 CVEs found  (live) ---------------------------+

  #   Severity    CVE ID              CVSS   EPSS%   KEV    Score
  1   CRITICAL    CVE-2021-44228      10.0   100.0   !!      8.0
  2   CRITICAL    CVE-2017-5645        9.8    99.9    -      7.9
  3   CRITICAL    CVE-2019-17571       9.8    97.2    -      7.8
  4   CRITICAL    CVE-2021-45046       9.0   100.0    -      7.6
  5   HIGH        CVE-2021-4104        7.5    98.6    -      6.9
```

## Scoring

spektr score = weighted combination of three signals:

| Signal | Weight | Source |
|--------|--------|--------|
| CVSS v3 base score (normalized) | 40% | NVD |
| EPSS percentile | 40% | FIRST.org |
| KEV status | 20% | CISA |

A CVE with high CVSS but low EPSS (theoretical risk, rarely exploited) scores lower than one with moderate CVSS but high EPSS (actively exploited in the wild). That's the point.

## Roadmap

- AI triage via Groq (free) or Ollama (local) -- contextual risk analysis
- Nmap XML parsing for batch scanning
- HTML report export
- GitHub Actions CI (ruff + pytest)

## Built with

Developed with [Claude](https://claude.ai) (Anthropic) as an AI coding assistant.

## License

[MIT](LICENSE) © 2025 Tunahan Kum

## Contact

- GitHub: [@tunakum](https://github.com/tunakum)
- LinkedIn: [tunahankum](https://linkedin.com/in/tunahankum)
