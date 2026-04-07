# spektr

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/github/license/tunakum/spektr)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)

CVE intelligence CLI. Fetches vulnerabilities from NVD, scores them using CVSS + EPSS + KEV data, and ranks results so you see what actually matters first.

No paid APIs. Cached results work offline. Built for pentesters and security folks who want fast answers from the terminal.

## Tech stack

Python, Typer, Rich, httpx, SQLite. No heavy frameworks, no cloud dependencies.

## What it does

- Searches NVD for CVEs by software name/version (CPE-based version filtering)
- Pulls EPSS exploit probability scores (batched in chunks of 100)
- Checks CISA KEV catalog for known-exploited vulns
- Combines everything into a single **spektr score** (0-10)
- Caches results in SQLite so repeated queries are instant
- Pretty Rich terminal output with color-coded severity
- **AI triage** via Groq (free) — auto-runs contextual risk analysis when configured
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

# raw table view (skip AI triage)
spektr "log4j" --raw

# pipe-friendly (auto-strips colors)
spektr "nginx" | grep CVE
spektr "nginx" > results.txt

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
  1   CRITICAL    CVE-2021-44228      10.0   100.0   !!     10.0
  2   CRITICAL    CVE-2017-5645        9.8    99.9    -      9.9
  3   CRITICAL    CVE-2021-45046       9.0   100.0    -      9.7
  4   CRITICAL    CVE-2019-17571       9.8    97.2    -      9.6
  5   HIGH        CVE-2021-4104        7.5    98.6    -      8.9
```

## Scoring

```
spektr score = (0.35 × CVSS) + (0.65 × EPSS²×10), capped at 10
If in CISA KEV: score × 1.3
```

EPSS is non-linear — a CVE at 90th percentile scores much higher than one at 45th percentile, even though it's only 2× the raw value. KEV adds a 30% boost on top.

## AI Triage

spektr includes built-in AI triage powered by **Groq** (free tier, runs `llama-3.1-8b-instant`). When configured, every search automatically gets a contextual risk assessment from an LLM acting as a senior pentester — prioritized CVEs, attack path analysis, and recommended actions.

### Setup

1. Get a free API key at [console.groq.com](https://console.groq.com) (no credit card needed)
2. Configure spektr:
```bash
spektr --config ai_provider groq
spektr --config groq_api_key YOUR_KEY
```

That's it. AI triage now runs on every search automatically. Use `--raw` to skip AI and see the classic table view only.

### How it works

- Top 10 CVEs (by spektr score) are sent to the LLM with CVSS, EPSS, and KEV context
- The AI returns a 2-sentence summary, top 5 priority CVEs with short reasoning, an attack path, and 3 recommended actions
- Output order: header → AI triage panel → CVE table → footer
- API keys are stored in `~/.config/spektr/config.toml` and never appear in output (masked as `gsk_****hhmG`)

## Roadmap

- Nmap XML parsing for batch scanning
- HTML report export
- GitHub Actions CI (ruff + pytest)

## Built with

Developed with [Claude](https://claude.ai) (Anthropic) as an AI coding assistant.

## License

[MIT](LICENSE) © 2026 Tunahan Kum

## Contact

- GitHub: [@tunakum](https://github.com/tunakum)
- LinkedIn: [tunahankum](https://linkedin.com/in/tunahankum)
