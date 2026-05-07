# ReconAI

AI-powered reconnaissance orchestrator for authorized penetration testing.

## Legal notice

This tool is for use **only** against systems you own or have **explicit written authorization** to test.
Unauthorized use is illegal. The built-in scope validator enforces this by default.

## Stack

- Python 3.11+
- `dnspython` — DNS enumeration
- `python-nmap` — port scanning (Phase 2)
- `anthropic` SDK — AI analysis
- `typer` + `rich` — CLI
- `supabase` — findings persistence (Phase 2)
- `playwright` — screenshots (Phase 2)

## Setup

```bash
# 1. Clone and enter
git clone https://github.com/jmsD3v/reconai && cd reconai

# 2. Install
pip install -e .

# 3. Configure
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env

# 4. Verify
reconai agents
```

## Usage

```bash
# Scan a HackTheBox machine (in-scope by default)
reconai scan 10.10.11.21

# Scan a .htb domain
reconai scan target.htb

# Scan your own lab (RFC1918 — in-scope by default)
reconai scan 192.168.1.100

# Skip AI analysis (faster, no API key needed)
reconai scan 10.10.11.21 --no-ai

# Save JSON report
reconai scan target.htb --output reports/target-htb-$(date +%Y%m%d).json

# External target with written authorization
reconai scan authorized-target.com --force-scope
```

## Authorized scope (default, no flag needed)

| Range | Environment |
|-------|-------------|
| `10.10.10.0/24`, `10.10.11.0/24` | HackTheBox |
| `10.10.0.0/16`, `10.8.0.0/16` | TryHackMe |
| `192.168.0.0/16`, `172.16.0.0/12`, `10.0.0.0/8` | RFC1918 / your lab |
| `*.htb`, `*.thm`, `*.local` | Lab DNS conventions |

Add your own authorized scopes in `.env`:
```
AUTHORIZED_SCOPE=203.0.113.0/24,bugbounty.example.com
```

## Architecture

```
Target → Scope Validator → Async Orchestrator → [Agent Pool] → AI Analyzer → Report
```

### Phase 1 agents (implemented)
- `dns_recon` — A/MX/NS/TXT/CNAME records, zone transfer, subdomain brute-force, email security

### Phase 2 agents (scaffolded)
- `port_scanner` — Nmap wrapper, service fingerprinting
- `whois_agent` — Domain registration, registrar, dates
- `web_tech` — HTTP headers, tech stack detection
- `shodan_agent` — IP intelligence via Shodan API
- `screenshot` — Playwright headless screenshots

## Output

Each scan produces:
- Rich terminal summary with severity-colored findings
- JSON export (`--output report.json`)
- AI narrative + attack path suggestions (requires `ANTHROPIC_API_KEY`)

---

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por @jmsDev  
https://www.linkedin.com/in/jmsilva83 · All rights reserved
