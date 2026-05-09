# 🔍 ReconAI — Offensive Reconnaissance Orchestrator

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Async](https://img.shields.io/badge/Async-asyncio-00b4d8?style=for-the-badge)
![Portfolio](https://img.shields.io/badge/Portfolio-P--01_Offensive-critical?style=for-the-badge)

**Automated multi-source OSINT & active reconnaissance with AI-powered attack surface analysis**

*P-01 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

ReconAI fires **6 reconnaissance agents in parallel** against a target, then feeds all findings to **Google Gemini** to reconstruct the attack surface, classify severity, and suggest initial exploitation paths — all from a single command.

```bash
reconai scan 10.10.11.21
```

```
┌─────────────────────────────────────────────────────────┐
│  ReconAI  v0.1.0 — Automated Recon Orchestrator         │
│  P-01 · DNS + Ports + WHOIS + WebTech + Shodan + AI     │
└─────────────────────────────────────────────────────────┘

[✓] DNS recon          8 findings  (1.2s)
[✓] Port scan          12 findings (4.8s)
[✓] WHOIS              3 findings  (0.9s)
[✓] Web tech           5 findings  (1.1s)
[✓] Shodan             4 findings  (0.8s)

Artifacts — 32 total
┌──────────┬─────────────────────┬──────────────────────────────────────────┐
│ Severity │ Type                │ Description                              │
├──────────┼─────────────────────┼──────────────────────────────────────────┤
│ HIGH     │ dns                 │ Zone transfer (AXFR) open on ns1.target  │
│ HIGH     │ port                │ SMB 445 open — EternalBlue potential     │
│ MEDIUM   │ web_tech            │ Apache 2.4.49 — CVE-2021-41773           │
│ ...      │ ...                 │ ...                                      │
└──────────┴─────────────────────┴──────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════╗
║  AI Incident Narrative                                ║
║  Target exposes a Jenkins instance (port 8080) with   ║
║  default credentials and an AXFR-open nameserver.    ║
║  Recommend: exploit Jenkins script console for RCE   ║
╚═══════════════════════════════════════════════════════╝
```

---

## Features

- **Parallel agent execution** — all agents run via `asyncio.gather`, total time = slowest agent
- **Scope gate** — validates every target before network activity; refuses unauthorized hosts
- **Gemini AI analysis** — attack surface reconstruction, severity prioritization, next-step suggestions
- **MITRE ATT&CK tagging** — every finding mapped to technique IDs
- **Rich terminal output** — color-coded severity table + AI narrative panel
- **JSON export** — machine-readable output for report pipelines

---

## Agents

| Agent | File | What it detects | MITRE Techniques |
|---|---|---|---|
| **DNS Recon** | `dns_recon.py` | A/MX/NS/TXT records, AXFR, subdomain enumeration, SPF/DMARC issues | T1590.002, T1596.001 |
| **Port Scanner** | `port_scanner.py` | Open TCP/UDP ports, service banners, version fingerprinting | T1046 |
| **WHOIS** | `whois_agent.py` | Registrar info, org data, expiry, privacy disclosure | T1590.001 |
| **Web Tech** | `web_tech.py` | CMS, frameworks, server versions, JS libraries, headers | T1592.002 |
| **Shodan** | `shodan_agent.py` | Historical exposure, CVEs, open services (free InternetDB) | T1596.005 |
| **Screenshot** | `screenshot.py` | Web page capture via Playwright | T1593 |

---

## Installation

```bash
git clone https://github.com/jmsdev83/reconai
cd reconai
pip install -e .

# Optional: Playwright for screenshots
playwright install chromium

# Configure
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### Requirements

- Python 3.11+
- `python-nmap` requires nmap installed (`winget install nmap` / `apt install nmap`)
- Gemini API key: [aistudio.google.com](https://aistudio.google.com) (free tier)

---

## Usage

```bash
# Full recon with AI analysis
reconai scan 10.10.11.21

# Skip AI (faster, no API key needed)
reconai scan target.htb --no-ai

# Save to JSON
reconai scan 10.10.11.21 --output report.json

# List available agents and their status
reconai agents
```

### Authorized targets (no flag needed)

| Range | Context |
|---|---|
| `10.10.10.0/23`, `10.10.11.0/24` | HackTheBox active machines |
| `10.10.0.0/16`, `10.8.0.0/16` | TryHackMe |
| RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`) | Private networks |
| `*.htb`, `*.thm`, `*.local` | Lab hostnames |

For external targets: add `--force-scope` and confirm written authorization.

---

## Architecture

```
reconai scan <target>
       │
       ▼
  Target.parse()          ← extract host, port, IP vs domain
       │
       ▼
  validate_scope()        ← ETHICAL GATE — raises ScopeError if unauthorized
       │
       ▼
  asyncio.gather(agents)  ← all agents run concurrently
  ┌────┴──────────────────────────────────────────────┐
  │  DNSReconAgent  PortScannerAgent  WHOISAgent      │
  │  WebTechAgent   ShodanAgent       ScreenshotAgent │
  └────┬──────────────────────────────────────────────┘
       │
       ▼
  analyze_with_ai()       ← Gemini: attack surface + next steps
       │
       ▼
  Rich table + AI panel / JSON export
```

---

## Severity Classification

| Level | Meaning | Example |
|---|---|---|
| 🔴 **CRITICAL** | Directly exploitable | AXFR open, RCE-vulnerable service |
| 🟠 **HIGH** | Serious misconfiguration | SMB exposed, `+all` in SPF |
| 🟡 **MEDIUM** | Missing security control | No DMARC, exposed admin panel |
| 🔵 **LOW** | Attacker-useful intel | Server version disclosed |
| ⚪ **INFO** | Neutral recon data | Open ports, DNS records |

---

## Project Structure

```
reconai/
├── reconai/
│   ├── agents/
│   │   ├── base.py           # BaseAgent ABC
│   │   ├── dns_recon.py      # DNS enumeration + AXFR + SPF/DMARC
│   │   ├── port_scanner.py   # TCP/UDP + service fingerprint
│   │   ├── whois_agent.py    # WHOIS + org lookup
│   │   ├── web_tech.py       # HTTP headers + tech detection
│   │   ├── shodan_agent.py   # Shodan InternetDB (no API key)
│   │   └── screenshot.py     # Playwright web capture
│   ├── core/
│   │   ├── target.py         # Scope validation (the ethical gate)
│   │   ├── orchestrator.py   # Async pipeline + result aggregation
│   │   └── ai_analyzer.py    # Gemini prompt + response parsing
│   ├── types/
│   │   └── findings.py       # Finding, ReconResult, Severity, FindingType
│   └── cli/
│       └── main.py           # Typer CLI entry point
├── .env.example
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=your-key-here      # Google AI Studio (free tier)
SHODAN_API_KEY=                   # Optional — enables full Shodan API
AUTHORIZED_SCOPE=10.0.0.0/8      # Additional authorized CIDRs/domains
```

---

## Portfolio

**9-project cybersecurity portfolio** — built to land a first infosec job.

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | **ReconAI** ← you are here | ✅ |
| P-02 | Offensive | WebHunter — OWASP Top 10 Scanner | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing Platform | ✅ |
| D-01 | Defensive | SOC-Lite — AI-Powered SIEM | ✅ |
| D-02 | Defensive | ThreatFeed — CTI Aggregator | ✅ |
| D-03 | Defensive | HoneyGrid — SSH/HTTP Honeypot | ✅ |
| F-01 | Forensics | DFIR-Auto — Forensic Triage | ✅ |
| F-02 | Forensics | MalwareScope — Static Malware Analyzer | ✅ |
| F-03 | Forensics | PCAPForge — Network Forensics | ✅ |

---

> ⚠️ **Legal Notice** — ReconAI is designed exclusively for authorized security testing.
> The scope validator enforces this at the code level.
> Always obtain written authorization before scanning any target you do not own.

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
