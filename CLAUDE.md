# CLAUDE.md — ReconAI

Este archivo es el contexto completo para Claude Code.
Leelo antes de tocar cualquier archivo del proyecto.

---

## Qué es este proyecto

**ReconAI** es un orquestador de reconocimiento ofensivo con IA para pentesting autorizado.
Es el proyecto P-01 de un portfolio de ciberseguridad de 9 proyectos (3 ofensivos, 3 defensivos, 3 forenses).
El objetivo final es conseguir el primer trabajo en ciberseguridad.

El autor es **Juanma** (Juan Manuel Silva), Full Stack Developer TypeScript/Python en Las Breñas, Chaco, Argentina.
Está estudiando Tecnicatura en Seguridad Informática (TECLAB) + Licenciatura en Ciberdefensa (UNDEF-FADENA).

---

## Estado actual del proyecto

### Fase 1 — COMPLETA (generada en Claude.ai)

Archivos creados y funcionales:

```
reconai/
├── pyproject.toml
├── .env.example
├── README.md
└── reconai/
    ├── __init__.py
    ├── types/
    │   └── findings.py        ← modelos de datos: Finding, ReconResult, Severity, FindingType
    ├── core/
    │   ├── target.py          ← scope validator (puerta ética, no tocar sin revisión)
    │   ├── orchestrator.py    ← pipeline async, despacha agents concurrentemente
    │   └── ai_analyzer.py     ← Claude API integration (claude-sonnet-4-20250514)
    ├── agents/
    │   ├── base.py            ← BaseAgent ABC
    │   └── dns_recon.py       ← AGENT 1: DNS completo y funcional
    ├── cli/
    │   └── main.py            ← CLI Typer: `reconai scan` y `reconai agents`
    └── report/                ← vacío, Fase 3
```

### Lo que funciona ahora mismo

```bash
pip install -e .
reconai agents                    # lista agents disponibles
reconai scan 10.10.11.21          # scan contra HTB (in-scope por default)
reconai scan target.htb --no-ai   # sin Claude API
reconai scan target.htb --output report.json
```

### Lo que falta — por orden de prioridad

#### Fase 2 — Agents (hacer acá en Claude Code)

Cada agent va en `reconai/agents/` y se registra en `reconai/core/orchestrator.py` en la lista `AGENTS`.
Todos heredan `BaseAgent` de `reconai/agents/base.py`.

| Archivo | Agent | Tools | Estado |
|---|---|---|---|
| `port_scanner.py` | `PortScannerAgent` | python-nmap | **PENDIENTE** |
| `whois_agent.py` | `WHOISAgent` | python-whois | **PENDIENTE** |
| `web_tech.py` | `WebTechAgent` | httpx, patrones manuales | **PENDIENTE** |
| `shodan_agent.py` | `ShodanAgent` | shodan SDK (API key opcional) | **PENDIENTE** |
| `screenshot.py` | `ScreenshotAgent` | playwright | **PENDIENTE** |

#### Fase 3 — Report Generator (hacer en Claude.ai + Claude Code)

- `reconai/report/generator.py` — Jinja2 → HTML → PDF con WeasyPrint
- `reconai/report/template.html` — template profesional del informe
- Integrar en `orchestrator.py` como paso final

#### Fase 4 — Dashboard Next.js (hacer en Claude.ai)

- Separar en monorepo: `/backend` (Python) y `/frontend` (Next.js)
- Supabase para persistir findings entre sesiones
- Dashboard con findings color-coded por severidad

---

## Arquitectura del pipeline

```
Target (string)
  → Target.parse()         # extrae host, puerto, is_ip
  → target.validate_scope() # scope gate — lanza ScopeError si no está autorizado
  → run_recon()            # orchestrator async
      → asyncio.gather([agents])  # todos corren en paralelo
          → DNSReconAgent.run()
          → PortScannerAgent.run()   # pendiente
          → WHOISAgent.run()         # pendiente
          → WebTechAgent.run()       # pendiente
          → ShodanAgent.run()        # pendiente
          → ScreenshotAgent.run()    # pendiente
      → analyze_with_ai()  # Claude API
  → print_summary()        # Rich table en terminal
  → PDF report             # pendiente Fase 3
```

---

## Cómo agregar un nuevo agent

```python
# reconai/agents/port_scanner.py
from reconai.agents.base import BaseAgent
from reconai.types.findings import Finding, FindingType, ReconResult, Severity
from reconai.core.target import Target

class PortScannerAgent(BaseAgent):
    name = "port_scanner"
    description = "TCP/UDP port scan with service fingerprinting"

    async def run(self, target: Target, result: ReconResult) -> None:
        # tu lógica acá
        # siempre usar result.add(Finding(...))
        # nunca retornar data directamente
        pass
```

Luego en `reconai/core/orchestrator.py`, agregar en `AGENTS`:
```python
from reconai.agents.port_scanner import PortScannerAgent

AGENTS = [
    DNSReconAgent(),
    PortScannerAgent(),  # agregar acá
]
```

---

## Reglas del proyecto

### Ética / scope
- El `ScopeValidator` en `core/target.py` es la puerta ética. **Nunca bypassearlo silenciosamente.**
- Ranges in-scope por default: HTB (10.10.10-11.x), THM (10.10.x.x, 10.8.x.x), RFC1918, *.htb, *.thm, *.local
- Externals: necesitan `--force-scope` + autorización escrita del usuario

### Código
- Python 3.11+, type hints en todo
- Agents: async, tolerantes a fallos (no crashear el orchestrator), agregar `Finding` de tipo ERROR si algo falla
- `Finding` es inmutable después de `result.add()` — no modificar findings ajenos
- pnpm para el frontend cuando llegue la Fase 4

### Severidades de findings
```
CRITICAL → explotable directamente, acceso sin auth
HIGH     → misconfiguration grave (ej: AXFR abierto, +all en SPF)
MEDIUM   → falta de control (ej: sin DMARC, subdomain expuesto)
LOW      → información útil para el atacante
INFO     → datos de reconocimiento neutrales
```

### MITRE ATT&CK — técnicas por agent

| Agent | Técnicas principales |
|---|---|
| dns_recon | T1590.002, T1596.001 |
| port_scanner | T1046 (Network Service Discovery) |
| whois_agent | T1590.001 (Domain Properties) |
| web_tech | T1592.002 (Software Discovery) |
| shodan_agent | T1596.005 (Scan Databases) |
| screenshot | T1593 (Search Open Websites) |

---

## Variables de entorno (.env)

```bash
ANTHROPIC_API_KEY=sk-ant-...     # requerida para AI analysis
SHODAN_API_KEY=                  # opcional, habilita ShodanAgent
SUPABASE_URL=                    # opcional, Fase 4
SUPABASE_ANON_KEY=               # opcional, Fase 4
AUTHORIZED_SCOPE=                # dominios/CIDRs autorizados adicionales
```

---

## Setup desde cero

```bash
# Windows PowerShell
pip install -e .
playwright install chromium       # para ScreenshotAgent (Fase 2)

# Verificar
reconai --help
reconai agents

# Primer scan (necesita HTB VPN activo)
reconai scan 10.10.11.21
```

---

## Comandos útiles para Claude Code

```bash
# Correr un scan de prueba contra localhost (siempre in-scope)
reconai scan 127.0.0.1 --no-ai

# Ver findings en JSON
reconai scan 127.0.0.1 --no-ai --output /tmp/test.json && cat /tmp/test.json

# Correr tests
python -m pytest tests/ -v

# Ver estructura del proyecto
find . -name "*.py" | grep -v __pycache__ | sort
```

---

## Contexto del portfolio completo

Este es el proyecto **P-01** de 9. Los otros proyectos están planificados pero no iniciados.
Cuando Juanma vuelva a Claude.ai, va a pedir planificar el proyecto siguiente.

### Los 9 proyectos

**Ofensivos (P)**
- P-01 ReconAI ← este proyecto
- P-02 WebHunter — OWASP Top 10 AI Scanner
- P-03 PhishSim — Red Team Phishing Platform

**Defensivos (D)**
- D-01 SOC-Lite — AI-Powered Lightweight SIEM
- D-02 ThreatFeed — CTI Aggregator
- D-03 HoneyGrid — SSH/HTTP Honeypot

**Forenses (F)**
- F-01 DFIR-Auto — Automated Forensic Triage
- F-02 MalwareScope — Static Malware Analyzer
- F-03 PCAPForge — Network Forensics Investigator

---

## Footer obligatorio en todo output del proyecto

```
Copyright © 2025 Desarrollado desde Las Breñas con 💜 por @jmsDev All rights reserved
```

`@jmsDev` → https://www.linkedin.com/in/jmsilva83
