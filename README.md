# ReconAI

Orquestador de reconocimiento ofensivo (P-01 del portfolio de ciberseguridad) que dispara varios agentes de recon en paralelo contra un target y usa IA para resumir la superficie de ataque.

---

## Qué hace

ReconAI recibe un target (IP, dominio o host de laboratorio) y corre **6 agentes de reconocimiento de forma concurrente** con `asyncio.gather`: DNS, escaneo de puertos (nmap), WHOIS, fingerprinting web (headers/tecnologías), Shodan y captura de pantalla con navegador headless. Cada hallazgo se normaliza como un `Finding` con severidad (`critical` → `info`) y técnica MITRE ATT&CK asociada. Si hay configurada **cualquiera** de `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` u `OPENAI_API_KEY`, al final del scan se le pasan todos los hallazgos al proveedor de IA detectado (Claude, Gemini u OpenAI, según la key presente) para que redacte un resumen ejecutivo del attack surface y sugiera rutas de ataque a investigar manualmente. Todo corre detrás de un "scope gate" (`core/target.py`) que bloquea por default cualquier target que no sea de laboratorio (HTB, THM, RFC1918, `.htb`/`.thm`/`.local`) salvo que se fuerce explícitamente con autorización.

> **Nota de precisión:** la etiqueta de portfolio de este proyecto menciona "Gemini AI analysis". El código real (`reconai/core/ai_analyzer.py` + `reconai/core/ai_provider.py`) soporta **Anthropic/Claude**, **Google Gemini** y **OpenAI** por igual — el proveedor se auto-detecta según qué API key esté configurada, con prioridad `ANTHROPIC_API_KEY` > `GEMINI_API_KEY` > `OPENAI_API_KEY` cuando hay más de una seteada. Este README describe lo que el código efectivamente hace.

---

## Características

- **Agentes en paralelo real** — los 6 agentes corren vía `asyncio.gather`; el tiempo total de scan es el del agente más lento, no la suma de todos.
- **Scope gate ético** — `Target.validate_scope()` rechaza targets fuera de rangos autorizados (HTB, THM, RFC1918, `.htb`/`.thm`/`.local`, loopback) a menos que se use `--force-scope` o se agregue el target a `AUTHORIZED_SCOPE`.
- **Tolerante a fallos** — cada agente atrapa sus propias excepciones (`BaseAgent.execute`) y agrega un `Finding` de error en vez de tirar abajo el orchestrator completo. Se verificó en este entorno: sin `nmap` instalado, sin API key de Shodan y sin navegadores de Playwright descargados, el scan igual termina y reporta 6 findings informativos en vez de crashear.
- **Análisis con IA opcional, multi-proveedor** — `--no-ai` lo desactiva por completo; sin ninguna de `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` configurada, el análisis se omite con un mensaje claro en vez de romper el scan.
- **Tagging MITRE ATT&CK** — cada finding lleva técnicas asociadas (ej. `T1046` para puertos, `T1590.002` para DNS).
- **Salida enriquecida** — tabla en terminal con Rich (color por severidad), export a JSON, y generación de reporte HTML/PDF (Jinja2 + WeasyPrint) vía `--report`.
- **Persistencia opcional en Supabase** — si `SUPABASE_URL`/`SUPABASE_ANON_KEY` están seteadas, cada scan se guarda en Supabase (`persist_scan`, best-effort — si falla, no rompe el CLI) para verse en el dashboard de Next.js incluido en `frontend/` (app separada, no hace falta para correr el CLI).

---

## Requisitos

- **Python 3.11+** (declarado en `pyproject.toml`; probado en este entorno con Python 3.14.6 sin conflictos).
- **nmap** instalado y en el `PATH` del sistema para que `PortScannerAgent` funcione (`winget install nmap` en Windows, `apt install nmap` en Linux). Sin él, el agente no crashea: agrega un finding de error y el resto del scan sigue.
- (Opcional) **Playwright + Chromium** para `ScreenshotAgent`: `playwright install chromium`.
- Variables de entorno (ver `.env.example`, copiarlo a `.env`):

| Variable | Requerida | Para qué |
|---|---|---|
| `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` | Solo si no usás `--no-ai` — con cualquiera de estas API keys alcanza | Habilita el análisis con IA al final del scan. Si hay más de una seteada, se usa por prioridad: `ANTHROPIC_API_KEY` > `GEMINI_API_KEY` > `OPENAI_API_KEY` |
| `SHODAN_API_KEY` | No | Habilita `ShodanAgent` (sin ella, el agente se salta con un finding informativo) |
| `SUPABASE_URL` | No | Persistencia de scans/findings para el dashboard |
| `SUPABASE_ANON_KEY` | No | Idem — clave anónima del proyecto Supabase |
| `AUTHORIZED_SCOPE` | No | CIDRs/dominios adicionales autorizados, separados por coma (ej. `192.168.1.0/24,lab.miempresa.com`) |

---

## Instalación

Probado end-to-end en Windows (PowerShell/Git Bash) contra este mismo repo:

```bash
git clone <url-de-este-repo>
cd reconai

python -m venv .venv

# Activar el entorno virtual
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (Git Bash):
source .venv/Scripts/activate

pip install -e .

# Configurar variables de entorno
cp .env.example .env
# Editar .env y completar UNA de ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENAI_API_KEY
# (y opcionalmente SHODAN_API_KEY / SUPABASE_*)

# Opcional, solo si vas a usar el agente de screenshots:
playwright install chromium
```

La instalación con `pip install -e .` corrió limpia en este entorno, sin conflictos de versiones.

---

## Uso

Flags reales, tomados directo de la definición de Typer en `reconai/cli/main.py`:

```bash
reconai --help                 # ver comandos disponibles
reconai agents                 # listar los 6 agentes registrados

reconai scan <target> [OPTIONS]

Opciones de "scan":
  --force-scope           Fuerza el scan fuera de los rangos autorizados (requiere autorización escrita)
  --no-ai                 Salta el análisis con IA
  --output, -o <path>     Guarda el reporte en JSON
  --report, -r <path>     Genera reporte PDF (o HTML si el path termina en .html)
  --quiet, -q              Suprime el banner y la barra de progreso
```

Ejemplo completo, verificado en este entorno:

```bash
reconai scan 127.0.0.1 --no-ai --output scan.json
```

Otros ejemplos:

```bash
reconai scan 10.10.11.21                              # scan completo con análisis de IA (in-scope por default, HTB)
reconai scan target.htb --no-ai                       # sin llamar a la API de IA
reconai scan target.htb --report informe.pdf          # genera reporte PDF
reconai scan 192.168.1.50 --force-scope --output r.json  # target fuera de scope, con autorización explícita
```

### Targets autorizados por default (sin `--force-scope`)

`10.10.10.0/24` y `10.10.11.0/24` (HackTheBox), `10.10.0.0/16` y `10.8.0.0/16` (TryHackMe), rangos RFC1918 completos (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), `127.0.0.0/8`, y hosts `.htb` / `.thm` / `.local` / `localhost`. Cualquier otro target necesita `--force-scope` **y autorización escrita real** — el scope gate no se debe bypassear a la ligera.

---

## Estructura del proyecto

```
reconai/
├── pyproject.toml
├── .env.example
├── reconai/                     # paquete Python (el CLI)
│   ├── cli/main.py              # entrypoint Typer: `scan` y `agents`
│   ├── core/
│   │   ├── target.py            # Target.parse() + scope gate (ScopeValidator)
│   │   ├── orchestrator.py      # dispatch async de los 6 agentes + AGENTS registry
│   │   ├── ai_analyzer.py       # prompt building + parsing de la respuesta de IA
│   │   └── ai_provider.py       # auto-detección de proveedor (Anthropic/Gemini/OpenAI)
│   ├── agents/
│   │   ├── base.py              # BaseAgent ABC — tolerante a fallos
│   │   ├── dns_recon.py         # DNS, AXFR, subdominios, SPF/DMARC
│   │   ├── port_scanner.py      # nmap top-1000 + fingerprint de servicio
│   │   ├── whois_agent.py       # WHOIS de dominio/IP, expiración, privacidad
│   │   ├── web_tech.py          # headers HTTP, WAF, tech stack, security headers
│   │   ├── shodan_agent.py      # Shodan (requiere SHODAN_API_KEY)
│   │   └── screenshot.py        # captura headless con Playwright
│   ├── integrations/
│   │   └── supabase_writer.py   # persistencia opcional best-effort en Supabase
│   ├── report/
│   │   ├── generator.py         # Jinja2 → HTML → PDF (WeasyPrint)
│   │   └── template.html
│   └── types/findings.py        # Finding, ReconResult, Severity, FindingType
├── frontend/                     # dashboard Next.js + Supabase (app aparte, opcional)
├── tests/                        # sin tests todavía (carpeta vacía)
└── docs/                         # sin contenido todavía (carpeta vacía)
```

---

## Aviso legal

ReconAI es una herramienta educativa y de práctica para pentesting **autorizado**. Solo debe usarse contra sistemas propios o para los cuales se cuenta con autorización escrita explícita del propietario. Escanear infraestructura de terceros sin autorización puede constituir un delito según la legislación aplicable. El scope gate (`core/target.py`) es un control técnico de ayuda, no un sustituto de la autorización legal correspondiente.
