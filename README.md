# SecAgent-Core

FastAPI service that scans an **authorised** host with Nmap, parses the real XML output, matches the detected
service versions to a small local CVE knowledge base, and returns a structured threat report with a
conservative remediation plan. Optional LLM agents (CrewAI) can run the same tools, but **scanning never depends on an LLM**.

## How a scan works
```
POST /api/v1/scan  ->  validate request  ->  scope check (private + allow-listed + port cap)
   -> nmap_scan: subprocess argv list, shell=False, `-oX -`, timeout   (live mode)
      or built-in fixtures                                              (mock mode)
   -> parse XML: open ports + services are taken ONLY from nmap
   -> version-match against local CVE KB -> report (ThreatReport) -> JSON response + reports/<id>.{json,md}
```
The response says **where the data came from**, separately from **which pipeline analysed it**:

| Field | Values | Meaning |
|---|---|---|
| `data_source` | `live_nmap` / `mock_fixture` / `provided_scan_data` | Where the observations came from |
| `real_scan` | `true` only for `live_nmap` | A real nmap process ran for this request |
| `scan_evidence` | present only for `live_nmap` | nmap version, exact command, exit code, elapsed time, hosts up |
| `execution_mode` | `agentic` / `deterministic_fallback` | Which analysis pipeline ran (the name is historical: "deterministic_fallback" with `live_nmap` is still a **real** scan analysed without an LLM) |

The schema enforces the labels (`real_scan` and `scan_evidence` cannot be set unless `data_source == "live_nmap"`).
A failed scan returns an HTTP error (`403` out of scope, `422` invalid, `502` nmap failed/bad output, `503` nmap missing,
`504` timeout). **Failures never fall back to mock data.**

## Windows setup (PowerShell)
1. Install **Python 3.10+** (python.org; tick "Add python.exe to PATH") and **Nmap** from https://nmap.org/download (Windows installer; this also offers Npcap). SecAgent uses a TCP connect scan (`-sT`), so it needs no administrator rights.
2. In the project folder:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1            # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements-dev.txt
Copy-Item .env.example .env
nmap --version                           # if "not recognised", set SECAGENT_NMAP_PATH in .env
python -m pytest -q                      # all tests mock subprocess; no scan, no network
```

## Run
**Demo (mock, default):** nothing is scanned; results are labelled `mock_fixture`.
```powershell
python -m uvicorn app.main:app --reload
```
**Real scan of your own machine or lab:** edit `.env`:
```
SECAGENT_TOOL_MODE=live
SECAGENT_ALLOWED_CIDRS=127.0.0.1/32
```
then start the server and open http://127.0.0.1:8000/ (dashboard) or http://127.0.0.1:8000/docs.

### Environment variables (`SECAGENT_` prefix; see `.env.example`)
| Variable | Default | Purpose |
|---|---|---|
| `TOOL_MODE` | `mock` | `mock` fixtures or `live` nmap |
| `ALLOWED_CIDRS` | empty | Live targets must be private/loopback **and** inside this list. Empty = every live scan refused |
| `TOOL_TIMEOUT_S` | 60 | nmap `--host-timeout`; the process is killed 10 s later |
| `MAX_PORTS` | 2000 | Max ports per scan |
| `NMAP_PATH` | auto | Optional explicit `nmap.exe`. Otherwise: `shutil.which('nmap')`, then the default Windows install folders (honours `%ProgramFiles(x86)%` / `%ProgramFiles%`) |
| `NMAP_SKIP_HOST_DISCOVERY` | false | `true` adds `-Pn` for hosts that block ping |
| `AGENTS_ENABLED` / `LLM_API_KEY` / `LLM_MODEL` | true / blank / `anthropic/claude-sonnet-5-5` | Optional agents; `ANTHROPIC_API_KEY` is also read. A blank key means agents are off |
| `SCAN_TIMEOUT_S`, `SCAN_MAX_ATTEMPTS`, `MAX_CONCURRENT_SCANS`, `LOG_LEVEL` | 180, 2, 4, INFO | Service limits |

## API examples
```powershell
# Health (shows tool mode and configured pipeline)
Invoke-RestMethod http://127.0.0.1:8000/health

# Real scan (live mode, allow-listed target)
$body = @{ target = "127.0.0.1"; ports = "22,80,443,8000-8100"; authorization_confirmed = $true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/scan -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 8

# Analyse existing nmap output (-oN text or -oX XML, ONE host); nothing is scanned
$raw = Get-Content scan.xml -Raw
$body = @{ raw_scan_data = $raw; authorization_confirmed = $true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/scan -ContentType "application/json" -Body $body
```
### Confirm nmap really ran (not fallback data)
In the response check: `data_source = "live_nmap"`, `real_scan = true`, and `scan_evidence` (nmap version, the exact
command ending in your target, `exit_code: 0`, `elapsed_s`). In the dashboard the report shows "Real nmap scan" and the command.
Cross-check with `Test-NetConnection 127.0.0.1 -Port 8000`, or start a listener (`python -m http.server 8081`) and scan port 8081.

## Troubleshooting: `TOOL_UNAVAILABLE` (Nmap not found) on Windows
`nmap --version` working in your terminal does not guarantee the **server process** can see Nmap: a terminal or editor opened
before installing Nmap keeps an old `PATH`. SecAgent therefore also checks the default install folders. To diagnose:
```powershell
python scripts\check_nmap.py            # prints every location checked, the one found, and runs `nmap --version`
Invoke-RestMethod http://127.0.0.1:8000/health   # in live mode: "nmap": "found" or "not_found"
```
The error text lists what was checked. Fixes, in order: fully stop and restart `uvicorn` (and open a new terminal), or set the full path in `.env`
using **single quotes or forward slashes**, because inside double quotes `.env` turns `\nmap.exe` into a newline:
```
SECAGENT_NMAP_PATH='C:\Program Files (x86)\Nmap\nmap.exe'
SECAGENT_NMAP_PATH=C:/Program Files (x86)/Nmap/nmap.exe
```
If you still see the message `nmap is not installed on this host.`, you are running an **older copy** of SecAgent (that text no longer exists in the code).

## Safety controls
- Target must be a single IP (no hostnames, CIDRs or URLs). Live mode additionally requires a private/loopback/link-local address **and** membership in `ALLOWED_CIDRS`; public addresses are always refused.
- Nmap argv is built in one function from fixed flags plus validated target/ports; there is no way to pass other options. `shell=False`, hard timeout, port cap, output parsed as XML (entity declarations rejected).
- `authorization_confirmed: true` is required. Secrets are read from the environment, never returned, and redacted from logs.

## Optional: LLM agents and the Anthropic error
Scans work without any key. To enable agents, set `SECAGENT_LLM_API_KEY` (or `ANTHROPIC_API_KEY`) and run
`python scripts/check_llm.py`: it sends a 1-token request and prints Anthropic's exact error (never the key).
A workspace/credential error is an **account** issue (key belongs to a workspace without model access or credits); the script's hints say which HTTP status means what. If agents fail at run time the service falls back to the deterministic pipeline and records a warning.

## Limitations
- CVE matching is **version-string matching** against ~9 curated entries. Findings are *candidates to confirm*, not confirmed vulnerabilities: distro backports and spoofed banners cause false positives, and absence of a match does not mean the host is secure. No exploitation or validation is performed; no retest.
- TCP connect scan only (no UDP, no OS detection, no scripts); `--version-light` favours speed over service-detection depth. A scan that hits the time limit is flagged as possibly incomplete.
- Single host per assessment; one request at a time per scan; no scan history or authentication (keep it on 127.0.0.1).
- Remediation text comes from the local knowledge base, not from live vendor advisories. Verified on Linux with Nmap 7.94; the Windows steps above are untested here.

## Layout
`app/api` routes · `app/schemas` contracts · `app/services` orchestration/analysis · `app/tools` nmap runner, XML parser, guarded tools ·
`app/agents` optional CrewAI · `app/core` config/scope/validators/logging · `app/web` dashboard · `scripts/check_llm.py`, `scripts/check_nmap.py` · `tests/` (81 tests).
