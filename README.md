# SecAgent

**Automated security assessment with Nmap, FastAPI, and deterministic CVE matching**

SecAgent is a Python application that scans an authorized single host with Nmap, parses the scan's XML output, compares detected service-version evidence with a small local CVE knowledge base, and produces a structured report with remediation guidance.

The core scan and analysis workflow does **not** require an LLM API key. An optional CrewAI-based agent layer is available, but the deterministic workflow is the reliable baseline; the optional LLM path should be treated as experimental until validated end to end.

> **Use responsibly:** Scan only systems you own or have explicit permission to assess. Live scans are restricted to private, loopback, or link-local IP addresses that are also included in the configured allow-list.

## 🚀 Live Demo

**Live Application:** https://secagent-kc32.onrender.com

**API Documentation:** https://secagent-kc32.onrender.com/docs

**Health Check:** https://secagent-kc32.onrender.com/health

The application is deployed on Render. The public demo uses mock scan fixtures to demonstrate the deterministic assessment pipeline without sending network packets to the target.

## What it does

- **Runs Nmap scans** through a FastAPI service, using validated targets and ports.
- **Parses real Nmap XML output** to extract open TCP ports and service details.
- **Matches service-version evidence** against a curated local CVE knowledge base.
- **Generates remediation guidance** and exports structured JSON and Markdown reports.
- **Supports mock mode** for demos and tests without running a network scan.
- **Keeps scan evidence separate from analysis mode**, so a real scan is not confused with mock data or with whether an LLM was used.

## How the workflow works

```text
Request
  ↓
Validate target and ports
  ↓
Check live-scan scope and allow-list
  ↓
Run Nmap (live mode) OR load a fixture (mock mode)
  ↓
Parse Nmap XML into open-port and service observations
  ↓
Compare available service/version evidence with local CVE entries
  ↓
Build remediation guidance and a structured report
  ↓
Return the API response and save JSON/Markdown reports
```

### Understanding the report fields

| Field | Meaning |
|---|---|
| `data_source` | Where observations came from: `live_nmap`, `mock_fixture`, or `provided_scan_data`. |
| `real_scan` | `true` only when an actual Nmap process ran for the request. |
| `scan_evidence` | Evidence for live scans, such as Nmap version, command, exit code, and elapsed time. |
| `execution_mode` | Analysis pipeline used: `agentic` or `deterministic_fallback`. A real Nmap scan can still be analyzed by the deterministic pipeline. |
| `identified_cves` | CVE candidates matched by the current local knowledge base; these are not confirmed vulnerabilities. |
| `recommended_remediation_plan` | Suggested actions derived from the available analysis and remediation data. |

A failed live scan returns an error instead of silently substituting mock results.

## Tech stack

- **Language:** Python
- **API:** FastAPI, Uvicorn
- **Scanning:** Nmap
- **Parsing:** Nmap XML
- **Analysis:** Deterministic service/version matching against a local CVE knowledge base
- **Optional agent layer:** CrewAI and an LLM provider
- **Testing:** pytest

## Setup on Windows

### 1. Install prerequisites

- Python 3.10 or newer
- Nmap for Windows: https://nmap.org/download

During Nmap installation, follow its installer instructions. SecAgent uses a TCP connect scan (`-sT`).

### 2. Open the project folder in PowerShell

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation for the current terminal, you can run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

Install development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Create a local environment file from the example:

```powershell
Copy-Item .env.example .env
```

Check that Nmap is available:

```powershell
nmap --version
```

If the command is not found, configure `SECAGENT_NMAP_PATH` in `.env` with the path to `nmap.exe`. For example:

```dotenv
SECAGENT_NMAP_PATH='C:\Program Files (x86)\Nmap\nmap.exe'
```

Do not commit `.env` or put real API keys in `.env.example`.

### 3. Run the tests

```powershell
python -m pytest -q
```

The test suite mocks scan subprocesses where appropriate, so running tests does not require scanning a real host.

## Run the application

From the project root, start the server:

```powershell
python -m uvicorn app.main:app --reload
```

Open these local addresses in your browser:

- Dashboard: http://127.0.0.1:8000/
- Interactive API documentation: http://127.0.0.1:8000/docs
- Health endpoint: http://127.0.0.1:8000/health

The default configuration is **mock mode**. Mock mode uses fixtures and does not scan a host.

## Run a real scan against an authorized host

1. Open `.env`.
2. Set live mode and explicitly allow the local machine:

```dotenv
SECAGENT_TOOL_MODE=live
SECAGENT_ALLOWED_CIDRS=127.0.0.1/32
```

3. Restart the server after changing the environment.
4. Submit a scan request for `127.0.0.1` from the dashboard or API.

Example PowerShell request:

```powershell
$body = @{
    target = "127.0.0.1"
    ports = "22,80,443,8000-8100"
    authorization_confirmed = $true
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/scan" `
    -ContentType "application/json" `
    -Body $body |
    ConvertTo-Json -Depth 8
```

The example ports are illustrative; the response depends on what is actually listening on the target. A port appearing open does not by itself prove a vulnerability or that the service is exposed beyond the local machine.

### Confirm that a real scan ran

For a live scan, inspect the response for:

- `data_source` set to `live_nmap`
- `real_scan` set to `true`
- `scan_evidence` containing the scan command and execution details

If the scan fails, investigate the returned error; the application is designed not to silently fall back to mock data after a failed live scan.

## Analyze existing Nmap output

The API can also analyze provided scan data without launching a new scan. For example, to submit XML saved as `scan.xml`:

```powershell
$raw = Get-Content .\scan.xml -Raw

$body = @{
    raw_scan_data = $raw
    authorization_confirmed = $true
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/scan" `
    -ContentType "application/json" `
    -Body $body |
    ConvertTo-Json -Depth 8
```

Use scan data from systems you are authorized to assess.

## Configuration

The application reads configuration from environment variables with the `SECAGENT_` prefix. Check `.env.example` for the project's current configuration names.

| Variable | Purpose |
|---|---|
| `SECAGENT_TOOL_MODE` | Selects `mock` or `live` scan mode. |
| `SECAGENT_ALLOWED_CIDRS` | Allow-list required for live targets. An empty allow-list refuses live scans. |
| `SECAGENT_TOOL_TIMEOUT_S` | Nmap host timeout. |
| `SECAGENT_MAX_PORTS` | Maximum number of ports accepted for a scan. |
| `SECAGENT_NMAP_PATH` | Optional explicit path to `nmap.exe`; otherwise the application attempts to locate Nmap. |
| `SECAGENT_NMAP_SKIP_HOST_DISCOVERY` | Enables `-Pn` when set to `true`. |
| `SECAGENT_AGENTS_ENABLED` | Enables the optional agent layer when configured. |
| `SECAGENT_LLM_API_KEY` / `ANTHROPIC_API_KEY` | Optional LLM credentials. Keep keys private and out of Git. |
| `SECAGENT_LLM_MODEL` | Optional model identifier for the configured LLM provider. |

Other scan limits and logging settings are documented in `.env.example` and the application configuration.

## Security controls

- Accepts a single IP address rather than a hostname, URL, or CIDR as the scan target.
- Live scanning requires a private, loopback, or link-local address **and** membership in `SECAGENT_ALLOWED_CIDRS`.
- Requires `authorization_confirmed: true` in scan requests.
- Builds Nmap arguments from validated inputs and uses `shell=False`.
- Applies scan timeouts and a maximum-port limit.
- Parses XML output while rejecting entity declarations.
- Reads secrets from environment configuration rather than returning them in scan reports.

The authorization flag is an explicit user attestation, not an authentication system. Keep the service bound to localhost unless you add appropriate authentication and deployment controls.

## Limitations

- The local CVE knowledge base is small (approximately nine curated entries) and matching is based on available service/version strings. Coverage is incomplete.
- A CVE match is a **candidate for further verification**, not proof that a system is vulnerable. Distribution patches, inaccurate banners, and other factors can affect results.
- No exploitation, independent vulnerability validation, or automated retest is performed.
- The scan workflow uses TCP connect scanning; it does not perform UDP scanning, OS detection, or Nmap scripting.
- Service/version detection may be incomplete. No CVE match does not mean the host is secure.
- Remediation guidance is based on the local knowledge base and generic hardening logic, not live vendor advisories.
- The optional LLM-agent workflow should not be represented as fully validated unless it has been tested with a real configured model and its tool calls.

## Project structure

```text
app/
  api/          API routes
  schemas/      Request and response models
  services/     Scan orchestration, analysis, and reporting
  tools/        Nmap runner, XML parser, and guarded tools
  agents/       Optional CrewAI agent integration
  core/         Configuration, scope checks, validation, and logging
  web/          Dashboard
scripts/        Nmap and optional LLM diagnostic scripts
tests/          Automated tests
```

## Future improvements

- Expand CVE coverage and improve service identification using stronger evidence such as CPE data.
- Make unsupported services and missing version evidence explicit in reports.
- Improve the separation between CVE-specific remediation and general hardening guidance.
- Validate the optional agent layer end to end and add integration tests for tool use.
- Add authenticated access and scan-history management before considering shared or remote deployment.

---

**Status:** The deterministic scan-and-report workflow is the core of the project. Optional LLM-agent capabilities are an extension, not a requirement for scanning.
