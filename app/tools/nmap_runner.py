"""Run nmap safely: fixed argv list, shell=False, validated inputs only, XML on stdout, hard timeout."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings
from app.core.errors import ScopeViolation, ToolExecutionError
from app.core.scope import authorize_live_target
from app.core.validators import sanitize_banner, validate_ip, validate_port_spec
from app.tools.nmap_xml import NmapRun, NmapXmlError, parse_nmap_xml



def _is_windows() -> bool:  # module-level so tests can simulate Windows without touching os.name
    return sys.platform == "win32"


def _isfile(path: str) -> bool:
    return os.path.isfile(path)


def _windows_known_paths() -> list[str]:
    """Fixed install locations only (never built from user input). Honours non-C: drives via env vars."""
    roots = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"),
             r"C:\Program Files (x86)", r"C:\Program Files"]
    out: list[str] = []
    for root in roots:
        if root:
            p = root.rstrip("\\/") + "\\Nmap\\nmap.exe"
            if p not in out:
                out.append(p)
    return out


def resolve_nmap(settings: Settings) -> tuple[str | None, list[str]]:
    """Return (executable path or None, human-readable list of what was checked).

    Order: explicit SECAGENT_NMAP_PATH (opt-in) -> shutil.which('nmap') -> known Windows install folders.
    The diagnostics contain only file paths, never environment contents or secrets.
    """
    checked: list[str] = []
    explicit = (settings.nmap_path or "").strip().strip("\"'").strip()
    if explicit:
        if any(ord(ch) < 32 for ch in explicit):
            checked.append("SECAGENT_NMAP_PATH contains a control character (inside double quotes, .env turns "
                           "'\\n' in '\\Nmap\\nmap.exe' into a newline; use single quotes or forward slashes)")
        elif _isfile(explicit):
            return explicit, checked
        else:
            checked.append(f'SECAGENT_NMAP_PATH="{explicit}" (file not found)')
    found = shutil.which("nmap")
    if found:
        return found, checked
    checked.append("PATH lookup for 'nmap' (not found by this server process)")
    if _is_windows():
        for p in _windows_known_paths():
            if _isfile(p):
                return p, checked
            checked.append(f"{p} (not found)")
    return None, checked


def find_nmap(settings: Settings) -> str:
    path, checked = resolve_nmap(settings)
    if path:
        return path
    raise ToolExecutionError(
        "TOOL_UNAVAILABLE", "nmap executable not found. Checked: " + "; ".join(checked) + ".", retryable=False,
        hint="Install Nmap from https://nmap.org/download, then fully restart the SecAgent server (a terminal "
             "opened before the install has an old PATH), or set SECAGENT_NMAP_PATH to the full path of nmap.exe.")


@dataclass
class LiveScan:
    run: NmapRun
    raw_xml: str
    evidence: dict[str, Any]
    notes: list[str] = field(default_factory=list)


def build_argv(nmap: str, settings: Settings, target: str, ports: str, profile: str) -> list[str]:
    """The ONLY place a command line is built. Callers cannot add flags: every element is fixed or validated."""
    argv = [nmap, "-oX", "-", "-n", "-sT", "-T3", "--host-timeout", f"{int(settings.tool_timeout_s)}s", "-p", ports]
    if profile == "service_detection":
        argv += ["-sV", "--version-light"]  # fewer probes: faster, still real service detection
    if settings.nmap_skip_host_discovery:
        argv.append("-Pn")
    argv.append(target)
    return argv


def run_nmap(settings: Settings, target: str, ports: str, profile: str) -> LiveScan:
    target, ports = validate_ip(target), validate_port_spec(ports)  # re-validate at the boundary
    if profile not in ("quick", "service_detection"):
        raise ToolExecutionError("INVALID_ARGUMENTS", "unknown scan profile", hint="Use 'quick' or 'service_detection'.")
    try:
        authorize_live_target(settings, target)
    except ScopeViolation as exc:
        raise ToolExecutionError("OUT_OF_SCOPE", str(exc), retryable=False,
                                 hint="This target is not authorised for live scanning. Do not retry.") from None
    exe = find_nmap(settings)
    argv = build_argv(exe, settings, target, ports, profile)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=settings.tool_timeout_s + 10, shell=False, check=False)
    except subprocess.TimeoutExpired:
        raise ToolExecutionError(
            "TOOL_TIMEOUT", f"nmap exceeded the {settings.tool_timeout_s:.0f}s limit and was stopped.",
            hint="Retry with fewer ports (e.g. '22,80,443') or scan_profile='quick'.") from None
    except OSError as exc:  # FileNotFoundError, PermissionError, WinError 193 (not a valid executable), ...
        raise ToolExecutionError(
            "TOOL_UNAVAILABLE", f'nmap at "{exe}" could not be started: {exc.strerror or type(exc).__name__}.',
            retryable=False, hint="Check that SECAGENT_NMAP_PATH (or the installed nmap.exe) is a working Nmap "
                                  "executable that this user may run.") from None
    if proc.returncode != 0:
        raise ToolExecutionError("TOOL_FAILED", f"nmap exited with code {proc.returncode}: {sanitize_banner(proc.stderr, 200)}",
                                 retryable=False, hint="Do not retry; report the failure.")
    try:
        run = parse_nmap_xml(proc.stdout)
    except NmapXmlError as exc:
        raise ToolExecutionError("TOOL_BAD_OUTPUT", f"nmap output could not be parsed: {exc}", retryable=False) from None
    notes: list[str] = []
    if run.elapsed_s is not None and run.elapsed_s >= settings.tool_timeout_s - 1:
        notes.append(f"nmap hit its {settings.tool_timeout_s:.0f}s time limit; results may be incomplete "
                     "(raise SECAGENT_TOOL_TIMEOUT_S or scan fewer ports).")
    evidence = {"tool": "nmap", "nmap_version": run.nmap_version, "command": [re.split(r"[\\/]", argv[0])[-1], *argv[1:]],
                "exit_code": proc.returncode, "elapsed_s": run.elapsed_s, "hosts_up": len(run.hosts)}
    return LiveScan(run=run, raw_xml=proc.stdout, evidence=evidence, notes=notes)
