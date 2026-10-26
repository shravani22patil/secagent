"""Show exactly how SecAgent finds Nmap, then run `nmap --version` with the resolved path.

    python scripts/check_nmap.py
Uses the same resolver as the scan tool (SECAGENT_NMAP_PATH -> PATH -> default Windows folders).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.config import Settings  # noqa: E402
from app.tools.nmap_runner import resolve_nmap  # noqa: E402


def main() -> int:
    path, checked = resolve_nmap(Settings())
    print(f"platform: {sys.platform}")
    for line in checked:
        print(f"  checked: {line}")
    if not path:
        print("FAIL: nmap not found. Install it from https://nmap.org/download, restart this terminal, "
              "or set SECAGENT_NMAP_PATH in .env (use single quotes or forward slashes).")
        return 1
    print(f"found:    {path}")
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: found but could not run it: {type(exc).__name__}: {exc}")
        return 1
    print(f"runs:     {(out.stdout.splitlines() or ['(no output)'])[0]}  (exit {out.returncode})")
    return 0 if out.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
