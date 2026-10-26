"""Diagnose the Anthropic configuration WITHOUT running a scan. Never prints the API key.

    python scripts/check_llm.py
Reads SECAGENT_LLM_API_KEY (or ANTHROPIC_API_KEY) and SECAGENT_LLM_MODEL, sends a 1-token request, and prints
the HTTP status plus Anthropic's error type/message (redacted). Scans never depend on this succeeding.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.config import Settings  # noqa: E402
from app.core.logging import redact  # noqa: E402


def main() -> int:
    s = Settings()
    if s.llm_api_key is None:
        print("FAIL: no key. Set SECAGENT_LLM_API_KEY (or ANTHROPIC_API_KEY) in .env or the environment.")
        return 1
    key = s.llm_api_key.get_secret_value()
    model = s.llm_model.split("/", 1)[-1]  # 'anthropic/claude-x' -> 'claude-x'
    print(f"key: present ({len(key)} chars, starts '{key[:7]}…')  model: {model}")
    body = json.dumps({"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"OK: HTTP {r.status}. The key and model work; agents can be enabled.")
            return 0
    except urllib.error.HTTPError as e:
        try:
            err = json.load(e).get("error", {})
        except Exception:  # noqa: BLE001
            err = {}
        print(redact(f"FAIL: HTTP {e.code} type={err.get('type')} message={err.get('message')}"))
        print("Hints: 401 = key invalid/revoked; 403/404 = key's workspace lacks access to this model; "
              "400 mentioning credit = add billing/credits to the key's workspace; 429 = rate limit.")
    except urllib.error.URLError as e:
        print(redact(f"FAIL: could not reach api.anthropic.com ({e.reason})"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
