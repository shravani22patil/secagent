"""Single source of truth for 'may this host be actively scanned?'. Used by the API and the nmap tool."""
from __future__ import annotations

import ipaddress

from app.core.config import Settings
from app.core.errors import ScopeViolation


def authorize_live_target(settings: Settings, target: str) -> None:
    """Live scans require BOTH: a private/loopback address AND membership in SECAGENT_ALLOWED_CIDRS."""
    ip = ipaddress.ip_address(target)
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ScopeViolation(f"{target} is a public address; SecAgent only scans private/loopback targets")
    try:
        nets = [ipaddress.ip_network(c, strict=False) for c in settings.allowed_cidrs]
    except ValueError as exc:
        raise ScopeViolation(f"invalid SECAGENT_ALLOWED_CIDRS entry: {exc}") from None
    if not any(ip in n for n in nets):
        raise ScopeViolation(f"{target} is outside SECAGENT_ALLOWED_CIDRS; live scan refused")
