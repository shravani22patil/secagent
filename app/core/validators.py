"""Pure, dependency-free input validation and sanitisation helpers."""
from __future__ import annotations

import ipaddress
import re

_PORT_SPEC = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def validate_ip(value: str) -> str:
    v = str(value).strip()
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(
            f"{value!r} is not a valid IPv4/IPv6 address "
            "(hostnames, URLs and CIDR ranges are not accepted)"
        ) from None
    if ip.is_multicast or ip.is_unspecified:
        raise ValueError(f"{v} is a multicast/unspecified address and cannot be scanned")
    return str(ip)


def validate_port_spec(value: str) -> str:
    v = str(value).replace(" ", "")
    if len(v) > 100 or not _PORT_SPEC.match(v):
        raise ValueError("ports must look like '22,80,443' or '1-1024' or '22,80,8000-8100'")
    for part in v.split(","):
        lo, _, hi = part.partition("-")
        lo_i, hi_i = int(lo), int(hi or lo)
        if not (1 <= lo_i <= 65535 and 1 <= hi_i <= 65535 and lo_i <= hi_i):
            raise ValueError(f"port range {part!r} is outside 1-65535 or reversed")
    return v


def expand_ports(spec: str) -> set[int]:
    out: set[int] = set()
    for part in validate_port_spec(spec).split(","):
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def sanitize_banner(raw: str, limit: int = 200) -> str:
    """Banners are attacker-controlled: strip control chars, collapse whitespace, truncate."""
    cleaned = _CONTROL.sub(" ", raw)
    return re.sub(r"\s+", " ", cleaned).strip()[:limit]


def version_tuple(version: str) -> tuple[int, ...]:
    """'7.2p2' -> (7, 2, 2); '4.3.11-Ubuntu' -> (4, 3, 11). Empty tuple if no digits."""
    return tuple(int(x) for x in re.findall(r"\d+", version or ""))
