"""Parsers for nmap normal-format output and service banners (shared by mock and live modes)."""
from __future__ import annotations

import re

from app.schemas.report import DetectedService

_ROW = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+open(?:\|filtered)?\s+(?P<name>\S+)(?:[ \t]+(?P<rest>.*))?$",
    re.M,
)
_VERSION = re.compile(r"^(?P<product>.*?\S)\s+(?P<version>\d[\w.\-+~]*)(?:\s|$)")
_REPORT = re.compile(r"^Nmap scan report for (?:\S+ \()?(?P<ip>[0-9a-fA-F:.]+)\)?\s*$", re.M)

_BANNER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"SSH-\d\.\d+-OpenSSH_(\S+)", re.I), "OpenSSH"),
    (re.compile(r"vsFTPd (\S+?)\)?(?:\s|$)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD (\S+)", re.I), "ProFTPD"),
    (re.compile(r"Apache/(\S+)", re.I), "Apache httpd"),
    (re.compile(r"nginx/(\S+)", re.I), "nginx"),
    (re.compile(r"Exim (\S+)", re.I), "Exim smtpd"),
]


def split_product_version(rest: str | None) -> tuple[str | None, str | None]:
    rest = (rest or "").strip()
    if not rest:
        return None, None
    m = _VERSION.match(rest)
    if m:
        return m["product"][:128], m["version"][:64]
    return rest[:128], None


def parse_nmap_output(raw: str) -> list[DetectedService]:
    services: dict[tuple[int, str], DetectedService] = {}
    for m in _ROW.finditer(raw):
        port = int(m["port"])
        if not 1 <= port <= 65535:
            continue
        product, version = split_product_version(m["rest"])
        services[(port, m["proto"])] = DetectedService(
            port=port, protocol=m["proto"], name=m["name"][:64], product=product, version=version
        )
    return sorted(services.values(), key=lambda s: (s.port, s.protocol))


def extract_target(raw: str) -> str | None:
    m = _REPORT.search(raw)
    return m["ip"] if m else None


def infer_product_version(banner: str) -> tuple[str | None, str | None]:
    for pattern, product in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            return product, m.group(1).rstrip(");,")
    return None, None


def count_report_hosts(raw: str) -> int:
    return len(_REPORT.findall(raw))
