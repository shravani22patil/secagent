"""Parse `nmap -oX -` output. Nmap's XML is the source of truth; nothing is inferred or invented."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.schemas.report import DetectedService


class NmapXmlError(ValueError):
    """Output was not valid, trustworthy nmap XML."""


@dataclass
class NmapRun:
    nmap_version: str | None = None
    elapsed_s: float | None = None
    exit_status: str | None = None
    hosts: list[str] = field(default_factory=list)  # addresses of hosts reported up
    hosts_down: int = 0
    services: list[DetectedService] = field(default_factory=list)  # OPEN ports only
    closed_or_filtered: int = 0

    @property
    def host_up(self) -> bool:
        return bool(self.hosts)


def _clip(v: str | None, n: int) -> str | None:
    v = (v or "").strip()
    return v[:n] if v else None


def parse_nmap_xml(xml_text: str) -> NmapRun:
    if not xml_text or not xml_text.strip():
        raise NmapXmlError("nmap produced no output")
    if "<!ENTITY" in xml_text:  # nmap never emits entities; refuse expansion tricks outright
        raise NmapXmlError("XML entity declarations are not allowed")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapXmlError(f"malformed nmap XML: {exc}") from None
    if root.tag != "nmaprun":
        raise NmapXmlError("not an nmap XML document")

    run = NmapRun(nmap_version=root.get("version"))
    fin = root.find("runstats/finished")
    if fin is not None:
        run.exit_status = fin.get("exit")
        try:
            run.elapsed_s = float(fin.get("elapsed", ""))
        except ValueError:
            pass
    for host in root.findall("host"):
        status = host.find("status")
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if status is None or status.get("state") != "up" or not addr:
            run.hosts_down += 1
            continue
        run.hosts.append(addr)
        for port in host.findall("ports/port"):
            state = port.find("state")
            try:
                num = int(port.get("portid", ""))
            except ValueError:
                continue
            proto = port.get("protocol")
            if state is None or state.get("state") != "open":
                run.closed_or_filtered += 1
                continue
            if proto not in ("tcp", "udp") or not 1 <= num <= 65535:
                continue
            svc = port.find("service")
            attrs = svc.attrib if svc is not None else {}
            run.services.append(DetectedService(
                port=num, protocol=proto, name=_clip(attrs.get("name"), 64) or "unknown",
                product=_clip(attrs.get("product"), 128), version=_clip(attrs.get("version"), 64)))
        for extra in host.findall("ports/extraports"):
            try:
                run.closed_or_filtered += int(extra.get("count", "0"))
            except ValueError:
                pass
    run.services.sort(key=lambda s: (s.port, s.protocol))
    return run
