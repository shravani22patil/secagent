"""Deterministic nmap/banner imitation. Sends no packets. Scenario chosen by int(ip) % 3."""
from __future__ import annotations

import ipaddress
from typing import NamedTuple

from app.core.validators import expand_ports


class Row(NamedTuple):
    port: int
    name: str
    version: str
    banner: str


SCENARIOS: list[list[Row]] = [
    # 0: legacy web/FTP host
    [
        Row(21, "ftp", "vsftpd 2.3.4", "220 (vsFTPd 2.3.4)"),
        Row(22, "ssh", "OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8"),
        Row(80, "http", "Apache httpd 2.4.49 ((Unix))", "HTTP/1.1 200 OK Server: Apache/2.4.49 (Unix)"),
    ],
    # 1: mail/file server
    [
        Row(22, "ssh", "OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)", "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"),
        Row(25, "smtp", "Exim smtpd 4.87", "220 mail ESMTP Exim 4.87 Tue, 01 Jan 2030 00:00:00 +0000"),
        Row(445, "netbios-ssn", "Samba smbd 4.3.11-Ubuntu", "SMB negotiate response"),
    ],
    # 2: hardened host
    [
        Row(22, "ssh", "OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"),
        Row(443, "http", "nginx 1.25.3", "HTTP/1.1 200 OK Server: nginx/1.25.3"),
    ],
]


def scenario_for(target: str) -> list[Row]:
    return SCENARIOS[int(ipaddress.ip_address(target)) % len(SCENARIOS)]


def nmap_output(target: str, ports_spec: str, profile: str) -> str:
    wanted = expand_ports(ports_spec)
    rows = [r for r in scenario_for(target) if r.port in wanted]
    head = ["Starting Nmap 7.94 ( https://nmap.org ) [MOCK BACKEND]", f"Nmap scan report for {target}", "Host is up (0.00040s latency)."]
    if not rows:
        return "\n".join(head + [f"All {len(wanted)} scanned ports on {target} are closed"])
    head += [f"Not shown: {len(wanted) - len(rows)} closed tcp ports (reset)", "PORT      STATE SERVICE     VERSION"]
    for r in rows:
        version = r.version if profile == "service_detection" else ""
        head.append(f"{f'{r.port}/tcp':<9} open  {r.name:<11} {version}".rstrip())
    head.append("Nmap done: 1 IP address (1 host up) scanned in 1.02 seconds")
    return "\n".join(head)


def banner(target: str, port: int) -> str | None:
    for r in scenario_for(target):
        if r.port == port:
            return r.banner
    return None
