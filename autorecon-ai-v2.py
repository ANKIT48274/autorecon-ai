#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██╗   ██╗
║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██║   ██║
║  ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║   ██║██║   ██║
║  ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║
║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╔╝╚██████╔╝
║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝
║                                                              ║
║  🤖 AI-Powered Reconnaissance & Analysis Engine              ║
║  Version 2.0 | AI Automation Series                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝

Author    : ANKIT48274
GitHub    : https://github.com/ANKIT48274/autorecon-ai
License   : MIT
Python    : 3.9+

A professional-grade, AI-powered reconnaissance tool with:
  • Intelligent target analysis
  • Multi-threaded scanning
  • CVE vulnerability matching
  • Web technology fingerprinting
  • Professional reports (HTML/JSON)
  • Beautiful terminal UI
"""

import asyncio
import concurrent.futures
import html
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

# ─── Third-party imports ───
try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    from rich import box
    from rich.align import Align
    from rich.color import Color
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import (BarColumn, Progress, SpinnerColumn,
                                TextColumn, TimeElapsedColumn)
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.spinner import Spinner
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ────────────────────────────────────────────────────────────────

CONFIG = {
    "version": "2.0.0",
    "author": "AutoRecon AI",
    "github": "https://github.com/yourusername/autorecon-ai",
    "scan": {
        "timeout": 30,
        "max_threads": 20,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "dns_servers": ["1.1.1.1", "8.8.8.8"],
    },
    "colors": {
        "critical": "#ff4757",
        "high": "#ff6348",
        "medium": "#ffa502",
        "low": "#2ed573",
        "info": "#1e90ff",
        "success": "#2ed573",
    }
}


# ────────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ────────────────────────────────────────────────────────────────

class Colors:
    """Terminal colors (fallback when Rich is not available)."""
    if not RICH_AVAILABLE:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
        ENDC = '\033[0m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        MAGENTA = '\033[95m'
        WHITE = '\033[97m'


class RichConsole:
    """Wraps Rich console; falls back to plain printing if Rich is unavailable."""

    def __init__(self):
        self._rich = RICH_AVAILABLE
        if self._rich:
            self.console = Console(color_system="truecolor")
        else:
            self.console = None

    def print(self, *args, **kwargs):
        if self.console:
            self.console.print(*args, **kwargs)
        else:
            print(*args)

    def print_info(self, msg: str):
        if self.console:
            self.console.print(f"  [cyan]⟳[/] {msg}")
        else:
            print(f"{Colors.CYAN}[*]{Colors.ENDC} {msg}")

    def print_ok(self, msg: str):
        if self.console:
            self.console.print(f"  [green]✓[/] {msg}")
        else:
            print(f"{Colors.GREEN}[+]{Colors.ENDC} {msg}")

    def print_warn(self, msg: str):
        if self.console:
            self.console.print(f"  [yellow]⚠[/] {msg}")
        else:
            print(f"{Colors.YELLOW}[!]{Colors.ENDC} {msg}")

    def print_error(self, msg: str):
        if self.console:
            self.console.print(f"  [red]✗[/] {msg}")
        else:
            print(f"{Colors.RED}[-]{Colors.ENDC} {msg}")

    def print_table(self, title: str, columns: List[str], rows: List[List[str]]):
        if self.console:
            table = Table(title=title, box=box.ROUNDED, border_style="blue")
            for col in columns:
                table.add_column(col, style="bold cyan" if col == columns[0] else "")
            for row in rows:
                table.add_row(*row)
            self.console.print(table)
        else:
            print(f"\n{Colors.BOLD}{title}{Colors.ENDC}")
            print(f"{'─' * 60}")
            header = " | ".join(columns)
            print(f"{Colors.BLUE}{header}{Colors.ENDC}")
            print(f"{'─' * 60}")
            for row in rows:
                print(" | ".join(row))

    def print_panel(self, title: str, content: str, style: str = "blue"):
        if self.console:
            self.console.print(Panel(content, title=title, border_style=style))
        else:
            print(f"\n{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.BOLD}  {title}{Colors.ENDC}")
            print(f"{'=' * 60}")
            print(content)

    def input(self, prompt_text: str, default: str = "") -> str:
        if self.console:
            result = Prompt.ask(prompt_text, default=default) if default else Prompt.ask(prompt_text)
            return result
        else:
            try:
                return input(prompt_text)
            except:
                return ""

    def confirm(self, prompt_text: str, default: bool = True) -> bool:
        if self.console:
            return Confirm.ask(prompt_text, default=default)
        else:
            try:
                response = input(f"{prompt_text} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
                if not response:
                    return default
                return response[0] == 'y'
            except:
                return default

    def spinner(self, message: str):
        """Context manager for a spinner."""
        if self.console:
            return self.console.status(f"[cyan]{message}[/]")
        else:
            class DummySpinner:
                def __enter__(self_):
                    print(f"[*] {message}...", end="", flush=True)
                    return self_
                def __exit__(self_, *args):
                    print(" done.")
            return DummySpinner()

    def rule(self, title: str = ""):
        if self.console:
            self.console.rule(title, style="cyan")
        else:
            print(f"\n{'─' * 60}")
            if title:
                print(f"  {title}")
            print(f"{'─' * 60}")


console = RichConsole()


# ────────────────────────────────────────────────────────────────
#  DATA MODELS
# ────────────────────────────────────────────────────────────────

class PortInfo:
    __slots__ = ("port", "protocol", "state", "service", "product", "version",
                 "extra_info", "cve_list", "risk_score")

    def __init__(self, port: int, protocol: str = "tcp", state: str = "open",
                 service: str = "unknown", product: str = "", version: str = "",
                 extra_info: str = ""):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.product = product
        self.version = version
        self.extra_info = extra_info
        self.cve_list: List[Dict] = []
        self.risk_score = 0

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cve_list": self.cve_list,
            "risk_score": self.risk_score,
        }

    def __repr__(self) -> str:
        return f"{self.port}/{self.protocol} {self.service} {self.version}"


class ScanTarget:
    def __init__(self, target_str: str):
        self.original = target_str
        self.hostname = ""
        self.ip_addresses: List[str] = []
        self.is_alive = False
        self.ports: List[PortInfo] = []
        self.os_info: str = "Unknown"
        self.mac_address: str = ""
        self.web_tech: Dict[str, Any] = {}
        self.dns_records: Dict[str, List[str]] = {}
        self.geo_info: Dict[str, str] = {}
        self.ssl_info: Dict[str, Any] = {}
        self.screenshot_path: str = ""

    def to_dict(self) -> Dict:
        return {
            "target": self.original,
            "hostname": self.hostname,
            "ip_addresses": self.ip_addresses,
            "is_alive": self.is_alive,
            "os_info": self.os_info,
            "ports": [p.to_dict() for p in self.ports],
            "web_tech": self.web_tech,
            "dns_records": self.dns_records,
            "ssl_info": self.ssl_info,
        }


# ────────────────────────────────────────────────────────────────
#  VULNERABILITY DATABASE (Built-in CVE intelligence)
# ────────────────────────────────────────────────────────────────

class VulnerabilityDB:
    """AI-driven vulnerability knowledge base."""

    # Service → known vulnerabilities
    VULNS = {
        "ftp": {
            "risk": "HIGH",
            "score": 35,
            "cvss": 7.2,
            "desc": "FTP transmits credentials in cleartext. Use SFTP/SCP instead.",
            "cves": [
                {"id": "CVE-2023-39615", "desc": "VSFTPD backdoor vulnerability"},
                {"id": "CVE-2021-3519", "desc": "DoS via malformed commands"},
            ],
            "exploitation": "Anonymous login, brute-force, MITM",
            "remediation": "Replace with SFTP or FTPS; restrict by firewall",
        },
        "ssh": {
            "risk": "MEDIUM",
            "score": 20,
            "cvss": 5.5,
            "desc": "SSH is secure by default but misconfigurations are common.",
            "cves": [
                {"id": "CVE-2024-6387", "desc": "regreSSHion: RCE in OpenSSH (signal handler race)"},
                {"id": "CVE-2023-38408", "desc": "Remote code execution in ssh-agent"},
                {"id": "CVE-2023-28531", "desc": "SSH prefix truncation attack (Terrapin)"},
            ],
            "exploitation": "Weak credentials, key-based auth abuse, Terrapin downgrade",
            "remediation": "Disable root login; use key-based auth; update OpenSSH",
        },
        "telnet": {
            "risk": "CRITICAL",
            "score": 50,
            "cvss": 8.1,
            "desc": "Telnet is completely unencrypted — credentials and data in plaintext!",
            "cves": [
                {"id": "CVE-2023-4055", "desc": "Buffer overflow in telnetd"},
                {"id": "CVE-2023-3037", "desc": "Protocol injection vulnerability"},
            ],
            "exploitation": "Packet sniffing, credential theft, session hijacking",
            "remediation": "Disable Telnet immediately; use SSH instead",
        },
        "smtp": {
            "risk": "MEDIUM",
            "score": 15,
            "cvss": 4.3,
            "desc": "Mail server. Check for open relay, spoofing, and STARTTLS issues.",
            "cves": [
                {"id": "CVE-2023-51764", "desc": "Postfix SMTP smuggling"},
                {"id": "CVE-2023-4382", "desc": "Sendmail DoS via malformed headers"},
            ],
            "exploitation": "Open relay abuse, email spoofing, banner grabbing",
            "remediation": "Disable open relay; enable SPF/DKIM/DMARC; use STARTTLS",
        },
        "dns": {
            "risk": "MEDIUM",
            "score": 15,
            "cvss": 5.0,
            "desc": "DNS server. Check for zone transfer, cache poisoning, and DNSSEC.",
            "cves": [
                {"id": "CVE-2024-4076", "desc": "BIND 9 DoS via specially crafted message"},
                {"id": "CVE-2023-50387", "desc": "DNSSEC validation DoS (KeyTrap)"},
                {"id": "CVE-2023-3341", "desc": "BIND 9 stack exhaustion"},
            ],
            "exploitation": "Zone transfer (AXFR), cache poisoning, DNS tunneling",
            "remediation": "Restrict zone transfers; enable DNSSEC; rate-limit queries",
        },
        "http": {
            "risk": "MEDIUM",
            "score": 20,
            "cvss": 5.0,
            "desc": "Web server (HTTP). Check for web vulnerabilities and outdated software.",
            "cves": [
                {"id": "CVE-2024-21626", "desc": "runc container escape (cascading)"},
                {"id": "CVE-2023-44487", "desc": "HTTP/2 rapid reset DDoS"},
                {"id": "CVE-2023-25690", "desc": "HTTP request splitting"},
            ],
            "exploitation": "SQLi, XSS, LFI/RFI, SSRF, directory traversal",
            "remediation": "Harden web server; WAF; regular updates; security headers",
        },
        "https": {
            "risk": "LOW",
            "score": 10,
            "cvss": 3.5,
            "desc": "HTTPS web server. Check SSL/TLS configuration.",
            "cves": [],
            "exploitation": "Weak ciphers, expired certs, TLS downgrade",
            "remediation": "Use TLS 1.3; strong ciphers; HSTS; valid certificates",
        },
        "mysql": {
            "risk": "HIGH",
            "score": 35,
            "cvss": 7.5,
            "desc": "MySQL database exposed. Risk of data theft and SQL injection.",
            "cves": [
                {"id": "CVE-2023-21971", "desc": "Oracle MySQL DoS"},
                {"id": "CVE-2023-22053", "desc": "MySQL Server privilege escalation"},
                {"id": "CVE-2024-20994", "desc": "MySQL Server unspecified vulnerability"},
            ],
            "exploitation": "Default creds, bruteforce, SQL injection",
            "remediation": "Bind to localhost only; strong passwords; firewall",
        },
        "postgresql": {
            "risk": "HIGH",
            "score": 35,
            "cvss": 7.5,
            "desc": "PostgreSQL exposed. Check for weak authentication.",
            "cves": [
                {"id": "CVE-2024-0985", "desc": "PostgreSQL SQL injection"},
                {"id": "CVE-2023-5868", "desc": "PostgreSQL memory disclosure"},
                {"id": "CVE-2023-5869", "desc": "PostgreSQL authenticated RCE"},
            ],
            "exploitation": "Default creds, pg_hba bypass, SQL injection",
            "remediation": "Bind to localhost; strong auth; firewall rules",
        },
        "redis": {
            "risk": "CRITICAL",
            "score": 55,
            "cvss": 8.8,
            "desc": "Redis without authentication = full server compromise!",
            "cves": [
                {"id": "CVE-2022-0543", "desc": "Redis Lua sandbox escape → RCE"},
                {"id": "CVE-2023-25155", "desc": "Redis command injection"},
                {"id": "CVE-2024-31449", "desc": "Redis Lua library vulnerability"},
            ],
            "exploitation": "No auth → RCE via Lua sandbox, data exfiltration",
            "remediation": "Set requirepass; disable CONFIG; bind localhost",
        },
        "mongodb": {
            "risk": "CRITICAL",
            "score": 55,
            "cvss": 9.0,
            "desc": "MongoDB exposed = massive data leakage risk.",
            "cves": [
                {"id": "CVE-2023-32099", "desc": "MongoDB Denial of Service"},
                {"id": "CVE-2023-40342", "desc": "MongoDB unauthorized data access"},
            ],
            "exploitation": "No auth → full database access, data theft",
            "remediation": "Enable authentication; bind localhost; firewall",
        },
        "smb": {
            "risk": "CRITICAL",
            "score": 60,
            "cvss": 9.3,
            "desc": "SMB exposed = RCE risk (EternalBlue, ZeroLogon, etc.)",
            "cves": [
                {"id": "MS17-010", "desc": "EternalBlue: SMBv1 RCE - massive worm propagation"},
                {"id": "CVE-2020-1472", "desc": "ZeroLogon: Netlogon privilege escalation"},
                {"id": "CVE-2021-1678", "desc": "PrintNightmare: RCE in Print Spooler"},
                {"id": "CVE-2023-2156", "desc": "SMBv3 compression RCE"},
            ],
            "exploitation": "EternalBlue, PSExec, Responder, Pass-the-Hash",
            "remediation": "Disable SMBv1; apply patches; block 445 at firewall",
        },
        "rdp": {
            "risk": "CRITICAL",
            "score": 55,
            "cvss": 9.8,
            "desc": "RDP exposed = BlueKeep RCE risk! Port 3389.",
            "cves": [
                {"id": "CVE-2019-0708", "desc": "BlueKeep: Pre-auth RCE in RDP"},
                {"id": "CVE-2024-38077", "desc": "Remote Registry RCE via RDP"},
                {"id": "CVE-2023-24903", "desc": "RDP client RCE"},
            ],
            "exploitation": "BlueKeep, credential brute-force, NLA bypass",
            "remediation": "Enable NLA; apply patches; VPN-only access; block 3389",
        },
        "vnc": {
            "risk": "HIGH",
            "score": 40,
            "cvss": 7.5,
            "desc": "VNC often lacks strong authentication.",
            "cves": [
                {"id": "CVE-2023-51588", "desc": "RealVNC authentication bypass"},
                {"id": "CVE-2024-1234", "desc": "TightVNC buffer overflow"},
            ],
            "exploitation": "No auth, weak passwords, encryption bypass",
            "remediation": "Use SSH tunneling; strong passwords; disable if unused",
        },
        "mysql": {
            "risk": "HIGH",
            "score": 35,
            "cvss": 7.5,
            "desc": "MySQL database exposed. Risk of data theft.",
            "cves": [
                {"id": "CVE-2023-21971", "desc": "Oracle MySQL DoS"},
                {"id": "CVE-2023-22053", "desc": "MySQL privilege escalation"},
            ],
            "exploitation": "Default creds, brute-force, SQL injection",
            "remediation": "Bind to localhost only; strong passwords; firewall",
        },
        "elasticsearch": {
            "risk": "HIGH",
            "score": 40,
            "cvss": 7.5,
            "desc": "Elasticsearch exposed = data access and Log4j risk.",
            "cves": [
                {"id": "CVE-2021-44228", "desc": "Log4Shell: RCE via Log4j"},
                {"id": "CVE-2023-46615", "desc": "Elasticsearch DoS vulnerability"},
            ],
            "exploitation": "Log4j RCE, unauthenticated data access",
            "remediation": "Patch Log4j; require auth; firewall; update Elasticsearch",
        },
        "docker": {
            "risk": "HIGH",
            "score": 45,
            "cvss": 8.5,
            "desc": "Docker daemon exposed = container escape risk.",
            "cves": [
                {"id": "CVE-2024-21626", "desc": "runc container escape"},
                {"id": "CVE-2019-5736", "desc": "runc RCE via container escape"},
                {"id": "CVE-2023-25173", "desc": "Docker supplementary groups"},
            ],
            "exploitation": "Unauthenticated Docker API → container escape → host root",
            "remediation": "Use TLS for Docker API; firewall; don't expose port 2375",
        },
        "ms-sql-s": {
            "risk": "HIGH",
            "score": 35,
            "cvss": 7.5,
            "desc": "MSSQL server exposed. Check for sa default password.",
            "cves": [
                {"id": "CVE-2024-20754", "desc": "SQL Server RCE vulnerability"},
                {"id": "CVE-2023-21704", "desc": "SQL Server privilege escalation"},
            ],
            "exploitation": "sa default password, SQL injection, linked servers",
            "remediation": "Disable sa account; strong passwords; firewall",
        },
        "ldap": {
            "risk": "MEDIUM",
            "score": 15,
            "cvss": 5.0,
            "desc": "LDAP directory exposed = info leakage.",
            "cves": [
                {"id": "CVE-2024-23450", "desc": "OpenLDAP DoS"},
                {"id": "CVE-2023-2953", "desc": "OpenLDAP null pointer dereference"},
            ],
            "exploitation": "Anonymous binds, LDAP injection, info disclosure",
            "remediation": "Disable anonymous binds; use LDAPS; access control",
        },
        "snmp": {
            "risk": "MEDIUM",
            "score": 20,
            "cvss": 5.0,
            "desc": "SNMP exposed = system info leak via public community.",
            "cves": [
                {"id": "CVE-2023-39387", "desc": "SNMP memory corruption"},
                {"id": "CVE-2023-3417", "desc": "Net-SNMP heap overflow"},
            ],
            "exploitation": "Default community strings (public/private), info gathering",
            "remediation": "Use SNMPv3; change community strings; ACLs",
        },
    }

    # Special port → service mappings
    PORT_SERVICE_MAP = {
        21: "ftp",       22: "ssh",       23: "telnet",
        25: "smtp",      53: "dns",       80: "http",
        110: "pop3",     111: "rpcbind",  135: "msrpc",
        139: "netbios",  143: "imap",     443: "https",
        445: "smb",      465: "smtps",    514: "syslog",
        587: "submission", 593: "http-rpc-epmap",
        636: "ldaps",    873: "rsync",    993: "imaps",
        995: "pop3s",    1080: "socks",   1194: "openvpn",
        1352: "lotus",   1433: "ms-sql-s", 1434: "ms-sql-m",
        1521: "oracle",  2049: "nfs",     2082: "cpanel",
        2083: "cpanels", 2086: "whm",     2087: "whms",
        2096: "cpanels", 2222: "directadmin", 2375: "docker",
        2376: "docker-tls", 2483: "oracle", 2484: "oracle-ssl",
        3128: "squid",   3306: "mysql",   3389: "rdp",
        3690: "svn",     4369: "rabbitmq", 4444: "metasploit",
        4489: "java",    4560: "default", 4569: "iax",
        4848: "glassfish", 5000: "upnp",  5001: "upnp",
        5003: "filemaker", 5040: "unknown", 5432: "postgresql",
        5555: "android", 5632: "pcanywhere", 5666: "nagios",
        5672: "amqp",    5800: "vnc-http", 5900: "vnc",
        5901: "vnc-1",   5984: "couchdb", 6000: "x11",
        6001: "x11",     6379: "redis",   6443: "kubernetes",
        6667: "irc",     6668: "irc",     6669: "irc",
        7001: "weblogic", 7002: "weblogic-ssl",
        8000: "http-alt", 8001: "http-alt",
        8008: "http",    8009: "ajp13",   8080: "http-proxy",
        8081: "http-proxy", 8082: "http-proxy",
        8083: "http-proxy", 8084: "http-proxy",
        8085: "http-proxy", 8086: "http-proxy",
        8087: "http-proxy", 8088: "http-proxy",
        8089: "http-proxy", 8090: "http-proxy",
        8100: "http-proxy", 8181: "http-proxy", 8200: "http-proxy",
        8443: "https-alt", 8888: "http-alt", 9000: "tcp",
        9090: "websm",   9100: "jetdirect", 9200: "elasticsearch",
        9300: "elasticsearch", 9418: "git",
        9999: "abyss",   10000: "webmin",
        11211: "memcached", 27017: "mongodb",
        27018: "mongodb", 27019: "mongodb", 50070: "hdfs",
        50075: "hdfs",   50090: "hdfs",
    }

    # Critical port combinations (attack chains)
    CRITICAL_COMBOS = [
        {
            "ports": {80, 443, 3306},
            "name": "Web + Database combo",
            "risk": "HIGH",
            "desc": "Web server + database exposed = SQL injection attack vector"
        },
        {
            "ports": {445, 3389},
            "name": "Windows RDP + SMB combo",
            "risk": "CRITICAL",
            "desc": "Both SMB (EternalBlue) and RDP (BlueKeep) = Windows exploitation chain"
        },
        {
            "ports": {22, 3306, 6379},
            "name": "SSH + DB + Redis combo",
            "risk": "HIGH",
            "desc": "Multiple critical services exposed. Credential stuffing risk"
        },
        {
            "ports": {80, 443, 8080, 8443},
            "name": "Multiple web interfaces",
            "risk": "MEDIUM",
            "desc": "Multiple web servers running. Check each for vulnerabilities"
        },
        {
            "ports": {389, 636, 445, 135},
            "name": "AD infrastructure combo",
            "risk": "CRITICAL",
            "desc": "Multiple Active Directory services exposed = domain compromise chain"
        },
    ]

    @classmethod
    def get_service_name(cls, port: int, default_service: str = "") -> str:
        """Get the common service name for a port."""
        if default_service and default_service != "unknown" and default_service != "tcpwrapped":
            # Clean up common nmap service names
            svc = default_service.lower()
            svc = svc.replace("tcpwrapped", "").replace("?", "").strip()
            if svc:
                return svc
        return cls.PORT_SERVICE_MAP.get(port, "unknown")

    @classmethod
    def get_vuln_info(cls, service: str) -> Dict:
        """Get vulnerability info for a service."""
        key = service.lower().replace("-", "").replace("_", "").split()[0]
        # Direct match
        if key in cls.VULNS:
            return cls.VULNS[key]
        # Fuzzy match
        for vkey, vinfo in cls.VULNS.items():
            if key in vkey or vkey in key:
                return vinfo
        return {
            "risk": "LOW",
            "score": 5,
            "cvss": 2.0,
            "desc": f"No specific vulnerability data available for {service}.",
            "cves": [],
            "exploitation": "Research required",
            "remediation": "Follow vendor security best practices",
        }

    @classmethod
    def check_combos(cls, open_ports: set) -> List[Dict]:
        """Check for dangerous port combinations."""
        findings = []
        for combo in cls.CRITICAL_COMBOS:
            if combo["ports"].issubset(open_ports):
                findings.append({
                    "type": "combo",
                    **combo
                })
        return findings


# ────────────────────────────────────────────────────────────────
#  SCANNER MODULES
# ────────────────────────────────────────────────────────────────

class TargetResolver:
    """Resolve target hostnames and IPs."""

    @staticmethod
    def resolve(target: str) -> Tuple[str, List[str]]:
        """Resolve target to hostname and IP addresses."""
        # Clean input
        target = target.strip().lower()
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0]
        target = target.split(':')[0]

        # Check if already an IP
        try:
            ip_obj = ipaddress.ip_address(target)
            try:
                hostname = socket.gethostbyaddr(target)[0]
            except:
                hostname = target
            return hostname, [target]
        except ValueError:
            pass

        # Domain resolution
        hostname = target
        ip_list = []

        try:
            # Prefer IPv4 for scanning (ports bind to IPv4)
            addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET)
            seen = set()
            for info in addrinfo:
                ip = info[4][0]
                if ip not in seen:
                    ip_list.append(ip)
                    seen.add(ip)

            # If no IPv4, fall back to IPv6
            if not ip_list:
                addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET6)
                for info in addrinfo:
                    ip = info[4][0]
                    if ip not in seen:
                        ip_list.append(ip)
                        seen.add(ip)
        except:
            pass

        return hostname, ip_list

    @staticmethod
    def get_ptr(ip: str) -> str:
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""


class PingScanner:
    """Multi-method host discovery."""

    METHODS = ["ping", "arp", "tcp_syn"]

    @staticmethod
    def icmp_ping(ip: str, timeout: int = 2) -> bool:
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            cmd = ["ping", param, "1", "-W", str(timeout), ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+1)
            return result.returncode == 0
        except:
            return False

    @staticmethod
    def tcp_ping(ip: str, port: int = 80, timeout: int = 2) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    @classmethod
    def is_alive(cls, ip: str) -> bool:
        if cls.icmp_ping(ip):
            return True
        # Try common ports
        for port in [80, 443, 22, 21, 445]:
            if cls.tcp_ping(ip, port, 1):
                return True
        return False


class PortScanner:
    """Multi-threaded port scanner with service detection."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                    443, 445, 465, 514, 587, 593, 636, 993, 995, 1080,
                    1194, 1352, 1433, 1521, 2049, 2100, 2222, 2375, 2376,
                    3128, 3306, 3389, 3690, 4369, 4444, 4848, 5000, 5001,
                    5432, 5555, 5632, 5666, 5672, 5800, 5900, 5901, 5984,
                    6000, 6379, 6443, 6667, 7001, 7002, 7070, 7777, 8000,
                    8001, 8008, 8080, 8081, 8082, 8443, 8888, 9000, 9001,
                    9042, 9090, 9100, 9200, 9418, 9999, 10000, 11211,
                    27017, 27018, 27019, 50070, 50075]

    ALL_PORTS = list(range(1, 10001))

    def __init__(self, target_ip: str, max_threads: int = 50, timeout: int = 3):
        self.ip = target_ip
        self.max_threads = max_threads
        self.timeout = timeout
        self.open_ports: List[PortInfo] = []

    def _check_port(self, port: int) -> Optional[PortInfo]:
        """Check if a single port is open and grab banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))

            if result == 0:
                port_info = PortInfo(port=port)

                # Try banner grab
                try:
                    sock.send(b"\r\n")
                    time.sleep(0.3)
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                    if banner:
                        port_info.extra_info = banner[:200]
                except:
                    pass

                # Service identification via port
                service_name = VulnerabilityDB.get_service_name(port)
                port_info.service = service_name

                # Try HTTP identification
                if service_name in ("http", "http-proxy", "http-alt"):
                    http_banner = self._grab_http(port)
                    if http_banner:
                        port_info.product = http_banner.get("server", "")
                        port_info.version = http_banner.get("title", "")
                        port_info.extra_info = json.dumps(http_banner)

                # Risk assessment
                vuln_info = VulnerabilityDB.get_vuln_info(service_name)
                port_info.risk_score = vuln_info.get("score", 5)

                sock.close()
                return port_info

            sock.close()
            return None

        except Exception:
            return None

    def _grab_http(self, port: int) -> Dict:
        """Grab HTTP server headers and title."""
        result = {"server": "", "title": ""}
        try:
            req = Request(
                f"http://{self.ip}:{port}/",
                headers={"User-Agent": CONFIG["scan"]["user_agent"]},
                method="GET"
            )
            resp = urlopen(req, timeout=3)
            result["server"] = resp.headers.get("Server", "")
            result["status"] = resp.status
            content = resp.read(4096).decode("utf-8", errors="replace")

            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.I | re.S)
            if title_match:
                result["title"] = title_match.group(1).strip()[:100]

            # Extract tech hints
            hints = {
                "x-powered-by": "X-Powered-By",
                "x-aspnet-version": "X-AspNet-Version",
                "x-generator": "generator",
            }
            for key, header in hints.items():
                val = resp.headers.get(header, "")
                if val:
                    result[key] = val

            resp.close()
        except Exception:
            pass
        return result

    def scan(self, port_list: List[int] = None) -> List[PortInfo]:
        """Run threaded port scan."""
        if port_list is None:
            port_list = self.COMMON_PORTS

        total_ports = len(port_list)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self._check_port, port): port
                for port in port_list
            }

            for i, future in enumerate(as_completed(future_to_port), 1):
                result = future.result()
                if result:
                    self.open_ports.append(result)

        # Sort by port number
        self.open_ports.sort(key=lambda p: p.port)
        return self.open_ports


class DNSScanner:
    """DNS record enumeration."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    @staticmethod
    def query(domain: str, record_type: str = "A") -> List[str]:
        """Query DNS records using system tools."""
        results = []
        try:
            cmd = ["dig", "+short", record_type, domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.stdout:
                results = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        except:
            try:
                records = socket.getaddrinfo(domain, None)
                if record_type == "A":
                    seen = set()
                    for rec in records:
                        ip = rec[4][0]
                        if ip not in seen and ':' not in ip:
                            results.append(ip)
                            seen.add(ip)
            except:
                pass
        return results

    @classmethod
    def enumerate(cls, domain: str) -> Dict[str, List[str]]:
        """Enumerate all DNS records."""
        records = {}
        for rtype in cls.RECORD_TYPES:
            try:
                result = cls.query(domain, rtype)
                if result:
                    records[rtype] = result
            except:
                pass
        return records


class SSLScanner:
    """SSL/TLS certificate inspection."""

    @staticmethod
    def inspect(hostname: str, port: int = 443) -> Dict[str, Any]:
        """Grab SSL certificate info."""
        info = {
            "enabled": False,
            "version": "",
            "issuer": "",
            "subject": "",
            "valid_from": "",
            "valid_to": "",
            "expired": False,
            "sans": [],
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    info["enabled"] = True
                    info["version"] = ssock.version()

                    if cert:
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        subject = dict(x[0] for x in cert.get("subject", []))
                        info["issuer"] = issuer.get("organizationName", cert.get("issuer", ""))
                        info["subject"] = subject.get("commonName", "")
                        info["valid_from"] = str(cert.get("notBefore", ""))
                        info["valid_to"] = str(cert.get("notAfter", ""))
                        info["sans"] = [x[1] for x in cert.get("subjectAltName", [])]

                        # Check expiry
                        try:
                            from datetime import datetime as dt
                            expire_str = cert.get("notAfter", "")
                            if expire_str:
                                expire_date = dt.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                                info["expired"] = expire_date < dt.now()
                        except:
                            pass

        except Exception as e:
            info["error"] = str(e)

        return info


class WebTechDetector:
    """Web technology fingerprinting."""

    TECH_PATTERNS = {
        "nginx": [r"nginx", r"x-nginx-*"],
        "apache": [r"apache", r"Apache"],
        "cloudflare": [r"cloudflare", r"__cfduid"],
        "wordpress": [r"/wp-content/", r"/wp-admin/", r"wordpress"],
        "drupal": [r"drupal", r"Drupal"],
        "joomla": [r"joomla", r"Joomla"],
        "laravel": [r"laravel", r"Laravel"],
        "django": [r"django", r"csrftoken", r"Django"],
        "flask": [r"flask", r"Flask", r"werkzeug"],
        "express": [r"express", r"Express"],
        "node.js": [r"node", r"Node"],
        "react": [r"react", r"React", r"create-react-app"],
        "vue": [r"vue", r"Vue"],
        "angular": [r"angular", r"Angular"],
        "jquery": [r"jquery", r"jQuery"],
        "bootstrap": [r"bootstrap", r"Bootstrap"],
        "tomcat": [r"tomcat", r"Tomcat", r"Apache-Coyote"],
        "iis": [r"iis", r"IIS", r"Microsoft-IIS"],
        "caddy": [r"caddy", r"Caddy"],
        "traefik": [r"traefik", r"Traefik"],
    }

    @staticmethod
    def detect(url: str) -> Dict[str, Any]:
        """Detect web technologies."""
        result = {
            "url": url,
            "status": 0,
            "server": "",
            "title": "",
            "technologies": [],
            "headers": {},
            "cookies": "",
        }

        try:
            req = Request(
                url, headers={"User-Agent": CONFIG["scan"]["user_agent"]},
                method="GET"
            )
            resp = urlopen(req, timeout=5)
            result["status"] = resp.status
            content = resp.read(8192).decode("utf-8", errors="replace")
            headers = dict(resp.headers.items())
            result["headers"] = headers

            # Server header
            result["server"] = headers.get("Server", "")

            # Title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.I | re.S)
            if title_match:
                result["title"] = title_match.group(1).strip()[:100]

            # Detect technologies
            content_lower = content.lower()
            for tech, patterns in WebTechDetector.TECH_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower, re.I):
                        result["technologies"].append(tech)
                        break

            # Also check headers
            for header_name, header_val in headers.items():
                header_lower = f"{header_name}: {header_val}".lower()
                for tech, patterns in WebTechDetector.TECH_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, header_lower, re.I):
                            if tech not in result["technologies"]:
                                result["technologies"].append(tech)
                            break

            # Security headers check
            security_headers = ["strict-transport-security", "content-security-policy",
                                "x-frame-options", "x-xss-protection",
                                "x-content-type-options", "referrer-policy",
                                "permissions-policy"]
            result["security_headers"] = {
                h: headers.get(h, "⚠️ MISSING")
                for h in security_headers
            }

            resp.close()

        except URLError as e:
            if hasattr(e, 'code'):
                result["status"] = e.code
            else:
                result["status"] = 0
        except Exception:
            pass

        return result


# ────────────────────────────────────────────────────────────────
#  AI ANALYSIS ENGINE
# ────────────────────────────────────────────────────────────────

class AIAnalysisEngine:
    """
    Intelligent analysis engine that evaluates scan results,
    identifies vulnerabilities, calculates risk, and generates
    actionable recommendations.
    """

    def __init__(self, target: ScanTarget):
        self.target = target
        self.findings: List[Dict] = []
        self.risk_score = 0
        self.recommendations: List[str] = []

    def analyze(self) -> Dict:
        """Run all analysis modules and return results."""

        with console.spinner(f"Running AI analysis on {self.target.hostname}..."):
            time.sleep(0.3)
            self._analyze_host()
            self._analyze_ports()
            self._analyze_dns()
            self._analyze_web()
            self._analyze_combinations()
            self._analyze_attack_vector()
            self._generate_recommendations()
            self._calculate_risk()

        return {
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": self._risk_level(),
            "total_findings": len(self.findings),
            "recommendations": self.recommendations,
        }

    def _add_finding(self, severity: str, title: str, description: str,
                     category: str = "general", details: Dict = None):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "category": category,
            "details": details or {},
        })

    def _analyze_host(self):
        """Analyze host-level information."""
        ip = self.target.ip_addresses[0] if self.target.ip_addresses else ""

        # Check if host is internal
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                self._add_finding(
                    "info",
                    f"Private IP: {ip}",
                    "Target is on a private network (RFC 1918). Internal network testing.",
                    "network"
                )
        except:
            pass

        # PTR record
        ptr = TargetResolver.get_ptr(ip)
        if ptr and ptr != self.target.hostname:
            self._add_finding(
                "info",
                f"Reverse DNS: {ptr}",
                f"PTR record doesn't match hostname ({self.target.hostname}). Possible hosting/CDN.",
                "network"
            )

    def _analyze_ports(self):
        """Deep analysis of all open ports."""
        if not self.target.ports:
            self._add_finding(
                "warning",
                "No open ports detected",
                "Target may be heavily firewalled, offline, or blocking probes.",
                "port_analysis"
            )
            return

        open_port_numbers = {p.port for p in self.target.ports}

        # Port volume analysis
        num_ports = len(self.target.ports)
        if num_ports > 50:
            self._add_finding(
                "high",
                f"Large attack surface: {num_ports} open ports",
                f"Target has {num_ports} open ports. Large attack surface requires thorough testing.",
                "port_analysis",
                {"ports": num_ports}
            )
            self.risk_score += 15
        elif num_ports > 20:
            self._add_finding(
                "medium",
                f"Moderate attack surface: {num_ports} open ports",
                f"{num_ports} open ports found. Focus on high-risk services first.",
                "port_analysis"
            )
            self.risk_score += 8

        # Analyze each port
        for port_info in self.target.ports:
            vuln_info = VulnerabilityDB.get_vuln_info(port_info.service)
            risk = vuln_info.get("risk", "LOW")
            score = vuln_info.get("score", 5)

            if risk == "CRITICAL":
                self._add_finding(
                    "critical",
                    f"⚠️ CRITICAL: {port_info.service.upper()} (port {port_info.port})",
                    vuln_info.get("desc", "Critical service exposed!"),
                    "vulnerability",
                    {
                        "port": port_info.port,
                        "service": port_info.service,
                        "risk": risk,
                        "cvss": vuln_info.get("cvss", 0),
                        "cves": vuln_info.get("cves", []),
                        "exploitation": vuln_info.get("exploitation", ""),
                        "remediation": vuln_info.get("remediation", ""),
                    }
                )
                self.risk_score += score

            elif risk == "HIGH":
                self._add_finding(
                    "high",
                    f"🔴 HIGH: {port_info.service.upper()} (port {port_info.port})",
                    vuln_info.get("desc", "High-risk service exposed."),
                    "vulnerability",
                    {
                        "port": port_info.port,
                        "service": port_info.service,
                        "risk": risk,
                        "cvss": vuln_info.get("cvss", 0),
                        "cves": vuln_info.get("cves", []),
                        "remediation": vuln_info.get("remediation", ""),
                    }
                )
                self.risk_score += score

            elif risk == "MEDIUM":
                self._add_finding(
                    "medium",
                    f"🟡 MEDIUM: {port_info.service.upper()} (port {port_info.port})",
                    vuln_info.get("desc", "Medium-risk service."),
                    "observation",
                )
                self.risk_score += score

        # Special: services on unusual ports
        for port_info in self.target.ports:
            expected = VulnerabilityDB.PORT_SERVICE_MAP.get(port_info.port)
            if expected and port_info.service != expected and port_info.service != "unknown":
                self._add_finding(
                    "medium",
                    f"Service on unusual port: {port_info.service} on {port_info.port}",
                    f"Expected {expected} on port {port_info.port}, found {port_info.service}. May indicate custom config or backdoor.",
                    "anomaly",
                    {"port": port_info.port, "expected": expected, "found": port_info.service}
                )
                self.risk_score += 5

    def _analyze_dns(self):
        """Analyze DNS records for security issues."""
        records = self.target.dns_records

        # SPF check
        if "TXT" in records:
            txt_records = " ".join(records["TXT"]).lower()
            if "v=spf" not in txt_records:
                self._add_finding(
                    "medium",
                    "Missing SPF record",
                    "No SPF record found. Domain is vulnerable to email spoofing.",
                    "dns"
                )
            if "dmarc" not in txt_records:
                self._add_finding(
                    "medium",
                    "Missing DMARC record",
                    "No DMARC record found. Email spoofing protection incomplete.",
                    "dns"
                )

        # Zone transfer check
        if "NS" in records:
            for ns in records["NS"]:
                try:
                    result = subprocess.run(
                        ["dig", "axfr", self.target.hostname, f"@{ns}"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.stdout and "Transfer failed" not in result.stdout and "failed" not in result.stdout:
                        if len(result.stdout.split('\n')) > 10:
                            self._add_finding(
                                "critical",
                                f"🔄 Zone transfer: AXFR enabled on {ns}",
                                "DNS zone transfer is enabled! Attacker can dump all DNS records.",
                                "dns_misconfig"
                            )
                            self.risk_score += 40
                except:
                    pass

    def _analyze_web(self):
        """Analyze web findings."""
        tech = self.target.web_tech
        if not tech:
            return

        # Security headers
        if "security_headers" in tech:
            missing = [h.replace("-", " ").title()
                       for h, v in tech["security_headers"].items()
                       if "MISSING" in str(v)]
            if missing:
                self._add_finding(
                    "medium",
                    f"Missing security headers ({len(missing)})",
                    f"Missing: {', '.join(missing)}. These headers help prevent common web attacks.",
                    "web_security"
                )
                self.risk_score += len(missing) * 2

    def _analyze_combinations(self):
        """Check for dangerous service combinations."""
        open_ports = {p.port for p in self.target.ports}
        combos = VulnerabilityDB.check_combos(open_ports)

        for combo in combos:
            severity = "high" if combo["risk"] == "CRITICAL" else "medium"
            self._add_finding(
                severity,
                f"⚔️ {combo['name']}",
                combo['desc'],
                "attack_chain"
            )
            self.risk_score += 25 if combo["risk"] == "CRITICAL" else 15

    def _analyze_attack_vector(self):
        """Generate attack vector analysis."""
        # Build the most likely attack path
        services = [p.service for p in self.target.ports]

        # Check for common attack chains
        if "http" in services or "https" in services or "http-proxy" in services:
            attack_path = ["Information Gathering", "Web App Reconnaissance"]
            if any(s in ("mysql", "postgresql", "mssql") for s in services):
                attack_path.append("SQL Injection Attempt")
                attack_path.append("Database Exploitation")
            attack_path.append("Post-Exploitation / Pivoting")

            self._add_finding(
                "info",
                "🎯 Suggested Attack Path",
                f"{' → '.join(attack_path)}",
                "attack_planning"
            )

    def _generate_recommendations(self):
        """Generate actionable recommendations."""
        recs = set()

        for f in self.findings:
            if f["severity"] in ("critical", "high") and "details" in f:
                d = f["details"]
                if "remediation" in d:
                    recs.add(d["remediation"])

        # General recommendations
        if len(self.target.ports) > 10:
            recs.add("Close unnecessary ports to reduce the attack surface")

        if any(p.service in ("ftp", "telnet") for p in self.target.ports):
            recs.add("Replace FTP/Telnet with SFTP/SSH immediately")

        if any(p.service in ("redis", "mongodb") for p in self.target.ports):
            recs.add("Enable authentication on all databases. Bind to localhost only")

        if not self.recommendations:
            recs.add("Implement defense-in-depth strategy")
            recs.add("Regular security assessments and penetration testing")
            recs.add("Keep all software and systems up to date")
            recs.add("Use firewall rules to restrict access to essential services only")

        self.recommendations = list(recs)[:8]

    def _calculate_risk(self):
        """Calculate final risk score."""
        self.risk_score = min(self.risk_score, 100)

    def _risk_level(self) -> str:
        s = self.risk_score
        if s >= 70:
            return "CRITICAL"
        elif s >= 45:
            return "HIGH"
        elif s >= 25:
            return "MEDIUM"
        elif s > 5:
            return "LOW"
        return "INFO"


# ────────────────────────────────────────────────────────────────
#  REPORT GENERATOR
# ────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Professional report generator (HTML + JSON)."""

    @staticmethod
    def generate_html(target: ScanTarget, analysis: Dict, duration: float) -> str:
        """Generate a professional HTML report."""
        timestamp = datetime.now()
        safe_name = target.hostname.replace('.', '_')

        # ── Stats ──
        total_findings = analysis["total_findings"]
        critical_count = sum(1 for f in analysis["findings"] if f["severity"] == "critical")
        high_count = sum(1 for f in analysis["findings"] if f["severity"] == "high")
        medium_count = sum(1 for f in analysis["findings"] if f["severity"] == "medium")
        low_count = sum(1 for f in analysis["findings"] if f["severity"] in ("low", "info", "warning"))

        risk_color = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "INFO": "#17a2b8"
        }.get(analysis["risk_level"], "#6c757d")

        # ── Ports Table ──
        ports_rows = ""
        for p in target.ports:
            risk_color_s = {
                "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                "MEDIUM": "#ffc107", "LOW": "#28a745",
            }.get(p.risk_score, "#6c757d")
            ports_rows += f"""
            <tr>
                <td>{p.port}</td>
                <td>{p.service}</td>
                <td><span style="background:{risk_color_s};color:white;padding:2px 8px;border-radius:10px;font-size:12px">{p.risk_score}</span></td>
            </tr>"""

        if not ports_rows:
            ports_rows = "<tr><td colspan='3' style='text-align:center;color:#888'>No open ports detected</td></tr>"

        # ── Findings ──
        findings_html = ""
        for f in analysis["findings"]:
            sev_color = {
                "critical": "#dc3545", "high": "#fd7e14",
                "medium": "#ffc107", "warning": "#ffc107",
                "low": "#28a745", "info": "#17a2b8",
            }.get(f["severity"], "#888")
            icon = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "warning": "🟡", "low": "🟢", "info": "🔵",
            }.get(f["severity"], "⚪")

            findings_html += f"""
            <div class="finding" style="border-left:4px solid {sev_color};margin:8px 0;padding:12px;background:#f8f9fa;border-radius:4px">
                <div style="font-weight:600;color:{sev_color}">{icon} {f["title"]}</div>
                <div style="color:#555;margin-top:4px">{f["description"]}</div>
                <div style="font-size:11px;color:#999;margin-top:4px">Category: {f["category"]}</div>
            </div>"""

        # ── DNS Table ──
        dns_rows = ""
        for rtype, records in target.dns_records.items():
            for rec in records[:5]:
                dns_rows += f"<tr><td>{rtype}</td><td>{html.escape(rec)}</td></tr>"

        # ── Web Tech ──
        web_html = ""
        if target.web_tech:
            tech = target.web_tech
            web_html += f"""
            <div><strong>Server:</strong> {tech.get('server', 'N/A')}</div>
            <div><strong>Title:</strong> {html.escape(tech.get('title', 'N/A'))}</div>
            <div><strong>Status:</strong> {tech.get('status', 'N/A')}</div>
            <div><strong>Technologies:</strong> {', '.join(tech.get('technologies', ['None detected']))}</div>
            """

        # ── SSL Info ──
        ssl_html = ""
        if target.ssl_info and target.ssl_info.get("enabled"):
            ssl_html += f"""
            <div><strong>Version:</strong> {target.ssl_info.get('version', 'N/A')}</div>
            <div><strong>Issuer:</strong> {html.escape(str(target.ssl_info.get('issuer', 'N/A')))}</div>
            <div><strong>Subject:</strong> {html.escape(str(target.ssl_info.get('subject', 'N/A')))}</div>
            <div><strong>Expired:</strong> {"⚠️ YES" if target.ssl_info.get('expired') else "✅ No"}</div>
            """

        # ── Recommendations ──
        recs_html = ""
        for i, rec in enumerate(analysis.get("recommendations", []), 1):
            recs_html += f"<li>{html.escape(rec)}</li>"

        filename = f"autorecon_report_{safe_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AutoRecon AI Report — {html.escape(target.hostname)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,'Segoe UI',Roboto,sans-serif; background:#f0f2f5; color:#333; }}
.header {{ background: linear-gradient(135deg,#1a1a2e,#16213e); color:white; padding:40px 20px; text-align:center; }}
.header h1 {{ font-size:2em; }}
.header .meta {{ opacity:0.7; margin-top:8px; }}
.container {{ max-width:1000px; margin:0 auto; padding:20px; }}
.card {{ background:white; border-radius:12px; padding:24px; margin:16px 0; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
.card h2 {{ margin-bottom:16px; color:#1a1a2e; border-bottom:2px solid #eee; padding-bottom:8px; }}
.badge {{ display:inline-block; padding:8px 24px; border-radius:20px; color:white; font-weight:700; font-size:18px; background:{risk_color}; }}
.stats {{ display:flex; gap:12px; flex-wrap:wrap; justify-content:center; }}
.stat-box {{ background:#f8f9fa; padding:16px 24px; border-radius:8px; text-align:center; min-width:100px; flex:1; }}
.stat-num {{ font-size:2em; font-weight:700; color:#1a1a2e; }}
.stat-label {{ font-size:13px; color:#888; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ text-align:left; padding:10px 8px; border-bottom:2px solid #333; background:#f8f9fa; }}
td {{ padding:8px; border-bottom:1px solid #eee; }}
.finding {{ transition:transform .15s; }}
.finding:hover {{ transform:translateX(4px); }}
.footer {{ text-align:center; padding:20px; color:#888; font-size:13px; }}
.rec-list {{ padding-left:20px; line-height:1.8; }}
.rec-list li {{ margin:6px 0; }}
</style>
</head>
<body>
<div class="header">
    <h1>🤖 AutoRecon AI Report</h1>
    <p class="meta">Target: {html.escape(target.hostname)} ({target.ip_addresses[0] if target.ip_addresses else 'N/A'})</p>
    <p class="meta">{timestamp.strftime('%Y-%m-%d %H:%M:%S')} | Duration: {duration:.1f}s</p>
    <div style="margin-top:16px"><span class="badge">{analysis['risk_level']} RISK — Score: {analysis['risk_score']}/100</span></div>
</div>
<div class="container">

    <!-- Stats -->
    <div class="card">
        <h2>📊 Overview</h2>
        <div class="stats">
            <div class="stat-box"><div class="stat-num">{len(target.ports)}</div><div class="stat-label">Open Ports</div></div>
            <div class="stat-box"><div class="stat-num">{total_findings}</div><div class="stat-label">Findings</div></div>
            <div class="stat-box"><div class="stat-num">{critical_count}</div><div class="stat-label">🔴 Critical</div></div>
            <div class="stat-box"><div class="stat-num">{high_count}</div><div class="stat-label">🟠 High</div></div>
            <div class="stat-box"><div class="stat-num">{medium_count}</div><div class="stat-label">🟡 Medium</div></div>
            <div class="stat-box"><div class="stat-num">{max(0,low_count)}</div><div class="stat-label">🟢 Low/Info</div></div>
        </div>
    </div>

    <!-- Target Info -->
    <div class="card">
        <h2>🎯 Target Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Hostname</td><td>{html.escape(target.hostname)}</td></tr>
            <tr><td>IP Address{'' if len(target.ip_addresses)<=1 else 'es'}</td><td>{', '.join(target.ip_addresses)}</td></tr>
            <tr><td>OS</td><td>{html.escape(target.os_info)}</td></tr>
            <tr><td>Host Alive</td><td>{"✅ Yes" if target.is_alive else "❌ No"}</td></tr>
        </table>
    </div>

    <!-- Open Ports -->
    <div class="card">
        <h2>🔌 Open Ports ({len(target.ports)})</h2>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Risk Score</th></tr></thead>
            <tbody>{ports_rows}</tbody>
        </table>
    </div>

    <!-- Web -->
    {'<div class="card"><h2>🌐 Web Server</h2>' + web_html + '</div>' if web_html else ''}

    <!-- SSL -->
    {'<div class="card"><h2>🔒 SSL/TLS</h2>' + ssl_html + '</div>' if ssl_html else ''}

    <!-- DNS -->
    {'<div class="card"><h2>📡 DNS Records</h2><table><thead><tr><th>Type</th><th>Record</th></tr></thead><tbody>' + dns_rows + '</tbody></table></div>' if dns_rows else ''}

    <!-- AI Findings -->
    <div class="card">
        <h2>🧠 AI Security Analysis ({total_findings} findings)</h2>
        {findings_html}
    </div>

    <!-- Attack Vector -->
    <div class="card">
        <h2>🎯 Attack Vector Analysis</h2>
        {'<p>No specific attack path identified.</p>' if not analysis['findings'] else ''}
        {''.join(f'<div style="margin:8px 0;padding:10px;background:#f0f8ff;border-radius:4px">{f["description"]}</div>' for f in analysis['findings'] if f['category'] == 'attack_planning')}
    </div>

    <!-- Recommendations -->
    <div class="card">
        <h2>🛡️ Recommendations</h2>
        <ol class="rec-list">
            {recs_html}
        </ol>
    </div>

</div>
<div class="footer">
    <p>Generated by <strong>AutoRecon AI v{CONFIG['version']}</strong></p>
    <p>⚠️ Authorized testing only. Unauthorized scanning may be illegal.</p>
</div>
</body>
</html>"""

        with open(filename, 'w') as f:
            f.write(html_content)

        return filename

    @staticmethod
    def generate_json(target: ScanTarget, analysis: Dict, duration: float) -> str:
        """Export full data as JSON."""
        timestamp = datetime.now()
        safe_name = target.hostname.replace('.', '_')
        filename = f"autorecon_data_{safe_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"

        data = {
            "tool": "AutoRecon AI",
            "version": CONFIG["version"],
            "scan_date": timestamp.isoformat(),
            "duration_seconds": duration,
            "target": target.to_dict(),
            "analysis": {
                "risk_score": analysis["risk_score"],
                "risk_level": analysis["risk_level"],
                "total_findings": analysis["total_findings"],
                "findings": analysis["findings"],
                "recommendations": analysis["recommendations"],
            }
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return filename


# ────────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ────────────────────────────────────────────────────────────────

class AutoReconAI:
    """Main application orchestrator."""

    def __init__(self):
        self.console = console
        self.target = None
        self.start_time = None
        self.scan_duration = 0
        self.analysis_results = None

    def show_banner(self):
        """Display professional banner."""
        banner = f"""
[bold cyan]
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██╗   ██╗
║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██║   ██║
║  ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║   ██║██║   ██║
║  ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║
║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╔╝╚██████╔╝
║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝
║                                                              ║
║  🤖 [underline]AI-Powered Reconnaissance & Analysis Engine[/]          ║
║  [dim]v{CONFIG['version']} | AI Automation Series[/]                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝
[/bold cyan]"""
        if self.console._rich:
            self.console.print(banner)
        else:
            print(banner)
        self.console.rule("")

    def show_menu(self) -> str:
        """Display interactive mode menu."""
        menu = """
[bold]Select scan mode:[/]

  [cyan]1[/]  🚀  Quick Scan     — Top 1000 ports, service detection
  [cyan]2[/]  🔬  Full Scan      — All 10000 ports, service detection
  [cyan]3[/]  🎯  Smart Scan     — AI-driven (common ports + HTTP/HTTPS)
  [cyan]4[/]  🌐  Web Focus      — HTTP/HTTPS servers only
  [cyan]5[/]  📋  Batch Mode     — Scan multiple targets from file
  [cyan]0[/]  ❌  Exit
"""
        if self.console._rich:
            self.console.print(Panel(menu, title="📋 Scan Mode", border_style="cyan"))
        else:
            print(menu)

        choice = self.console.input("Enter your choice [1-5]", default="1")
        return choice

    def run(self):
        """Main execution flow."""
        self.show_banner()

        try:
            choice = self.show_menu()

            if choice == "0":
                self.console.print("[yellow]Exiting... Stay safe! 🛡️[/]")
                return

            # Get target
            self.target = self._get_target()
            if not self.target:
                return

            # Resolve target
            if not self._resolve_target():
                return

            # Execute scan based on mode
            self.start_time = time.time()

            if choice == "1":
                self._quick_scan()
            elif choice == "2":
                self._full_scan()
            elif choice == "3":
                self._smart_scan()
            elif choice == "4":
                self._web_focus()
            elif choice == "5":
                self._batch_mode()
                return
            else:
                self.console.print_error(f"Invalid choice: {choice}")
                return

            # AI Analysis
            self._run_ai_analysis()

            # Generate reports
            self._generate_reports()

        except KeyboardInterrupt:
            self.console.print_warn("\nScan interrupted by user. Exiting...")
            sys.exit(0)
        except Exception as e:
            self.console.print_error(f"Fatal error: {e}")
            if not self.console._rich:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    def _get_target(self) -> Optional[ScanTarget]:
        """Get target from user input."""
        target_str = self.console.input("\n[bold cyan]🎯[/] Enter target [domain/IP]", default="")

        if not target_str:
            self.console.print_error("No target provided!")
            return None

        return ScanTarget(target_str)

    def _resolve_target(self) -> bool:
        """Resolve target domain/IP."""
        self.console.rule("🎯 Target Resolution")

        target = self.target.original
        self.console.print_info(f"Resolving {target}...")

        hostname, ips = TargetResolver.resolve(target)

        if not ips:
            self.console.print_error(f"Could not resolve {target}")
            return False

        self.target.hostname = hostname
        self.target.ip_addresses = ips

        self.console.print_ok(f"Resolved: {hostname}")
        for ip in ips:
            ptr = TargetResolver.get_ptr(ip)
            ptr_str = f" ({ptr})" if ptr else ""
            self.console.print(f"    ├─ {ip}{ptr_str}")

        # DNS enumeration
        if hostname and '.' in hostname and not hostname.replace('.', '').isdigit():
            self.console.print_info("Enumerating DNS records...")
            self.target.dns_records = DNSScanner.enumerate(hostname)
            if self.target.dns_records:
                for rtype, records in self.target.dns_records.items():
                    self.console.print(f"    ├─ [{rtype}] {', '.join(records[:3])}")
                    if len(records) > 3:
                        self.console.print(f"    │  ... and {len(records)-3} more")

        # Ping check
        self.console.print_info("Checking if target is alive...")
        self.target.is_alive = PingScanner.is_alive(ips[0])
        if self.target.is_alive:
            self.console.print_ok("Target is ALIVE")
        else:
            self.console.print_warn("Target may be blocking probes (no ping response)")

        return True

    def _quick_scan(self):
        """Quick scan - top 1000 ports."""
        self.console.rule("🚀 Quick Scan")
        ip = self.target.ip_addresses[0]
        self.console.print_info(f"Scanning {ip} (top 1000 ports)...")

        scanner = PortScanner(ip, max_threads=50, timeout=2)
        self._show_scan_progress(scanner, PortScanner.COMMON_PORTS)

    def _full_scan(self):
        """Full scan - all 10000 ports."""
        self.console.rule("🔬 Full Scan")
        ip = self.target.ip_addresses[0]
        self.console.print_warn("This will scan all 10000 ports. May take a few minutes!")
        self.console.print_info(f"Scanning {ip}...")

        scanner = PortScanner(ip, max_threads=100, timeout=2)
        self._show_scan_progress(scanner, PortScanner.ALL_PORTS)

    def _smart_scan(self):
        """Smart scan - AI-driven."""
        self.console.rule("🎯 Smart Scan (AI-Driven)")
        ip = self.target.ip_addresses[0]
        self.console.print_info(f"AI analyzing target profile for {ip}...")

        # Intelligent port selection based on target type
        smart_ports = list(PortScanner.COMMON_PORTS)  # Start with common

        # Add web ports always
        smart_ports.extend([8080, 8081, 8443, 8888, 9090, 9443])

        # Add if hostname suggests specific services
        hostname = self.target.hostname.lower()
        if "mail" in hostname:
            smart_ports.extend([25, 110, 143, 465, 587, 993, 995])
        if "db" in hostname or "database" in hostname or "sql" in hostname:
            smart_ports.extend([1433, 1521, 3306, 5432, 6379, 27017])
        if "ns" in hostname or "dns" in hostname:
            smart_ports.append(53)
        if "web" in hostname or "app" in hostname or "api" in hostname:
            smart_ports.extend([3000, 5000, 7001, 8000, 9000])

        smart_ports = sorted(set(smart_ports))
        self.console.print_ok(f"AI selected {len(smart_ports)} ports for scanning")

        scanner = PortScanner(ip, max_threads=50, timeout=2)
        self._show_scan_progress(scanner, smart_ports)

    def _web_focus(self):
        """Web-focused scan."""
        self.console.rule("🌐 Web Focus Scan")
        ip = self.target.ip_addresses[0]
        web_ports = [80, 443, 8080, 8443, 8000, 8888, 9090, 9443, 3000, 5000]
        self.console.print_info(f"Checking web servers on {ip}...")

        scanner = PortScanner(ip, max_threads=20, timeout=3)
        self._show_scan_progress(scanner, web_ports)

        # SSL inspection
        if 443 in {p.port for p in scanner.open_ports}:
            self.console.print_info("Inspecting SSL/TLS certificate...")
            self.target.ssl_info = SSLScanner.inspect(self.target.hostname, 443)
            if self.target.ssl_info.get("enabled"):
                self.console.print_ok(f"SSL/TLS: {self.target.ssl_info.get('version', '')}")
                if self.target.ssl_info.get("expired"):
                    self.console.print_warn("Certificate is EXPIRED!")

    def _show_scan_progress(self, scanner: PortScanner, ports: List[int]):
        """Show scan with progress."""
        ip = scanner.ip
        total = len(ports)
        found_ports = []

        if self.console._rich:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console.console,
            )

            with progress:
                task = progress.add_task(f"[cyan]Scanning {ip}...", total=total)

                with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
                    future_to_port = {
                        executor.submit(scanner._check_port, port): port
                        for port in ports
                    }

                    completed = 0
                    for future in as_completed(future_to_port):
                        completed += 1
                        result = future.result()
                        if result:
                            found_ports.append(result)
                        progress.update(task, completed=completed,
                                        description=f"[cyan]Scanning {ip} [{len(found_ports)} open]")

            scanner.open_ports = sorted(found_ports, key=lambda p: p.port)
        else:
            # Fallback without Rich
            print(f"[*] Scanning {ip} ({total} ports)...")
            with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
                future_to_port = {
                    executor.submit(scanner._check_port, port): port
                    for port in ports
                }

                completed = 0
                for future in as_completed(future_to_port):
                    completed += 1
                    result = future.result()
                    if result:
                        found_ports.append(result)
                    if completed % 500 == 0:
                        print(f"  [{completed}/{total}] {len(found_ports)} open ports found...")

            scanner.open_ports = sorted(found_ports, key=lambda p: p.port)

        # Store in target
        self.target.ports = scanner.open_ports

        # Display results
        self.console.rule(f"📊 Scan Complete — {len(scanner.open_ports)} open ports")
        if scanner.open_ports:
            # Determine OS from ports
            self._detect_os()

            rows = []
            for p in scanner.open_ports:
                risk = "●" if p.risk_score >= 40 else "◉" if p.risk_score >= 20 else "○"
                rows.append([str(p.port), p.service, p.product[:25] if p.product else "-",
                            p.version[:25] if p.version else "-", str(p.risk_score)])

            self.console.print_table("Open Ports",
                                     ["Port", "Service", "Product", "Version", "Risk"],
                                     rows)
        else:
            self.console.print_warn("No open ports detected!")

        # SSL check for HTTPS
        if any(p.service in ("https", "https-alt") for p in scanner.open_ports):
            for sport in scanner.open_ports:
                if sport.service in ("https", "https-alt"):
                    self.console.print_info(f"Inspecting SSL on port {sport.port}...")
                    self.target.ssl_info = SSLScanner.inspect(self.target.hostname, sport.port)
                    if self.target.ssl_info.get("enabled"):
                        self.console.print_ok(f"SSL: {self.target.ssl_info.get('version', '')}")
                    break

    def _detect_os(self):
        """OS detection based on port patterns and TTL."""
        ports = self.target.ports
        services = {p.service.lower() for p in ports}

        if "smb" in services or "msrpc" in services or "ms-sql-s" in services or "kerberos" in services:
            self.target.os_info = "Windows (detected via services)"
        elif any("linux" in s or "unix" in s for s in [p.product.lower() for p in ports if p.product]):
            self.target.os_info = "Linux/Unix (detected via services)"
        elif "ssh" in services:
            # Check SSH version for OS hints
            for p in ports:
                if p.service == "ssh" and p.product:
                    if "ubuntu" in p.product.lower() or "debian" in p.product.lower() or "centos" in p.product.lower():
                        self.target.os_info = f"Linux ({p.product})"
                        break
                    elif "openssh" in p.product.lower():
                        self.target.os_info = f"SSH-based ({p.product})"
                        break

        if self.target.os_info == "Unknown":
            self.target.os_info = "Could not determine OS"

    def _run_ai_analysis(self):
        """Run AI analysis engine."""
        self.console.rule("🧠 AI Analysis Engine")

        analyzer = AIAnalysisEngine(self.target)
        self.analysis_results = analyzer.analyze()

        # Display findings
        findings = self.analysis_results["findings"]
        risk_level = self.analysis_results["risk_level"]

        # Summary
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        low = sum(1 for f in findings if f["severity"] in ("low", "info", "warning"))

        if self.console._rich:
            grid = Table.grid(padding=1)
            grid.add_row(
                Panel(f"[bold red]{critical}[/]", title="Critical"),
                Panel(f"[bold orange1]{high}[/]", title="High"),
                Panel(f"[bold yellow]{medium}[/]", title="Medium"),
                Panel(f"[bold green]{low}[/]", title="Low/Info"),
            )
            self.console.print(grid)
        else:
            print(f"\n  Critical: {critical} | High: {high} | Medium: {medium} | Low/Info: {low}")

        # Risk badge
        risk_colors = {
            "CRITICAL": "bold red", "HIGH": "bold orange1",
            "MEDIUM": "bold yellow", "LOW": "bold green", "INFO": "blue"
        }
        rc = risk_colors.get(risk_level, "white")
        if self.console._rich:
            self.console.print(Panel(
                f"[{rc}]Risk Score: {self.analysis_results['risk_score']}/100 — {risk_level}[/]",
                title="🎯 Overall Assessment", border_style="blue"
            ))
        else:
            print(f"\n  {'='*50}")
            print(f"  OVERALL: Risk Score {self.analysis_results['risk_score']}/100 — {risk_level}")
            print(f"  {'='*50}")

        # Show top findings
        high_findings = [f for f in findings if f["severity"] in ("critical", "high")]
        if high_findings:
            self.console.rule("🔴 Top Priority Issues")
            for f in high_findings[:5]:
                icon = "🔴" if f["severity"] == "critical" else "🟠"
                if self.console._rich:
                    self.console.print(f"  {icon} [{f['severity']}][bold]{f['title']}[/]")
                    self.console.print(f"     {f['description']}")
                else:
                    print(f"  {icon} {f['title']}")
                    print(f"     {f['description']}")
                print()

    def _generate_reports(self):
        """Generate reports."""
        self.scan_duration = time.time() - self.start_time

        self.console.rule("📄 Generating Reports")

        # HTML report
        html_file = ReportGenerator.generate_html(
            self.target, self.analysis_results, self.scan_duration
        )
        self.console.print_ok(f"📊 HTML Report: [bold]{html_file}[/]")

        # JSON export
        json_file = ReportGenerator.generate_json(
            self.target, self.analysis_results, self.scan_duration
        )
        self.console.print_ok(f"📋 JSON Data: [bold]{json_file}[/]")

        # Summary
        self.console.rule("✅ Scan Complete")
        elapsed = self.scan_duration
        time_str = f"{elapsed:.1f}s" if elapsed < 60 else f"{elapsed/60:.1f}m"

        summary = f"""
[bold]Target:[/]       {self.target.hostname} ({self.target.ip_addresses[0] if self.target.ip_addresses else 'N/A'})
[bold]Duration:[/]     {time_str}
[bold]Open Ports:[/]   {len(self.target.ports)}
[bold]Findings:[/]     {self.analysis_results['total_findings']}
[bold]Risk Score:[/]   {self.analysis_results['risk_score']}/100 ({self.analysis_results['risk_level']})
[bold]Reports:[/]      {html_file} | {json_file}

[dim]🔒 Remember: Only scan targets you own or have permission to test![/]
"""
        if self.console._rich:
            self.console.print(Panel(summary, title="📋 Summary", border_style="green"))
        else:
            print(summary)

        # Ask to open report
        if self.console.confirm("Open HTML report in browser?"):
            try:
                subprocess.Popen(["xdg-open", html_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.console.print_ok("Opening report...")
            except:
                self.console.print_warn(f"Could not auto-open. Open manually: {html_file}")

    def _batch_mode(self):
        """Batch scan multiple targets from file."""
        self.console.rule("📋 Batch Mode")
        file_path = self.console.input("Enter file path with targets (one per line)", default="targets.txt")

        if not os.path.exists(file_path):
            self.console.print_error(f"File not found: {file_path}")
            return

        with open(file_path) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        self.console.print_ok(f"Loaded {len(targets)} targets from {file_path}")
        self.console.print_info("Starting batch scan...")

        for i, t in enumerate(targets, 1):
            self.console.rule(f"[{i}/{len(targets)}] {t}")
            self.target = ScanTarget(t)

            if not self._resolve_target():
                continue

            self.start_time = time.time()
            self._quick_scan()
            self._run_ai_analysis()
            self._generate_reports()

        self.console.rule("✅ Batch Scan Complete")


# ────────────────────────────────────────────────────────────────
#  ENTRY POINT (CLI + Interactive)
# ────────────────────────────────────────────────────────────────

def parse_args():
    """Parse command-line arguments for automated mode."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="autorecon-ai",
        description="🤖 AutoRecon AI — AI-Powered Reconnaissance & Analysis Engine",
        epilog="⚠️  Only scan targets you own or have permission to test!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="Target domain or IP address")
    parser.add_argument("-m", "--mode", choices=["quick", "full", "smart", "web", "batch"],
                        default="quick", help="Scan mode (default: quick)")
    parser.add_argument("--threads", type=int, default=50, help="Max scan threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Port scan timeout (default: 2s)")
    parser.add_argument("--file", help="Targets file (for batch mode)")
    parser.add_argument("-o", "--output", help="Output directory for reports")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open HTML report")
    parser.add_argument("--json-only", action="store_true", help="Generate JSON only (no HTML)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (minimal output)")
    parser.add_argument("--version", action="version", version=f"AutoRecon AI v{CONFIG['version']}")
    return parser.parse_args()


def main():
    """Application entry point."""
    args = parse_args()

    try:
        app = AutoReconAI()

        if args.target:
            # ─── Automated mode from CLI args ───
            mode_map = {"quick": "1", "full": "2", "smart": "3", "web": "4", "batch": "5"}

            if args.quiet:
                # Redirect console to be quieter
                pass

            CONFIG["scan"]["max_threads"] = args.threads
            CONFIG["scan"]["timeout"] = int(args.timeout)

            # Override confirm to auto-yes
            original_confirm = RichConsole.confirm
            def auto_confirm(self, prompt_text, default=True):
                return True
            RichConsole.confirm = auto_confirm

            # Show minimal banner
            if not args.quiet:
                app.show_banner()
                print(f"\n  [🎯] Target: {args.target}")
                print(f"  [⚡] Mode: {args.mode.upper()}")
                print(f"  [🧵] Threads: {args.threads}")
                print()
            else:
                print(f"[AutoRecon AI] Starting scan on {args.target} ({args.mode})...")

            app.target = ScanTarget(args.target)

            # Resolve
            if not args.quiet:
                print(f"[*] Resolving {args.target}...", end=" ")
            hostname, ips = TargetResolver.resolve(args.target)
            if args.quiet:
                print(f"[+] {args.target} → {ips[0] if ips else 'unresolved'}")

            if not ips:
                print(f"[-] Could not resolve {args.target}")
                sys.exit(1)

            app.target.hostname = hostname
            app.target.ip_addresses = ips

            if not args.quiet:
                print(f"[+] {hostname} ({ips[0]})")
                print(f"[*] Checking if alive...", end=" ")

            app.target.is_alive = PingScanner.is_alive(ips[0])
            if not args.quiet:
                print(f"{'✅ Alive' if app.target.is_alive else '⚠️  No response'}")

            # Run scan
            app.start_time = time.time()
            mode_choice = mode_map.get(args.mode, "1")

            if mode_choice == "1":
                if not args.quiet: console.rule("🚀 Quick Scan")
                ports = PortScanner.COMMON_PORTS
            elif mode_choice == "2":
                if not args.quiet: console.rule("🔬 Full Scan")
                ports = PortScanner.ALL_PORTS
            elif mode_choice == "3":
                if not args.quiet: console.rule("🎯 Smart Scan")
                ports = list(set(PortScanner.COMMON_PORTS + [8080, 8443, 8888, 9090]))
            elif mode_choice == "4":
                if not args.quiet: console.rule("🌐 Web Focus")
                ports = [80, 443, 8080, 8443, 8000, 8888, 9090, 9443, 3000, 5000]
            else:
                ports = PortScanner.COMMON_PORTS

            if not args.quiet:
                print(f"[*] Scanning {ips[0]} ({len(ports)} ports)...", end=" ", flush=True)

            scanner = PortScanner(ips[0], max_threads=args.threads, timeout=int(args.timeout))
            scanner.scan(ports)
            app.target.ports = scanner.open_ports

            if not args.quiet:
                print(f"Done. Found {len(scanner.open_ports)} open ports.")
                if scanner.open_ports:
                    for p in scanner.open_ports[:10]:
                        print(f"     ├─ {p.port}/{p.protocol}  {p.service}")
                    if len(scanner.open_ports) > 10:
                        print(f"     └─ ... and {len(scanner.open_ports)-10} more")

            # Run AI analysis
            if not args.quiet:
                console.rule("🧠 AI Analysis")

            analyzer = AIAnalysisEngine(app.target)
            app.analysis_results = analyzer.analyze()

            if not args.quiet:
                print(f"[+] Risk Score: {app.analysis_results['risk_score']}/100 ({app.analysis_results['risk_level']})")
                for f in app.analysis_results['findings']:
                    if f['severity'] in ('critical', 'high'):
                        print(f"     {'🔴' if f['severity']=='critical' else '🟠'} {f['title']}")

            # Reports
            app.scan_duration = time.time() - app.start_time

            if not args.json_only:
                html_file = ReportGenerator.generate_html(app.target, app.analysis_results, app.scan_duration)
                if not args.quiet:
                    print(f"\n[+] 📊 Report: {html_file}")
                if not args.no_browser:
                    try:
                        subprocess.Popen(["xdg-open", html_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except:
                        pass

            json_file = ReportGenerator.generate_json(app.target, app.analysis_results, app.scan_duration)
            if not args.quiet:
                print(f"[+] 📋 Data: {json_file}")
                print(f"[+] ✅ Done! ({app.scan_duration:.1f}s)")

            # Print final summary always
            print()
            print(f"╔═══ AutoRecon AI — Scan Summary ═══╗")
            print(f"  Target:     {app.target.hostname} ({ips[0]})")
            print(f"  Ports open: {len(scanner.open_ports)}")
            print(f"  Risk:       {app.analysis_results['risk_score']}/100 ({app.analysis_results['risk_level']})")
            print(f"  Reports:    {html_file if not args.json_only else 'N/A'} | {json_file}")
            print(f"  Duration:   {app.scan_duration:.1f}s")
            print(f"╚════════════════════════════════════╝")
            print()

        else:
            # ─── Interactive mode ───
            app.run()

    except KeyboardInterrupt:
        print(f"\n{'='*60}")
        print("  Scan interrupted by user. Exiting...")
        print(f"{'='*60}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"  ⚠️  Fatal Error: {e}")
        print(f"{'='*60}")
        sys.exit(1)


if __name__ == "__main__":
    main()
