#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   __   __  _  _   __    ____  _ __   __ _  _ __   __ _   __ _  _ __ ___     ║
║   \ \ / / | || | / _|  / ___|| '_ \ / _` || '_ \ / _` | / _` || '_ ` _ \    ║
║    \ V /  | || || |_   \___ \| | | | (_| || | | | (_| || (_| || | | | | |   ║
║     |_|   |_||_| \__|  |____/|_| |_|\__, ||_| |_|\__,_| \__,_||_| |_| |_|   ║
║                                      |___/                                   ║
║   ███████╗ ██████╗ ██████╗     █████╗ ██╗                                   ║
║   ██╔════╝██╔═══██╗██╔══██╗   ██╔══██╗██║                                   ║
║   █████╗  ██║   ██║██████╔╝   ███████║██║                                   ║
║   ██╔══╝  ██║   ██║██╔══██╗   ██╔══██║██║                                   ║
║   ██║     ╚██████╔╝██║  ██║   ██║  ██║███████╗                              ║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝  ╚═╝╚══════╝                              ║
║                                                                              ║
║   🤖 AI-Powered Vulnerability Analysis & Exploitation Engine                ║
║                                                                              ║
║   Author  : ANKIT48274                                                       ║
║   GitHub  : https://github.com/ANKIT48274/vulnforge-ai                       ║
║   License : MIT                                                              ║
║                                                                              ║
║   🔥 Professional penetration testing assistant with AI intelligence          ║
║   🎯 Zero-cost AI inference via Groq & Gemini APIs                           ║
║   📊 Executive-grade HTML reports for client deliverables                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

💻 One tool to rule them all: Recon → Analyze → Exploit → Report

Requirements:
    pip install rich requests python-dotenv

API Keys (at least one):
    Groq:   https://console.groq.com/  (FREE!)
    Gemini: https://aistudio.google.com/ (FREE!)
    Claude: https://console.anthropic.com/
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

# ─── Rich UI ───
try:
    from rich import box
    from rich.columns import Columns
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import (BarColumn, Progress, SpinnerColumn,
                                TextColumn, TimeElapsedColumn)
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    RICH = True
except ImportError:
    RICH = False

# ─── Console ───
console = Console() if RICH else None


# ═══════════════════════════════════════════════════════════════
#  UTILITY LAYER
# ═══════════════════════════════════════════════════════════════

import textwrap

# ─── Suppress escape sequence warnings ───
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning, module="vulnforge_ai")

class Colors:
    """Terminal colors when Rich is unavailable."""
    if not RICH:
        BOLD = '\033[1m'; RED = '\033[91m'; GREEN = '\033[92m'
        YELLOW = '\033[93m'; BLUE = '\033[94m'; CYAN = '\033[96m'
        MAGENTA = '\033[95m'; DIM = '\033[2m'; END = '\033[0m'

def cprint(msg: str = "", color: str = "", bold: bool = False):
    """Print with rich or fallback."""
    if console:
        style = f"{'bold ' if bold else ''}{color}"
        console.print(msg, style=style) if style else console.print(msg)
    else:
        c = getattr(Colors, color.upper(), "") if color else ""
        b = Colors.BOLD if bold else ""
        e = Colors.END if (c or b) else ""
        print(f"{b}{c}{msg}{e}")

def info(msg): cprint(f"  ⟳ {msg}", "cyan")
def ok(msg): cprint(f"  ✓ {msg}", "green")
def warn(msg): cprint(f"  ⚠ {msg}", "yellow")
def err(msg): cprint(f"  ✗ {msg}", "red")
def bold(msg): cprint(msg, bold=True)

def section(title: str):
    """Print a section divider."""
    if console: console.rule(f"[cyan]{title}[/]", style="dim")
    else: print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

def shell(cmd: list, timeout: int = 60) -> Tuple[int, str]:
    """Run a shell command safely."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors='replace')
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired: return -1, "TIMEOUT"
    except Exception as e: return -1, str(e)


# ═══════════════════════════════════════════════════════════════
#  AI PROVIDERS — Free-tier FIRST
# ═══════════════════════════════════════════════════════════════

class AIProvider:
    """
    Abstraction over multiple AI providers with auto-fallback.
    Primary: Groq (free, fast)  →  Fallback: Gemini (free)  →  Claude/OpenAI
    """

    PROVIDERS = {
        "groq": {
            "name": "Groq (FREE)",
            "env": "GROQ_API_KEY",
            "url": "https://api.groq.com/openai/v1/chat/completions",
            "model": "llama-3.3-70b-versatile",
            "free": True,
        },
        "gemini": {
            "name": "Google Gemini (FREE)",
            "env": "GEMINI_API_KEY",
            "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
            "model": "gemini-2.0-flash",
            "free": True,
        },
        "claude": {
            "name": "Claude (Anthropic)",
            "env": "ANTHROPIC_API_KEY",
            "url": "https://api.anthropic.com/v1/messages",
            "model": "claude-sonnet-5",
            "free": False,
        },
        "openai": {
            "name": "OpenAI (GPT-4o)",
            "env": "OPENAI_API_KEY",
            "url": "https://api.openai.com/v1/chat/completions",
            "model": "gpt-4o",
            "free": False,
        },
    }

    def __init__(self):
        self.active_provider = None
        self.api_key = None
        self.config = None
        self._discover()

    def _discover(self):
        """Auto-discover best available provider (free first)."""
        for name in ["groq", "gemini", "claude", "openai"]:
            info = self.PROVIDERS[name]
            key = os.environ.get(info["env"])
            if key:
                self.active_provider = name
                self.api_key = key
                self.config = info
                ok(f"AI Engine: {info['name']} ({info['model']})")
                return
        warn("No AI API keys found. Run: export GROQ_API_KEY=gsk_...")
        warn("Get free key at: https://console.groq.com/")

    def is_ready(self) -> bool:
        return self.api_key is not None

    def get_status(self) -> str:
        if not self.is_ready():
            return "❌ No API key"
        return f"✅ {self.config['name']} | {'FREE' if self.config['free'] else 'PAID'} | {self.config['model']}"

    def ask(self, system_prompt: str, user_prompt: str, temperature: float = 0.3) -> str:
        """Send prompt to AI and get response."""
        if not self.is_ready():
            return json.dumps({"error": "No AI provider configured"})

        try:
            if self.active_provider == "groq":
                return self._query_openai_compat(system_prompt, user_prompt, temperature)
            elif self.active_provider == "gemini":
                return self._query_gemini(system_prompt, user_prompt, temperature)
            elif self.active_provider == "claude":
                return self._query_claude(system_prompt, user_prompt, temperature)
            elif self.active_provider == "openai":
                return self._query_openai_compat(system_prompt, user_prompt, temperature)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _query_openai_compat(self, system: str, user: str, temp: float) -> str:
        """Query Groq or any OpenAI-compatible API."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = json.dumps({
            "model": self.config["model"],
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temp,
            "max_tokens": 4096,
        }).encode()

        req = Request(self.config["url"], data=body, headers=headers, method="POST")
        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            return data["choices"][0]["message"]["content"]

    def _query_gemini(self, system: str, user: str, temp: float) -> str:
        """Query Google Gemini API."""
        url = f"{self.config['url']}?key={self.api_key}"
        body = json.dumps({
            "contents": [{"parts": [{"text": f"{system}\n\n{user}"}]}],
            "generationConfig": {"temperature": temp, "maxOutputTokens": 4096},
        }).encode()

        req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            return data["candidates"][0]["content"]["parts"][0]["text"]

    def _query_claude(self, system: str, user: str, temp: float) -> str:
        """Query Anthropic Claude API."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        body = json.dumps({
            "model": self.config["model"],
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": temp,
        }).encode()

        req = Request(self.config["url"], data=body, headers=headers, method="POST")
        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            return data["content"][0]["text"]


# ═══════════════════════════════════════════════════════════════
#  VULNERABILITY KNOWLEDGE BASE (AI-Augmented)
# ═══════════════════════════════════════════════════════════════

class VulnDB:
    """Built-in vulnerability intelligence — augmented by AI queries."""

    PORT_RISK = {
        21: ("FTP", "HIGH", "Plaintext auth, anonymous access risk"),
        22: ("SSH", "MEDIUM", "Check for weak creds, outdated OpenSSH versions"),
        23: ("Telnet", "CRITICAL", "Completely unencrypted — credential theft!"),
        25: ("SMTP", "MEDIUM", "Open relay check, email spoofing risk"),
        53: ("DNS", "LOW", "Zone transfer check, cache poisoning"),
        80: ("HTTP", "MEDIUM", "Web server — check for LFI, SQLi, XSS"),
        110: ("POP3", "MEDIUM", "Plaintext email protocol"),
        111: ("RPC", "HIGH", "NFS enumeration, rpcbind exploitation"),
        135: ("MSRPC", "HIGH", "Windows RPC — MS08-067 risk"),
        139: ("NetBIOS", "HIGH", "SMB over NetBIOS — info leak"),
        143: ("IMAP", "MEDIUM", "Email protocol, check for creds in transit"),
        389: ("LDAP", "MEDIUM", "Directory service — info disclosure"),
        443: ("HTTPS", "LOW", "Check SSL/TLS config, security headers"),
        445: ("SMB", "CRITICAL", "EternalBlue (MS17-010) — RCE!"),
        636: ("LDAPS", "LOW", "Secure LDAP — check cert"),
        873: ("RSYNC", "HIGH", "Rsync without auth = file access!"),
        993: ("IMAPS", "LOW", "Secure IMAP"),
        995: ("POP3S", "LOW", "Secure POP3"),
        1080: ("SOCKS", "MEDIUM", "Proxy — potential tunneling risk"),
        1352: ("Lotus", "MEDIUM", "Lotus Notes — legacy attack surface"),
        1433: ("MSSQL", "HIGH", "Database — sa default password risk!"),
        1521: ("Oracle", "HIGH", "Oracle DB — TNS listener poisoning"),
        2049: ("NFS", "HIGH", "NFS share — no_root_squash risk!"),
        2375: ("Docker", "CRITICAL", "Docker API without TLS = container escape!"),
        3128: ("Squid", "MEDIUM", "HTTP proxy — potential abuse"),
        3306: ("MySQL", "HIGH", "Database — default creds, SQL injection"),
        3389: ("RDP", "CRITICAL", "BlueKeep (CVE-2019-0708) — RCE!"),
        3690: ("SVN", "MEDIUM", "Subversion — source code leak"),
        4369: ("RabbitMQ", "MEDIUM", "Message queue — default creds"),
        4848: ("GlassFish", "HIGH", "Admin console — default admin/admin!"),
        5000: ("UPnP", "MEDIUM", "Universal Plug and Play — SSDP amplification"),
        5432: ("PostgreSQL", "HIGH", "Database — weak auth, SQL injection"),
        5555: ("Android", "MEDIUM", "Android debug bridge risk"),
        5666: ("Nagios", "HIGH", "Nagios — RCE via NRPE!"),
        5672: ("AMQP", "LOW", "Message queue protocol"),
        5800: ("VNC-http", "HIGH", "VNC over HTTP — check auth"),
        5900: ("VNC", "HIGH", "VNC without password = full desktop access!"),
        5984: ("CouchDB", "HIGH", "NoSQL DB — check for open instance"),
        6379: ("Redis", "CRITICAL", "Redis without auth = RCE via Lua!"),
        6443: ("K8s API", "HIGH", "Kubernetes API — cluster takeover risk"),
        7001: ("WebLogic", "CRITICAL", "Oracle WebLogic — CVE-2020-14882 RCE!"),
        8080: ("HTTP-Alt", "MEDIUM", "Alternative web port — check all web vulns"),
        8443: ("HTTPS-Alt", "LOW", "Alternative HTTPS"),
        9000: ("Portainer", "MEDIUM", "Docker management UI"),
        9090: ("WebSM", "LOW", "Web-based admin interface"),
        9200: ("Elasticsearch", "HIGH", "Log4Shell (CVE-2021-44228) risk!"),
        10000: ("Webmin", "HIGH", "Webmin — check for RCE vulns"),
        11211: ("Memcached", "MEDIUM", "UDP amplification DDoS risk"),
        27017: ("MongoDB", "CRITICAL", "MongoDB without auth = full data access!"),
        50070: ("HDFS", "MEDIUM", "Hadoop NameNode UI"),
    }

    @classmethod
    def analyze_port(cls, port: int, service: str = "", version: str = "") -> Dict:
        """Get vulnerability intel for a port/service."""
        info = cls.PORT_RISK.get(port, {
            "risk": "LOW",
            "name": service or f"Port {port}",
            "desc": "Unknown service — manual research recommended"
        })
        return {
            "port": port,
            "service": service or info[0],
            "risk": info[1],
            "description": info[2],
            "version": version,
        }


# ═══════════════════════════════════════════════════════════════
#  RECONNAISSANCE ENGINE
# ═══════════════════════════════════════════════════════════════

class ReconEngine:
    """Professional-grade recon module."""

    def __init__(self, target: str):
        self.target = target.strip().lower()
        self.ip = ""
        self.ports: List[Dict] = []
        self.subdomains: List[str] = []
        self.dns_records: Dict[str, List[str]] = {}

    def resolve(self) -> bool:
        """Resolve target to IP (prefers IPv4)."""
        try:
            host = self.target.replace("https://", "").replace("http://", "").split("/")[0]
            addrs = socket.getaddrinfo(host, None, socket.AF_INET)
            self.ip = addrs[0][4][0]
            self.target = host
            return True
        except:
            return False

    def quick_scan(self) -> List[Dict]:
        """Quick port scan using nmap (top 1000 ports)."""
        section("🔍 PORT SCAN")

        if not shutil.which("nmap"):
            warn("nmap not found — using socket scan")
            return self._socket_scan()

        info(f"Scanning {self.ip} (top 1000 ports)...")
        rc, out = shell(["nmap", "-sS", "-sV", "--top-ports", "1000",
                         "-T4", "--open", self.ip], timeout=180)

        if rc != 0:
            warn(f"nmap error: {out[:100]}")
            return self._socket_scan()

        ports = re.findall(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$', out, re.MULTILINE)
        for p_num, svc, ver in ports:
            self.ports.append({
                "port": int(p_num), "service": svc,
                "version": ver.strip(), "protocol": "tcp"
            })

        self.ports.sort(key=lambda p: p["port"])
        ok(f"Found {len(self.ports)} open ports")
        return self.ports

    def _socket_scan(self) -> List[Dict]:
        """Fallback port scan using Python sockets."""
        info("Running socket-based scan (common ports)...")
        common = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
                  443, 445, 873, 993, 995, 1433, 1521, 2049, 2375, 3128,
                  3306, 3389, 5432, 5900, 5984, 6379, 6443, 7001, 8080,
                  8443, 9000, 9090, 9200, 10000, 11211, 27017]

        for port in common:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((self.ip, port)) == 0:
                    self.ports.append({
                        "port": port, "service": "",
                        "version": "", "protocol": "tcp"
                    })
                s.close()
            except:
                pass

        self.ports.sort(key=lambda p: p["port"])
        ok(f"Found {len(self.ports)} open ports")
        return self.ports

    def quick_dns(self):
        """Quick DNS record check."""
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            rc, out = shell(["dig", "+short", rtype, self.target], timeout=10)
            if rc == 0 and out.strip():
                records = [r for r in out.split("\n") if r.strip()]
                self.dns_records[rtype] = records


    def run(self) -> Dict:
        """Execute full recon."""
        section(f"🎯 TARGET: {self.target}")

        if not self.resolve():
            err(f"Cannot resolve {self.target}")
            return {"target": self.target, "status": "error"}

        ok(f"Resolved: {self.target} → {self.ip}")
        self.quick_dns()
        self.quick_scan()

        return {
            "target": self.target,
            "ip": self.ip,
            "ports": self.ports,
            "dns": self.dns_records,
            "timestamp": datetime.now().isoformat(),
        }


# ═══════════════════════════════════════════════════════════════
#  AI ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════

class AIAnalyzer:
    """
    AI-powered vulnerability analysis.
    Uses LLM to interpret scan results and provide expert guidance.
    """

    SYSTEM_PROMPT = """You are VulnForge AI, an elite cybersecurity analyst and penetration testing expert.
Your specialty is analyzing reconnaissance data and providing actionable exploitation guidance.

Rules:
1. Always respond in VALID JSON format only
2. Be specific with commands, CVEs, and exploitation techniques
3. Prioritize critical and high-severity findings
4. Consider real-world exploitability, not just CVSS scores
5. Provide step-by-step exploitation commands where applicable
6. Include references to relevant tools (Metasploit, Hydra, etc.)"""

    ANALYSIS_TEMPLATE = """
Analyze this reconnaissance data and provide expert exploitation guidance:

TARGET: {target} ({ip})
TIMESTAMP: {timestamp}

OPEN PORTS:
{ports}

DNS RECORDS:
{dns}

Respond in JSON format with this exact structure:
{{
    "risk_score": integer 0-100,
    "critical": integer,
    "high": integer,
    "medium": integer,
    "low": integer,
    "summary": "one paragraph summary",
    "findings": [
        {{
            "port": integer,
            "service": "string",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "issue": "brief title",
            "description": "detailed explanation",
            "exploitation": "specific exploitation steps with commands",
            "cve": "CVE-ID or 'Research required'",
            "remediation": "how to fix"
        }}
    ],
    "attack_vectors": ["ordered list of attack paths"],
    "recommendations": ["ordered list of actionable steps"],
    "tools_required": ["hydra", "metasploit", "sqlmap", etc]
}}
"""

    def __init__(self, ai: AIProvider):
        self.ai = ai

    def analyze(self, recon_data: Dict) -> Dict:
        """Run AI analysis on recon data."""
        section("🧠 AI VULNERABILITY ANALYSIS")

        if not self.ai.is_ready():
            warn("AI not available — using local analysis")
            return self._local_analysis(recon_data)

        # Build port summary
        port_lines = []
        for p in recon_data.get("ports", []):
            vuln = VulnDB.analyze_port(p["port"], p.get("service", ""), p.get("version", ""))
            port_lines.append(
                f"  {p['port']}/tcp  {p.get('service', vuln['service']):15} "
                f"v{p.get('version','?')[:30]:32} [{vuln['risk']}]"
            )

        dns_str = json.dumps(recon_data.get("dns", {}), indent=2)

        prompt = self.ANALYSIS_TEMPLATE.format(
            target=recon_data.get("target", "?"),
            ip=recon_data.get("ip", "?"),
            timestamp=recon_data.get("timestamp", "?"),
            ports="\n".join(port_lines) if port_lines else "  (no open ports)",
            dns=dns_str if dns_str != "{}" else "  (no DNS records)",
        )

        with console.status("[cyan]Querying AI for deep analysis...[/]" if RICH else ""):
            response = self.ai.ask(self.SYSTEM_PROMPT, prompt)

        try:
            # Try to parse JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                ok(f"AI Analysis complete! Risk: {result.get('risk_score', '?')}/100")
                return result
        except:
            pass

        # Fallback to local analysis if AI fails
        warn("AI response parsing failed — using local analysis")
        return self._local_analysis(recon_data)

    def _local_analysis(self, data: Dict) -> Dict:
        """Fallback analysis using built-in vulnerability database."""
        ports = data.get("ports", [])
        findings = []

        for p in ports:
            vuln = VulnDB.analyze_port(p["port"], p.get("service", ""), p.get("version", ""))
            if vuln["risk"] in ("CRITICAL", "HIGH"):
                findings.append({
                    "port": p["port"],
                    "service": vuln["service"],
                    "severity": vuln["risk"],
                    "issue": f"{vuln['service']} — {vuln['risk']} Risk",
                    "description": vuln["description"],
                    "exploitation": f"nmap -p {p['port']} -sV {data.get('ip','')}",
                    "cve": "Research required",
                    "remediation": "Update software, restrict access, enable auth"
                })

        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        score = min(critical * 30 + high * 15, 100)

        ok(f"Local analysis complete! Risk: {score}/100")
        return {
            "risk_score": score,
            "critical": critical,
            "high": high,
            "medium": 0, "low": 0,
            "summary": f"Found {critical} critical and {high} high-risk services. "
                       f"Recommended: Manual investigation and exploitation testing.",
            "findings": findings,
            "attack_vectors": [f"Exploit exposed services on ports: {[f['port'] for f in findings[:3]]}"],
            "recommendations": [
                "Close unnecessary ports", "Enable authentication on all services",
                "Update to latest versions", "Use firewall restrictions"
            ],
            "tools_required": ["nmap", "hydra", "searchsploit"],
        }


# ═══════════════════════════════════════════════════════════════
#  EXPLOITATION ADVISOR
# ═══════════════════════════════════════════════════════════════

class ExploitAdvisor:
    """AI-powered exploitation guidance generator."""

    def __init__(self, ai: AIProvider):
        self.ai = ai

    def generate_playbook(self, target_ip: str, findings: List[Dict]) -> str:
        """Generate a step-by-step exploitation playbook."""
        if not findings or not self.ai.is_ready():
            return ""

        section("💥 EXPLOITATION PLAYBOOK")
        info("Generating step-by-step exploitation guide...")

        finding_summary = "\n".join(
            f"- Port {f.get('port','?')}/{f.get('service','?')}: {f.get('issue','?')} [{f.get('severity','?')}]"
            for f in findings[:5]
        )

        prompt = f"""Target: {target_ip}
Findings:
{finding_summary}

Generate a step-by-step penetration testing playbook:
1. Enumeration commands (nmap, gobuster, etc.)
2. Vulnerability verification (specific checks)
3. Exploitation steps (with exact commands)
4. Post-exploitation (if successful)
5. Recommended tools and wordlists

Respond in concise markdown format with code blocks for commands."""

        response = self.ai.ask(
            "You are a penetration testing expert. Provide actionable exploitation steps only.",
            prompt,
            temperature=0.4
        )

        ok("Playbook generated!")
        return response


# ═══════════════════════════════════════════════════════════════
#  PROFESSIONAL REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

class ReportGenerator:
    """Professional-grade HTML report generator — client-ready."""

    @staticmethod
    def generate(recon: Dict, analysis: Dict, playbook: str) -> str:
        """Generate an executive-level HTML report."""
        timestamp = datetime.now()
        target = recon.get("target", "unknown")
        ip = recon.get("ip", "?")
        safe_name = target.replace(".", "_")
        filename = f"vulnforge_report_{safe_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"

        # Risk level
        score = analysis.get("risk_score", 0)
        if score >= 70: risk, rc = "CRITICAL", "#dc3545"
        elif score >= 40: risk, rc = "HIGH", "#fd7e14"
        elif score >= 20: risk, rc = "MEDIUM", "#ffc107"
        else: risk, rc = "LOW", "#28a745"

        # Findings table
        findings_rows = ""
        for f in analysis.get("findings", []):
            sev = f.get("severity", "INFO")
            sev_c = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}.get(sev, "#6c757d")
            findings_rows += f"""
            <tr>
                <td>{f.get('port','?')}</td>
                <td>{f.get('service','?')}</td>
                <td><span class="sev" style="background:{sev_c}">{sev}</span></td>
                <td>{f.get('issue','?')}</td>
                <td>{f.get('description','?')[:100]}</td>
                <td>{f.get('exploitation','N/A')[:80]}</td>
            </tr>"""

        # Ports table
        ports_rows = "".join(
            f"<tr><td>{p['port']}</td><td>{p.get('service','?')}</td><td>{p.get('version','?')[:30]}</td></tr>"
            for p in recon.get("ports", [])
        )

        # Attack vectors
        vectors_html = "<ol>" + "".join(
            f"<li>{v}</li>" for v in analysis.get("attack_vectors", [])
        ) + "</ol>"

        # Recommendations
        recs_html = "<ol>" + "".join(
            f"<li>{r}</li>" for r in analysis.get("recommendations", [])
        ) + "</ol>"

        playbook_html = Markdown(playbook) if playbook and RICH else f"<pre>{playbook}</pre>"

        # DNS
        dns_html = ""
        for rtype, records in recon.get("dns", {}).items():
            dns_html += f"<div><strong>{rtype}:</strong> {', '.join(records[:3])}</div>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnForge AI — Security Assessment Report</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif; background: #0a0a1a; color: #e0e0e0; }}
        .header {{ background: linear-gradient(135deg, #0d0d2b, #1a1a4e); padding: 50px 30px; text-align: center; border-bottom: 3px solid #00ff88; }}
        .header h1 {{ color: #00ff88; font-size: 2.5em; letter-spacing: 2px; }}
        .header .subtitle {{ color: #888; margin-top: 8px; font-size: 14px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
        .card {{ background: #12122a; border-radius: 16px; padding: 30px; margin: 20px 0; border: 1px solid #2a2a5a; box-shadow: 0 8px 32px rgba(0,0,0,.4); }}
        .card h2 {{ color: #00ff88; margin-bottom: 20px; font-size: 1.3em; border-bottom: 1px solid #2a2a5a; padding-bottom: 12px; }}
        .badge {{ display: inline-block; padding: 12px 40px; border-radius: 30px; font-weight: 800; font-size: 22px; color: white; background: {rc}; }}
        .stats {{ display: flex; gap: 15px; flex-wrap: wrap; justify-content: center; margin: 20px 0; }}
        .stat-box {{ background: #1a1a3e; padding: 20px 30px; border-radius: 12px; text-align: center; min-width: 120px; flex: 1; }}
        .stat-num {{ font-size: 2.5em; font-weight: 800; color: #00ff88; }}
        .stat-label {{ font-size: 13px; color: #888; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ text-align: left; padding: 12px 10px; color: #00ff88; border-bottom: 2px solid #333366; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
        td {{ padding: 10px; border-bottom: 1px solid #1a1a3e; font-size: 13px; }}
        .sev {{ padding: 3px 10px; border-radius: 12px; color: white; font-size: 11px; font-weight: 700; }}
        tr:hover {{ background: #1a1a3e; }}
        .data-row {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .data-row > div {{ background: #1a1a3e; padding: 10px 16px; border-radius: 8px; font-size: 13px; }}
        .footer {{ text-align: center; padding: 30px; color: #555; font-size: 12px; border-top: 1px solid #1a1a3e; margin-top: 40px; }}
        a {{ color: #00ff88; }}
        @media print {{ .header {{ padding: 30px; }} .card {{ break-inside: avoid; }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ VulnForge AI</h1>
        <div style="margin-top: 20px;"><span class="badge">{risk} — Score: {score}/100</span></div>
        <p class="subtitle">Target: {target} ({ip}) | {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div class="container">

        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat-box"><div class="stat-num">{len(recon.get('ports',[]))}</div><div class="stat-label">Open Ports</div></div>
                <div class="stat-box"><div class="stat-num">{analysis.get('critical',0)}</div><div class="stat-label">🔴 Critical</div></div>
                <div class="stat-box"><div class="stat-num">{analysis.get('high',0)}</div><div class="stat-label">🟠 High</div></div>
                <div class="stat-box"><div class="stat-num">{analysis.get('medium',0)}</div><div class="stat-label">🟡 Medium</div></div>
                <div class="stat-box"><div class="stat-num">{len(analysis.get('findings',[]))}</div><div class="stat-label">Total Findings</div></div>
            </div>
            <p style="margin-top: 16px; line-height: 1.6; color: #ccc;">{analysis.get('summary', 'No analysis summary.')}</p>
        </div>

        <div class="card">
            <h2>🔌 Open Ports & Services</h2>
            <table>
                <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
                <tbody>{ports_rows if ports_rows else '<tr><td colspan="3" style="color:#888">No open ports</td></tr>'}</tbody>
            </table>
        </div>

        {f'<div class="card"><h2>📡 DNS Records</h2><div class="data-row">{dns_html}</div></div>' if dns_html else ''}

        <div class="card">
            <h2>🛡️ Security Findings ({len(analysis.get('findings',[]))})</h2>
            <table>
                <thead><tr><th>Port</th><th>Service</th><th>Severity</th><th>Issue</th><th>Description</th><th>Exploitation</th></tr></thead>
                <tbody>{findings_rows if findings_rows else '<tr><td colspan="6" style="color:#888">No vulnerabilities identified</td></tr>'}</tbody>
            </table>
        </div>

        <div class="card">
            <h2>⚔️ Attack Vectors</h2>
            {vectors_html}
        </div>

        <div class="card">
            <h2>🛡️ Recommendations</h2>
            {recs_html}
        </div>

        {f'<div class="card"><h2>💥 Exploitation Playbook</h2><div style="line-height:1.6">{playbook_html}</div></div>' if playbook else ''}

        <div class="footer">
            <p>Generated by <strong>VulnForge AI</strong> — Professional Security Assessment Tool</p>
            <p>Author: ANKIT48274 | GitHub: https://github.com/ANKIT48274/vulnforge-ai</p>
            <p style="margin-top: 4px; color: #ff4444;">⚠ For authorized testing only</p>
        </div>
    </div>
</body>
</html>"""

        with open(filename, "w") as f:
            f.write(html)

        return filename


# ═══════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════

class VulnForge:
    """Main application — where everything comes together."""

    def __init__(self):
        self.ai = AIProvider()
        self.recon_data = {}
        self.analysis = {}
        self.playbook = ""

    def show_banner(self):
        """Display professional banner."""
        cprint(f"""
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   __   __  _  _   __    ____  _ __   __ _  _ __      ║
    ║   \\ \\ / / | || | / _|  / ___|| '_ \\ / _` || '_ \\     ║
    ║    \\ V /  | || || |_   \\___ \\| | | | (_| || | | |    ║
    ║     |_|   |_||_| \\__|  |____/|_| |_|\\__, ||_| |_|    ║
    ║                                      |___/           ║
    ║   🔥 AI-Powered Pentesting Assistant                 ║
    ║   v1.0 | ANKIT48274                                  ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
""", color="cyan", bold=True)
        cprint(f"  AI: {self.ai.get_status()}", "cyan")
        cprint(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "dim")

    def show_menu(self):
        """Display interactive menu."""
        menu = f"""
    [1] 🎯  Full Assessment     — Recon → AI Analyze → Playbook → Report
    [2] 🔍  Quick Recon         — Port scan + DNS only
    [3] 🧠  AI Deep Analysis    — Analyze existing data with AI
    [4] 💥  Exploit Playbook    — Generate exploitation guide
    [5] 📊  View Report         — Open latest HTML report
    [6] 🔑  AI Provider Info    — Show API status & switch provider
    [0] ❌  Exit
"""
        if RICH:
            console.print(Panel(menu, title="[red]☠ VulnForge AI[/]", border_style="red"))
        else:
            print(menu)

    def run_full(self):
        """Run complete assessment pipeline."""
        target = Prompt.ask("  🎯 Target", default="") if RICH else input("  🎯 Target: ").strip()
        if not target: return

        # Phase 1: Recon
        recon = ReconEngine(target)
        self.recon_data = recon.run()

        if not self.recon_data.get("ports"):
            warn("No open ports found — analysis will be limited")
            if not Confirm.ask("Continue?", default=False):
                return

        # Phase 2: AI Analysis
        analyzer = AIAnalyzer(self.ai)
        self.analysis = analyzer.analyze(self.recon_data)

        # Phase 3: Exploit Playbook
        if self.ai.is_ready() and self.analysis.get("findings"):
            advisor = ExploitAdvisor(self.ai)
            self.playbook = advisor.generate_playbook(
                self.recon_data.get("ip", ""),
                self.analysis.get("findings", [])
            )

        # Phase 4: Report
        self._generate_report()

    def run_recon_only(self):
        """Run recon only."""
        target = Prompt.ask("  🎯 Target", default="") if RICH else input("  🎯 Target: ").strip()
        if not target: return
        recon = ReconEngine(target)
        self.recon_data = recon.run()

    def run_ai_analysis(self):
        """Run AI analysis on existing/historical data."""
        if not self.recon_data:
            file_path = Prompt.ask("  📁 JSON data file", default="") if RICH else input("  📁 JSON file: ").strip()
            if file_path and os.path.exists(file_path):
                with open(file_path) as f:
                    self.recon_data = json.load(f)
                ok("Loaded data from file")
            else:
                warn("No data to analyze. Run recon first (option 1 or 2)")
                return

        analyzer = AIAnalyzer(self.ai)
        self.analysis = analyzer.analyze(self.recon_data)
        self._display_findings()

    def _display_findings(self):
        """Show analysis results in terminal."""
        findings = self.analysis.get("findings", [])
        if not findings:
            info("No significant findings")
            return

        if RICH:
            table = Table(title="Findings", box=box.ROUNDED)
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="blue")
            table.add_column("Severity")
            table.add_column("Issue", style="white")
            for f in findings:
                sev = f.get("severity", "INFO")
                color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow"
                table.add_row(str(f.get("port","?")), f.get("service","?"), f"[{color}]{sev}[/]", f.get("issue","?"))
            console.print(table)
        else:
            print(f"\n  {'Port':<6} {'Service':<15} {'Severity':<10} Issue")
            print(f"  {'-'*60}")
            for f in findings:
                print(f"  {f.get('port','?'):<6} {f.get('service','?'):<15} {f.get('severity','?'):<10} {f.get('issue','?')[:30]}")

    def _generate_report(self):
        """Generate HTML report."""
        section("📊 GENERATING REPORT")
        filename = ReportGenerator.generate(self.recon_data, self.analysis, self.playbook)
        ok(f"Report: {filename}")

        if RICH and Confirm.ask("Open in browser?", default=True):
            try:
                import subprocess as sp
                sp.Popen(["xdg-open", filename], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                ok("Opening report...")
            except:
                warn("Could not auto-open")

    def show_ai_status(self):
        """Show AI provider status and allow switching."""
        section("🔑 AI PROVIDER STATUS")
        cprint(f"  Current: {self.ai.get_status()}\n", "cyan")
        cprint("  Environment variables checked:", "dim")
        for name, info in AIProvider.PROVIDERS.items():
            key = os.environ.get(info["env"], "NOT SET")
            shown = key[:15] + "..." if key != "NOT SET" and len(key) > 15 else key
            status = "✅" if key != "NOT SET" else "❌"
            cprint(f"    {status} {info['name']:25} → {shown}", "dim")
        cprint(f"\n  💡 Get a free key at: https://console.groq.com/", "yellow")
        cprint(f"  💡 Then: export GROQ_API_KEY=gsk_your_key", "yellow")

    def run(self):
        """Main application loop."""
        os.makedirs("output", exist_ok=True)
        self.show_banner()

        while True:
            self.show_menu()
            if RICH:
                choice = Prompt.ask("  Choice", choices=["1","2","3","4","5","6","0"], default="1")
            else:
                choice = input("  Choice [0-6]: ").strip()

            if choice == "0":
                section("Exiting")
                ok("Stay stealthy! 🚀")
                break
            elif choice == "1": self.run_full()
            elif choice == "2": self.run_recon_only()
            elif choice == "3": self.run_ai_analysis()
            elif choice == "4":
                if not self.analysis:
                    warn("Run assessment first (option 1)")
                else:
                    advisor = ExploitAdvisor(self.ai)
                    self.playbook = advisor.generate_playbook(
                        self.recon_data.get("ip", ""),
                        self.analysis.get("findings", [])
                    )
            elif choice == "5":
                import glob
                reports = sorted(glob.glob("vulnforge_report_*.html"))
                if reports:
                    latest = reports[-1]
                    ok(f"Opening: {latest}")
                    subprocess.Popen(["xdg-open", latest], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    warn("No reports found")
            elif choice == "6": self.show_ai_status()
            print()


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

def cli():
    """CLI argument parser for direct usage."""
    import argparse
    p = argparse.ArgumentParser(prog="vulnforge", description="VulnForge AI — AI-Powered Pentesting Assistant")
    p.add_argument("-t", "--target", help="Target domain/IP")
    p.add_argument("--recon-only", action="store_true", help="Run recon only")
    p.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    p.add_argument("--version", action="version", version="VulnForge AI v1.0")

    # If no args, run interactive
    if len(sys.argv) == 1:
        app = VulnForge()
        app.run()
        return

    args = p.parse_args()
    app = VulnForge()
    app.show_banner()

    if args.target:
        recon = ReconEngine(args.target)
        app.recon_data = recon.run()
        if not args.recon_only:
            analyzer = AIAnalyzer(app.ai)
            app.analysis = analyzer.analyze(app.recon_data)

            if app.ai.is_ready() and app.analysis.get("findings"):
                advisor = ExploitAdvisor(app.ai)
                app.playbook = advisor.generate_playbook(
                    app.recon_data.get("ip", ""),
                    app.analysis.get("findings", [])
                )

            if not args.no_report:
                app._generate_report()

        section("✅ Complete")


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        print(f"\n  Interrupted. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\n  Fatal: {e}")
        sys.exit(1)