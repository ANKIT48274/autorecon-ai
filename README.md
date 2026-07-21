# 🤖 AutoRecon AI v2.0

**AI-Powered Reconnaissance & Analysis Engine**

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0.0-purple)

AutoRecon AI is a professional-grade, AI-powered reconnaissance tool built for cybersecurity professionals, bug bounty hunters, and CTF players. It combines multi-threaded port scanning with intelligent vulnerability analysis and beautiful report generation.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🚀 **Multi-threaded Scanner** | Fast parallel port scanning (up to 100 threads) |
| 🧠 **AI Analysis Engine** | Intelligent vulnerability assessment with CVE matching |
| 🔴 **Risk Scoring** | Automated risk calculation (0-100) per service |
| 🌐 **Web Tech Detection** | Fingerprint web technologies (Apache, Nginx, WordPress, etc.) |
| 📡 **DNS Enumeration** | A, AAAA, MX, NS, TXT, SOA, CNAME records |
| 🔒 **SSL Inspection** | Certificate validation, expiry, SANs, version |
| ⚔️ **Attack Vector Analysis** | Identify dangerous service combinations |
| 📊 **HTML Reports** | Professional, styled reports ready for sharing |
| 📋 **JSON Export** | Machine-readable data for further analysis |
| 🎯 **Multiple Scan Modes** | Quick, Full, Smart, Web Focus, Batch |

## 🚀 Quick Start

```bash
# Clone (anyone can clone without login!)
git clone https://github.com/ANKIT48274/autorecon-ai.git
cd autorecon-ai

# Run interactive
python3 autorecon-ai-v2.py

# Or use CLI mode
python3 autorecon-ai-v2.py -t example.com -m quick
```

## 📋 Scan Modes

```
1  🚀  Quick Scan     — Top 1000 ports, service detection
2  🔬  Full Scan      — All 10000 ports, service detection  
3  🎯  Smart Scan     — AI-driven (chooses ports based on target)
4  🌐  Web Focus      — HTTP/HTTPS servers + SSL inspection
5  📋  Batch Mode     — Scan multiple targets from file
```

## 🧠 AI Analysis Capabilities

### Vulnerability Intelligence
- **CRITICAL**: SMB (EternalBlue), RDP (BlueKeep), Redis, MongoDB, Telnet
- **HIGH**: FTP, MySQL, PostgreSQL, VNC, Docker, Elasticsearch
- **MEDIUM**: SSH, SMTP, DNS, HTTP, LDAP, SNMP
- Plus CVE references and exploitation techniques

### Attack Chain Detection
- Web + Database exposed = SQLi risk
- SMB + RDP = Windows exploitation chain
- AD services exposed = Domain compromise risk
- Multiple web interfaces = Increased attack surface

## 📊 Reports

The tool generates two types of reports:

1. **HTML Report** — Beautiful, styled report with:
   - Risk score dashboard
   - Open ports table with risk levels
   - AI findings with severity indicators
   - DNS records
   - SSL/TLS information
   - Web technology detection
   - Actionable recommendations

2. **JSON Export** — Full machine-readable data for integration with other tools

## 🛡️ Example

```bash
$ python3 autorecon-ai-v2.py

╔══════════════════════════════════════╗
║   AutoRecon AI v2.0                  ║
║   AI-Powered Reconnaissance Engine   ║
╚══════════════════════════════════════╝

Enter target: example.com
[+] Resolved: example.com → 93.184.216.34
[+] Target is ALIVE

Select scan mode:
  1  Quick Scan
  2  Full Scan
  3  Smart Scan

> 1

Scanning 93.184.216.34...
22/open  ssh
80/open  http  
443/open https

🧠 AI ANALYSIS:
  🔴 MEDIUM: SSH (port 22)
  🟡 MEDIUM: HTTP (port 80)
  🟢 LOW: HTTPS (port 443)

📊 Report: autorecon_report_example_com.html
```

## 🔧 Requirements

- Python 3.9+
- `rich` library (auto-installed or use fallback mode)
- `nmap` (optional, for extended scanning)

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. 
Unauthorized scanning of systems you don't own or have written permission to test may be illegal.

## 📝 License

MIT License — use freely, contribute openly.

---

Built with ❤️ Ankit Patidar
