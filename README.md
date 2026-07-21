# ☠️ AutoRecon AI — ULTIMATE v3.0

**Full AI-Powered Penetration Testing & Exploitation Engine**

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.0-red)
![Kali](https://img.shields.io/badge/Kali-Linux-blueviolet)

AutoRecon AI is a **complete penetration testing framework** built for cybersecurity professionals, bug bounty hunters, and CTF players. It combines multi-threaded scanning, AI-powered vulnerability analysis, brute-force, exploitation, and professional reporting — all in one tool.

---

## 🔥 FEATURES (v3 ULTIMATE)

| Phase | Module | What it does |
|---|---|---|
| 🕵️ **RECON** | Intelligence Gathering | Subdomains (crt.sh/fierce), DNS enum, Port scan (nmap), WHOIS, Dir enum (gobuster) |
| 🌐 **WEB SCAN** | Vulnerability Assessment | SQLi (sqlmap), XSS, Nikto, Security Headers, Tech detection (whatweb) |
| 🔓 **BRUTE FORCE** | Credential Attack | Hydra on SSH/FTP/HTTP/SMB/RDP/VNC with wordlists |
| 💥 **EXPLOIT** | Auto Exploitation | SMB (EternalBlue), RDP (BlueKeep), Reverse payloads (msfvenom), Searchsploit |
| 🎧 **LISTENER** | Shell Handler | Built-in reverse shell listener |
| 🧠 **AI DEEP** | AI Analysis | Claude/OpenAI/Grok API integration for deep intelligence |
| 📊 **REPORT** | HTML Reports | Cyberpunk-themed professional reports with risk scoring |

## 🚀 QUICK START

```bash
# Clone (no login required!)
git clone https://github.com/ANKIT48274/autorecon-ai.git
cd autorecon-ai

# 🥇 RECOMMENDED: Run v3 ULTIMATE (interactive menu)
python3 autorecon-v3-ultimate.py

# One-shot recon mode
python3 autorecon-v3-ultimate.py -t scanme.nmap.org -m recon

# Full auto attack chain
python3 autorecon-v3-ultimate.py -t TARGET --lhost YOUR_IP -m full

# Or use v2 scanner
python3 autorecon-ai-v2.py -t example.com -m quick
```

## 🎯 SCAN MODES (v3 ULTIMATE)

```
1  🕵️  FULL RECON     — Subdomains, Ports, DNS, WHOIS, Directories
2  🌐  WEB SCAN        — SQLi, XSS, Nikto, Headers
3  🔓  BRUTE FORCE     — Hydra SSH/FTP/HTTP/SMB/RDP
4  💥  EXPLOIT          — SMB (EternalBlue), RDP (BlueKeep), Payloads
5  🎧  LISTENER         — Reverse shell handler
6  🔥  FULL AUTO        — 1→2→3→4 (Complete attack chain!)
7  🧠  AI DEEP          — Claude/OpenAI/Grok analysis
0  ❌  EXIT
```

## 📁 PROJECT FILES

| File | Size | Purpose |
|---|---|---|
| `autorecon-v3-ultimate.py` | ~50 KB | 🔥 **Main tool — Full exploitation engine** |
| `autorecon-ai-v2.py` | ~96 KB | Scanner + AI engine (v2) |
| `ai_api.py` | ~20 KB | Claude/OpenAI/Grok API integration |
| `autorecon_launcher.py` | ~14 KB | Unified launcher for all tools |
| `README.md` | ~4 KB | Documentation |

## 💡 EXAMPLE USAGE

```bash
# Full penetration test on a target
python3 autorecon-v3-ultimate.py -t 192.168.1.100 -m full --lhost 192.168.1.50

# Output:
# 📁 autorecon_v3_output_TIMESTAMP/
#   ├── nmap_quick.xml
#   ├── nmap_quick.txt
#   ├── gobuster_80.txt
#   ├── hydra_ssh.txt
#   ├── payload.elf
#   ├── rev_shell.py
#   └── ...
# 📊 autorecon_v3_report_TARGET_TIMESTAMP.html
```

## 🔧 REQUIREMENTS

- Python 3.9+
- Kali Linux (recommended) or any Linux with security tools
- `rich` library (auto-fallback available)
- Installed tools: nmap, hydra, sqlmap, gobuster, nikto, whatweb, searchsploit, msfvenom
- Optional: Claude/OpenAI/Grok API keys for AI deep analysis

## 🧪 AI API SETUP (Optional)

```bash
# For deep AI analysis (Claude, OpenAI, or Grok)
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export GROK_API_KEY=...

# Then run v3 and choose option 7 (AI Deep)
python3 autorecon-v3-ultimate.py
```

## ⚠️ LEGAL DISCLAIMER

This tool is for **authorized security testing only**. Unauthorized scanning of systems you don't own or have written permission to test may be illegal.

## 📝 LICENSE

MIT License — use freely, contribute openly.

---

**Author: ANKIT48274** | Built with ❤️ for the cybersecurity community
