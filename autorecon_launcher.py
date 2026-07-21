#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   AutoRecon AI Suite - Unified Launcher                     ║
║   AI-Powered Reconnaissance + Analysis + Reporting          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Supports:
  1. 🚀 AutoRecon AI v2     - Multi-threaded scanner + AI analysis
  2. 🤖 AI API Integration  - Claude / OpenAI / Grok deep analysis

Run: python3 autorecon_launcher.py
"""

import os
import sys
import json
import subprocess
import shutil
from datetime import datetime

# ─── Colors ───
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██╗   ██╗
║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██║   ██║
║  ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║   ██║██║   ██║
║  ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║
║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╔╝╚██████╔╝
║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝
║                                                              ║
║  🤖 AI-Powered Reconnaissance Suite v2.0                     ║
║  Author: ANKIT48274 | AI Automation Series                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝
{RESET}"""


def print_msg(icon, msg, color=GREEN):
    print(f"  {color}{icon}{RESET} {msg}")

def print_ok(msg):    print_msg("✅", msg, GREEN)
def print_info(msg):  print_msg("➜", msg, CYAN)
def print_warn(msg):  print_msg("⚠️", msg, YELLOW)
def print_err(msg):   print_msg("❌", msg, RED)


def check_dependencies():
    """Check if all required files exist."""
    files = {
        "autorecon-ai-v2.py": "Main Recon Tool",
        "ai_api.py": "AI API Integration",
        "README.md": "Documentation",
    }

    print_info("Checking project files...")
    missing = []
    for fname, desc in files.items():
        if os.path.exists(fname):
            print_ok(f"{desc} ({fname})")
        else:
            print_warn(f"{desc} ({fname}) — MISSING")
            missing.append(fname)

    return missing


def run_scan():
    """Run the main scanner."""
    print_info("Starting AutoRecon AI Scanner...")
    print()

    target = input(f"  {CYAN}🎯 Target (domain/IP):{RESET} ").strip()
    if not target:
        print_err("No target provided!")
        return

    print()
    print_info(f"Target: {target}")
    print_info("Choose scan mode:")
    print("       1 - Quick Scan (fast)")
    print("       2 - Full Scan (thorough)")
    print("       3 - Smart Scan (AI-driven)")
    print("       4 - Web Focus")
    mode = input(f"  {CYAN}Mode [1-4]:{RESET} ").strip() or "1"

    mode_map = {"1": "quick", "2": "full", "3": "smart", "4": "web"}
    mode_str = mode_map.get(mode, "quick")

    print_info(f"Scanning {target} ({mode_str})...")
    print()

    # Run the scanner
    cmd = [
        sys.executable, "autorecon-ai-v2.py",
        "-t", target,
        "-m", mode_str,
        "-q",
        "--no-browser",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    # Print output
    for line in result.stdout.split("\n"):
        if line.strip():
            print(f"  {line}")

    if result.returncode != 0:
        print_err(f"Scan failed (code {result.returncode})")
        if result.stderr:
            print(result.stderr)
        return None

    # Find the generated JSON
    json_files = [f for f in os.listdir(".") if f.startswith("autorecon_data_") and f.endswith(".json")]
    if json_files:
        # Get the most recent
        latest = max(json_files, key=os.path.getctime)
        print_ok(f"Latest data file: {latest}")
        return latest

    return None


def run_ai_analysis(data_file=None):
    """Run AI API analysis on scan results."""
    from ai_api import AIAPIAnalyzer, APIConfig

    providers = APIConfig.get_available_providers()
    if not providers:
        print_warn("No AI API keys configured!")
        print_info("Set one of:")
        print("    export ANTHROPIC_API_KEY=sk-ant-...")
        print("    export OPENAI_API_KEY=sk-...")
        print("    export GROK_API_KEY=...")
        return None

    provider_name = APIConfig.PROVIDERS[providers[0]]["name"]
    print_ok(f"AI Provider available: {provider_name}")

    if not data_file:
        data_file = input(f"  {CYAN}📁 JSON data file:{RESET} ").strip()
        if not data_file or not os.path.exists(data_file):
            print_err("File not found!")
            return None

    with open(data_file) as f:
        scan_data = json.load(f)

    target_info = scan_data.get("target", scan_data.get("scan_results", {}))
    hostname = target_info.get("hostname", "unknown")

    print_info(f"Sending {hostname} scan data to {provider_name}...")
    print_info("This may take 10-30 seconds...")
    print()

    analyzer = AIAPIAnalyzer()
    result = analyzer.enhance_findings([], target_info)

    if "error" in result:
        print_err(f"AI Analysis error: {result['error']}")
        return None

    # Display results
    print(f"\n  {'='*55}")
    print(f"  {BOLD}🧠 AI DEEP ANALYSIS RESULTS{RESET}")
    print(f"  {'='*55}")
    print(f"  Provider:   {result.get('ai_provider', 'Unknown')}")
    print(f"  Risk Level: {result.get('ai_risk_level', 'N/A')}")
    print(f"  Risk Score: {result.get('ai_risk_score', 'N/A')}/100")
    print()

    if result.get("summary"):
        print(f"  📝 Summary: {result['summary'][:300]}")
        print()

    findings = result.get("ai_findings", [])
    if findings:
        print(f"  🔍 AI Findings ({len(findings)}):")
        for f in findings[:5]:
            sev = f.get("severity", "INFO").upper()
            sev_color = RED if sev in ("CRITICAL", "HIGH") else YELLOW if sev == "MEDIUM" else GREEN
            print(f"    {sev_color}[{sev}]{RESET} {f.get('title', '')}")
            if f.get("description"):
                print(f"           {f['description'][:100]}")
            print()

    attack = result.get("attack_vector", {})
    if attack:
        print(f"  ⚔️  Attack Vector:")
        print(f"     Path: {attack.get('path', 'N/A')}")
        print(f"     Exploitation: {str(attack.get('exploitation', ''))[:150]}")

    recs = result.get("recommendations", [])
    if recs:
        print(f"\n  🛡️  Recommendations:")
        for i, r in enumerate(recs[:5], 1):
            print(f"     {i}. {r[:120]}")

    strategy = result.get("pentesting_strategy", "")
    if strategy:
        print(f"\n  🎯 PT Strategy: {strategy[:200]}")

    print(f"\n  {'='*55}")
    print()

    # Save enhanced report
    ai_report_file = f"ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(ai_report_file, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print_ok(f"AI Report saved: {ai_report_file}")

    return result


def show_menu():
    """Show main menu."""
    print()
    print(f"  {BOLD}Select Mode:{RESET}")
    print(f"  {CYAN}1{RESET} 🚀  Full Scan + AI Analysis (recommended)")
    print(f"  {CYAN}2{RESET} 🔍  Quick Scan only")
    print(f"  {CYAN}3{RESET} 🧠  AI Analysis on existing data")
    print(f"  {CYAN}4{RESET} 📊  View HTML Report")
    print(f"  {CYAN}5{RESET} 📋  Batch Scan (from targets.txt)")
    print(f"  {CYAN}6{RESET} 🔧  API Key Setup")
    print(f"  {CYAN}0{RESET} ❌  Exit")
    print()
    return input(f"  {CYAN}Choice [0-6]:{RESET} ").strip()


def view_reports():
    """Open latest HTML report."""
    html_files = [f for f in os.listdir(".") if f.startswith("autorecon_report_") and f.endswith(".html")]
    if not html_files:
        print_warn("No HTML reports found!")
        return

    latest = max(html_files, key=os.path.getctime)
    print_ok(f"Opening: {latest}")
    try:
        subprocess.Popen(["xdg-open", latest], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        print_warn(f"Could not auto-open. File: {latest}")


def setup_api_keys():
    """Guide user to set up API keys."""
    print()
    print(f"  {BOLD}🔧 AI API Key Setup{RESET}")
    print(f"  {'='*40}")
    print()
    print("  Get your API key from:")
    print(f"  {CYAN}Claude:{RESET} https://console.anthropic.com/")
    print(f"  {CYAN}OpenAI:{RESET} https://platform.openai.com/")
    print(f"  {CYAN}Grok:{RESET}   https://console.x.ai/")
    print()

    key = input(f"  {CYAN}Paste API key (any provider):{RESET} ").strip()
    if not key:
        return

    # Detect provider by key prefix
    provider = None
    if key.startswith("sk-ant-"):
        provider = "claude"
        var = "ANTHROPIC_API_KEY"
    elif key.startswith("sk-"):
        provider = "openai"
        var = "OPENAI_API_KEY"
    elif key.startswith("xai-"):
        provider = "grok"
        var = "GROK_API_KEY"
    else:
        # Ask user
        print()
        print("  Which provider?")
        print("  1 - Claude (Anthropic)")
        print("  2 - OpenAI (GPT)")
        print("  3 - Grok (xAI)")
        p = input(f"  {CYAN}Provider [1-3]:{RESET} ").strip()
        mapping = {"1": ("claude", "ANTHROPIC_API_KEY"), "2": ("openai", "OPENAI_API_KEY"), "3": ("grok", "GROK_API_KEY")}
        provider, var = mapping.get(p, (None, None))

    if not provider:
        print_err("Invalid choice!")
        return

    # Set in current session
    os.environ[var] = key

    # Save to shell profile
    shell_rc = os.path.expanduser("~/.zshrc")
    line = f'\nexport {var}="{key}"'

    try:
        with open(shell_rc, "a") as f:
            f.write(line)
        print_ok(f"Saved to {shell_rc}")
    except:
        print_warn("Could not save to profile. Set manually:")
        print(f"  export {var}=\"{key[:10]}...\"")

    print_ok(f"✅ {provider.upper()} API key configured!")


def batch_scan():
    """Run batch scan from targets.txt."""
    if not os.path.exists("targets.txt"):
        print_warn("No targets.txt found!")
        print_info("Creating sample targets.txt...")
        with open("targets.txt", "w") as f:
            f.write("# One target per line\n# scanme.nmap.org\n")
        print_ok("Created targets.txt — add your targets!")
        return

    with open("targets.txt") as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not targets:
        print_warn("No targets in file!")
        return

    print_ok(f"Found {len(targets)} targets")
    for i, t in enumerate(targets, 1):
        print_info(f"[{i}/{len(targets)}] Scanning {t}...")
        cmd = [
            sys.executable, "autorecon-ai-v2.py",
            "-t", t, "-m", "quick", "-q", "--no-browser"
        ]
        subprocess.run(cmd, timeout=300)


def main():
    """Main launcher."""
    print(BANNER)

    # Check env
    try:
        from ai_api import APIConfig
        providers = APIConfig.get_available_providers()
        if providers:
            print_ok(f"AI API ready ({', '.join(providers)})")
        else:
            print_info("No AI API keys set (set in menu option 6)")
    except ImportError:
        print_info("AI API module loaded (no extra providers)")

    print()

    while True:
        choice = show_menu()

        if choice == "0":
            print_ok("Exiting... Happy Hacking! 🚀")
            break

        elif choice == "1":
            # Full Scan + AI
            data_file = run_scan()
            if data_file:
                print()
                run_ai_analysis(data_file)

        elif choice == "2":
            run_scan()

        elif choice == "3":
            data_file = input(f"  {CYAN}📁 JSON file:{RESET} ").strip()
            if data_file:
                run_ai_analysis(data_file)

        elif choice == "4":
            view_reports()

        elif choice == "5":
            batch_scan()

        elif choice == "6":
            setup_api_keys()

        else:
            print_err("Invalid choice!")

        print()


if __name__ == "__main__":
    main()
