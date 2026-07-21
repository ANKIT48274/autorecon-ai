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
║  🤖 AI API Integration Module                                ║
║  Supports: Claude (Anthropic) • OpenAI (GPT-4) • Grok (xAI) ║
║  Version 1.0 | Part of AutoRecon AI Suite                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝

Author: ANKIT48274 | GitHub: https://github.com/ANKIT48274/autorecon-ai
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional


# ─── API Configuration ───
# Set these as environment variables, or create a .env file

class APIConfig:
    """API key management and configuration."""

    # Environment variable names
    ENV_CLAUDE_KEY = "ANTHROPIC_API_KEY"
    ENV_OPENAI_KEY = "OPENAI_API_KEY"
    ENV_GROK_KEY = "GROK_API_KEY"  # X.AI Grok
    ENV_TOGETHER_KEY = "TOGETHER_API_KEY"  # Together AI (fallback)

    # Available AI providers
    PROVIDERS = {
        "claude": {
            "name": "Claude (Anthropic)",
            "env_key": ENV_CLAUDE_KEY,
            "base_url": "https://api.anthropic.com/v1",
            "models": ["claude-sonnet-5", "claude-haiku-4-5", "claude-opus-4-8"],
            "default_model": "claude-sonnet-5",
        },
        "openai": {
            "name": "OpenAI (GPT-4o)",
            "env_key": ENV_OPENAI_KEY,
            "base_url": "https://api.openai.com/v1",
            "models": ["gpt-4o", "gpt-4o-mini", "o3-mini"],
            "default_model": "gpt-4o",
        },
        "grok": {
            "name": "Grok (xAI)",
            "env_key": ENV_GROK_KEY,
            "base_url": "https://api.x.ai/v1",
            "models": ["grok-beta", "grok-2"],
            "default_model": "grok-beta",
        },
        "together": {
            "name": "Together AI",
            "env_key": ENV_TOGETHER_KEY,
            "base_url": "https://api.together.xyz/v1",
            "models": ["mistralai/Mixtral-8x22B-Instruct-v0.1", "meta-llama/Llama-3.3-70B-Instruct-Turbo"],
            "default_model": "mistralai/Mixtral-8x22B-Instruct-v0.1",
        },
    }

    @classmethod
    def get_key(cls, provider: str) -> Optional[str]:
        """Get API key for a provider from environment."""
        info = cls.PROVIDERS.get(provider)
        if not info:
            return None
        return os.environ.get(info["env_key"])

    @classmethod
    def get_available_providers(cls) -> List[str]:
        """Get list of providers with configured API keys."""
        available = []
        for provider in cls.PROVIDERS:
            if cls.get_key(provider):
                available.append(provider)
        return available

    @classmethod
    def is_any_available(cls) -> bool:
        """Check if any AI provider is configured."""
        return len(cls.get_available_providers()) > 0

    @classmethod
    def get_best_provider(cls) -> Optional[str]:
        """Get the best available provider (priority: Claude > OpenAI > Grok > Together)."""
        for provider in ["claude", "openai", "grok", "together"]:
            if cls.get_key(provider):
                return provider
        return None


# ─── AI Analysis Engine (API-powered) ───

class AIAPIAnalyzer:
    """
    Connects to AI APIs (Claude, OpenAI, Grok) for deep intelligence analysis.
    Goes beyond the rule-based engine by using LLM reasoning.
    """

    def __init__(self, scan_data: Dict = None):
        self.scan_data = scan_data or {}
        self.last_response = ""

    def analyze_scan(self, scan_data: Dict, provider: str = None) -> Dict:
        """
        Send scan results to AI for deep analysis.

        Args:
            scan_data: Full scan data dictionary
            provider: AI provider to use (auto-pick if None)

        Returns:
            AI analysis results with findings
        """
        if not provider:
            provider = APIConfig.get_best_provider()

        if not provider:
            return {"error": "No AI API configured!", "note": "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GROK_API_KEY"}

        return self._query_ai(scan_data, provider)

    def _query_ai(self, scan_data: Dict, provider: str) -> Dict:
        """Query the specified AI provider with scan data."""
        api_key = APIConfig.get_key(provider)
        config = APIConfig.PROVIDERS[provider]

        # Build the prompt
        prompt = self._build_analysis_prompt(scan_data)

        try:
            if provider == "claude":
                return self._query_claude(api_key, config, prompt)
            elif provider == "openai":
                return self._query_openai(api_key, config, prompt)
            elif provider == "grok":
                return self._query_grok(api_key, config, prompt)
            elif provider == "together":
                return self._query_together(api_key, config, prompt)
            else:
                return {"error": f"Unknown provider: {provider}"}
        except Exception as e:
            return {"error": str(e), "provider": provider}

    def _build_analysis_prompt(self, scan_data: Dict) -> str:
        """Build a comprehensive analysis prompt from scan data."""
        target = scan_data.get("target", {})
        hostname = target.get("hostname", "unknown")
        ip = ", ".join(target.get("ip_addresses", []))

        # Ports summary
        ports = target.get("ports", [])
        ports_text = ""
        if ports:
            ports_text = "\n".join([
                f"  - {p['port']}/tcp: {p['service']} (product: {p.get('product','')}, version: {p.get('version','')})"
                for p in ports[:20]
            ])
        else:
            ports_text = "  (no open ports detected)"

        # DNS records
        dns = target.get("dns_records", {})
        dns_text = ""
        for rtype, records in dns.items():
            dns_text += f"  - {rtype}: {', '.join(records[:3])}\n"

        # SSL info
        ssl = target.get("ssl_info", {})
        ssl_text = f"  - SSL Enabled: {ssl.get('enabled', False)}\n"
        if ssl.get("enabled"):
            ssl_text += f"  - Version: {ssl.get('version', '')}\n"
            ssl_text += f"  - Issuer: {ssl.get('issuer', '')}\n"
            ssl_text += f"  - Expired: {ssl.get('expired', False)}\n"

        prompt = f"""You are AutoRecon AI, an elite cybersecurity analysis engine. Analyze the following reconnaissance data and provide expert-level security assessment.

## TARGET INFORMATION
- Hostname: {hostname}
- IP Addresses: {ip}
- OS Detection: {target.get('os_info', 'Unknown')}
- Host Alive: {target.get('is_alive', False)}

## OPEN PORTS ({len(ports)} found)
{ports_text}

## DNS RECORDS
{dns_text if dns_text else '  (no DNS records)'}

## SSL/TLS INFORMATION
{ssl_text if ssl.get('enabled') else '  (SSL not detected or not checked)'}

## ANALYSIS REQUIRED

Based on the above data, provide:

1. **SECURITY RISK ASSESSMENT**
   - Overall risk level (Critical/High/Medium/Low/Info)
   - Risk score (0-100)
   - Top 3 most dangerous findings

2. **ATTACK VECTOR ANALYSIS**
   - Most likely attack path
   - Easiest exploitation method
   - Potential impact if compromised

3. **SERVICE-SPECIFIC VULNERABILITIES**
   - For each open port/service, list specific vulnerabilities
   - Include CVE IDs where possible
   - Rate exploitation difficulty (Easy/Medium/Hard)

4. **CRITICAL RECOMMENDATIONS**
   - Top 5 actionable security fixes
   - Priority order (highest to lowest)

5. **PENETRATION TESTING STRATEGY**
   - Recommended tools to use
   - Step-by-step approach
   - Things to watch out for

Respond in JSON format with these keys:
- risk_level: string
- risk_score: integer (0-100)
- top_findings: array of {title, severity, description, cve}
- attack_vector: {path, exploitation, impact}
- recommendations: array of strings
- pentesting_strategy: string
- summary: string (one paragraph)
"""
        return prompt

    def _query_claude(self, api_key: str, config: Dict, prompt: str) -> Dict:
        """Query Claude API."""
        import urllib.request
        import json as j

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        data = j.dumps({
            "model": config["default_model"],
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}],
        })

        req = urllib.request.Request(
            f"{config['base_url']}/messages",
            data=data.encode(),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                response = j.loads(resp.read().decode())
                text = response.get("content", [{}])[0].get("text", "{}")
                self.last_response = text
                return self._parse_ai_response(text)
        except Exception as e:
            return {"error": f"Claude API error: {e}"}

    def _query_openai(self, api_key: str, config: Dict, prompt: str) -> Dict:
        """Query OpenAI API."""
        import urllib.request
        import json as j

        headers = {
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        }

        data = j.dumps({
            "model": config["default_model"],
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        })

        req = urllib.request.Request(
            f"{config['base_url']}/chat/completions",
            data=data.encode(),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                response = j.loads(resp.read().decode())
                text = response.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                self.last_response = text
                return self._parse_ai_response(text)
        except Exception as e:
            return {"error": f"OpenAI API error: {e}"}

    def _query_grok(self, api_key: str, config: Dict, prompt: str) -> Dict:
        """Query Grok (xAI) API - OpenAI compatible."""
        import urllib.request
        import json as j

        headers = {
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        }

        data = j.dumps({
            "model": config["default_model"],
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        })

        req = urllib.request.Request(
            f"{config['base_url']}/chat/completions",
            data=data.encode(),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                response = j.loads(resp.read().decode())
                text = response.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                self.last_response = text
                return self._parse_ai_response(text)
        except Exception as e:
            return {"error": f"Grok API error: {e}"}

    def _query_together(self, api_key: str, config: Dict, prompt: str) -> Dict:
        """Query Together AI API."""
        import urllib.request
        import json as j

        headers = {
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        }

        data = j.dumps({
            "model": config["default_model"],
            "max_tokens": 4000,
            "messages": [
                {"role": "system", "content": "You are an expert cybersecurity analyst. Always respond in valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        })

        req = urllib.request.Request(
            f"{config['base_url']}/chat/completions",
            data=data.encode(),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                response = j.loads(resp.read().decode())
                text = response.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                self.last_response = text
                return self._parse_ai_response(text)
        except Exception as e:
            return {"error": f"Together AI error: {e}"}

    def _parse_ai_response(self, text: str) -> Dict:
        """Parse AI response JSON, handling markdown code blocks."""
        # Remove markdown code block delimiters
        text = text.strip()
        if text.startswith("```"):
            # Extract JSON from code block
            lines = text.split("\n")
            start = 0
            for i, line in enumerate(lines):
                if "```" in line and "json" in line.lower():
                    start = i + 1
                    break
            end = len(lines)
            for i in range(len(lines) - 1, -1, -1):
                if lines[i].strip() == "```":
                    end = i
                    break
            text = "\n".join(lines[start:end])

        try:
            result = json.loads(text)
            return result
        except json.JSONDecodeError:
            # If not JSON, return as raw text
            return {"raw_analysis": text, "format_error": "Response was not valid JSON"}

    def enhance_findings(self, local_findings: List[Dict], scan_data: Dict) -> Dict:
        """
        Use AI to enhance/enrich locally-generated findings.
        Runs rule-based + AI analysis together.
        """
        result = self.analyze_scan(scan_data)

        if "error" in result:
            return result

        # Merge AI findings with local ones
        ai_findings = result.get("top_findings", [])

        return {
            "ai_provider": APIConfig.get_best_provider(),
            "ai_risk_level": result.get("risk_level", "Unknown"),
            "ai_risk_score": result.get("risk_score", 0),
            "ai_findings": ai_findings,
            "attack_vector": result.get("attack_vector", {}),
            "recommendations": result.get("recommendations", []),
            "pentesting_strategy": result.get("pentesting_strategy", ""),
            "summary": result.get("summary", ""),
            "raw_ai_response": self.last_response,
            "total_ai_findings": len(ai_findings),
        }

    def generate_exploit_suggestions(self, service: str, version: str = "") -> Dict:
        """
        Ask AI for specific exploit suggestions for a service.
        """
        prompt = f"""You are an expert penetration tester. For the following service, provide:
1. Known public exploits (with CVE, EDB-ID if possible)
2. Recommended exploitation tools
3. Example commands
4. Common misconfigurations to check

Service: {service}
Version: {version}

Respond in JSON format with keys: exploits (array), tools (array), commands (array), misconfigurations (array)"""

        provider = APIConfig.get_best_provider()
        if not provider:
            return {"error": "No AI provider configured"}

        api_key = APIConfig.get_key(provider)
        config = APIConfig.PROVIDERS[provider]

        if provider == "claude":
            return self._query_claude(api_key, config, prompt)
        elif provider in ("openai", "grok", "together"):
            return self._query_openai(api_key, config, prompt)

        return {"error": "Unsupported provider"}


# ─── Simple CLI for testing ───

def main():
    """Simple CLI to test the API integration."""
    print("╔════════════════════════════════════════════════╗")
    print("║   AutoRecon AI - API Integration Test         ║")
    print("╚════════════════════════════════════════════════╝")
    print()

    # Check available providers
    providers = APIConfig.get_available_providers()

    if not providers:
        print("❌ No AI providers configured!")
        print()
        print("Set one of these environment variables:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...    # Claude")
        print("  export OPENAI_API_KEY=sk-...           # OpenAI")
        print("  export GROK_API_KEY=...                # Grok (xAI)")
        print()
        print("Or create a .env file with any of these.")
        return

    print(f"✅ Available providers: {', '.join(providers)}")
    provider = APIConfig.get_best_provider()
    print(f"✅ Using: {APIConfig.PROVIDERS[provider]['name']}")

    # Sample scan data for testing
    sample = {
        "target": {
            "hostname": "test.example.com",
            "ip_addresses": ["192.168.1.1"],
            "os_info": "Linux",
            "is_alive": True,
            "ports": [
                {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9p1"},
                {"port": 80, "service": "http", "product": "nginx", "version": "1.24.0"},
                {"port": 443, "service": "https", "product": "nginx", "version": "1.24.0"},
                {"port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0.35"},
            ],
            "dns_records": {"A": ["192.168.1.1"], "MX": ["mail.example.com"]},
            "ssl_info": {"enabled": True, "version": "TLSv1.3", "issuer": "Let's Encrypt"},
        }
    }

    print(f"\n🧠 Sending sample scan data to {APIConfig.PROVIDERS[provider]['name']}...")
    print(f"   Target: test.example.com (with 4 open ports)")
    print()

    analyzer = AIAPIAnalyzer()
    result = analyzer.analyze_scan(sample["target"])

    if "error" in result:
        print(f"❌ Error: {result['error']}")
        return

    print(f"📊 Analysis Results:")
    print(f"   Risk Level: {result.get('risk_level', 'N/A')}")
    print(f"   Risk Score: {result.get('risk_score', 'N/A')}/100")
    print(f"   Summary: {result.get('summary', 'N/A')[:200]}...")
    print()

    findings = result.get("top_findings", [])
    if findings:
        print(f"🔍 Top Findings ({len(findings)}):")
        for f in findings[:3]:
            print(f"   [{f.get('severity', 'INFO').upper()}] {f.get('title', 'N/A')}")

    recs = result.get("recommendations", [])
    if recs:
        print(f"\n🛡️  Recommendations ({len(recs)}):")
        for r in recs[:3]:
            print(f"   • {r}")

    print()
    print("✅ API integration test complete!")


if __name__ == "__main__":
    main()
