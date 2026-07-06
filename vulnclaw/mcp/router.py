"""VulnClaw MCP Router — route natural language intents to MCP tool calls."""

from __future__ import annotations

import re
from typing import Any, Optional

# ── Intent → Tool mapping ───────────────────────────────────────────

INTENT_TOOL_MAP: dict[str, list[dict[str, Any]]] = {
    # Browser automation
    "open page|open url|visit url|visit page|navigate": [
        {"tool": "new_page", "server": "chrome-devtools"},
        {"tool": "navigate", "server": "chrome-devtools"},
    ],
    "screenshot|screen capture|capture screen": [
        {"tool": "screenshot", "server": "chrome-devtools"},
    ],
    "run js|eval js|run javascript|execute js": [
        {"tool": "evaluate_js", "server": "chrome-devtools"},
    ],
    # HTTP requests
    "send request|http request|fetch|call endpoint|call api": [
        {"tool": "fetch", "server": "fetch"},
        {"tool": "send_http1_request", "server": "burp"},
    ],
    # Burp Suite
    "capture packet|view request|intercept request|proxy": [
        {"tool": "get_proxy_http_history", "server": "burp"},
    ],
    "modify packet|replay|tamper": [
        {"tool": "send_http1_request", "server": "burp"},
    ],
    # Memory
    "remember|record|save memory": [
        {"tool": "save", "server": "memory"},
    ],
    "recall|query record|retrieve memory": [
        {"tool": "retrieve", "server": "memory"},
    ],
}


class MCPRouter:
    """Routes natural language intents to MCP tool calls."""

    def route(self, user_input: str) -> list[dict[str, Any]]:
        """Analyze user input and return suggested tool calls.

        Returns a list of dicts with keys: tool, server, confidence.
        """
        input_lower = user_input.lower()
        results = []

        for pattern, tools in INTENT_TOOL_MAP.items():
            keywords = pattern.split("|")
            if any(kw in input_lower for kw in keywords):
                for tool_entry in tools:
                    results.append(
                        {
                            "tool": tool_entry["tool"],
                            "server": tool_entry["server"],
                            "confidence": 0.8,
                        }
                    )

        return results

    def extract_url(self, text: str) -> Optional[str]:
        """Extract URL from text."""
        url_match = re.search(r"(https?://\S+)", text)
        return url_match.group(1) if url_match else None

    def extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        return ip_match.group(1) if ip_match else None

    def suggest_tools_for_phase(self, phase: str) -> list[dict[str, Any]]:
        """Suggest tools based on pentest phase."""
        phase_tools = {
            "Recon": [
                {"tool": "fetch", "server": "fetch", "reason": "HTTP request to probe the target"},
                {"tool": "new_page", "server": "chrome-devtools", "reason": "Access the target in a browser"},
                {"tool": "screenshot", "server": "chrome-devtools", "reason": "Screenshot the target page"},
            ],
            "Vulnerability Discovery": [
                {"tool": "fetch", "server": "fetch", "reason": "Send a vulnerability-probe request"},
                {"tool": "send_http1_request", "server": "burp", "reason": "Construct a detection request via proxy"},
            ],
            "Exploitation": [
                {"tool": "send_http1_request", "server": "burp", "reason": "Construct an exploitation request"},
                {"tool": "fetch", "server": "fetch", "reason": "Send the exploitation payload"},
                {"tool": "evaluate_js", "server": "chrome-devtools", "reason": "In-browser exploitation"},
            ],
        }

        return phase_tools.get(phase, [])
