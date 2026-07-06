"""Agent built-in tools and OpenAI tool schema helpers."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from vulnclaw.agent.constraint_policy import validate_tool_action

BLOCKED_PATTERNS: list[str] = [
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"open\s*\(\s*['\"].*vulnclaw.*config",
    r"open\s*\(\s*['\"].*\.vulnclaw",
]

RESERVED_IP_RANGES: list[tuple[str, str, str]] = [
    ("198.18.0.0", "198.19.255.255", "RFC 2544 benchmarking address"),
    ("10.0.0.0", "10.255.255.255", "RFC 1918 private address"),
    ("172.16.0.0", "172.31.255.255", "RFC 1918 private address"),
    ("192.168.0.0", "192.168.255.255", "RFC 1918 private address"),
    ("127.0.0.0", "127.255.255.255", "RFC 1122 loopback address"),
    ("169.254.0.0", "169.254.255.255", "RFC 3927 link-local"),
    ("0.0.0.0", "0.255.255.255", "RFC 1122 current network"),
    ("224.0.0.0", "239.255.255.255", "RFC 5771 multicast address"),
    ("240.0.0.0", "255.255.255.255", "RFC 1112 reserved address"),
]

SAFE_MODE_PATTERNS: list[str] = [
    r"open\s*\(",
    r"with\s+open\s*\(",
    r"socket\.",
    r"urllib",
    r"http\.client",
    r"ftplib",
    r"smtplib",
    r"requests\.",
    r"import\s+os",
    r"from\s+os\s+import",
    r"import\s+subprocess",
    r"from\s+subprocess\s+import",
    r"import\s+shutil",
    r"from\s+shutil\s+import",
    r"import\s+pathlib",
    r"from\s+pathlib\s+import",
    r"__import__",
]

LAB_MODE_PATTERNS: list[str] = [
    r"import\s+subprocess",
    r"from\s+subprocess\s+import",
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
]


async def execute_mcp_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str:
    """Execute a tool call via MCP manager or built-in tools."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is not None:
        tool_violation = validate_tool_action(tool_name, args, constraints)
        if tool_violation is not None:
            if session is not None and hasattr(session, "add_constraint_violation_event"):
                from vulnclaw.agent.constraint_policy import infer_tool_action

                session.add_constraint_violation_event(
                    source="tool",
                    action=infer_tool_action(tool_name, args),
                    tool_name=tool_name,
                    code="tool_action_blocked",
                    severity="high",
                    summary=tool_violation,
                    detail=json.dumps(args, ensure_ascii=False)[:500],
                )
            return f"[constraint_violation] {tool_violation}"

    if tool_name == "python_execute":
        return await execute_python(agent, args)

    if tool_name == "load_skill_reference":
        try:
            from vulnclaw.skills.loader import load_skill_reference

            skill_name = args.get("skill_name", "")
            ref_name = args.get("reference_name", "")
            content = load_skill_reference(skill_name, ref_name)
            if content:
                return content
            return f"[!] Reference doc not found: {skill_name}/{ref_name}"
        except Exception as e:
            return f"[!] Error loading reference doc: {e}"

    if tool_name == "nmap_scan":
        return await execute_nmap(agent, args)

    if tool_name == "crypto_decode":
        try:
            from vulnclaw.skills.crypto_tools import execute as crypto_execute

            operation = args.get("operation", "")
            input_str = args.get("input", "")
            kwargs: dict[str, Any] = {}
            for key in ("key", "iv", "shift", "secret", "header", "algorithm"):
                if key in args and args[key]:
                    kwargs[key] = args[key]
                    if key == "shift":
                        kwargs[key] = int(args[key])
            result = crypto_execute(operation=operation, input_str=input_str, **kwargs)
            if result.get("success"):
                return f"[✓] {operation} result:\n{result['result']}"
            return f"[!] {operation} failed: {result.get('error', 'unknown error')}"
        except Exception as e:
            return f"[!] Crypto tool execution error: {e}"

    if tool_name == "brute_force_login":
        return await execute_brute_force(agent, args)

    if tool_name in {"space_search", "subdomain_enum", "js_recon", "dir_enum", "unauth_test"}:
        from vulnclaw.agent import recon_tools

        dispatch = {
            "space_search": recon_tools.execute_space_search,
            "subdomain_enum": recon_tools.execute_subdomain_enum,
            "js_recon": recon_tools.execute_js_recon,
            "dir_enum": recon_tools.execute_dir_enum,
            "unauth_test": recon_tools.execute_unauth_test,
        }
        try:
            return await dispatch[tool_name](agent, args)
        except Exception as e:
            return f"[!] Tool execution error ({tool_name}): {e}"

    if not agent.mcp_manager:
        return f"[!] MCP manager not initialized; cannot execute tool: {tool_name}"

    try:
        result = await agent.mcp_manager.call_tool(tool_name, args)
        if isinstance(result, dict):
            if result.get("ok", False):
                content = result.get("content")
                structured = result.get("structured_content")
                summary_parts: list[str] = []
                if content is not None:
                    summary_parts.append(str(content))
                if isinstance(structured, dict) and structured:
                    summary_parts.append(
                        f"[structured] {json.dumps(structured, ensure_ascii=False)}"
                    )
                if summary_parts:
                    return "\n".join(summary_parts)
                return f"[tool:{tool_name}] completed"

            message = str(result.get("message") or "")
            suggestion = str(result.get("suggestion") or "")
            error_type = str(result.get("error_type") or "error")
            if suggestion:
                return f"[{error_type}] {message}\n[suggestion] {suggestion}".strip()
            return f"[{error_type}] {message}".strip()

        text = str(result)
        if text.strip() in ("undefined", "null", "None"):
            return f"[!] Tool {tool_name} returned an empty result (undefined); the call may have failed"
        return text
    except Exception as e:
        return f"[!] Tool execution error ({tool_name}): {e}"


def enforce_port_constraints(agent: Any, ports: list[int], *, target: str = "") -> str | None:
    """Return a user-facing violation message when requested ports are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_ports:
        disallowed = [port for port in ports if port not in constraints.allowed_ports]
        if disallowed:
            allowed = ", ".join(str(p) for p in constraints.allowed_ports)
            denied = ", ".join(str(p) for p in disallowed)
            suffix = f" for target {target}" if target else ""
            return f"[constraint_violation] Port(s) {denied} are outside allowed scope [{allowed}]{suffix}."

    blocked = [port for port in ports if port in constraints.blocked_ports]
    if blocked:
        denied = ", ".join(str(p) for p in blocked)
        suffix = f" for target {target}" if target else ""
        return f"[constraint_violation] Port(s) {denied} are blocked by task constraints{suffix}."

    return None


def enforce_host_path_constraints(
    agent: Any, *, host: str = "", path: str = "", target: str = ""
) -> str | None:
    """Return a user-facing violation when host/path are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_hosts and host and host not in constraints.allowed_hosts:
        allowed = ", ".join(constraints.allowed_hosts)
        return f"[constraint_violation] Host {host} is outside allowed scope [{allowed}] for target {target or host}."

    if host and host in constraints.blocked_hosts:
        return f"[constraint_violation] Host {host} is blocked by task constraints for target {target or host}."

    if constraints.allowed_paths and path and path not in constraints.allowed_paths:
        allowed = ", ".join(constraints.allowed_paths)
        return f"[constraint_violation] Path {path} is outside allowed scope [{allowed}] for target {target or host}."

    if path and path in constraints.blocked_paths:
        return f"[constraint_violation] Path {path} is blocked by task constraints for target {target or host}."

    return None


def infer_ports_from_nmap_args(args: dict[str, Any]) -> list[int]:
    """Infer concrete target ports from nmap arguments for constraint checks."""
    custom_ports = str(args.get("ports", "") or "").strip()
    scan_type = str(args.get("scan_type", "top_ports") or "top_ports")

    if custom_ports:
        ports: list[int] = []
        for chunk in custom_ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_text, end_text = chunk.split("-", 1)
                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    continue
                if 0 < start <= end <= 65535:
                    ports.extend(range(start, end + 1))
                continue
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 0 < port <= 65535:
                ports.append(port)
        return sorted(set(ports))

    if scan_type == "top_ports":
        return []
    return []


def infer_port_from_url(url: str) -> int | None:
    """Infer request port from URL."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def build_openai_tools(mcp_manager: Any) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools."""
    tools: list[dict[str, Any]] = []

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "load_skill_reference",
                "description": "Load the reference doc of a given Skill to get detailed penetration-testing methodology, workflow, or command reference. When the system prompt mentions 'available reference docs', use this tool to fetch the specific content.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "skill_name": {
                            "type": "string",
                            "description": "Skill name, e.g. client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist, crypto-toolkit, ctf-web, ctf-crypto, ctf-misc, osint-recon, secknowledge-skill",
                        },
                        "reference_name": {
                            "type": "string",
                            "description": "Reference doc filename, e.g. 02-client-api-reverse-and-burp.md, web-injection.md, encoding-cheatsheet.md",
                        },
                    },
                    "required": ["skill_name", "reference_name"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "python_execute",
                "description": (
                    "Execute a Python code snippet. Used to: construct complex HTTP requests and parse responses, "
                    "do encoding conversion and data processing, batch-test different payloads, compare response diffs, "
                    "perform math, etc. Code runs in a restricted environment with a 30-second timeout. "
                    "Pre-installed libraries: requests, beautifulsoup4, pycryptodome, base64, json, re, etc. "
                    "Important: use this tool to construct HTTP requests rather than guessing the response content."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The Python code to execute. Multi-line supported; you may import the stdlib and requests/bs4, etc.",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "Brief statement of purpose (for the audit log), e.g. 'construct an HTTP request to test the weak-comparison bypass'",
                        },
                    },
                    "required": ["code"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "crypto_decode",
                "description": (
                    "Encoding/decoding and encryption/decryption tool. Call it for base64/hex/URL/HTML/Unicode-encoded strings, "
                    "when you need to compute hashes, decrypt AES/DES, parse JWT, etc. "
                    "Important: do not imagine the decode result yourself — always use this tool for accuracy. "
                    "Supported operations: base64_encode/decode, base32_encode/decode, base58_encode/decode, "
                    "hex_encode/decode, url_encode/decode, html_encode/decode, unicode_encode/decode, "
                    "rot13_encode/decode, caesar_encode/decode, morse_encode/decode, "
                    "md5_hash, sha1_hash, sha256_hash, sha512_hash, "
                    "aes_encrypt/decrypt, jwt_decode/encode, auto_decode"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "description": "Operation name"},
                        "input": {
                            "type": "string",
                            "description": "The input string to process (text to encode/decode/hash/encrypt)",
                        },
                        "key": {
                            "type": "string",
                            "description": "Encryption/decryption key (required for AES/DES, 16/24/32 bytes)",
                        },
                        "iv": {"type": "string", "description": "AES initialization vector (16 bytes, optional)"},
                        "shift": {
                            "type": "integer",
                            "description": "Caesar cipher shift (default 3; if omitted when decoding, brute-force all shifts)",
                        },
                        "secret": {"type": "string", "description": "JWT signing key"},
                    },
                    "required": ["operation", "input"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": (
                    "nmap network port-scanning tool. Used during recon to discover open ports, service versions, and OS fingerprint.\n"
                    "Usage examples:\n"
                    "  Scan common ports: scan_type=top_ports, target=1.2.3.4\n"
                    "  SYN scan: scan_type=syn, target=1.2.3.4 (requires admin privileges)\n"
                    "  Service version detection: scan_type=service, target=1.2.3.4\n"
                    "  Vulnerability scan: scan_type=vuln, target=1.2.3.4\n"
                    "  Full scan: scan_type=full, target=1.2.3.4\n"
                    "Prefer nmap_scan over constructing a socket scan via python_execute — nmap is more professional and accurate."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or domain (required), e.g. 192.168.1.1 or scanme.nmap.org",
                        },
                        "scan_type": {
                            "type": "string",
                            "description": "Scan type: top_ports/syn/tcp/service/os/vuln/full",
                        },
                        "ports": {
                            "type": "string",
                            "description": "Specific ports or range (optional), e.g. 80,443,8080 or 1-1000",
                        },
                        "timing": {
                            "type": "integer",
                            "description": "Scan speed template 0-5 (default 4); higher is faster but easier to detect",
                        },
                    },
                    "required": ["target"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "brute_force_login",
                "description": (
                    "Password brute force against a login form. Automatically manages the session cookie, "
                    "extracts and updates the CSRF token, and judges login success/failure. "
                    "Completes all password attempts in a single call and returns the result for each password."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Login page URL",
                        },
                        "username_field": {
                            "type": "string",
                            "description": "Username field name, e.g. 'username'",
                        },
                        "password_field": {
                            "type": "string",
                            "description": "Password field name, e.g. 'password'",
                        },
                        "csrf_field": {
                            "type": "string",
                            "description": "CSRF token field name, e.g. 'user_token'",
                        },
                        "username": {
                            "type": "string",
                            "description": "Username to brute-force",
                        },
                        "passwords": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of passwords to try (max 20)",
                        },
                        "success_keyword": {
                            "type": "string",
                            "description": "Signature word appearing on the page after a successful login, e.g. 'Welcome', 'Dashboard'",
                        },
                        "failure_keyword": {
                            "type": "string",
                            "description": "Signature word appearing on the page after a failed login, e.g. 'Login failed'",
                        },
                        "submit_action": {
                            "type": "string",
                            "description": "Target URL for form submission (optional; if omitted, extracted from the form's action attribute)",
                        },
                        "extra_data": {
                            "type": "object",
                            "description": "Extra form fields, e.g. {\"Login\": \"Login\"}",
                        },
                    },
                    "required": ["url", "password_field", "passwords"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "space_search",
                "description": (
                    "Cyberspace-mapping asset search (FOFA/Hunter/Quake/Shodan/ZoomEye/0.zone). "
                    "Used during recon to passively discover target assets, IPs, ports, subdomains, titles, and component fingerprints without touching the target. "
                    "Given a domain, it auto-constructs a domain query per engine syntax; you may also pass full query syntax. "
                    "With engine=all it queries all engines that have a configured key concurrently."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "engine": {
                            "type": "string",
                            "description": "fofa/hunter/quake/shodan/zoomeye/zerozone/all, default fofa",
                        },
                        "query": {
                            "type": "string",
                            "description": "Engine-native query syntax, e.g. 'domain=\"x.com\"', 'app=\"Struts2\"' (optional)",
                        },
                        "domain": {
                            "type": "string",
                            "description": "Target primary domain; auto-constructs a per-engine domain query (used when query is not given)",
                        },
                        "size": {"type": "integer", "description": "Number of results to return, default 100"},
                    },
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "subdomain_enum",
                "description": (
                    "Subdomain enumeration. First passively aggregates from configured cyberspace-mapping engines, then does DNS-resolution brute force with a built-in small dictionary, "
                    "returning a deduplicated list of live subdomains. Prefer this over writing your own brute force via python_execute."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Primary domain, e.g. nju.edu.cn"},
                        "brute": {
                            "type": "boolean",
                            "description": "Whether to enable built-in dictionary DNS brute force (default true)",
                        },
                    },
                    "required": ["domain"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "js_recon",
                "description": (
                    "JS recon (inspired by URLFinder). Crawls the target page and all .js files it references, "
                    "extracting API endpoints/paths, related domains, absolute URLs, and suspected hardcoded secrets (AK/SK, token, JWT, private keys, etc.). "
                    "Default auto_probe=true: automatically probes each collected same-origin endpoint for unauthorized access (safe GET only, skipping destructive endpoints). "
                    "Prefer calling this during recon and feed the real extracted endpoints into later testing, rather than guessing endpoints out of thin air."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target page URL"},
                        "max_js": {
                            "type": "integer",
                            "description": "Max number of JS files to fetch (default 30)",
                        },
                        "auto_probe": {
                            "type": "boolean",
                            "description": "Whether to auto-probe collected endpoints for unauthorized access (default true)",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "Optional auth header for a differential comparison, e.g. 'Authorization: Bearer xxx', to check whether data is obtainable without a token",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "unauth_test",
                "description": (
                    "Unauthorized-access probing. Requests a batch of endpoints (usually collected by js_recon) one by one without credentials, "
                    "judging by status code / response body / content type: ⚠ suspected unauthorized (returns data) / ✓ blocked by auth / ↪ redirects to login / — does not exist. "
                    "When auth_header is provided, does a with/without-token differential comparison; if the same data is obtainable without a token, judged as 🔴 unauthorized confirmed. "
                    "Strictly read-only: sends safe GET only, auto-skips destructive endpoints like delete/update/sms, and does not batch-iterate IDs."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "Target base URL (defines the same-origin scope)"},
                        "endpoints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of endpoint paths/URLs to test (from js_recon's endpoints/paths)",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "Optional auth header for a differential, e.g. 'Authorization: Bearer xxx' or 'Cookie: session=...'",
                        },
                        "max_endpoints": {
                            "type": "integer",
                            "description": "Max number of endpoints to probe (default 60)",
                        },
                    },
                    "required": ["base_url", "endpoints"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "dir_enum",
                "description": (
                    "Directory/file enumeration (inspired by dirsearch). Concurrent dictionary brute force, with a 404 baseline and global disguise-response detection "
                    "(a random path returning 200 is judged as disguise and stops), plus status-code and response-length filtering. "
                    "Safe GET probing only; does not touch destructive paths like delete/update."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target base URL, e.g. https://x.com/"},
                        "extensions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Extension expansion, e.g. ['php','jsp','bak','zip'] (optional)",
                        },
                        "wordlist": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Additional custom paths (a heuristic dictionary based on naming patterns, optional)",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": schema.get("name", ""),
                        "description": schema.get("description", ""),
                        "parameters": schema.get(
                            "inputSchema", {"type": "object", "properties": {}}
                        ),
                    },
                }
            )

    return tools


async def execute_nmap(agent: Any, args: dict[str, Any]) -> str:
    target = args.get("target", "").strip()
    if not target:
        return "[!] nmap_scan requires the target parameter (target IP or domain)"

    host_violation = enforce_host_path_constraints(agent, host=target.lower(), target=target)
    if host_violation:
        return host_violation

    violation = enforce_port_constraints(agent, infer_ports_from_nmap_args(args), target=target)
    if violation:
        return violation

    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if ips:
            ip = ips[0][4][0]
            is_reserved, reason = is_reserved_ip(ip)
            if is_reserved:
                return (
                    f"[SKIP] Target {target} resolves to a reserved/internal address ({reason}, IP: {ip})\n"
                    f"Skipping the nmap scan. Prefer gathering info directly via web fingerprinting, directory enumeration, etc.; "
                    f"don't waste rounds on a reserved address."
                )
    except Exception:
        pass

    scan_type = args.get("scan_type", "top_ports")
    custom_ports = args.get("ports", "")
    timing = int(args.get("timing", 4))

    nmap_cmd = shutil.which("nmap")
    if not nmap_cmd:
        try:
            result = subprocess.run(
                ["where.exe", "nmap"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                nmap_cmd = result.stdout.strip().split("\n")[0]
        except Exception:
            pass
    if not nmap_cmd:
        return "[!] nmap is not installed or not on PATH. Ensure nmap is installed and added to the system PATH."

    cmd = [nmap_cmd, "-v" if scan_type == "full" else "-q", f"-T{max(0, min(5, timing))}"]
    if scan_type == "top_ports":
        cmd.extend(["--top-ports", "100", "-oX", "-"])
    elif scan_type == "syn":
        cmd.extend(["-sS", "-oX", "-"])
    elif scan_type == "tcp":
        cmd.extend(["-sT", "-oX", "-"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-oX", "-"])
    elif scan_type == "os":
        cmd.extend(["-O", "-oX", "-"])
    elif scan_type == "vuln":
        cmd.extend(["--script", "vuln", "-oX", "-"])
    elif scan_type == "full":
        cmd.extend(["-sS", "-O", "-sV", "--script", "default,safe", "-oX", "-"])
    else:
        cmd.extend(["-sV", "-oX", "-"])

    if custom_ports:
        cmd.extend(["-p", custom_ports])
    cmd.append(target)

    try:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": 120,
        }
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
        result = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return "[!] nmap scan timed out (120s); reduce the scan scope or use a faster timing"
    except PermissionError:
        return "[!] nmap execution denied (insufficient privileges). On Windows, run the terminal as administrator."
    except Exception as e:
        return f"[!] nmap execution error: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"[!] nmap scan failed ({result.returncode}): {result.stderr[:500]}"
    return parse_nmap_xml(result.stdout or result.stderr, target)


def is_reserved_ip(ip: str) -> tuple[bool, str]:
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        for start, end, desc in RESERVED_IP_RANGES:
            if ipaddress.ip_address(start) <= addr <= ipaddress.ip_address(end):
                return True, desc
        return False, ""
    except Exception:
        return False, ""


def validate_scan_target(target: str) -> str:
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if not ips:
            return ""
        ip = ips[0][4][0]
        is_reserved, reason = is_reserved_ip(ip)
        if is_reserved:
            return (
                f"\n\n⚠️ **Warning: target {target} resolves to a reserved/internal address ({reason})\n"
                f"   IP: {ip}\n"
                f"   Results from scanning this address do not represent the real system's security posture.\n"
                f"   The port info in the nmap results may be unrelated to the real target.**"
            )
    except Exception:
        pass
    return ""


def parse_nmap_xml(xml_output: str, target: str) -> str:
    if not xml_output or "<nmaprun" not in xml_output:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap raw output:\n" + "\n".join(lines)

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap raw output:\n" + "\n".join(lines)

    lines = [f"nmap scan results — {target}", "=" * 60]
    for host in root.findall(".//host"):
        hostname = host.find(".//hostname[@type='user']")
        addrs = [a.get("addr", "") for a in host.findall("address")]
        status = host.find("status")
        status_val = status.get("state", "unknown") if status is not None else "unknown"
        host_ip = addrs[0] if addrs else target
        reserved, reason = is_reserved_ip(host_ip)
        if reserved:
            host_str = (
                f"\n[Host] {host_ip} ⚠️ **reserved address ({reason}); test-network results do not represent the real target's security posture**"
            )
        else:
            host_str = f"\n[Host] {host_ip}"
        if hostname is not None:
            host_str += f" ({hostname.get('name', '')})"
        host_str += f" — {status_val}"
        lines.append(host_str)

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            port_state = port.find("state")
            svc = port.find("service")
            state_val = port_state.get("state", "unknown") if port_state is not None else "unknown"
            svc_name = svc.get("name", "") if svc is not None else ""
            svc_product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            lines.append(
                f"  {proto.upper():5} {port_id}/{'s' if svc is not None and svc.get('tunnel') == 'ssl' else ''} "
                f"{state_val:8}{svc_name:15}{(svc_product + ' ' + svc_version).rstrip()}"
            )
            for script in port.findall("script"):
                lines.append(f"    | {script.get('id', '')}: {script.get('output', '')[:120]}")

    runstats = root.find(".//runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            elapsed = finished.get("elapsed", "")
            summary = finished.get("summary", "")
            lines.append(f"\nFinished: {elapsed}s | {summary}")
    return "\n".join(lines) or f"nmap scan complete (no output): {target}"


def _resolve_python_execute_mode(agent: Any) -> str:
    safety = getattr(agent.config, "safety", None)
    if safety is None:
        return "trusted-local"

    mode = str(getattr(safety, "python_execute_mode", "") or "").strip().lower()
    if not mode and getattr(safety, "python_execute_restricted", False):
        return "safe"
    if mode in {"safe", "lab", "trusted-local"}:
        return mode
    return "trusted-local"


def _validate_python_execute_mode(mode: str, code: str) -> str | None:
    patterns = SAFE_MODE_PATTERNS if mode == "safe" else LAB_MODE_PATTERNS if mode == "lab" else []
    for pattern in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return pattern
    return None


def _write_python_audit(
    agent: Any,
    *,
    purpose: str,
    code: str,
    mode: str,
    outcome: str,
    blocked_reason: str = "",
) -> None:
    safety = getattr(agent.config, "safety", None)
    if safety is None or not getattr(safety, "python_execute_audit_enabled", True):
        return

    try:
        from datetime import datetime

        from vulnclaw.config.settings import PYTHON_EXECUTE_AUDIT_FILE, ensure_dirs

        ensure_dirs()
        record = {
            "timestamp": datetime.now().isoformat(),
            "target": getattr(getattr(agent, "session_state", None), "target", None),
            "mode": mode,
            "purpose": purpose,
            "outcome": outcome,
            "blocked_reason": blocked_reason,
            "code_preview": code[:300],
            "code_lines": code.count("\n") + 1,
        }
        with open(PYTHON_EXECUTE_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        return


async def execute_python(agent: Any, args: dict[str, Any]) -> str:
    code = args.get("code", "")
    purpose = args.get("purpose", "")
    if not code.strip():
        return "[!] Code is empty; nothing executed"

    url_matches = re.findall(r"https?://([a-zA-Z0-9._:-]+)(/[^\s'\"`]*)?", code)
    for raw_host, path in url_matches:
        # Strip the port before the scope check so an in-scope target referenced
        # with a port (e.g. localhost:3000) is not falsely flagged out of scope.
        # The fetch tool already compares against urlparse().hostname (no port);
        # this keeps python_execute consistent with that behavior.
        host = raw_host.split(":", 1)[0].lower()
        host_violation = enforce_host_path_constraints(
            agent,
            host=host,
            path=(path or "").rstrip("/"),
            target=host,
        )
        if host_violation:
            return host_violation

    safety = getattr(agent.config, "safety", None)
    if safety is None or not safety.enable_python_execute:
        return (
            "[!] python_execute is disabled. Set safety.enable_python_execute = true to enable it"
        )

    mode = _resolve_python_execute_mode(agent)
    max_lines = getattr(safety, "python_execute_max_lines", 50)
    if code.count("\n") + 1 > max_lines:
        _write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason="max_lines",
        )
        return f"[!] Code exceeds the max line limit ({max_lines})"

    show_warning = getattr(safety, "python_execute_show_warning", True)
    warning_prefix = ""
    if show_warning:
        warning_prefix = (
            f"[!] Security warning: python_execute runs local Python code in {mode} mode.\n"
            "Review the code carefully before execution.\n"
            "---\n"
        )

    recon_keywords = ["recon", "crawl", "spider", "scan", "enum", "probe"]
    timeout_seconds = 60 if any(kw in purpose.lower() for kw in recon_keywords) else 30

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, code):
            _write_python_audit(
                agent,
                purpose=purpose,
                code=code,
                mode=mode,
                outcome="blocked",
                blocked_reason=pattern,
            )
            return f"[!] Code contains a blocked operation pattern: {pattern}"

    blocked_pattern = _validate_python_execute_mode(mode, code)
    if blocked_pattern:
        _write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason=blocked_pattern,
        )
        if mode == "safe":
            return f"[!] safe mode blocked operation: {blocked_pattern}"
        return f"[!] lab mode blocked operation: {blocked_pattern}"

    max_output_chars = getattr(safety, "python_execute_max_output_chars", 8000)
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            preamble = (
                "import sys, json, re, os, base64, hashlib, itertools, collections, datetime, struct, binascii, textwrap\n"
                "try:\n    import requests\nexcept ImportError:\n    pass\n"
                "try:\n    from bs4 import BeautifulSoup\nexcept ImportError:\n    pass\n"
                "try:\n    from Crypto.Cipher import AES\nexcept ImportError:\n    pass\n\n"
            )
            f.write(preamble)
            f.write(code)
            tmp_path = f.name

        base_env = {"PYTHONIOENCODING": "utf-8"}
        env = {**os.environ, **base_env} if mode == "trusted-local" else base_env

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                [sys.executable, tmp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                cwd=tempfile.gettempdir(),
                env=env,
            ),
        )

        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        output_parts: list[str] = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            stderr_lines = [
                line
                for line in result.stderr.splitlines()
                if "ImportError" not in line and "No module named" not in line
            ]
            if stderr_lines:
                output_parts.append("[stderr]\n" + "\n".join(stderr_lines))

        if not output_parts:
            _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
            return f"{warning_prefix}[+] Python executed successfully with no output"

        output = "\n".join(output_parts)
        for sig in ["[DONE]", "[COMPLETE]"]:
            output = output.replace(sig, f"[BLOCKED_{sig[1:-1]}]")
        if len(output) > max_output_chars:
            clip = max_output_chars // 2
            output = output[:clip] + "\n...[truncated]...\n" + output[-clip:]
        _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
        return f"{warning_prefix}[+] Python execution result ({mode}):\n{output}"
    except subprocess.TimeoutExpired:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        agent.runtime.python_timeout_rounds += 1
        _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="timeout")
        return f"[!] Python execution timed out after {timeout_seconds} seconds"
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        _write_python_audit(
            agent, purpose=purpose, code=code, mode=mode, outcome="error", blocked_reason=str(e)
        )
        return f"[!] Python execution error: {e}"


def _sync_cookies_to_shared_jar(
    agent: Any, cookies: list[tuple[str, str, str, str]]
) -> None:
    """Copy session cookies into the agent's shared _fetch_cookies jar.

    This allows the ``fetch`` tool (which uses ``_fetch_cookies``) to
    immediately use the authenticated session obtained by
    ``brute_force_login`` without requiring a separate re-login.
    """
    if not agent or not cookies:
        return
    mcp = getattr(agent, "mcp_manager", None)
    if not mcp:
        return
    try:
        import httpx

        jar = getattr(mcp, "_fetch_cookies", None)
        if jar is None:
            jar = httpx.Cookies()
            mcp._fetch_cookies = jar
        for name, value, domain, path in cookies:
            if name and value:
                jar.set(name, value, domain=domain or "", path=path or "/")
    except Exception:
        pass


async def execute_brute_force(agent: Any, args: dict[str, Any]) -> str:
    """Execute a login brute-force with automatic CSRF/session management.

    Handles the full flow in one call:
    GET login page → extract CSRF + session → POST passwords → detect result
    """
    import asyncio
    import re
    import time

    url = str(args.get("url", "") or "").strip()
    password_field = str(args.get("password_field", "") or "").strip()
    csrf_field = str(args.get("csrf_field", "") or "").strip()
    username_field = str(args.get("username_field", "") or "").strip()
    username = str(args.get("username", "") or "").strip()
    passwords = args.get("passwords", [])
    success_keyword = str(args.get("success_keyword", "") or "").strip()
    failure_keyword = str(args.get("failure_keyword", "") or "").strip()
    submit_action = str(args.get("submit_action", "") or "").strip()
    extra_data = args.get("extra_data", {}) or {}
    submit_url = submit_action or url

    if not url or not password_field or not passwords:
        return "[!] Missing required parameters: url, password_field, passwords"

    if not isinstance(passwords, list) or not passwords:
        return "[!] passwords must be a non-empty list"

    passwords = passwords[:20]
    total = len(passwords)

    try:
        import httpx
    except ImportError:
        return "[!] httpx is not installed; cannot run brute force"

    def extract_csrf(html: str, field_name: str) -> str | None:
        """Extract CSRF token from HTML input field."""
        if not field_name:
            return None
        pattern = re.compile(
            rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)',
            re.IGNORECASE,
        )
        m = pattern.search(html)
        if m:
            return m.group(1)
        # Try alternative: value before name
        pattern2 = re.compile(
            rf'value=["\']([^"\']+)[^>]*name=["\']{re.escape(field_name)}',
            re.IGNORECASE,
        )
        m = pattern2.search(html)
        return m.group(1) if m else None

    results: list[str] = []
    start_time = time.time()
    attempts = 0
    found_password: str | None = None

    # Collect cookies from the internal client so we can sync them
    # back to the shared _fetch_cookies jar after a successful login.
    session_cookies: list[tuple[str, str, str, str]] = []  # name, value, domain, path

    async with httpx.AsyncClient(
        verify=False,
        timeout=30.0,
        follow_redirects=True,
    ) as client:
        # Step 1: Get login page for initial CSRF and session
        try:
            resp = await asyncio.wait_for(
                client.get(url),
                timeout=30.0,
            )
            html = resp.text
        except Exception as e:
            return f"[!] Failed to fetch the login page: {e}"

        csrf_token = extract_csrf(html, csrf_field)
        if csrf_token is None and csrf_field:
            results.append(f"[!] Warning: CSRF field '{csrf_field}' not found on the login page")

        # Auto-detect submit button values from login page HTML.
        # Many forms (DVWA, etc.) check isset($_POST['SubmitButtonName'])
        # before processing authentication. Without the button's name=value,
        # the server skips auth and just re-renders the page.
        auto_fields: dict[str, str] = {}
        for input_match in re.finditer(
            r'<(?:input|button)\s[^>]*type=["\']submit["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = input_match.group()
            name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                auto_fields[name_m.group(1)] = val_m.group(1) if val_m else name_m.group(1)

        # Step 2: Try each password
        for i, password in enumerate(passwords, 1):
            form_data: dict[str, str] = {}
            if username_field and username:
                form_data[username_field] = username
            form_data[password_field] = password
            if csrf_token and csrf_field:
                form_data[csrf_field] = csrf_token
            # Auto-detected submit buttons come first so they can be
            # overridden by explicit extra_data if needed.
            form_data.update(auto_fields)
            form_data.update({k: str(v) for k, v in extra_data.items()})

            try:
                resp = await asyncio.wait_for(
                    client.post(submit_url, data=form_data),
                    timeout=30.0,
                )
                attempts += 1
                response_html = resp.text
                status = resp.status_code

                # Determine success or failure
                is_success = False
                reason = ""
                csrf_markers = ["csrf token is incorrect", "csrf token mismatch",
                                "token mismatch", "invalid token"]

                if success_keyword and success_keyword.lower() in response_html.lower():
                    is_success = True
                    reason = f"'{success_keyword}'"
                elif failure_keyword and failure_keyword.lower() in response_html.lower():
                    is_success = False
                    reason = f"'{failure_keyword}'"
                elif any(m in response_html.lower() for m in csrf_markers):
                    is_success = False
                    reason = "CSRF token incorrect (new token auto-synced)"
                elif status == 302:
                    is_success = True
                    reason = "Status 302 (redirect)"
                elif "logout" in response_html.lower() or "welcome" in response_html.lower():
                    is_success = True
                    reason = "logged-in state detected"
                else:
                    # Include a short snippet from the response so the model
                    # can diagnose what the server actually returned.
                    snippet = response_html.strip()[:200].replace("\n", " ")
                    is_success = False
                    reason = snippet

                prefix = "[✓]" if is_success else "[✗]"
                pw_preview = password[:40].replace("\n", "\\n")
                results.append(f"{prefix} {pw_preview} → {'success' if is_success else 'failure'} ({reason})")

                # Extract new CSRF from response for next attempt
                new_token = extract_csrf(response_html, csrf_field)
                if new_token:
                    csrf_token = new_token

                # Stop early on success if keyword matched
                if is_success and success_keyword:
                    found_password = password
                    break

            except Exception as e:
                pw_preview = password[:30].replace("\n", "\\n")
                results.append(f"[!] {pw_preview} → request failed: {e}")
                continue

        # Save cookies from the internal client for potential sharing with
        # the fetch tool's cookie jar.
        try:
            for cookie in client.cookies.jar:
                session_cookies.append(
                    (cookie.name, cookie.value, cookie.domain, cookie.path)
                )
        except Exception:
            pass

    elapsed = time.time() - start_time

    # Sync session cookies to the shared _fetch_cookies jar so that
    # subsequent `fetch` calls from the agent are already authenticated.
    if found_password and session_cookies:
        _sync_cookies_to_shared_jar(agent, session_cookies)

    summary = [
        f"[+] Brute force complete — {url}",
        f"    User: {username or '(unspecified)'}",
        "",
        "    Results:",
    ]
    for r in results:
        summary.append(f"    {r}")
    summary.append("")
    summary.append(f"    Elapsed: {elapsed:.1f}s")
    summary.append(f"    Attempts: {attempts}/{total}")

    return "\n".join(summary)
