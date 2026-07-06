"""Anti-loop and phase-detection helpers for AgentCore."""

from __future__ import annotations

import re
from typing import Optional

from vulnclaw.agent.context import PentestPhase

FAILED_ACCESS_PATTERNS = [
    "SSLError",
    "ReadTimeout",
    "connection timed out",
    "connection failed",
    "502 Bad Gateway",
    "502",
    "503",
    "unable to access",
    "access failed",
    "Connection refused",
    "ConnectionError",
    "TimeoutError",
    "Name or service not known",
    "No route to host",
    "SSL: CERTIFICATE_VERIFY_FAILED",
    "timeout",
]


def detect_phase_from_output(output: str) -> Optional[PentestPhase]:
    """Detect phase transition signals from LLM output."""
    output_lower = output.lower()
    transitions = [
        (
            PentestPhase.VULN_DISCOVERY,
            ["entering vulnerability discovery", "start vuln scan", "vuln detection", "switch to vulnerability discovery", "phase: vuln_discovery"],
        ),
        (
            PentestPhase.EXPLOITATION,
            ["entering exploitation", "start exploiting", "attempt exploitation", "switch to exploitation", "phase: exploitation"],
        ),
        (
            PentestPhase.POST_EXPLOITATION,
            ["entering post-exploitation", "internal-network pentest", "lateral movement", "switch to post-exploitation", "phase: post_exploitation"],
        ),
        (
            PentestPhase.REPORTING,
            ["generate report", "consolidate results", "pentest complete", "switch to reporting", "phase: reporting"],
        ),
    ]

    for phase, signals in transitions:
        if any(signal in output_lower for signal in signals):
            return phase
    return None


def is_completion_signal(output: str) -> bool:
    """Check if the LLM output signals task completion."""
    completion_signals = [
        "[DONE]",
        "[COMPLETE]",
        "penetration test complete",
        "testing finished",
        "task complete",
    ]
    return any(signal in output for signal in completion_signals)


def track_failed_target(agent, response_text: str) -> Optional[str]:
    """Track target-level failures and detect repeatedly failed targets."""
    hostname = None
    url_match = re.search(r'https?://([^\s/<>"\')\]]+)', response_text)
    if url_match:
        hostname = url_match.group(1)

    if not hostname:
        return None

    is_failed_access = any(pattern in response_text for pattern in FAILED_ACCESS_PATTERNS)

    if is_failed_access:
        agent.runtime.failed_targets[hostname] = agent.runtime.failed_targets.get(hostname, 0) + 1
        if agent.runtime.failed_targets[hostname] >= 3:
            agent.runtime.blocked_targets.add(hostname)
            return hostname
    else:
        if hostname in agent.runtime.failed_targets and agent.runtime.failed_targets[hostname] > 0:
            agent.runtime.failed_targets[hostname] -= 1

    return None


def is_meaningful_step(step: str) -> bool:
    """Check if a step represents meaningful progress (not just a failed retry)."""
    failure_only_keywords = [
        "SSLError",
        "ReadTimeout",
        "connection timed out",
        "connection failed",
        "502 Bad Gateway",
        "unable to access",
        "access failed",
        "Connection refused",
        "ConnectionError",
        "TimeoutError",
        "request failed",
    ]
    progress_keywords = [
        "found",
        "discovered",
        "confirmed",
        "vuln",
        "port",
        "path",
        "flag",
        "success",
        "CVE",
        "leak",
        "bypass",
        "verified",
    ]

    if any(keyword in step for keyword in progress_keywords):
        return True
    if any(keyword in step for keyword in failure_only_keywords):
        return False
    return True


def detect_attack_path(output: str) -> Optional[str]:
    """Detect the current attack path/technique from LLM output."""
    output_lower = output.lower()
    path_patterns = [
        (
            "regex_bypass",
            ["preg_replace", "preg_match", "regex bypass", "case bypass", "array bypass", "double-write bypass"],
        ),
        (
            "file_inclusion",
            ["php://filter", "file inclusion", "include", "require", "wrapper protocol", "php://input", "data://"],
        ),
        ("rce", ["eval(", "system(", "exec(", "passthru(", "shell_exec(", "command execution", "rce"]),
        ("sqli", ["sql injection", "union select", "information_schema", "sqli", "sqlmap"]),
        ("ssti", ["ssti", "template", "jinja2", "twig", "{{", "template injection"]),
        ("deserialization", ["deserialization", "unserialize", "serialize", "pop chain", "wakeup"]),
        ("file_upload", ["file upload", "upload", "webshell", "one-liner webshell"]),
        ("ssrf", ["ssrf", "gopher://", "dict://", "internal-network access"]),
        ("xxe", ["xxe", "xml external entity", "entity"]),
        ("info_leak", ["source-code leak", ".git", ".svn", "backup file", "directory traversal", "robots.txt"]),
        ("brute_force", ["brute force", "weak password", "dictionary", "brute"]),
    ]

    for path_name, keywords in path_patterns:
        if any(keyword in output_lower for keyword in keywords):
            return path_name
    return None
