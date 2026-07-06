"""Recon dimension tracking helpers for AgentCore."""

from __future__ import annotations

from typing import Any

RECON_MIN_ROUNDS = 8  # Minimum rounds for the recon phase; below this a [DONE] is ignored

# ★ Include BOTH tool-result signatures AND natural-language descriptions from notes/confirmed_facts
RECON_DIM_KEYWORDS: dict[str, list[str]] = {
    "server": [
        "port",
        "nmap",
        "open",
        "service version",
        "service",
        "real ip",
        "cdn",
        "origin",
        "operating system",
        "os detection",
        "ttl",
        "middleware",
        "database",
        "mysql",
        "redis",
        "scan",
        "port scan",
        "ip address",
        "ip probe",
        "live host",
        "apache",
        "nginx",
        "tomcat",
        "iis",
        "jetty",
        "linux",
        "windows",
        "ubuntu",
        "centos",
    ],
    "website": [
        "waf",
        "web application firewall",
        "sensitive directory",
        "directory scan",
        "dirsearch",
        "gobuster",
        "source code leak",
        ".git",
        ".svn",
        ".ds_store",
        ".env",
        "backup file",
        ".bak",
        "neighbor site",
        "same ip",
        "c-segment",
        "same subnet",
        "fingerprint",
        "cms",
        "framework",
        "architecture",
        "tech stack",
        "web fingerprint",
        "website",
        "web",
        "javascript",
        "js file",
        "api endpoint",
        "wordpress",
        "dedecms",
        "phpcms",
        "discuz",
        "login",
        "admin panel",
        "management",
        "admin",
        "page",
        "url",
        "directory",
        "file",
    ],
    "domain": [
        "whois",
        "registrant",
        "registrar",
        "icp",
        "filing",
        "subdomain",
        "dns record",
        "cname",
        "mx record",
        "txt record",
        "certificate transparency",
        "crt.sh",
        "certificate info",
        "ssl certificate",
        "domain",
        "dns",
        " registr",
        "registration info",
        "icp filing",
        "sub-site",
        "certificate",
    ],
    "personnel": [
        "github_id",
        "followers",
        "following",
        "public_repos",
        "unclecheng",
        "twitter",
        "social engineering",
        "personnel info",
        "author tracking",
        "persona profiling",
    ],
}


def update_recon_dimension_completion(agent: Any, response: str) -> None:
    """Auto-detect which recon dimensions have been explored.

    Uses signal-weighted sources instead of blindly scanning all round text.
    The `response` parameter is kept for call-signature compatibility, but the raw
    reasoning text is not used by the logic.
    """
    note_text = " ".join(agent.context.state.notes[-15:]).lower()
    fact_text = " ".join(getattr(agent.context.state, "confirmed_facts", [])[-15:]).lower()
    step_text = " ".join(agent.context.state.executed_steps[-15:]).lower()

    for dim, keywords in RECON_DIM_KEYWORDS.items():
        if dim == "personnel":
            if not agent.context.state.recon_dimension4_active:
                continue
            source_text = fact_text
        else:
            source_text = f"{fact_text} {note_text} {step_text}"

        if not source_text.strip():
            continue

        if not agent.context.state.recon_dimensions_completed.get(dim, False):
            if any(kw.lower() in source_text for kw in keywords):
                agent.context.state.mark_recon_dimension(dim)
