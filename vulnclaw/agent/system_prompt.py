"""Dynamic system prompt assembly for AgentCore."""

from __future__ import annotations

from typing import Optional

from vulnclaw.agent.prompts import AUTO_PENTEST_INSTRUCTION, RECON_INSTRUCTION, build_system_prompt


def build_dynamic_system_prompt(
    *,
    target: Optional[str],
    phase: Optional[str],
    skill_context: Optional[str],
    mcp_tools: list[dict],
    enable_personnel_dim: bool,
    auto_mode: bool,
    user_input: Optional[str],
    kb_context: str,
) -> str:
    """Build the dynamic system prompt for one turn."""
    prompt = build_system_prompt(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
    )

    if auto_mode:
        prompt += "\n\n" + AUTO_PENTEST_INSTRUCTION

    if user_input:
        recon_triggers = [
            "gather",
            "collect",
            "information gathering",
            "recon",
            "reconnaissance",
            "osint",
            "social engineering",
            "investigate",
            "author",
            "person",
            "intelligence",
            "analyze target",
            "target analysis",
            "asset discovery",
            "subdomain",
        ]
        if any(trigger in user_input.lower() for trigger in recon_triggers):
            if enable_personnel_dim:
                prompt += "\n\n" + RECON_INSTRUCTION
            else:
                recon_no_personnel = RECON_INSTRUCTION.replace(
                    "### Dimension 4: Personnel Information ⚡ Conditionally triggered",
                    "### Dimension 4: Personnel Information ⚡ Conditionally triggered (not active this time — user did not mention social-eng / personnel-tracking needs)",
                )
                recon_no_personnel = (
                    recon_no_personnel.replace(
                        "- [ ] Name & role",
                        "- [x] Name & role (not active, skipped)",
                    )
                    .replace(
                        "- [ ] Birthday & contact phone",
                        "- [x] Birthday & contact phone (not active, skipped)",
                    )
                    .replace(
                        "- [ ] Email address",
                        "- [x] Email address (not active, skipped)",
                    )
                    .replace(
                        "- [ ] Social-media accounts (Bilibili, Weibo, Zhihu, Twitter, LinkedIn, GitHub)",
                        "- [x] Social-media accounts (not active, skipped)",
                    )
                    .replace(
                        "- [ ] Cross-platform correlation (search other platforms by username/email, check emails in historical commit records)",
                        "- [x] Cross-platform correlation (not active, skipped)",
                    )
                )
                prompt += "\n\n" + recon_no_personnel

    if kb_context:
        prompt += "\n\n" + kb_context

    return prompt
