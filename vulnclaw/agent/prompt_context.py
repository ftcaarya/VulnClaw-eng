"""Prompt/round-context helpers for AgentCore."""

from __future__ import annotations

from typing import Any


def build_round_context(agent: Any, round_num: int, max_rounds: int) -> str:
    """Build context string for the current round in auto loop."""
    state = agent.context.state
    constraints_summary = ""
    constraints_block = (
        state.get_constraints_prompt_block()
        if hasattr(state, "get_constraints_prompt_block")
        else ""
    )
    if constraints_block:
        constraints_summary = f"\n\n{constraints_block}"

    reasoning_summary = ""
    session_config = getattr(agent.config, "session", None)
    reasoning_enabled = getattr(session_config, "reasoning_state_enabled", True)
    if reasoning_enabled:
        reasoning = getattr(state, "reasoning", None)
        reasoning_block = (
            reasoning.to_prompt_block()
            if hasattr(reasoning, "to_prompt_block")
            else ""
        )
        if reasoning_block:
            reasoning_summary = f"\n\n{reasoning_block}"

    reflexion_summary = ""
    reflexion_enabled = getattr(session_config, "reflexion_enabled", True)
    reflexion = getattr(agent.runtime, "reflexion", None)
    if reflexion_enabled and hasattr(reflexion, "to_prompt_block"):
        reflexion_block = reflexion.to_prompt_block()
        if reflexion_block:
            reflexion_summary = f"\n\n{reflexion_block}"
        if hasattr(reflexion, "to_reflection_prompt"):
            reflection_block = reflexion.to_reflection_prompt()
            if reflection_block:
                reflexion_summary += f"\n\n{reflection_block}"

    findings_summary = ""
    if state.findings:
        findings_summary = f"\nFindings so far: {len(state.findings)}"
        for finding in state.findings[-5:]:
            findings_summary += (
                f"\n  - [{finding.severity}] {finding.title}: {finding.evidence[:100]}"
            )

    user_hint_directive = ""
    if round_num <= agent.runtime.user_vuln_hint_rounds and agent.runtime.user_vuln_hint:
        user_hint_directive = (
            f"\n\n{'=' * 50}\n"
            f"[Explicit user hint — round {round_num}/{agent.runtime.user_vuln_hint_rounds}]\n"
            f"{agent.runtime.user_vuln_hint}\n"
            f"{'=' * 50}\n"
        )
        agent.runtime.user_vuln_hint_rounds -= 1

    steps_summary = ""
    if state.executed_steps:
        recent_steps = state.executed_steps[-8:]
        steps_summary = f"\nRecent steps executed: {len(state.executed_steps)} total"
        for step in recent_steps:
            steps_summary += f"\n  - {step[:150]}"

    failed_summary = ""
    if state.executed_steps:
        failed_attempts = []
        failure_markers = [
            "fail",
            "none",
            "same response",
            "blocked",
            "404",
            "did not succeed",
            "invalid",
            "error",
            "failed",
            "still",
            "not found",
            "no result",
            "timeout",
            "forbidden",
            "denied",
            "does not exist",
            "unable",
            "cannot",
            "incorrect",
        ]
        for step in state.executed_steps:
            if any(marker in step.lower() for marker in failure_markers):
                failed_attempts.append(step[:150])
        if failed_attempts:
            failed_summary = "\nFailure history (do not repeat these actions):"
            for failure in failed_attempts[-10:]:
                failed_summary += f"\n  ❌ {failure}"

    recon_summary = ""
    if state.recon_data:
        recon_summary = f"\nRecon data: {list(state.recon_data.keys())}"

    resume_summary = ""
    if getattr(state, "resume_summary", ""):
        resume_summary = f"\n\n{state.resume_summary}"

    notes_summary = ""
    if state.notes:
        notes_summary = f"\nImportant notes: {'; '.join(state.notes[-5:])}"

    facts_summary = ""
    if hasattr(state, "confirmed_facts") and state.confirmed_facts:
        facts_summary = "\nConfirmed facts (tool-verified, trustworthy):"
        for fact in state.confirmed_facts[-8:]:
            facts_summary += f"\n  ✅ {fact[:150]}"

    assumptions_summary = ""
    if hasattr(state, "unverified_assumptions") and state.unverified_assumptions:
        assumptions_summary = "\n⚠️ Unverified assumptions (basis of reasoning but not confirmed, may be wrong):"
        for assumption in state.unverified_assumptions[-5:]:
            assumptions_summary += f"\n  ❓ {assumption[:150]}"
        assumptions_summary += "\n→ If an assumption is wrong, all reasoning based on it is void! Verify the key assumptions first."

    path_warning = ""
    same_path_fails = agent.runtime.same_path_fail_count

    if state.executed_steps:
        recent = state.executed_steps[-8:]
        if len(recent) >= 5:
            recent_text = " ".join(recent).lower()
            stuck_indicators = ["get=", "post=", "payload", "param", "attempt"]
            stuck_count = sum(
                1 for indicator in stuck_indicators if recent_text.count(indicator) >= 3
            )
            if stuck_count >= 1:
                path_warning = (
                    "\n\n⚠️ You've tried the current path for several rounds with no breakthrough."
                    "\nReview the source/info again — is there a simpler exploitation path?"
                    "\nList all possible paths, then switch to the simplest one."
                )

    path_switch_warning = ""
    if not reflexion_enabled and same_path_fails >= 3:
        path_switch_warning = (
            f"\n\n🔴 Path-switch mandatory directive: you have failed on the same attack path {same_path_fails} times!"
            f"\nYou must immediately do the following:"
            f"\n1. Stop and list at least 3 **completely different** alternative attack paths"
            f"\n   (not a different payload value, but a different attack method: e.g. switch from 'regex bypass' to 'wrapper-protocol file read' or 'array bypass')"
            f"\n2. Order these alternatives from easiest to hardest"
            f"\n3. Start with the simplest alternative"
            f"\n4. Before trying the new path, spend 1 round validating your new assumption"
            f"\n\n⚠️ Do not keep trying different payload values on the same path!"
        )
        agent.runtime.same_path_fail_count = 0
        agent.runtime.path_switch_forced = True

    assumption_reminder = ""
    if round_num > 2 and round_num % 3 == 0:
        assumption_reminder = (
            "\n\n🧠 Assumption-validation checkpoint:"
            "\nBefore your next step, take 10 seconds and ask yourself:"
            "\n1. What assumptions does my current reasoning rest on?"
            "\n2. Have I verified those assumptions, or am I taking them for granted?"
            "\n3. If one assumption is wrong, does my whole reasoning chain collapse?"
            "\n4. Could I spend 1 round sending a request to verify the most critical assumption?"
            "\n\n❌ Common fatal assumptions: preg_replace only replaces the first match / Python simulation = server behavior / the parameter name is some value"
        )

    python_timeout_warning = ""
    python_timeout_rounds = agent.runtime.python_timeout_rounds
    if python_timeout_rounds >= 1:
        python_timeout_warning = (
            "\n\n⚠️ **Code-execution warning**: last round's Python script timed out."
            "\nDo not write complex scripts longer than 10 lines."
            "\nPrefer the existing tools (fetch/python_execute) over writing your own crawler/parser code."
            "\nDo not repeatedly execute the same large script."
        )

    dead_loop_warning = ""
    rounds_no_progress = agent.runtime.rounds_without_progress
    stale_threshold = agent.config.session.stale_rounds_threshold

    blocked_targets_warning = ""
    blocked_targets = agent.runtime.blocked_targets
    if blocked_targets:
        blocked_targets_warning = (
            f"\n\n🚨 **Target-unreachable warning**: the following targets have failed repeatedly; do not try them again:"
            f"\n{chr(10).join(f'  ❌ {target} — confirmed unreachable' for target in blocked_targets)}"
            f"\n\nYou must:"
            f"\n1. Immediately stop accessing the above targets"
            f"\n2. Focus on other live targets"
            f"\n3. If there are no other targets, switch to deeper exploitation of confirmed vulnerabilities"
            f"\n4. Do not waste rounds trying to connect to unreachable targets"
        )

    if rounds_no_progress >= stale_threshold:
        dead_loop_warning = (
            f"\n\n🔴 Serious warning: you have had no new findings for {rounds_no_progress} consecutive rounds!"
            f"\nThis indicates you are stuck in a loop. You must immediately take one of these actions:"
            f"\n1. 🔥 Re-fetch the full source (use python_execute + strip_tags)"
            f"\n2. 🔥 Try a completely different attack path (different param name, method, tool)"
            f"\n3. 🔥 If current info is insufficient, admit it and try other recon methods"
            f"\n4. 🔥 Stop repeating the same action! Review the failure history and pick a new direction"
            f"\n\n⚠️ Repeating the same action again will not produce a different result!"
        )
    elif rounds_no_progress >= max(stale_threshold // 2, 2):
        dead_loop_warning = (
            f"\n\n⚠️ Warning: you have had no new findings for {rounds_no_progress} consecutive rounds."
            f"\nCheck: are you repeating the same action? Are there other untried paths?"
            f"\nIf the current method isn't working, switch to another method immediately."
        )

    flag_warning = ""
    claimed_flag = agent.runtime.claimed_flag
    flag_verified = agent.runtime.flag_verified
    if claimed_flag and flag_verified:
        flag_warning = (
            f"\n\n✅ FLAG verified: {claimed_flag}"
            f"\nYour task is complete! Concisely summarize the solving process, then mark [DONE] to finish."
            f"\n⚠️ Do not re-verify or re-send requests! Summarize and finish immediately."
        )
    elif claimed_flag and not flag_verified:
        flag_warning = (
            f"\n\n⚠️ You previously claimed to have found a flag: {claimed_flag}"
            f"\nBut this flag has not been independently verified! You must:"
            f"\n1. Re-send the payload with a tool to confirm the result is reproducible"
            f"\n2. Or cross-validate with a different method (e.g. read the same content with a different function/path)"
            f"\n3. If verification fails, admit the previous flag was wrong and keep solving"
            f"\nDo not mark [DONE] until verification is complete"
        )

    ctf_mode_warning = ""
    is_ctf = agent.runtime.is_ctf_mode
    if is_ctf and not claimed_flag:
        ctf_mode_warning = (
            "\n\n🔴 CTF solving mode — your task is to find the flag and verify it."
            "\nYou have not found any flag yet; do not mark [DONE]."
            "\nAnalyze the available info, pick the most likely attack path, and keep pushing forward."
            "\nIf the current path is blocked, try switching to another path."
        )
    elif is_ctf and claimed_flag and not flag_verified:
        ctf_mode_warning = (
            "\n\n🔴 CTF solving mode — you claimed to have found a flag but did not verify it."
            "\nYou must verify the flag's authenticity with a tool before marking [DONE]."
            "\nIf verification fails, you must keep looking for the correct flag."
        )

    recon_dim_status = ""
    if agent.runtime.is_recon_phase:
        dim_status_text = state.get_recon_status_text()
        is_complete = state.is_recon_complete()
        rounds_no_progress = agent.runtime.rounds_without_progress

        recon_dim_status = f"\n\n📊 Recon dimension completeness:\n{dim_status_text}"
        if not is_complete:
            recon_dim_status += (
                "\n\n🔴 Recon incomplete! Some dimensions are unchecked; do not mark [DONE]."
                "\nKeep checking the incomplete dimensions, ensuring each has run at least once."
            )
        elif (is_complete and rounds_no_progress >= 3) or (rounds_no_progress >= 8 + 5):
            output_dir = str(agent.config.session.output_dir.resolve())
            if is_complete:
                trigger_reason = f"all dimensions complete ✅, {rounds_no_progress} consecutive rounds with no new progress"
            else:
                trigger_reason = f"{rounds_no_progress} consecutive rounds with no new progress (8+5 safety valve)"
            recon_dim_status += (
                f"\n\n🔴 ★★★ FORCED RECON → EXPLOITATION PHASE SWITCH ★★★\n"
                f"{trigger_reason}.\n"
                f"You must immediately switch to the [Exploitation phase] rather than keep gathering info or saving reports.\n\n"
                f"★ Do the following immediately:\n"
                f"1. Output 'switch to vulnerability discovery' or 'phase: vuln_discovery' in your reply\n"
                f"2. Based on the recon results already collected (target profile / neighbor sites / API leaks, etc.),\n"
                f"   perform actual exploitation against the highest-value attack surface\n"
                f"3. [FORBIDDEN] continuing to save recon reports or calling recon-type tools\n"
                f"4. [FORBIDDEN] repeating existing findings — you must have a new, actual validation step\n\n"
                f"★ Output directory (the recon report is saved automatically by the framework; you don't need to save it manually):\n"
                f"   {output_dir}\n"
                f"⚠️ The goal of this engagement is [actual successful exploitation], not a recon report!"
            )
        if round_num < 8:
            recon_dim_status += (
                f"\n\n🔴 Recon minimum-rounds guarantee: currently round {round_num}, "
                f"minimum 8 required. Even if you think it's enough, keep going deeper."
            )

    return (
        f"\n\n[Autonomous loop Round {round_num}/{max_rounds}]"
        f"\nCurrent target: {state.target or 'not set'}"
        f"\nCurrent phase: {state.phase.value}"
        f"\nOutput directory: {agent.config.session.output_dir.resolve()}"
        f"{constraints_summary}"
        f"{reasoning_summary}"
        f"{reflexion_summary}"
        f"{user_hint_directive}"
        f"{findings_summary}"
        f"{facts_summary}"
        f"{assumptions_summary}"
        f"{steps_summary}"
        f"{failed_summary}"
        f"{recon_summary}"
        f"{resume_summary}"
        f"{notes_summary}"
        f"{path_warning}"
        f"{path_switch_warning}"
        f"{assumption_reminder}"
        f"{python_timeout_warning}"
        f"{blocked_targets_warning}"
        f"{dead_loop_warning}"
        f"{flag_warning}"
        f"{ctf_mode_warning}"
        f"{recon_dim_status}"
        f"\n\nBased on the current state and all previous findings, decide the next action and keep advancing the pentest."
        f"\nNote: do not repeat actions you've already done; focus on advancing to the next step."
        f"\nIf you find an important lead or complete the test, append a [DONE] marker at the end of your reply."
    )


async def generate_attack_summary(agent: Any) -> str:
    """Generate a detailed attack path summary for the cycle report."""
    state = agent.context.state

    steps = state.executed_steps[-30:] if state.executed_steps else []
    steps_text = (
        "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps)) if steps else "(no step records)"
    )

    notes = state.notes[-20:] if state.notes else []
    notes_text = "\n".join(f"- {note}" for note in notes) if notes else "(no observation records)"

    findings = state.findings
    if findings:
        lines = []
        for finding in findings:
            evidence = (finding.evidence or "")[:150].strip()
            lines.append(f"[{finding.severity}] {finding.title} | evidence: {evidence or 'none'}")
        findings_text = "\n".join(lines)
    else:
        findings_text = "none"

    prompt = (
        f"Target: {state.target or '?'}  |  Current phase: {state.phase.value}\n"
        f"\n=== Steps executed ===\n{steps_text}\n"
        f"\n=== Key observations/results ===\n{notes_text}\n"
        f"\n=== Findings ===\n{findings_text}\n\n"
        f"Write a detailed attack-path narrative in English, including these elements:\n"
        f"1. Specific URLs/paths tested (e.g. https://target.com/admin/login)\n"
        f"2. The specific technique/tool used at each step (e.g. SQLMap blind injection, directory enumeration, nmap port scan)\n"
        f"3. Key response characteristics (e.g. 155-byte length difference, HTTP 500 error echo)\n"
        f"4. The link between vulnerability and attack surface (e.g. found /manager/html via directory enumeration, matched CVE-2023-44487)\n"
        f"5. Subdomain discoveries (e.g. found api.target.com, cms.target.com, etc.)\n"
        f"Format: narrate in natural paragraphs, no lists, 200-400 words, plain English, no <thinking> tags."
    )

    try:
        client = agent._get_client()
        messages = [{"role": "user", "content": prompt}]
        from vulnclaw.agent.llm_client import build_chat_completion_kwargs

        response = client.chat.completions.create(
            **build_chat_completion_kwargs(
                agent,
                messages,
                max_tokens=800,
                temperature=0.3,
            )
        )
        if response and response.choices:
            raw = response.choices[0].message.content or ""
            from vulnclaw.agent.think_filter import strip_think_tags

            return strip_think_tags(raw).strip()
    except Exception:
        pass
    return ""
