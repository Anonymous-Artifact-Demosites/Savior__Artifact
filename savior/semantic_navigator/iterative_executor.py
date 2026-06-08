"""Iterative Execution Strategy for SAVIOR (Section 6.2).

Python API for running a task N times and aggregating verdicts to mitigate
LLM randomness. Each iteration goes through the full pipeline:
CONSTRUCTPROMPT -> LLMORACLE -> PARSESTRUCTUREDOUTPUT -> invariants -> cross_check.

Special handling:
- T1: runs step1 -> step2 as a pair per iteration (caller provides both
  variable sets; credential management is the caller's responsibility)
- T3_T4: aggregates dual verdicts (T3 + T4) independently

This module is NOT the default entry point for tasks/*.py scripts -
those default to single execution for backward compatibility.
The CLI batch runner (batch_runner.py) uses subprocess-based iteration
for full task compat; this module is for programmatic use where all
variables (including credentials) are pre-populated.
"""

from __future__ import annotations

from pathlib import Path

from savior.browser_interactor.claude_runner import run_claude
from savior.semantic_navigator.task_orchestrator import construct_prompt
from savior.state_auditor.auditor import capture_evidence, cross_check, cross_check_with_evidence
from savior.state_auditor.invariants import evaluate_invariants, get_task_config
from savior.state_auditor.verdict_parser import parse_output


# ---------------------------------------------------------------------------
# Single-iteration runner (standard tasks)
# ---------------------------------------------------------------------------

def _cross_check_with_optional_screenshot_evidence(
    task_id,
    variables,
    task_config,
    rule_result,
    llm_result,
    observations,
):
    """Run dual-path cross-check and attach best-effort screenshot evidence."""
    try:
        from savior.state_auditor.screenshot_verifier import verify_observations

        screenshot_dir = Path(variables.get("screenshot_path", ""))
        screenshot_verification = verify_observations(task_id, observations, screenshot_dir)
        result = cross_check_with_evidence(task_config, rule_result, llm_result, screenshot_verification)
    except Exception:
        # Path C is advisory only; screenshot/OCR failures must not affect verdicts.
        result = cross_check(task_config, rule_result, llm_result)
    return result


def _run_single_iteration(task_id, variables, task_config, timeout_seconds):
    """Run one iteration of a standard (single-status) task."""
    prompt = construct_prompt(task_id, variables)
    claude_result = run_claude(prompt, timeout_seconds=timeout_seconds)
    parsed = parse_output(task_id, claude_result["output"])
    rule_verdict = evaluate_invariants(task_id, parsed["observations"])
    final_verdict = _cross_check_with_optional_screenshot_evidence(
        task_id,
        variables,
        task_config,
        rule_verdict,
        parsed["verdict"],
        parsed["observations"],
    )
    evidence = capture_evidence(task_id, claude_result["output"], parsed["observations"], final_verdict)

    return {
        "status": final_verdict.get("status"),
        "source": final_verdict.get("source"),
        "confidence": final_verdict.get("confidence"),
        "duration_seconds": claude_result.get("duration_seconds"),
        "observations_valid": parsed["observations_valid"],
        "raw_output": claude_result["output"],
        "cross_check": final_verdict,
        "evidence": evidence,
        "parsed": parsed,
    }


# ---------------------------------------------------------------------------
# T1 paired iteration: step1 -> step2 per iteration
# ---------------------------------------------------------------------------

def _run_t1_paired_iteration(variables_step1, variables_step2, iteration_index, timeout_seconds):
    """Run one T1 iteration: step1 then step2.

    Caller must provide fully populated variable dicts for both steps
    (including credentials). Credential isolation across iterations is
    the caller's responsibility.

    Combined verdict:
    - T1_VULN: step1 SUCCESS/DOUBT (no verification) AND step2 SUCCESS (OAuth links)
    - T1_SAFE: either step requires verification or OAuth fails
    """
    # Step 1: registration
    s1_config = get_task_config("T1_STEP1")
    s1_result = _run_single_iteration("T1_STEP1", variables_step1, s1_config, timeout_seconds)

    # Step 2: OAuth login
    s2_config = get_task_config("T1_STEP2")
    s2_result = _run_single_iteration("T1_STEP2", variables_step2, s2_config, timeout_seconds)

    # Combined T1 verdict:
    # step1 SUCCESS/DOUBT = registration without verification (vulnerable precondition)
    # step2 SUCCESS = OAuth login links to account (attack completes)
    s1_status = s1_result["status"]  # SUCCESS/DOUBT/FAIL
    s2_status = s2_result["status"]  # SUCCESS/FAIL
    combined_source = "verified" if s1_result["source"] == "verified" and s2_result["source"] == "verified" else "uncertain"

    if s1_status in ("SUCCESS", "DOUBT") and s2_status == "SUCCESS":
        combined_status = "T1_VULN"
    else:
        combined_status = "T1_SAFE"

    return {
        "status": combined_status,
        "source": combined_source,
        "confidence": "high" if combined_source == "verified" else "low",
        "duration_seconds": (s1_result["duration_seconds"] or 0) + (s2_result["duration_seconds"] or 0),
        "observations_valid": s1_result["observations_valid"] and s2_result["observations_valid"],
        "raw_output": s1_result["raw_output"] + "\n---STEP2---\n" + s2_result["raw_output"],
        "cross_check": {"source": combined_source, "status": combined_status,
                        "step1_status": s1_status, "step2_status": s2_status},
        "evidence": s2_result["evidence"],
        "parsed": s2_result["parsed"],
        "step1_result": s1_result,
        "step2_result": s2_result,
    }


# ---------------------------------------------------------------------------
# T3_T4 dual-verdict iteration
# ---------------------------------------------------------------------------

def _run_t3t4_iteration(variables, task_config, timeout_seconds):
    """Run one T3_T4 iteration with dual verdict handling."""
    prompt = construct_prompt("T3_T4", variables)
    claude_result = run_claude(prompt, timeout_seconds=timeout_seconds)
    parsed = parse_output("T3_T4", claude_result["output"])
    rule_verdict = evaluate_invariants("T3_T4", parsed["observations"])

    # Dual cross-check
    import re
    normalized = re.sub(r"\*", "", claude_result["output"])
    status_t3 = "UNKNOWN"
    status_t4 = "UNKNOWN"
    if re.search(r"STATUS_T3[:\s]+T3_SAFE", normalized):
        status_t3 = "T3_SAFE"
    elif re.search(r"STATUS_T3[:\s]+T3_VULN\b", normalized):
        status_t3 = "T3_VULN"
    if re.search(r"STATUS_T4[:\s]+T4_SAFE", normalized):
        status_t4 = "T4_SAFE"
    elif re.search(r"STATUS_T4[:\s]+T4_VULN\b", normalized):
        status_t4 = "T4_VULN"

    t3_rule = {"status": rule_verdict["status_t3"]} if rule_verdict and rule_verdict.get("status_t3") else None
    t4_rule = {"status": rule_verdict["status_t4"]} if rule_verdict and rule_verdict.get("status_t4") else None
    t3_llm = {"status": status_t3, "confidence": None} if status_t3 != "UNKNOWN" else None
    t4_llm = {"status": status_t4, "confidence": None} if status_t4 != "UNKNOWN" else None

    t3_verdict = _cross_check_with_optional_screenshot_evidence(
        "T3_T4",
        variables,
        task_config,
        t3_rule,
        t3_llm,
        parsed["observations"],
    )
    t4_verdict = _cross_check_with_optional_screenshot_evidence(
        "T3_T4",
        variables,
        task_config,
        t4_rule,
        t4_llm,
        parsed["observations"],
    )

    evidence = capture_evidence("T3_T4", claude_result["output"], parsed["observations"],
                                t3_verdict, verdict_t4=t4_verdict)

    return {
        "status_t3": t3_verdict.get("status"),
        "status_t4": t4_verdict.get("status"),
        "source_t3": t3_verdict.get("source"),
        "source_t4": t4_verdict.get("source"),
        "duration_seconds": claude_result.get("duration_seconds"),
        "observations_valid": parsed["observations_valid"],
        "raw_output": claude_result["output"],
        "t3_verdict": t3_verdict,
        "t4_verdict": t4_verdict,
        "evidence": evidence,
        "parsed": parsed,
    }


# ---------------------------------------------------------------------------
# Main entry: run_iterations
# ---------------------------------------------------------------------------

def run_iterations(task_id, variables, *, iterations=5, timeout_seconds=600,
                   variables_step2=None):
    """Run a task multiple times and aggregate verdicts.

    Args:
        task_id: Task identifier (T1_STEP1, T2, T3_T4, T5, T6, T7, or "T1" for paired)
        variables: Template variables for the prompt
        iterations: Number of iterations (default 5)
        timeout_seconds: Per-iteration timeout
        variables_step2: For T1 paired execution, the step2 variables

    Returns a dict with:
        status: final aggregated status
        decisive_iteration: index (1-based) of the decisive iteration
        iteration_history: list of per-iteration result dicts
        raw_output: output from the decisive iteration
        cross_check: cross_check result from the decisive iteration
        evidence: evidence from the decisive iteration
    """
    normalized_id = task_id.upper()

    # T1 paired execution
    if normalized_id == "T1" and variables_step2 is not None:
        return _run_t1_iterations(variables, variables_step2, iterations, timeout_seconds)

    # T3_T4 dual verdict
    if normalized_id == "T3_T4":
        return _run_t3t4_iterations(variables, iterations, timeout_seconds)

    # Standard single-status tasks
    return _run_standard_iterations(task_id, variables, iterations, timeout_seconds)


def _run_standard_iterations(task_id, variables, iterations, timeout_seconds):
    """Standard iteration loop for single-status tasks."""
    task_config = get_task_config(task_id)
    status_values = task_config.get("status_values", [])
    vuln_statuses = {s for s in status_values if "VULN" in s or s == "SUCCESS"}
    weak_statuses = {s for s in status_values if "WEAK" in s or s == "DOUBT"}

    iteration_history = []
    decisive_iteration = None
    decisive_result = None

    for i in range(1, iterations + 1):
        result = _run_single_iteration(task_id, variables, task_config, timeout_seconds)
        iter_record = {
            "iteration": i,
            "status": result["status"],
            "source": result["source"],
            "confidence": result["confidence"],
            "duration_seconds": result["duration_seconds"],
            "observations_valid": result["observations_valid"],
        }
        iteration_history.append(iter_record)

        # Early exit: verified VULN
        if result["status"] in vuln_statuses and result["source"] == "verified":
            decisive_iteration = i
            decisive_result = result
            break

        if decisive_result is None or _severity(result["status"], vuln_statuses, weak_statuses) > _severity(
            decisive_result["status"], vuln_statuses, weak_statuses
        ):
            decisive_iteration = i
            decisive_result = result

    return _aggregate(iteration_history, decisive_iteration, decisive_result, iterations, vuln_statuses, weak_statuses)


def _run_t1_iterations(variables_step1, variables_step2, iterations, timeout_seconds):
    """T1 paired iteration: step1 -> step2 per iteration."""
    # _run_t1_paired_iteration returns T1_VULN/T1_SAFE as combined status
    vuln_statuses = {"T1_VULN"}
    weak_statuses = set()  # T1 has no weak/doubt at the combined level

    iteration_history = []
    decisive_iteration = None
    decisive_result = None

    for i in range(1, iterations + 1):
        result = _run_t1_paired_iteration(variables_step1, variables_step2, i, timeout_seconds)
        iter_record = {
            "iteration": i,
            "status": result["status"],
            "source": result["source"],
            "confidence": result["confidence"],
            "duration_seconds": result["duration_seconds"],
            "observations_valid": result["observations_valid"],
        }
        iteration_history.append(iter_record)

        if result["status"] in vuln_statuses and result["source"] == "verified":
            decisive_iteration = i
            decisive_result = result
            break

        if decisive_result is None or _severity(result["status"], vuln_statuses, weak_statuses) > _severity(
            decisive_result["status"], vuln_statuses, weak_statuses
        ):
            decisive_iteration = i
            decisive_result = result

    return _aggregate(iteration_history, decisive_iteration, decisive_result, iterations, vuln_statuses, weak_statuses)


def _run_t3t4_iterations(variables, iterations, timeout_seconds):
    """T3_T4 dual-verdict aggregation: aggregate T3 and T4 independently."""
    task_config = get_task_config("T3_T4")
    t3_vuln = {"T3_VULN"}
    t4_vuln = {"T4_VULN"}

    iteration_history = []
    best_t3 = None
    best_t4 = None
    decisive_result = None

    for i in range(1, iterations + 1):
        result = _run_t3t4_iteration(variables, task_config, timeout_seconds)
        iter_record = {
            "iteration": i,
            "status_t3": result["status_t3"],
            "status_t4": result["status_t4"],
            "source_t3": result["source_t3"],
            "source_t4": result["source_t4"],
            "duration_seconds": result["duration_seconds"],
            "observations_valid": result["observations_valid"],
        }
        iteration_history.append(iter_record)

        if decisive_result is None:
            decisive_result = result

        # Early exit: both VULN verified
        t3_verified = result["status_t3"] in t3_vuln and result["source_t3"] == "verified"
        t4_verified = result["status_t4"] in t4_vuln and result["source_t4"] == "verified"
        if t3_verified and t4_verified:
            decisive_result = result
            break

        # Track worst per-sub-verdict
        if result["status_t3"] in t3_vuln and (best_t3 is None or best_t3 not in t3_vuln):
            best_t3 = result["status_t3"]
            decisive_result = result
        if result["status_t4"] in t4_vuln and (best_t4 is None or best_t4 not in t4_vuln):
            best_t4 = result["status_t4"]

    # Aggregate T3 and T4 independently
    t3_counts = {}
    t4_counts = {}
    for ir in iteration_history:
        t3_counts[ir["status_t3"]] = t3_counts.get(ir["status_t3"], 0) + 1
        t4_counts[ir["status_t4"]] = t4_counts.get(ir["status_t4"], 0) + 1

    # Aggregate T3 independently
    t3_verified_vuln = any(
        ir["status_t3"] == "T3_VULN" and ir["source_t3"] == "verified" for ir in iteration_history
    )
    t3_safe_count = sum(1 for ir in iteration_history if ir["status_t3"] == "T3_SAFE")
    t3_vuln_count = sum(1 for ir in iteration_history if ir["status_t3"] == "T3_VULN")
    t3_na_count = sum(1 for ir in iteration_history if ir["status_t3"] == "T3_N/A")
    safe_count = t3_safe_count
    vuln_count = t3_vuln_count

    if t3_na_count == len(iteration_history):
        final_t3 = "T3_N/A"
    elif t3_verified_vuln:
        final_t3 = "T3_VULN"
    elif safe_count > len(iteration_history) // 2:
        final_t3 = "T3_SAFE"
    elif vuln_count > safe_count:
        final_t3 = "T3_VULN"
    else:
        final_t3 = "T3_SAFE"

    # Aggregate T4 independently
    t4_verified_vuln = any(
        ir["status_t4"] == "T4_VULN" and ir["source_t4"] == "verified" for ir in iteration_history
    )
    t4_safe_count = sum(1 for ir in iteration_history if ir["status_t4"] == "T4_SAFE")
    t4_vuln_count = sum(1 for ir in iteration_history if ir["status_t4"] == "T4_VULN")
    t4_na_count = sum(1 for ir in iteration_history if ir["status_t4"] == "T4_N/A")

    if t4_na_count == len(iteration_history):
        final_t4 = "T4_N/A"
    elif t4_verified_vuln:
        final_t4 = "T4_VULN"
    elif t4_safe_count > len(iteration_history) // 2:
        final_t4 = "T4_SAFE"
    elif t4_vuln_count > t4_safe_count:
        final_t4 = "T4_VULN"
    else:
        final_t4 = "T4_SAFE"

    return {
        "status_t3": final_t3,
        "status_t4": final_t4,
        "status": f"{final_t3}/{final_t4}",
        "decisive_iteration": len(iteration_history),
        "iteration_history": iteration_history,
        "status_counts_t3": t3_counts,
        "status_counts_t4": t4_counts,
        "total_iterations": len(iteration_history),
        "raw_output": decisive_result["raw_output"] if decisive_result else "",
        "evidence": decisive_result["evidence"] if decisive_result else {},
        "parsed": decisive_result["parsed"] if decisive_result else {},
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _aggregate(iteration_history, decisive_iteration, decisive_result, iterations, vuln_statuses, weak_statuses):
    """Aggregate iteration results into final verdict."""
    status_counts = {}
    for ir in iteration_history:
        s = ir["status"] or "UNKNOWN"
        status_counts[s] = status_counts.get(s, 0) + 1

    final_status = decisive_result["status"] if decisive_result else "UNKNOWN"

    verified_vuln_count = sum(1 for ir in iteration_history if ir["status"] in vuln_statuses and ir["source"] == "verified")
    uncertain_vuln_count = sum(1 for ir in iteration_history if ir["status"] in vuln_statuses and ir["source"] == "uncertain")

    if verified_vuln_count >= 1:
        final_status = decisive_result["status"]
    elif any(ir["status"] in weak_statuses for ir in iteration_history):
        for ir in iteration_history:
            if ir["status"] in weak_statuses:
                final_status = ir["status"]
                break
    elif sum(1 for ir in iteration_history if ir["status"] not in vuln_statuses and ir["status"] not in weak_statuses and ir["status"] is not None) > iterations // 2:
        safe = [ir["status"] for ir in iteration_history if ir["status"] not in vuln_statuses and ir["status"] not in weak_statuses and ir["status"] is not None]
        if safe:
            final_status = safe[0]

    return {
        "status": final_status,
        "decisive_iteration": decisive_iteration,
        "iteration_history": iteration_history,
        "status_counts": status_counts,
        "verified_vuln_count": verified_vuln_count,
        "uncertain_vuln_count": uncertain_vuln_count,
        "total_iterations": len(iteration_history),
        "raw_output": decisive_result["raw_output"] if decisive_result else "",
        "cross_check": decisive_result["cross_check"] if decisive_result else {},
        "evidence": decisive_result["evidence"] if decisive_result else {},
        "parsed": decisive_result["parsed"] if decisive_result else {},
    }


def _severity(status, vuln_statuses, weak_statuses):
    """Return numeric severity for comparison. Higher = more severe."""
    if status in vuln_statuses:
        return 3
    if status in weak_statuses:
        return 2
    if status is not None:
        return 1
    return 0
