"""Cross-check helpers for the SAVIOR State Auditor layer."""

from __future__ import annotations

import re


_VULN_ANALYSIS_PATTERN = re.compile(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", re.DOTALL | re.IGNORECASE)


def _na_status(task_config: dict) -> str | None:
    if task_config.get("na_status"):
        return task_config["na_status"]
    for status in task_config.get("statuses", []):
        if status.endswith("_N/A") or status == "N/A":
            return status
    return None


def cross_check(task_config: dict, path_a_result: dict | None, path_b_result: dict | None) -> dict:
    """Cross-check the rule-based and LLM verdict paths."""
    rule_status = path_a_result.get("status") if path_a_result else None
    llm_status = path_b_result.get("status") if path_b_result else None
    na_status = _na_status(task_config)

    if llm_status and na_status and llm_status == na_status:
        return {
            "status": llm_status,
            "confidence": path_b_result.get("confidence"),
            "source": "llm_only_na",
            "requires_manual_review": False,
            "note": "Task not applicable per LLM; rule-based check skipped",
            "rule_status": rule_status,
            "llm_status": llm_status,
        }

    if path_a_result is None and path_b_result is None:
        return {
            "status": None,
            "confidence": None,
            "source": "unavailable",
            "requires_manual_review": True,
            "note": "Neither rule-based nor LLM verdict available",
            "rule_status": None,
            "llm_status": None,
        }

    if path_a_result is not None and path_b_result is None:
        return {
            "status": rule_status,
            "confidence": "medium",
            "source": "rule_only",
            "requires_manual_review": True,
            "note": "LLM verdict block missing; using rule-based result",
            "rule_status": rule_status,
            "llm_status": None,
        }

    if path_a_result is None and path_b_result is not None:
        return {
            "status": llm_status,
            "confidence": path_b_result.get("confidence"),
            "source": "llm_only",
            "requires_manual_review": False,
            "note": "Observations JSON unavailable; degraded to LLM-only",
            "rule_status": None,
            "llm_status": llm_status,
        }

    if rule_status == llm_status:
        return {
            "status": rule_status,
            "confidence": "high",
            "source": "verified",
            "requires_manual_review": False,
            "note": "Rule-based and LLM verdicts agree",
            "rule_status": rule_status,
            "llm_status": llm_status,
        }

    return {
        "status": llm_status,
        "confidence": "low",
        "source": "uncertain",
        "requires_manual_review": True,
        "note": f"CONFLICT: rule={rule_status}, llm={llm_status}; using LLM",
        "rule_status": rule_status,
        "llm_status": llm_status,
    }


def cross_check_with_evidence(task_config, path_a_result, path_b_result, screenshot_verification):
    """Augment dual-path cross-check with advisory screenshot evidence.

    Screenshot verification supplements the primary dual-path verdict. It does
    not modify status, source, confidence, or requires_manual_review from
    cross_check().
    """
    base_result = cross_check(task_config, path_a_result, path_b_result)

    if not screenshot_verification or not screenshot_verification.get("available"):
        base_result["screenshot_evidence"] = {
            "available": False,
            "agreement_rate": None,
            "checks": [],
            "interpretation": "Screenshot verification unavailable (no screenshots or OCR dependencies not installed)",
        }
        return base_result

    agreement = screenshot_verification["agreement_rate"]
    checks = screenshot_verification["checks"]

    if agreement is not None and agreement >= 0.8:
        interpretation = f"Screenshot evidence corroborates the verdict (agreement: {agreement:.0%})"
    elif agreement is not None and agreement < 0.5:
        interpretation = f"Screenshot evidence shows discrepancy (agreement: {agreement:.0%}); recommend manual review of screenshots"
    else:
        interpretation = f"Screenshot evidence partially corroborating (agreement: {agreement:.0%})"

    base_result["screenshot_evidence"] = {
        "available": True,
        "agreement_rate": agreement,
        "checks": checks,
        "interpretation": interpretation,
    }

    return base_result


def extract_vulnerable_path(task_id: str, evidence_text: str | None, observations: dict | None) -> list[dict]:
    """Extract numbered attack-path steps from a VULN_ANALYSIS block."""
    if task_id.upper() != "T6" or not evidence_text:
        return []

    attack_path_match = re.search(
        r"Attack Path:\s*(.*?)(?:Missing Security Check:|$)",
        evidence_text,
        re.DOTALL | re.IGNORECASE,
    )
    if not attack_path_match:
        return []

    completed = set((observations or {}).get("steps_completed", []))
    steps = []
    for match in re.finditer(r"^\s*(\d+)\.\s*(.+)$", attack_path_match.group(1), re.MULTILINE):
        step_number = int(match.group(1))
        steps.append(
            {
                "step_number": step_number,
                "description": match.group(2).strip(),
                "observation_backing": step_number in completed,
            }
        )
    return steps


def capture_evidence(task_id: str, raw_output: str, observations: dict | None,
                     verdict: dict | None, *, verdict_t4: dict | None = None) -> dict:
    """Capture report-ready evidence fields from a task run.

    For T3_T4, pass both verdicts: verdict=t3_verdict, verdict_t4=t4_verdict.
    """
    vuln_analysis = None
    vuln_analysis_t3 = None
    vuln_analysis_t4 = None

    # T3_T4 has separate VULN_ANALYSIS blocks
    if task_id.upper() == "T3_T4":
        t3_match = re.search(r"T3_VULN_ANALYSIS_START(.*?)T3_VULN_ANALYSIS_END", raw_output, re.DOTALL | re.IGNORECASE)
        t4_match = re.search(r"T4_VULN_ANALYSIS_START(.*?)T4_VULN_ANALYSIS_END", raw_output, re.DOTALL | re.IGNORECASE)
        if t3_match:
            vuln_analysis_t3 = t3_match.group(1).strip()
        if t4_match:
            vuln_analysis_t4 = t4_match.group(1).strip()
        vuln_analysis = vuln_analysis_t3  # primary for backward compat
    else:
        match = _VULN_ANALYSIS_PATTERN.search(raw_output)
        if match:
            vuln_analysis = match.group(1).strip()

    def _meta(v):
        if v is None:
            return {"source": None, "confidence": None, "note": None, "rule_status": None, "llm_status": None}
        return {
            "source": v.get("source"),
            "confidence": v.get("confidence"),
            "note": v.get("note"),
            "rule_status": v.get("rule_status"),
            "llm_status": v.get("llm_status"),
        }

    result = {
        "vuln_analysis": vuln_analysis,
        "vuln_analysis_t3": vuln_analysis_t3,
        "vuln_analysis_t4": vuln_analysis_t4,
        "vulnerable_path": extract_vulnerable_path(task_id, vuln_analysis, observations),
        "screenshots": list((observations or {}).get("screenshots", [])),
        "step_log": list((observations or {}).get("step_log", [])),
        "cross_check_meta": _meta(verdict),
    }

    # T3_T4: also carry T4's cross-check metadata
    if verdict_t4 is not None:
        result["cross_check_meta_t4"] = _meta(verdict_t4)

    return result
