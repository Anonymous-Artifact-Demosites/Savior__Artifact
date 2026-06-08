"""Structured and fallback output parsing for SAVIOR tasks."""

from __future__ import annotations

import json
import re

from .invariants import get_task_config


def _extract_block(tag: str, raw_output: str) -> str | None:
    pattern = rf"<{tag}>\s*(.*?)\s*</{tag}>"
    match = re.search(pattern, raw_output, re.DOTALL | re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def _parse_verdict_block(verdict_text: str | None, task_id: str = "") -> dict | None:
    if not verdict_text:
        return None

    confidence_match = re.search(r"^\s*CONFIDENCE:\s*(.+?)\s*$", verdict_text, re.MULTILINE)
    reasoning_match = re.search(r"^\s*REASONING:\s*(.+?)\s*$", verdict_text, re.MULTILINE)

    # T3_T4 special: extract both STATUS_T3 and STATUS_T4
    if task_id.upper() == "T3_T4":
        t3_match = re.search(r"^\s*STATUS_T3:\s*(.+?)\s*$", verdict_text, re.MULTILINE)
        t4_match = re.search(r"^\s*STATUS_T4:\s*(.+?)\s*$", verdict_text, re.MULTILINE)
        if t3_match or t4_match:
            return {
                "status": t3_match.group(1).strip() if t3_match else None,
                "status_t3": t3_match.group(1).strip() if t3_match else None,
                "status_t4": t4_match.group(1).strip() if t4_match else None,
                "confidence": confidence_match.group(1).strip() if confidence_match else None,
                "reasoning": reasoning_match.group(1).strip() if reasoning_match else None,
            }

    # Standard: try STATUS: first, then RESULT: (T2/T5 use RESULT)
    status_match = re.search(r"^\s*(?:STATUS|RESULT):\s*(.+?)\s*$", verdict_text, re.MULTILINE)
    if not status_match:
        # Fallback: try STATUS_T3 (in case T3_T4 not detected via task_id)
        status_match = re.search(r"^\s*STATUS_T3:\s*(.+?)\s*$", verdict_text, re.MULTILINE)
    if not status_match:
        return None

    return {
        "status": status_match.group(1).strip(),
        "confidence": confidence_match.group(1).strip() if confidence_match else None,
        "reasoning": reasoning_match.group(1).strip() if reasoning_match else None,
    }


def _extract_fallback_status(task_id: str, raw_output: str) -> str | None:
    """Extract STATUS/RESULT from raw output using task-specific regex.

    Each task has its own output format. This dispatch table handles
    task-specific status markers when XML tags are absent.
    """
    normalized = task_id.upper()

    # T1_STEP1: STATUS with optional markdown asterisks, case-insensitive
    if normalized == "T1_STEP1":
        m = re.search(r"\*{0,2}STATUS:\*{0,2}\s*(SUCCESS|DOUBT|FAIL)", raw_output, re.IGNORECASE)
        return m.group(1).upper() if m else None

    # T1_STEP2: STATUS with optional asterisks
    if normalized == "T1_STEP2":
        m = re.search(r"\*{0,2}STATUS:\*{0,2}\s*(SUCCESS|FAIL)", raw_output, re.IGNORECASE)
        return m.group(1).upper() if m else None

    # T2: uses RESULT: not STATUS:
    if normalized == "T2":
        m = re.search(r"RESULT:\s*(T2_VULN|T2_SAFE|T2_N/A)", raw_output)
        return m.group(1) if m else None

    # T3_T4: strip all asterisks, match STATUS_T3/T4, longer match first
    if normalized == "T3_T4":
        cleaned = re.sub(r"\*", "", raw_output)
        t3 = None
        if re.search(r"STATUS_T3[:\s]+T3_SAFE", cleaned):
            t3 = "T3_SAFE"
        elif re.search(r"STATUS_T3[:\s]+T3_VULN\b", cleaned):
            t3 = "T3_VULN"
        # Return T3 status as primary (T4 extracted separately by entry point)
        return t3

    # T5: uses RESULT:
    if normalized == "T5":
        if re.search(r"RESULT:\s*T5_SAFE", raw_output):
            return "T5_SAFE"
        elif re.search(r"RESULT:\s*T5_VULN", raw_output):
            return "T5_VULN"
        elif re.search(r"RESULT:\s*T5_N/A", raw_output):
            return "T5_N/A"
        return None

    # T6, T7, and others: use config-generated pattern
    task_config = get_task_config(task_id)
    pattern = task_config.get("llm_status_pattern")
    if not pattern:
        return None
    match = re.search(pattern, raw_output)
    if not match:
        return None
    return match.group(1).strip()


def _extract_fallback_extra(task_id: str, raw_output: str) -> dict:
    """Extract task-specific extra fields from raw output."""
    normalized = task_id.upper()
    extra = {}

    if normalized == "T1_STEP2":
        # OAUTH_IDPS
        m = re.search(r"\*{0,2}OAUTH_IDPS:\*{0,2}\s*(.+?)(?:\r?\n|$)", raw_output, re.IGNORECASE)
        if m:
            extra["idps"] = re.sub(r"^\*+|\*+$", "", m.group(1).strip())
        # ACCOUNT_INFO
        m = re.search(r"(?s)\*{0,2}ACCOUNT_INFO_START\*{0,2}(.*?)\*{0,2}ACCOUNT_INFO_END\*{0,2}", raw_output, re.IGNORECASE)
        if m:
            extra["account_info"] = m.group(1).strip()
        # REASON
        m = re.search(r"\*{0,2}REASON:\*{0,2}\s*(.+?)(?:\r?\n|$)", raw_output, re.IGNORECASE)
        if m:
            extra["fail_reason"] = re.sub(r"^\*+|\*+$", "", m.group(1).strip())

    elif normalized == "T2":
        for phase in ["PHASE1", "PHASE2", "PHASE3"]:
            m = re.search(rf"{phase}:\s*(.+)", raw_output)
            if m:
                extra[phase.lower()] = m.group(1).strip()

    elif normalized == "T3_T4":
        # Extract T4 status (T3 is in fallback_status)
        cleaned = re.sub(r"\*", "", raw_output)
        if re.search(r"STATUS_T4[:\s]+T4_SAFE", cleaned):
            extra["status_t4"] = "T4_SAFE"
        elif re.search(r"STATUS_T4[:\s]+T4_VULN\b", cleaned):
            extra["status_t4"] = "T4_VULN"

    return extra


def parse_output(task_id: str, raw_output: str) -> dict:
    """Parse Claude output into structured observations, verdict, and evidence blocks.

    For T3_T4 (dual-verdict task), the returned dict includes:
    - llm_status: explicitly None - prevents callers from accidentally
      using a partial (T3-only) value
    - llm_status_t3, llm_status_t4: the two individual statuses
    - is_dual_verdict: True - callers MUST check this flag and use
      llm_status_t3/t4 instead of llm_status when True
    """
    observations = None
    observations_error = None
    observations_valid = False

    observations_text = _extract_block("observations", raw_output)
    if observations_text is not None:
        try:
            observations = json.loads(observations_text)
            observations_valid = True
        except json.JSONDecodeError as exc:
            observations_error = str(exc)

    verdict_text = _extract_block("verdict", raw_output)
    verdict = _parse_verdict_block(verdict_text, task_id=task_id)

    fallback_status = _extract_fallback_status(task_id, raw_output)
    if verdict is None and fallback_status is not None:
        verdict = {
            "status": fallback_status,
            "confidence": None,
            "reasoning": None,
        }

    # For T3_T4, expose both sub-statuses at the top level
    llm_status = verdict["status"] if verdict else fallback_status
    llm_status_t3 = verdict.get("status_t3") if verdict else None
    llm_status_t4 = verdict.get("status_t4") if verdict else None

    fallback_extra = _extract_fallback_extra(task_id, raw_output)

    # Symmetric fallback: T3 from fallback_status, T4 from fallback_extra
    if llm_status_t3 is None and fallback_status is not None and task_id.upper() == "T3_T4":
        llm_status_t3 = fallback_status
    if llm_status_t4 is None and "status_t4" in fallback_extra:
        llm_status_t4 = fallback_extra["status_t4"]

    # Flag for callers: if True, use llm_status_t3/t4 instead of llm_status
    is_dual_verdict = llm_status_t3 is not None or llm_status_t4 is not None

    # For dual-verdict tasks, llm_status is explicitly None to prevent
    # callers from accidentally using a partial (T3-only) value.
    if is_dual_verdict:
        llm_status = None

    return {
        "observations": observations,
        "observations_text": observations_text,
        "observations_valid": observations_valid,
        "observations_error": observations_error,
        "verdict": verdict,
        "verdict_text": verdict_text,
        "evidence_text": _extract_block("evidence", raw_output),
        "fallback_status": fallback_status,
        "legacy_status": fallback_status,
        "fallback_extra": fallback_extra,
        "llm_status": llm_status,
        "llm_status_t3": llm_status_t3,
        "llm_status_t4": llm_status_t4,
        "is_dual_verdict": is_dual_verdict,
        "raw_output": raw_output,
    }
