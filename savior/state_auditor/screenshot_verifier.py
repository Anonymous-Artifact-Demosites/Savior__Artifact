"""Deterministic screenshot verification for the State Auditor.

Provides independent ground-truth signals by analyzing screenshots saved
during LLM-driven browser execution. Uses OCR for text extraction - no LLM
calls required.

This module is best-effort: if screenshots or dependencies are unavailable,
verification is skipped gracefully and the existing dual-path logic is
unaffected.
"""

from __future__ import annotations

from pathlib import Path


def _ocr_extract(image_path):
    """Extract text from image using OCR. Returns empty string if unavailable."""
    try:
        import pytesseract
        from PIL import Image

        img = Image.open(image_path)
        return pytesseract.image_to_string(img)
    except ImportError:
        return ""
    except Exception:
        return ""


def _get_nested(d, dotted_path):
    """Walk a dotted path into a nested dict."""
    current = d
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _verify_t1_step1(observations, screenshot_dir):
    """Check registration screenshots for email verification requirement.

    Uses phrases specific to email verification flows. Generic verification
    terms are excluded because they appear in CAPTCHAs, age gates, cookie
    banners, and other unrelated contexts.
    """
    target_files = []
    reported_screenshots = (observations or {}).get("screenshots", [])
    for fname in reported_screenshots:
        candidate = screenshot_dir / fname
        if candidate.exists():
            target_files.append(candidate)

    if not target_files:
        target_files = sorted(screenshot_dir.glob("*.png"))

    if not target_files:
        return []

    all_text = ""
    for screenshot in target_files:
        all_text += _ocr_extract(screenshot) + "\n"

    if not all_text.strip():
        return []

    email_verification_phrases = [
        'verify your email',
        'verify your email address',
        "verification email sent",
        "verification email has been sent",
        "check your inbox",
        "check your email",
        "confirm your email",
        "confirm your email address",
        "confirmation email sent",
        "we sent you a verification",
        "we sent a verification",
        "email verification required",
        "please verify your email",
        "please confirm your email",
        "a verification link has been sent",
        "click the link in your email",
        "click the verification link",
    ]
    text_lower = all_text.lower()
    found = any(phrase in text_lower for phrase in email_verification_phrases)
    matched_phrases = [phrase for phrase in email_verification_phrases if phrase in text_lower]

    obs_value = _get_nested(observations, "task_specific.verification_text_found")

    return [
        {
            "field": "task_specific.verification_text_found",
            "observation_value": obs_value,
            "screenshot_value": found,
            "match": obs_value == found,
            "method": "ocr",
            "detail": (
                f"Matched email verification phrases: {matched_phrases}"
                if matched_phrases
                else f"No email verification phrases found across {len(target_files)} screenshots"
            ),
        }
    ]


def _verify_t6(observations, screenshot_dir):
    """Verify T6 by OCR-extracting identifiers from Step 5 and Step 7 screenshots.

    Uses OCR text matching instead of visual similarity, which is fragile to
    scroll position, viewport state, and page load timing.
    """
    all_pngs = sorted(screenshot_dir.glob("*.png"))
    if len(all_pngs) < 2:
        return []

    text_step5 = _ocr_extract(all_pngs[-2])
    text_step7 = _ocr_extract(all_pngs[-1])

    if not text_step5 and not text_step7:
        return []

    checks = []

    step5_ids = _get_nested(observations, "task_specific.oauth_b_identifiers") or {}
    step5_found = 0
    step5_total = 0
    for value in step5_ids.values():
        if value is not None and str(value).strip():
            step5_total += 1
            if str(value).lower() in text_step5.lower():
                step5_found += 1

    if step5_total > 0:
        checks.append(
            {
                "field": "task_specific.oauth_b_identifiers",
                "observation_value": step5_ids,
                "screenshot_value": f"{step5_found}/{step5_total} identifiers found in screenshot",
                "match": step5_found > 0,
                "method": "ocr",
                "detail": f"OCR text (step5, first 300 chars): {text_step5[:300]}",
            }
        )

    step7_ids = _get_nested(observations, "task_specific.oauth_a_identifiers") or {}
    step7_found = 0
    step7_total = 0
    for value in step7_ids.values():
        if value is not None and str(value).strip():
            step7_total += 1
            if str(value).lower() in text_step7.lower():
                step7_found += 1

    if step7_total > 0:
        checks.append(
            {
                "field": "task_specific.oauth_a_identifiers",
                "observation_value": step7_ids,
                "screenshot_value": f"{step7_found}/{step7_total} identifiers found in screenshot",
                "match": step7_found > 0,
                "method": "ocr",
                "detail": f"OCR text (step7, first 300 chars): {text_step7[:300]}",
            }
        )

    obs_identical = _get_nested(observations, "task_specific.is_identifiers_identical")
    if step5_ids and step7_ids:
        shared_values = set()
        for key in set(step5_ids.keys()) & set(step7_ids.keys()):
            v5 = str(step5_ids.get(key, "")).strip().lower()
            v7 = str(step7_ids.get(key, "")).strip().lower()
            if v5 and v7 and v5 == v7:
                if v5 in text_step5.lower() and v5 in text_step7.lower():
                    shared_values.add(v5)

        screenshot_identical = len(shared_values) > 0
        checks.append(
            {
                "field": "task_specific.is_identifiers_identical",
                "observation_value": obs_identical,
                "screenshot_value": screenshot_identical,
                "match": obs_identical == screenshot_identical,
                "method": "ocr",
                "detail": (
                    f"Shared identifiers confirmed in both screenshots: {shared_values}"
                    if shared_values
                    else "No shared identifiers found in both screenshots via OCR"
                ),
            }
        )

    return checks


_TASK_VERIFIERS = {
    "T1_STEP1": _verify_t1_step1,
    "T6": _verify_t6,
}


def verify_observations(task_id, observations, screenshot_dir):
    """Verify LLM-reported observations against screenshot evidence."""
    if observations is None:
        return {"available": False, "checks": [], "agreement_rate": None}

    screenshot_dir = Path(screenshot_dir)
    if not screenshot_dir.exists():
        return {"available": False, "checks": [], "agreement_rate": None}

    verifier = _TASK_VERIFIERS.get(task_id.upper())
    if verifier is None:
        return {"available": False, "checks": [], "agreement_rate": None}

    checks = verifier(observations, screenshot_dir)
    if not checks:
        return {"available": False, "checks": [], "agreement_rate": None}

    matches = sum(1 for check in checks if check["match"])
    return {
        "available": True,
        "checks": checks,
        "agreement_rate": matches / len(checks) if checks else None,
    }
