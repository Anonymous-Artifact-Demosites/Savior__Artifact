"""Result/report compilation helpers for SAVIOR tasks."""

from __future__ import annotations

import re
from pathlib import Path

from savior.utils.file_utils import ensure_directory


def _cross_check_section(cross_check: dict | None) -> str:
    if not cross_check:
        return ""
    return (
        "========================================\n"
        "Cross-check Verification\n"
        "========================================\n"
        f"Verdict Source: {cross_check.get('source')}\n"
        f"Confidence: {cross_check.get('confidence')}\n"
        f"Rule-based: {cross_check.get('rule_status')}\n"
        f"LLM: {cross_check.get('llm_status')}\n"
        f"Note: {cross_check.get('note')}\n\n"
        f"{_screenshot_evidence_section(cross_check)}"
    )


def _screenshot_evidence_section(cross_check: dict | None, *, report_style: bool = False) -> str:
    if not cross_check or "screenshot_evidence" not in cross_check:
        return ""

    evidence = cross_check.get("screenshot_evidence") or {}
    checks = evidence.get("checks") or []
    agreement = evidence.get("agreement_rate")
    agreement_text = "N/A" if agreement is None else f"{agreement:.0%}"

    if report_style:
        lines = [
            "",
            "================================================================================",
            "[Screenshot Evidence]",
            "================================================================================",
            f"Available       : {evidence.get('available')}",
            f"Agreement Rate  : {agreement_text}",
            f"Interpretation  : {evidence.get('interpretation')}",
        ]
        for index, check in enumerate(checks, 1):
            lines.extend(
                [
                    f"Check {index} Field : {check.get('field')}",
                    f"Check {index} Method: {check.get('method')}",
                    f"Check {index} Match : {check.get('match')}",
                    f"Check {index} Detail: {check.get('detail')}",
                ]
            )
        return "\n".join(lines) + "\n"

    lines = [
        "========================================",
        "Screenshot Evidence",
        "========================================",
        f"Available: {evidence.get('available')}",
        f"Agreement Rate: {agreement_text}",
        f"Interpretation: {evidence.get('interpretation')}",
    ]
    for index, check in enumerate(checks, 1):
        lines.extend(
            [
                f"Check {index} Field: {check.get('field')}",
                f"Check {index} Method: {check.get('method')}",
                f"Check {index} Match: {check.get('match')}",
                f"Check {index} Detail: {check.get('detail')}",
            ]
        )
    return "\n".join(lines) + "\n\n"


def _step_log_section(observations: dict | None, *, report_style: bool = False) -> str:
    if not observations:
        return ""

    step_log = observations.get("step_log") or []
    if not step_log:
        return ""

    if report_style:
        lines = [
            "\n================================================================================",
            "[Step Log]",
            "================================================================================",
        ]
    else:
        lines = [
            "========================================",
            "Step Log",
            "========================================",
        ]

    for index, entry in enumerate(step_log, 1):
        if isinstance(entry, dict):
            summary = entry.get("summary") or entry.get("action") or entry.get("description") or str(entry)
            status = entry.get("status")
            screenshot = entry.get("screenshot")
            line = f"{index}. {summary}"
            if status is not None:
                line += f" [{status}]"
            if screenshot:
                line += f" (screenshot: {screenshot})"
        else:
            line = f"{index}. {entry}"
        lines.append(line)

    return "\n".join(lines) + "\n\n"


def _cross_check_report_block(cross_check: dict | None) -> str:
    if not cross_check:
        return ""
    return (
        "\n================================================================================\n"
        "[Cross-check Verification]\n"
        "================================================================================\n"
        f"Verdict Source  : {cross_check.get('source')}\n"
        f"Confidence      : {cross_check.get('confidence')}\n"
        f"Rule-based      : {cross_check.get('rule_status')}\n"
        f"LLM             : {cross_check.get('llm_status')}\n"
        f"Note            : {cross_check.get('note')}\n"
        f"{_screenshot_evidence_section(cross_check, report_style=True)}"
    )


def strip_structured_blocks(raw_output: str) -> str:
    """Remove <observations>, <verdict>, and <evidence> XML blocks from raw output.

    These blocks are intermediate artefacts consumed by the State Auditor.
    The final user-facing report should show only the LLM's narrative text,
    matching the SAVIOR report format.
    """
    cleaned = re.sub(
        r"<(observations|verdict|evidence)>.*?</\1>",
        "",
        raw_output,
        flags=re.DOTALL,
    )
    # Collapse runs of 3+ blank lines left behind after stripping.
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _strip_vuln_markers(vuln_analysis: str | None) -> str:
    if not vuln_analysis:
        return "No vulnerability analysis provided"
    match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", vuln_analysis, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return vuln_analysis.strip()


def compile_t6_result(
    *,
    url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    email_a: str,
    email_b: str,
    output: str,
    status: str,
    test_date: str,
    duration_str: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T6 result file content."""
    cross_check_section = _cross_check_section(cross_check)
    step_log_section = _step_log_section(observations)
    return (
        "========================================\n"
        "T6 Security Test Result\n"
        "========================================\n"
        f"URL: {url}\n"
        f"Domain: {domain}\n"
        f"Test Date: {test_date}\n"
        f"Start Time: {start_time_str}\n"
        f"End Time: {end_time_str}\n"
        f"Duration: {duration_str}\n\n"
        f"Email A: {email_a}\n"
        f"Email B: {email_b}\n\n"
        "========================================\n"
        "Test Results\n"
        "========================================\n"
        f"Main Status: {status}\n\n"
        f"{cross_check_section}"
        f"{step_log_section}"
        "========================================\n"
        "Raw Output\n"
        "========================================\n"
        f"{output}\n\n"
        "========================================\n"
    )


def compile_t6_report(
    *,
    url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    email_a: str,
    email_b: str,
    output: str,
    status: str,
    duration_str: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T6 vulnerability report content."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered_vuln_analysis = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T6\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time_str} - {end_time_str}\n"
        f"Duration        : {duration_str}\n"
        f"Status          : {status}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T6\n"
        "Name            : The Shadow Binding Attack\n"
        "Risk Level      : High\n\n"
        "Description:\n"
        "After changing the email associated with an OAuth account, a shadow binding is created.\n"
        "Both the original OAuth account (A) and the new OAuth account (B) can access the same\n"
        "website account, allowing an attacker to maintain persistent access even after the\n"
        "victim changes their email.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered_vuln_analysis}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Unbind the original OAuth account when email is changed\n"
        "- Require re-authentication with the new OAuth account after email change\n"
        "- Notify users about OAuth binding status after email change\n"
        "- Implement proper OAuth account to email binding validation\n"
        "- Do not allow multiple OAuth accounts to bind to the same website account\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Email A: {email_a}\n"
        f"Email B: {email_b}\n"
        "Passwords: [REDACTED]\n\n"
        "================================================================================\n"
        "[Raw Test Output]\n"
        "================================================================================\n"
        f"{output}\n\n"
        "================================================================================\n"
    )


def compile_t1s1_result(
    *,
    status: str,
    test_date: str,
    start_time_str: str,
    end_time_str: str,
    duration: str,
    url: str,
    email: str,
    username: str,
    user_info: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T1 step1 result file content."""
    cross_check_section = _cross_check_section(cross_check)
    step_log_section = _step_log_section(observations)
    return (
        f"REGISTRATION {status}\n"
        f"Test Date: {test_date}\n"
        f"Start Time: {start_time_str}\n"
        f"End Time: {end_time_str}\n"
        f"Duration: {duration}\n"
        f"URL: {url}\n"
        f"Email: {email}\n"
        f"Username: {username}\n"
        f"{user_info}\n"
        f"{cross_check_section}"
        f"{step_log_section}"
    )


def compile_t1s1_report(
    *,
    url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    duration: str,
    status: str,
    email: str,
    username: str,
    user_info: str,
    output: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T1 step1 vulnerability report."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered_vuln_analysis = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T1\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time_str} - {end_time_str}\n"
        f"Duration        : {duration}\n"
        f"Status          : {status}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T1\n"
        "Name            : Implicit Pre-hijacking of First-party Accounts\n"
        "Risk Level      : High\n\n"
        "Description:\n"
        "The website allows account registration without requiring email verification,\n"
        "enabling attackers to pre-register accounts using victim's email addresses.\n"
        "When the legitimate email owner later attempts to use OAuth or recover the\n"
        "account, they may access the attacker's pre-configured account.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered_vuln_analysis}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Require email verification before account activation\n"
        "- Do not allow account login until email is verified\n"
        "- Implement email ownership verification during registration\n"
        "- Send notification to email when account is created with that address\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Email: {email}\n"
        f"Username: {username}\n\n"
        "================================================================================\n"
        "[User Information Collected]\n"
        "================================================================================\n"
        f"{user_info}\n\n"
        "================================================================================\n"
        "[Raw Test Output]\n"
        "================================================================================\n"
        f"{output}\n\n"
        "================================================================================\n"
    )


def compile_t1s2_result(
    *,
    timestamp: str,
    url: str,
    email: str,
    status: str,
    idps: str = "",
    fail_reason: str = "",
    account_info_lines: list | None = None,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T1 step2 result file content."""
    content = f"OAuth Login Result\nTimestamp: {timestamp}\nURL: {url}\nEmail: {email}\n\n"

    if idps:
        content += f"Supported OAuth IdPs: {idps}\n\n"

    if fail_reason:
        content += f"Fail Reason: {fail_reason}\n\n"

    if account_info_lines:
        content += "Account Information:\n" + "\n".join(account_info_lines) + "\n"

    if status == "UNKNOWN":
        content = "WARNING: Could not parse STATUS from Claude output\n\n" + content

    cross_check_section = _cross_check_section(cross_check)
    if cross_check_section:
        content += "\n" + cross_check_section

    step_log_section = _step_log_section(observations)
    if step_log_section:
        content += "\n" + step_log_section

    return content


def compile_t7_result(
    *,
    target_url: str,
    domain: str,
    test_date: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    email: str,
    status: str,
    output: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T7 result file."""
    cross_check_section = _cross_check_section(cross_check)
    step_log_section = _step_log_section(observations)
    return (
        "========================================\n"
        "T7 - First-party Registration DoS\n"
        "========================================\n"
        f"URL: {target_url}\n"
        f"Domain: {domain}\n"
        f"Test Date: {test_date}\n"
        f"Start Time: {start_time_str}\n"
        f"End Time: {end_time_str}\n"
        f"Duration: {duration_str}\n\n"
        f"Test Email: {email}\n"
        "Test Password 1: [REDACTED]\n"
        "Test Password 2: [REDACTED]\n\n"
        "========================================\n"
        "Test Results\n"
        "========================================\n"
        f"Status: {status}\n\n"
        f"{cross_check_section}"
        f"{step_log_section}"
        "========================================\n"
        "Raw Output\n"
        "========================================\n"
        f"{output}\n\n"
        "========================================\n"
    )


def compile_t7_report(
    *,
    target_url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    status: str,
    email: str,
    output: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T7 vulnerability report."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T7\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {target_url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time_str} - {end_time_str}\n"
        f"Duration        : {duration_str}\n"
        f"Status          : {status}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T7\n"
        "Name            : First-party Registration DoS\n"
        "Risk Level      : Medium\n\n"
        "Description:\n"
        "The system does not properly check for duplicate email registrations. An attacker\n"
        "can pre-register with a victim's email address (without verification), and when\n"
        "the victim later tries to register, they will be blocked or encounter errors,\n"
        "effectively denying them service.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Check for existing registrations before allowing new registration\n"
        "- Display clear \"email already registered\" error message\n"
        "- Implement email verification with expiration for pending registrations\n"
        "- Clean up unverified registrations after a timeout period\n"
        "- Allow re-registration if previous registration was not verified\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Test Email: {email}\n"
        "Passwords: [REDACTED]\n\n"
        "================================================================================\n"
        "[Raw Test Output]\n"
        "================================================================================\n"
        f"{output}\n\n"
        "================================================================================\n"
    )


def compile_t5_result(
    *,
    result_status: str,
    url: str,
    start_time: str,
    end_time: str,
    duration_seconds: float,
    reason: str,
    oauth_info: str = "",
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T5 result file."""
    cross_check_section = _cross_check_section(cross_check)
    content = (
        f"Test Result: {result_status}\n"
        f"URL: {url}\n"
        f"Start Time: {start_time}\n"
        f"End Time: {end_time}\n"
        f"Duration: {duration_seconds:.2f} seconds\n"
        f"Reason: {reason}"
        f"{oauth_info}\n"
    )
    if cross_check_section:
        content += "\n" + cross_check_section
    step_log_section = _step_log_section(observations)
    if step_log_section:
        content += "\n" + step_log_section
    return content


def compile_t5_report(
    *,
    url: str,
    domain: str,
    start_time: str,
    end_time: str,
    duration_seconds: float,
    result_status: str,
    risk_level: str,
    vuln_desc: str,
    reason: str,
    oauth_info: str,
    google_email: str,
    output: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T5 vulnerability report."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T5\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time} - {end_time}\n"
        f"Duration        : {duration_seconds:.2f} seconds\n"
        f"Status          : {result_status}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T5\n"
        "Name            : Unauthorized IdP Association Manipulation\n"
        f"Risk Level      : {risk_level}\n\n"
        "Description:\n"
        f"{vuln_desc}\n"
        "Sensitive IdP association changes are accepted without verifying that the\n"
        "currently active user is still authorized to perform the operation.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[Classification Reason]\n"
        "================================================================================\n"
        f"{reason}\n"
        f"{oauth_info}\n\n"
        "================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Require password entry, MFA, or fresh login before binding a new IdP\n"
        "- Require password entry, MFA, or fresh login before unbinding an existing IdP\n"
        "- Treat IdP association changes as sensitive account-management operations\n"
        "- Send notifications when IdP associations are added or removed\n"
        "- Record IdP association changes in account security logs\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Google Email: {google_email}\n"
        "Google Password: [REDACTED]\n\n"
        "================================================================================\n"
        "[Raw Test Output]\n"
        "================================================================================\n"
        f"{output}\n\n"
        "================================================================================\n"
    )


def compile_t3t4_result(
    *,
    target_url: str,
    domain: str,
    test_date: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    email: str,
    password: str,
    new_email: str,
    new_password: str,
    status_t3: str,
    status_t4: str,
    output: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T3_T4 result file."""
    cross_check_section = _cross_check_section(cross_check)
    step_log_section = _step_log_section(observations)
    return (
        "========================================\n"
        "T3 & T4 Email Rebinding Security Test Result\n"
        "========================================\n"
        f"URL: {target_url}\n"
        f"Domain: {domain}\n"
        f"Test Date: {test_date}\n"
        f"Start Time: {start_time_str}\n"
        f"End Time: {end_time_str}\n"
        f"Duration: {duration_str}\n\n"
        f"Login Email: {email}\n"
        "Login Password: [REDACTED]\n"
        f"New Email: {new_email}\n"
        "New Email Password: [REDACTED]\n\n"
        "========================================\n"
        "Test Results\n"
        "========================================\n"
        f"T3 Status (Old Email Verification): {status_t3}\n"
        f"T4 Status (Session Termination): {status_t4}\n\n"
        f"{cross_check_section}"
        f"{step_log_section}"
        "========================================\n"
        "Raw Output\n"
        "========================================\n"
        f"{output}\n\n"
        "========================================\n"
    )


def compile_t3_report(
    *,
    target_url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    status_t3: str,
    email: str,
    new_email: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T3 vulnerability report."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T3\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {target_url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time_str} - {end_time_str}\n"
        f"Duration        : {duration_str}\n"
        f"Status          : {status_t3}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T3\n"
        "Name            : Account Takeover via Identifier Update\n"
        "Risk Level      : High\n\n"
        "Description:\n"
        "The email change process does not require verification from the old email address.\n"
        "An attacker who gains temporary access to an account can change the email to their\n"
        "own address without the original owner being notified or able to prevent it.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Require verification from the OLD email before allowing email change\n"
        "- Send notification to old email about the change request\n"
        "- Implement a waiting period before email change takes effect\n"
        "- Allow old email to cancel the change within a time window\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Original Email: {email}\n"
        f"New Email: {new_email}\n"
        "Passwords: [REDACTED]\n\n"
        "================================================================================\n"
    )


def compile_t4_report(
    *,
    target_url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    status_t4: str,
    email: str,
    new_email: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T4 vulnerability report."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T4\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {target_url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time_str} - {end_time_str}\n"
        f"Duration        : {duration_str}\n"
        f"Status          : {status_t4}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T4\n"
        "Name            : Session Persistence after Credential Change\n"
        "Risk Level      : Medium\n\n"
        "Description:\n"
        "After changing account credentials (email), the existing session remains active.\n"
        "This allows an attacker to maintain access even after the legitimate user\n"
        "attempts to secure the account by changing credentials.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Terminate all active sessions after credential changes\n"
        "- Require re-authentication after email/password change\n"
        "- Notify user of active sessions and provide option to terminate all\n"
        "- Implement session binding to credentials\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Original Email: {email}\n"
        f"New Email: {new_email}\n"
        "Passwords: [REDACTED]\n\n"
        "================================================================================\n"
    )


def compile_t2_result(
    *,
    target_url: str,
    domain: str,
    test_date: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    email: str,
    password_registration: str,
    password_gmail: str,
    result_status: str,
    phase1_status: str,
    phase2_status: str,
    phase3_status: str,
    output: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T2 result file content."""
    cross_check_section = _cross_check_section(cross_check)
    step_log_section = _step_log_section(observations)
    return (
        "========================================\n"
        "T2 Registration Security Test Result\n"
        "========================================\n"
        f"URL: {target_url}\n"
        f"Domain: {domain}\n"
        f"Test Date: {test_date}\n"
        f"Start Time: {start_time_str}\n"
        f"End Time: {end_time_str}\n"
        f"Duration: {duration_str}\n\n"
        f"Test Email: {email}\n"
        "Registration Password: [REDACTED]\n"
        "Gmail Password: [REDACTED]\n\n"
        "========================================\n"
        "Test Results\n"
        "========================================\n"
        f"Final Result: {result_status}\n\n"
        f"Phase 1 (Normal Registration): {phase1_status}\n"
        f"Phase 2 (OAuth Registration): {phase2_status}\n"
        f"Phase 3 (Email Login): {phase3_status}\n\n"
        f"{cross_check_section}"
        f"{step_log_section}"
        "========================================\n"
        "Raw Output\n"
        "========================================\n"
        f"{output}\n\n"
        "========================================\n"
    )


def compile_t2_report(
    *,
    target_url: str,
    domain: str,
    start_time_str: str,
    end_time_str: str,
    duration_str: str,
    result_status: str,
    email: str,
    phase1_status: str,
    phase2_status: str,
    phase3_status: str,
    output: str,
    vuln_analysis: str,
    cross_check: dict | None = None,
    observations: dict | None = None,
) -> str:
    """Compile the T2 vulnerability report."""
    cross_check_block = _cross_check_report_block(cross_check)
    step_log_block = _step_log_section(observations, report_style=True)

    rendered_vuln_analysis = _strip_vuln_markers(vuln_analysis)
    return (
        "================================================================================\n"
        "                    VULNERABILITY ANALYSIS REPORT - T2\n"
        "================================================================================\n\n"
        "[Basic Information]\n"
        f"Target URL      : {target_url}\n"
        f"Domain          : {domain}\n"
        f"Test Time       : {start_time_str} - {end_time_str}\n"
        f"Duration        : {duration_str}\n"
        f"Status          : {result_status}\n\n"
        "================================================================================\n"
        "[Vulnerability Overview]\n"
        "================================================================================\n"
        "ID              : T2\n"
        "Name            : Unaligned First-party Verification Hijacking\n"
        "Risk Level      : High\n\n"
        "Description:\n"
        "OAuth login can bypass email verification and link to unverified accounts.\n"
        "When a user registers with email (requiring verification) but doesn't verify,\n"
        "an attacker can use OAuth with the same email to activate and take over the account.\n\n"
        "================================================================================\n"
        "[Attack Analysis (Site-Specific)]\n"
        "================================================================================\n"
        f"{rendered_vuln_analysis}\n"
        f"{cross_check_block}"
        f"{step_log_block}"
        "\n================================================================================\n"
        "[Test Phases Summary]\n"
        "================================================================================\n"
        f"Phase 1 (Email Registration): {phase1_status}\n"
        f"Phase 2 (OAuth Registration): {phase2_status}\n"
        f"Phase 3 (Email Login Test): {phase3_status}\n\n"
        "================================================================================\n"
        "[General Remediation]\n"
        "================================================================================\n"
        "- Do not link OAuth accounts to unverified email registrations\n"
        "- Require email verification before allowing any login method\n"
        "- Treat OAuth registration and email registration as separate accounts until verified\n"
        "- Implement proper account merging only after both methods verify email ownership\n\n"
        "================================================================================\n"
        "[Test Credentials (Redacted)]\n"
        "================================================================================\n"
        f"Email: {email}\n"
        "Registration Password: [REDACTED]\n"
        "Gmail Password: [REDACTED]\n\n"
        "================================================================================\n"
        "[Raw Test Output]\n"
        "================================================================================\n"
        f"{output}\n\n"
        "================================================================================\n"
    )


def write_result_file(task_id: str, domain: str, content: str) -> Path:
    """Write a task result file and return the saved path."""
    result_dir = ensure_directory(task_id)
    result_path = result_dir / f"{domain}.txt"
    result_path.write_text(content, encoding="utf-8")
    return result_path


def write_report_file(task_id: str, domain: str, content: str, *, prefix: str = "") -> Path:
    """Write a task report file and return the saved path."""
    report_dir = ensure_directory(Path(task_id) / "reports")
    filename = f"{prefix}{domain}_report.txt"
    report_path = report_dir / filename
    report_path.write_text(content, encoding="utf-8")
    return report_path
