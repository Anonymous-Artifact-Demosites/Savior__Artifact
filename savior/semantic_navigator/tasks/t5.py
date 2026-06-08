#!/usr/bin/env python3
"""T5 - Unauthorized IdP Association Manipulation entry point."""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from savior.browser_interactor.claude_runner import run_claude
from savior.semantic_navigator.task_orchestrator import construct_prompt
from savior.state_auditor.auditor import capture_evidence, cross_check
from savior.state_auditor.evidence_compiler import (
    compile_t5_report,
    compile_t5_result,
    strip_structured_blocks,
)
from savior.state_auditor.invariants import evaluate_invariants, get_task_config
from savior.state_auditor.verdict_parser import parse_output
from savior.utils.credentials import get_domain_name, get_secure_input


def main():
    if len(sys.argv) < 2:
        print("Usage: python t5.py <URL>", file=sys.stderr)
        print("Example: python t5.py https://example.com", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]

    # Get credentials from user
    print("\nPlease enter Google credentials for T5 test:")
    google_email = input("Google Email: ")
    google_password = get_secure_input("Google Password")

    # Extract domain name from URL
    domain = get_domain_name(url)

    # Create T5 result folders first (we need them for screenshots)
    result_folder = Path("T5")
    t5_safe_folder = result_folder / "T5_SAFE"
    t5_vuln_folder = result_folder / "T5_VULN"
    t5_na_folder = result_folder / "T5_NA"

    for folder in [result_folder, t5_safe_folder, t5_vuln_folder, t5_na_folder]:
        folder.mkdir(parents=True, exist_ok=True)

    # Build PROMPT
    t5_safe_folder_abs = t5_safe_folder.resolve()
    t5_vuln_folder_abs = t5_vuln_folder.resolve()
    t5_na_folder_abs = t5_na_folder.resolve()

    variables = {
        "url": url,
        "google_email": google_email,
        "google_password": google_password,
        "domain": domain,
        "t5_safe_folder_abs": str(t5_safe_folder_abs),
        "t5_vuln_folder_abs": str(t5_vuln_folder_abs),
        "t5_na_folder_abs": str(t5_na_folder_abs),
    }
    prompt = construct_prompt("T5", variables)

    print("=" * 40)
    print("Test - T5")
    print("=" * 40)
    print(f"URL: {url}")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 40)
    print()

    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"[{current_time}] Executing test task...")
    print()

    start_time = datetime.now()

    # Execute Claude Code via Browser Interactor
    try:
        result = run_claude(prompt)
    except FileNotFoundError:
        print("Error: claude command not found in PATH", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error executing claude command: {e}", file=sys.stderr)
        sys.exit(1)

    output = result["output"]
    print(output)

    end_time = datetime.now()
    duration = end_time - start_time

    # --- State Auditor: parse + evaluate ---
    parsed = parse_output("T5", output)
    rule_verdict = evaluate_invariants("T5", parsed["observations"])
    final_verdict = cross_check(get_task_config("T5"), rule_verdict, parsed["verdict"])
    evidence = capture_evidence("T5", output, parsed["observations"], final_verdict)

    result_status = None
    if re.search(r"RESULT:\s*T5_SAFE", output):
        result_status = "T5_SAFE"
    elif re.search(r"RESULT:\s*T5_VULN", output):
        result_status = "T5_VULN"
    elif re.search(r"RESULT:\s*T5_N/A", output):
        result_status = "T5_N/A"

    if result_status:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if result_status == "T5_SAFE":
            target_folder = t5_safe_folder
        elif result_status == "T5_VULN":
            target_folder = t5_vuln_folder
        else:
            target_folder = t5_na_folder

        target_file = target_folder / f"{domain}.txt"
        screenshot_file = target_folder / f"{domain}.png"

        # Extract reason
        reason = "No reason provided"
        reason_match = re.search(r"(?i)REASON:\s*(.+?)(?=\n\n|\nOAUTH_INFO|$)", output)
        if reason_match:
            reason = reason_match.group(1).strip()

        # Extract OAuth info
        oauth_info = ""
        oauth_info_match = re.search(r"(?s)OAUTH_INFO_START(.*?)OAUTH_INFO_END", output)
        if oauth_info_match:
            oauth_info_raw = oauth_info_match.group(1).strip()
            if oauth_info_raw:
                oauth_info = "\n\nDetails:\n" + oauth_info_raw

        file_content = compile_t5_result(
            result_status=result_status,
            url=url,
            start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            end_time=timestamp,
            duration_seconds=duration.total_seconds(),
            reason=reason,
            oauth_info=oauth_info,
            cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
            observations=parsed["observations"],
        )

        target_file.write_text(file_content, encoding="utf-8")

        # Generate vulnerability report only for Q8 violations.
        if result_status == "T5_VULN":
            reports_folder = result_folder / "reports"
            reports_folder.mkdir(exist_ok=True)

            vuln_analysis_match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", output, re.DOTALL | re.IGNORECASE)
            vuln_analysis = vuln_analysis_match.group(1).strip() if vuln_analysis_match else "No vulnerability analysis provided"

            risk_level = "High"
            vuln_desc = (
                "An available IdP binding or unbinding operation can proceed without "
                "password entry, MFA, fresh login, or another reauthentication gate."
            )

            clean_output = strip_structured_blocks(output)
            report_content = compile_t5_report(
                url=url,
                domain=domain,
                start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
                end_time=timestamp,
                duration_seconds=duration.total_seconds(),
                result_status=result_status,
                risk_level=risk_level,
                vuln_desc=vuln_desc,
                reason=reason,
                oauth_info=oauth_info,
                google_email=google_email,
                output=clean_output,
                vuln_analysis=vuln_analysis,
                cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
                observations=parsed["observations"],
            )

            report_file = reports_folder / f"{domain}_report.txt"
            report_file.write_text(report_content, encoding="utf-8")
            print(f"Vulnerability report saved to: {report_file}")

        print("\n" + "=" * 40)
        print("Test Summary")
        print("=" * 40)

        print(f"Result: {result_status}")
        print(f"End Time: {timestamp}")
        print(f"Duration: {duration.total_seconds():.2f} seconds")
        print(f"Saved to: {target_file}")

        # Check if screenshot exists
        if screenshot_file.exists():
            print(f"Screenshot: {screenshot_file}")
        else:
            print("Screenshot: Not found (may not have been saved)")

        print("=" * 40)

        sys.exit(0)

    else:
        print("\n" + "=" * 40)
        print("ERROR: Could not parse result")
        print("=" * 40)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_file = t5_safe_folder / f"{domain}.txt"
        log_entry = f"[{timestamp}] ERROR: {url} - Could not parse result\nDuration: {duration.total_seconds():.2f} seconds"
        target_file.write_text(log_entry, encoding="utf-8")

        sys.exit(1)


if __name__ == "__main__":
    main()
