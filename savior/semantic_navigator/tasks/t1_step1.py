#!/usr/bin/env python3
"""T1 Step 1 - Implicit Pre-hijacking (Registration Phase) entry point."""

from __future__ import annotations

import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from savior.browser_interactor.claude_runner import run_claude
from savior.semantic_navigator.task_orchestrator import construct_prompt
from savior.state_auditor.auditor import capture_evidence, cross_check
from savior.state_auditor.evidence_compiler import (
    compile_t1s1_report,
    compile_t1s1_result,
    strip_structured_blocks,
)
from savior.state_auditor.invariants import evaluate_invariants, get_task_config
from savior.state_auditor.verdict_parser import parse_output
from savior.utils.credentials import get_t1_credentials


def main():
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python t1_step1.py <URL>", file=sys.stderr)
        print("Example: python t1_step1.py https://example.com", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]

    # Get credentials from user (registration password for T1_step1)
    creds = get_t1_credentials(url, step=1)
    email = creds["Email"]
    password = creds["Password"]  # Registration password
    username = creds["Username"]

    # Extract domain name from URL - uses raw urlparse (keeps dots), NOT get_domain_name
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or url
        domain = re.sub(r"^www\.", "", domain)  # Remove www. prefix
    except Exception:
        domain = re.sub(r"[^a-zA-Z0-9-.]", "_", url)  # Fallback: sanitize URL

    # Create Screenshot folder structure
    screenshot_folder = Path("T1_step1_Screenshots")
    domain_screenshot_folder = screenshot_folder / domain

    screenshot_folder.mkdir(exist_ok=True)
    domain_screenshot_folder.mkdir(exist_ok=True)

    # Convert to absolute path for Claude Code
    absolute_screenshot_path = domain_screenshot_folder.resolve()
    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    stopwatch_start = time.time()

    # Build prompt via Semantic Navigator
    variables = {
        "url": url,
        "email": email,
        "password": password,
        "username": username,
        "screenshot_path": str(absolute_screenshot_path),
    }
    prompt = construct_prompt("T1_STEP1", variables)

    print("=" * 40)
    print("Test - T1")
    print("=" * 40)
    print(f"Target URL: {url}")
    print(f"Email: {email}")
    print(f"Start Time: {start_time_str}")
    print("=" * 40)
    print()

    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"[{current_time}] Executing test task...")
    print()

    # Execute Claude Code via Browser Interactor
    try:
        result = run_claude(prompt)
    except FileNotFoundError:
        print("Error: claude command not found in PATH", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error executing claude command: {e}", file=sys.stderr)
        sys.exit(1)

    stopwatch_end = time.time()
    end_time = datetime.now()
    end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    duration_seconds = stopwatch_end - stopwatch_start
    duration = time.strftime("%H:%M:%S", time.gmtime(duration_seconds))

    output = result["output"]

    # Display output
    print(output)

    # Create register_result folder structure if not exists
    result_folder = Path("T1_step1_results")
    success_folder = result_folder / "success"
    doubt_folder = result_folder / "doubt"
    fail_folder = result_folder / "fail"

    for folder in [result_folder, success_folder, doubt_folder, fail_folder]:
        folder.mkdir(exist_ok=True)

    # --- State Auditor: parse + evaluate ---
    parsed = parse_output("T1_STEP1", output)
    rule_verdict = evaluate_invariants("T1_STEP1", parsed["observations"])
    final_verdict = cross_check(get_task_config("T1_STEP1"), rule_verdict, parsed["verdict"])
    evidence = capture_evidence("T1_STEP1", output, parsed["observations"], final_verdict)

    # Extract result from the task output.
    status_match = re.search(r"\*{0,2}STATUS:\*{0,2}\s*(SUCCESS|DOUBT|FAIL)", output, re.IGNORECASE)
    if status_match:
        status = status_match.group(1).upper()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check if verification text was properly reported
        verify_match = re.search(r"VERIFICATION TEXT FOUND:\s*(.+)", output, re.IGNORECASE)
        if verify_match:
            verify_text = verify_match.group(1).strip()
            if verify_text.lower() != "none" and not verify_text.lower().startswith("none") and status == "SUCCESS":
                print()
                print("=" * 40)
                print("WARNING: Verification text detected but reported as SUCCESS!")
                print(f"Found text: {verify_text}")
                print("Overriding to DOUBT")
                print("=" * 40)
                status = "DOUBT"

        # Check screenshot count
        screenshot_count = 0
        screenshot_match = re.search(r"SCREENSHOTS_SAVED:\s*(\d+)", output, re.IGNORECASE)
        if screenshot_match:
            screenshot_count = int(screenshot_match.group(1))

        # Verify mandatory screenshots for SUCCESS/DOUBT
        if status in ["SUCCESS", "DOUBT"]:
            mandatory_screenshots = [
                "register_email_verification_status.png",
                "register_user_info.png",
            ]

            missing_screenshots = []
            for screenshot in mandatory_screenshots:
                screenshot_path = domain_screenshot_folder / screenshot
                if not screenshot_path.exists():
                    missing_screenshots.append(screenshot)

            if missing_screenshots:
                print()
                print("=" * 40)
                print("WARNING: Missing mandatory screenshots:")
                for missing in missing_screenshots:
                    print(f"  - {missing}")
                print("=" * 40)

        # Handle SUCCESS or DOUBT status - save detailed user info
        if status in ["SUCCESS", "DOUBT"]:
            target_folder = success_folder if status == "SUCCESS" else doubt_folder
            target_file = target_folder / f"{domain}.txt"

            # Extract user information if available
            user_info_match = re.search(r"USER_INFO_START(.*?)USER_INFO_END", output, re.DOTALL | re.IGNORECASE)
            if user_info_match:
                user_info_raw = user_info_match.group(1).strip()

                # Filter: only remove lines that are COMPLETELY empty or have "(empty)" as value
                user_info_lines = []
                for line in user_info_raw.split("\n"):
                    line = line.strip()
                    if line:
                        field_match = re.match(r"^(.+?):\s*(.+)$", line)
                        if field_match:
                            field_value = field_match.group(2).strip()
                            # Filter out only if value is exactly "(empty)" or empty
                            if field_value and field_value != "(empty)":
                                user_info_lines.append(line)

                if user_info_lines:
                    user_info = "\n".join(user_info_lines)
                else:
                    user_info = "No additional user information available"
            else:
                user_info = "No user information collected"

            file_content = compile_t1s1_result(
                status=status,
                test_date=datetime.now().strftime("%Y-%m-%d"),
                start_time_str=start_time_str,
                end_time_str=end_time_str,
                duration=duration,
                url=url,
                email=email,
                username=username,
                user_info=user_info,
                cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
                observations=parsed["observations"],
            )

            with open(target_file, "w", encoding="utf-8") as f:
                f.write(file_content)

            print(f"\nDetailed info saved to: {target_file}")

            # Generate vulnerability analysis report
            reports_folder = result_folder / "reports"
            reports_folder.mkdir(exist_ok=True)

            # Extract vulnerability analysis
            vuln_analysis_match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", output, re.DOTALL | re.IGNORECASE)
            vuln_analysis = vuln_analysis_match.group(1).strip() if vuln_analysis_match else "No vulnerability analysis provided"

            clean_output = strip_structured_blocks(output)
            report_content = compile_t1s1_report(
                url=url,
                domain=domain,
                start_time_str=start_time_str,
                end_time_str=end_time_str,
                duration=duration,
                status=status,
                email=email,
                username=username,
                user_info=user_info,
                output=clean_output,
                vuln_analysis=vuln_analysis,
                cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
                observations=parsed["observations"],
            )

            report_file = reports_folder / f"{domain}_report.txt"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_content)
            print(f"Vulnerability report saved to: {report_file}")

        # Handle FAIL status
        else:
            target_file = fail_folder / "fail.txt"
            log_entry = f"[{timestamp}] {url}\n"
            with open(target_file, "a", encoding="utf-8") as f:
                f.write(log_entry)

        # Display summary
        print()
        print("=" * 40)
        print(f"Start Time    : {start_time_str}")
        print(f"End Time      : {end_time_str}")
        print(f"Duration      : {duration}")
        print(f"Test Date     : {datetime.now().strftime('%Y-%m-%d')}")
        print(f"Result saved to: {target_file}")
        if screenshot_count > 0:
            print(f"Screenshots ({screenshot_count}) saved to: {absolute_screenshot_path}")

        if status == "SUCCESS":
            print("Result: SUCCESS")
            print("Description: No email verification required")
            print("User info has been saved to the file")
            sys.exit(0)
        elif status == "DOUBT":
            print("Result: DOUBT")
            print("Description: Email verification pending but not blocking")
            print("User info has been saved to the file")
            sys.exit(0)
        elif status == "FAIL":
            print("Result: FAIL")
            print("Description: Email verification required or registration failed")
            sys.exit(2)
        else:
            print(f"Result: UNEXPECTED STATUS - {status}")
            print("Please check output above for details")
            sys.exit(3)

        print("=" * 40)
    else:
        print()
        print("=" * 40)
        print("ERROR: Could not parse registration result")
        print("Output does not contain valid STATUS line")
        print("Expected: STATUS: SUCCESS or DOUBT or FAIL")
        print("=" * 40)

        # Save to fail.txt on error
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_file = fail_folder / "fail.txt"
        log_entry = f"[{timestamp}] {url} - ERROR: Could not parse STATUS\n"
        with open(target_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        print(f"Error logged to: {target_file}")

        sys.exit(2)


if __name__ == "__main__":
    main()
