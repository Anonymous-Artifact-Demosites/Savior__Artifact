#!/usr/bin/env python3
"""T3/T4 - Email Rebinding Security (T3 + T4) entry point."""

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
    compile_t3_report,
    compile_t3t4_result,
    compile_t4_report,
    strip_structured_blocks,
    write_report_file,
)
from savior.state_auditor.invariants import evaluate_invariants, get_task_config
from savior.state_auditor.verdict_parser import parse_output
from savior.utils.credentials import get_domain_name, get_secure_input


def show_menu():
    """Show website selection menu"""
    websites = {
        "1": {"Name": "Zoom", "Url": "https://www.zoom.com"},
        "2": {"Name": "Adobe", "Url": "https://www.adobe.com"},
        "3": {"Name": "Dropbox", "Url": "https://www.dropbox.com"},
        "4": {"Name": "Slack", "Url": "https://slack.com"},
        "5": {"Name": "Notion", "Url": "https://www.notion.so"},
        "6": {"Name": "Figma", "Url": "https://www.figma.com"},
        "7": {"Name": "Canva", "Url": "https://www.canva.com"},
        "8": {"Name": "Trello", "Url": "https://trello.com"},
    }

    print("\n" + "=" * 40)
    print("Email Rebinding Security Test - T3 & T4")
    print("=" * 40)
    print("\nPlease select a website to test:")

    for key in sorted(websites.keys()):
        site = websites[key]
        print(f"{key}. {site['Name']} ({site['Url']})")

    print("0. Custom URL")
    print("q. Quit")
    print("=" * 40)

    return websites


def main():
    target_url = None

    # Check if URL provided as argument
    if len(sys.argv) >= 2:
        target_url = sys.argv[1]
    else:
        # Show menu
        websites = show_menu()

        while True:
            choice = input("\nEnter your choice: ").strip()

            if choice.lower() == "q":
                print("Exiting program")
                sys.exit(0)

            if choice == "0":
                target_url = input("Enter custom URL: ").strip()
                if target_url:
                    break
            elif choice in websites:
                target_url = websites[choice]["Url"]
                print(f"Selected: {websites[choice]['Name']} - {target_url}")
                break
            else:
                print("Invalid choice, please try again")

    # Validate URL
    if not target_url:
        print("Error: No URL provided", file=sys.stderr)
        print("Usage: python t3_t4.py <URL>", file=sys.stderr)
        print("Example: python t3_t4.py https://www.zoom.com", file=sys.stderr)
        sys.exit(1)

    # Extract domain name
    domain = get_domain_name(target_url)

    # Get credentials from user
    print("\nPlease enter credentials for T3_T4 test:")
    email = input("Current Email: ")
    password = get_secure_input("Current Password")
    new_email = input("New Email (for rebinding): ")
    new_password = get_secure_input("New Email Password")

    # Create result folder
    result_folder = Path("T3_T4")
    result_folder.mkdir(exist_ok=True)

    # Result file paths
    result_file = result_folder / f"{domain}.txt"
    exist_file_t3 = result_folder / "T3_exist.txt"
    exist_file_t4 = result_folder / "T4_exist.txt"

    # Record start time
    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

    # Build prompt via Semantic Navigator
    variables = {
        "target_url": target_url,
        "email": email,
        "password": password,
        "new_email": new_email,
        "new_password": new_password,
    }
    prompt = construct_prompt("T3_T4", variables)

    print("\n" + "=" * 40)
    print("Test - T3 & T4")
    print("=" * 40)
    print(f"Target URL: {target_url}")
    print(f"Email A: {email}")
    print(f"Email B: {new_email}")
    print(f"Start Time: {start_time_str}")
    print("=" * 40)
    print()

    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"[{current_time}] Executing test task...")
    print()

    # Execute Claude Code via Browser Interactor
    try:
        result = run_claude(prompt, timeout_seconds=1200)
    except FileNotFoundError:
        print("Error: claude command not found in PATH", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error executing claude command: {e}", file=sys.stderr)
        sys.exit(1)

    output = result["output"]

    # Display output
    print(output)

    # Record end time
    end_time = datetime.now()
    end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time

    # --- State Auditor: parse + evaluate ---
    parsed = parse_output("T3_T4", output)
    rule_verdict = evaluate_invariants("T3_T4", parsed["observations"])
    # T3_T4 rule_verdict has status_t3/status_t4 keys; cross_check handles per-status

    # Parse results while stripping asterisks and matching longer statuses first.
    status_t3 = "UNKNOWN"
    status_t4 = "UNKNOWN"

    normalized_output = re.sub(r"\*", "", output)

    if re.search(r"STATUS_T3[:\s]+T3_SAFE", normalized_output):
        status_t3 = "T3_SAFE"
    elif re.search(r"STATUS_T3[:\s]+T3_VULN\b", normalized_output):
        status_t3 = "T3_VULN"

    if re.search(r"STATUS_T4[:\s]+T4_SAFE", normalized_output):
        status_t4 = "T4_SAFE"
    elif re.search(r"STATUS_T4[:\s]+T4_VULN\b", normalized_output):
        status_t4 = "T4_VULN"

    # Dual cross_check - once for T3, once for T4
    task_config = get_task_config("T3_T4")
    t3_rule = {"status": rule_verdict["status_t3"], "reason": rule_verdict.get("reason_t3", "")} if rule_verdict and rule_verdict.get("status_t3") else None
    t4_rule = {"status": rule_verdict["status_t4"], "reason": rule_verdict.get("reason_t4", "")} if rule_verdict and rule_verdict.get("status_t4") else None
    t3_llm = {"status": status_t3, "confidence": None} if status_t3 != "UNKNOWN" else None
    t4_llm = {"status": status_t4, "confidence": None} if status_t4 != "UNKNOWN" else None

    t3_verdict = cross_check(task_config, t3_rule, t3_llm)
    t4_verdict = cross_check(task_config, t4_rule, t4_llm)

    evidence = capture_evidence("T3_T4", output, parsed["observations"], t3_verdict, verdict_t4=t4_verdict)

    # Create result content
    duration_str = f"{int(duration.total_seconds() // 3600):02d}:{int((duration.total_seconds() % 3600) // 60):02d}:{int(duration.total_seconds() % 60):02d}"
    clean_output = strip_structured_blocks(output)
    result_content = compile_t3t4_result(
        target_url=target_url,
        domain=domain,
        test_date=datetime.now().strftime("%Y-%m-%d"),
        start_time_str=start_time_str,
        end_time_str=end_time_str,
        duration_str=duration_str,
        email=email,
        password=password,
        new_email=new_email,
        new_password=new_password,
        status_t3=status_t3,
        status_t4=status_t4,
        output=clean_output,
        observations=parsed["observations"],
    )

    # Save result to file
    result_file.write_text(result_content, encoding="utf-8")

    # Create reports folder
    reports_folder = result_folder / "reports"
    reports_folder.mkdir(exist_ok=True)

    # If status is T3_VULN, record URL and generate report
    if status_t3 == "T3_VULN":
        exist_entry = f"[{end_time_str}] {target_url}\n"
        with exist_file_t3.open("a", encoding="utf-8") as f:
            f.write(exist_entry)

        t3_analysis_match = re.search(r"T3_VULN_ANALYSIS_START(.*?)T3_VULN_ANALYSIS_END", output, re.DOTALL | re.IGNORECASE)
        t3_analysis = t3_analysis_match.group(1).strip() if t3_analysis_match else "No vulnerability analysis provided"

        t3_report = compile_t3_report(
            target_url=target_url,
            domain=domain,
            start_time_str=start_time_str,
            end_time_str=end_time_str,
            duration_str=duration_str,
            status_t3=status_t3,
            email=email,
            new_email=new_email,
            vuln_analysis=t3_analysis,
            cross_check=t3_verdict if t3_verdict["source"] != "unavailable" else None,
            observations=parsed["observations"],
        )
        t3_report_file = reports_folder / f"T3_{domain}_report.txt"
        t3_report_file.write_text(t3_report, encoding="utf-8")
        print(f"T3 vulnerability report saved to: {t3_report_file}")

    # If status is T4_VULN, record URL and generate report
    if status_t4 == "T4_VULN":
        exist_entry = f"[{end_time_str}] {target_url}\n"
        with exist_file_t4.open("a", encoding="utf-8") as f:
            f.write(exist_entry)

        t4_analysis_match = re.search(r"T4_VULN_ANALYSIS_START(.*?)T4_VULN_ANALYSIS_END", output, re.DOTALL | re.IGNORECASE)
        t4_analysis = t4_analysis_match.group(1).strip() if t4_analysis_match else "No vulnerability analysis provided"

        t4_report = compile_t4_report(
            target_url=target_url,
            domain=domain,
            start_time_str=start_time_str,
            end_time_str=end_time_str,
            duration_str=duration_str,
            status_t4=status_t4,
            email=email,
            new_email=new_email,
            vuln_analysis=t4_analysis,
            cross_check=t4_verdict if t4_verdict["source"] != "unavailable" else None,
            observations=parsed["observations"],
        )
        t4_report_file = reports_folder / f"T4_{domain}_report.txt"
        t4_report_file.write_text(t4_report, encoding="utf-8")
        print(f"T4 vulnerability report saved to: {t4_report_file}")

    # Display summary
    print("\n" + "=" * 40)
    print("Test Summary")
    print("=" * 40)

    print(f"T3 Status: {status_t3}")
    print(f"T4 Status: {status_t4}")
    print(f"Duration: {duration_str}")
    print(f"Result saved to: {result_file}")

    if status_t3 == "T3_VULN":
        print(f"T3 URL recorded in: {exist_file_t3}")

    if status_t4 == "T4_VULN":
        print(f"T4 URL recorded in: {exist_file_t4}")

    print("=" * 40)

    sys.exit(0)


if __name__ == "__main__":
    main()
