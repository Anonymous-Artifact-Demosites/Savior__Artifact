#!/usr/bin/env python3
"""T7 - First-party Registration DoS entry point."""

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
    compile_t7_report,
    compile_t7_result,
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
    print("Test - T7")
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
        print("Usage: python t7.py <URL>", file=sys.stderr)
        print("Example: python t7.py https://www.zoom.com", file=sys.stderr)
        sys.exit(1)

    # Extract domain name
    domain = get_domain_name(target_url)

    # Get credentials from user
    print("\nPlease enter credentials for T7 test:")
    email = input("Email (for duplicate registration test): ")
    password_1 = get_secure_input("Password 1 (first registration attempt)")
    password_2 = get_secure_input("Password 2 (second registration attempt)")

    # Create result folder
    result_folder = Path("T7")
    result_folder.mkdir(exist_ok=True)

    # Result file path
    result_file = result_folder / f"{domain}.txt"
    exist_file = result_folder / "exist.txt"

    # Record start time
    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

    # Build prompt via Semantic Navigator
    variables = {
        "target_url": target_url,
        "email": email,
        "password_1": password_1,
        "password_2": password_2,
    }
    prompt = construct_prompt("T7", variables)

    print("\n" + "=" * 40)
    print("Test - T7")
    print("=" * 40)
    print(f"Target URL: {target_url}")
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

    output = result["output"]

    # Display output
    print(output)

    # Record end time
    end_time = datetime.now()
    end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time

    # --- State Auditor: parse + evaluate ---
    parsed = parse_output("T7", output)
    rule_verdict = evaluate_invariants("T7", parsed["observations"])
    final_verdict = cross_check(get_task_config("T7"), rule_verdict, parsed["verdict"])
    evidence = capture_evidence("T7", output, parsed["observations"], final_verdict)

    # Parse results
    status = "UNKNOWN"

    status_match = re.search(r"STATUS:\s*(T7_VULN|T7_SAFE)", output)
    if status_match:
        status = status_match.group(1)

    # Create result content
    duration_str = f"{int(duration.total_seconds() // 3600):02d}:{int((duration.total_seconds() % 3600) // 60):02d}:{int(duration.total_seconds() % 60):02d}"
    clean_output = strip_structured_blocks(output)
    result_content = compile_t7_result(
        target_url=target_url,
        domain=domain,
        test_date=datetime.now().strftime("%Y-%m-%d"),
        start_time_str=start_time_str,
        end_time_str=end_time_str,
        duration_str=duration_str,
        email=email,
        status=status,
        output=clean_output,
        cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
        observations=parsed["observations"],
    )

    # Save result to file
    result_file.write_text(result_content, encoding="utf-8")

    # If status is T7_VULN, record URL and generate report
    if status == "T7_VULN":
        exist_entry = f"[{end_time_str}] {target_url}\n"
        with exist_file.open("a", encoding="utf-8") as f:
            f.write(exist_entry)

        # Generate vulnerability analysis report
        reports_folder = result_folder / "reports"
        reports_folder.mkdir(exist_ok=True)

        vuln_analysis_match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", output, re.DOTALL | re.IGNORECASE)
        vuln_analysis = vuln_analysis_match.group(1).strip() if vuln_analysis_match else "No vulnerability analysis provided"

        report_content = compile_t7_report(
            target_url=target_url,
            domain=domain,
            start_time_str=start_time_str,
            end_time_str=end_time_str,
            duration_str=duration_str,
            status=status,
            email=email,
            output=clean_output,
            vuln_analysis=vuln_analysis,
            cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
            observations=parsed["observations"],
        )
        report_file = reports_folder / f"{domain}_report.txt"
        report_file.write_text(report_content, encoding="utf-8")
        print(f"Vulnerability report saved to: {report_file}")

    # Display summary
    print("\n" + "=" * 40)
    print("Test Summary - T7: First-party Registration DoS")
    print("=" * 40)

    if status == "T7_VULN":
        status_desc = "VULNERABLE - System allows duplicate registration (DoS possible)"
    elif status == "T7_SAFE":
        status_desc = "SAFE - System detects duplicate email (DoS protected)"
    else:
        status_desc = "UNKNOWN"

    print(f"Status: {status}")
    print(f"Description: {status_desc}")
    print(f"Duration: {duration_str}")
    print(f"Result saved to: {result_file}")

    if status == "T7_VULN":
        print(f"URL recorded in: {exist_file}")

    print("=" * 40)

    sys.exit(0)


if __name__ == "__main__":
    main()
