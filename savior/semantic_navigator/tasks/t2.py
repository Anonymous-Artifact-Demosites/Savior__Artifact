#!/usr/bin/env python3
"""T2 - Unaligned First-party Verification Hijacking entry point."""

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
    compile_t2_report,
    compile_t2_result,
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
        "3": {"Name": "Pinterest", "Url": "https://www.pinterest.com"},
        "4": {"Name": "nytimes", "Url": "https://www.nytimes.com"},
        "5": {"Name": "Notion", "Url": "https://www.notion.so"},
        "6": {"Name": "Figma", "Url": "https://www.figma.com"},
        "7": {"Name": "Vimeo", "Url": "https://vimeo.com/"},
        "8": {"Name": "Samsung", "Url": "https://v3.account.samsung.com/dashboard/intro"},
        "9": {"Name": "Nginx", "Url": "https://community.nginx.org/"},
    }

    print("\n" + "=" * 40)
    print("OAuth vs Email Registration Test - T2")
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
        print("Usage: python t2.py <URL>", file=sys.stderr)
        print("Example: python t2.py https://www.zoom.com", file=sys.stderr)
        sys.exit(1)

    # Extract domain name
    domain = get_domain_name(target_url)

    # Get credentials from user
    print("\nPlease enter credentials for T2 test:")
    email = input("Email (for registration and Gmail): ")
    password_registration = get_secure_input("Password (for website registration)")
    password_gmail = get_secure_input("Gmail Password (for OAuth login)")

    # Create result folder
    result_folder = Path("T2")
    result_folder.mkdir(exist_ok=True)

    # Result file paths
    result_file = result_folder / f"{domain}.txt"
    exist_file = result_folder / "exist.txt"

    # Record start time
    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

    # Build prompt via Semantic Navigator
    variables = {
        "target_url": target_url,
        "email": email,
        "password_registration": password_registration,
        "password_gmail": password_gmail,
    }
    prompt = construct_prompt("T2", variables)

    print("\n" + "=" * 40)
    print("Test - T2")
    print("=" * 40)
    print(f"Target URL: {target_url}")
    print(f"Email: {email}")
    print("Registration Password: [REDACTED]")
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
    print(output)

    end_time = datetime.now()
    end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time

    # --- State Auditor: parse + evaluate ---
    parsed = parse_output("T2", output)
    rule_verdict = evaluate_invariants("T2", parsed["observations"])
    final_verdict = cross_check(get_task_config("T2"), rule_verdict, parsed["verdict"])
    evidence = capture_evidence("T2", output, parsed["observations"], final_verdict)

    # Parse task result.
    result_status = "UNKNOWN"
    phase1_status = "UNKNOWN"
    phase2_status = "UNKNOWN"
    phase3_status = "UNKNOWN"

    phase1_match = re.search(r"PHASE1:\s*(.+)", output)
    if phase1_match:
        phase1_status = phase1_match.group(1).strip()

    phase2_match = re.search(r"PHASE2:\s*(.+)", output)
    if phase2_match:
        phase2_status = phase2_match.group(1).strip()

    phase3_match = re.search(r"PHASE3:\s*(.+)", output)
    if phase3_match:
        phase3_status = phase3_match.group(1).strip()

    result_match = re.search(r"RESULT:\s*(T2_VULN|T2_SAFE|T2_N/A)", output)
    if result_match:
        result_status = result_match.group(1)

    # Create result content
    duration_str = f"{int(duration.total_seconds() // 3600):02d}:{int((duration.total_seconds() % 3600) // 60):02d}:{int(duration.total_seconds() % 60):02d}"
    clean_output = strip_structured_blocks(output)
    result_content = compile_t2_result(
        target_url=target_url,
        domain=domain,
        test_date=datetime.now().strftime("%Y-%m-%d"),
        start_time_str=start_time_str,
        end_time_str=end_time_str,
        duration_str=duration_str,
        email=email,
        password_registration=password_registration,
        password_gmail=password_gmail,
        result_status=result_status,
        phase1_status=phase1_status,
        phase2_status=phase2_status,
        phase3_status=phase3_status,
        output=clean_output,
        cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
        observations=parsed["observations"],
    )

    # Save result to file
    result_file.write_text(result_content, encoding="utf-8")

    # If result is T2_VULN, append URL to exist.txt and generate report
    if result_status == "T2_VULN":
        with exist_file.open("a", encoding="utf-8") as f:
            f.write(f"{target_url}\n")
        print("\nURL recorded to exist.txt (T2 vulnerability found)")

        # Generate vulnerability analysis report
        vuln_analysis_match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", output, re.DOTALL | re.IGNORECASE)
        vuln_analysis = vuln_analysis_match.group(1).strip() if vuln_analysis_match else "No vulnerability analysis provided"

        report_content = compile_t2_report(
            target_url=target_url,
            domain=domain,
            start_time_str=start_time_str,
            end_time_str=end_time_str,
            duration_str=duration_str,
            result_status=result_status,
            email=email,
            phase1_status=phase1_status,
            phase2_status=phase2_status,
            phase3_status=phase3_status,
            output=clean_output,
            vuln_analysis=vuln_analysis,
            cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
            observations=parsed["observations"],
        )
        report_file = write_report_file("T2", domain, report_content)
        print(f"Vulnerability report saved to: {report_file}")

    # If result is T2_N/A, do not record anything
    if result_status == "T2_N/A":
        print("\nTest stopped - No email verification required for normal registration")

    # Display summary
    print("\n" + "=" * 40)
    print("Test Summary")
    print("=" * 40)

    print(f"Final Result: {result_status}")
    print(f"Phase 1: {phase1_status}")
    print(f"Phase 2: {phase2_status}")
    print(f"Phase 3: {phase3_status}")
    print(f"Duration: {duration_str}")
    print(f"Result saved to: {result_file}")

    if result_status == "T2_VULN":
        print("\nSECURITY ISSUE DETECTED!")
        print("OAuth and email registration link to the same account")
    elif result_status == "T2_N/A":
        print("\nTest not applicable - No email verification in normal registration")

    print("=" * 40)

    sys.exit(0)


if __name__ == "__main__":
    main()
