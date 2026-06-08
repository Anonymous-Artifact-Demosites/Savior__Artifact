#!/usr/bin/env python3
"""T6 - The Shadow Binding Attack entry point."""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from savior.browser_interactor.claude_runner import run_claude
from savior.semantic_navigator.task_orchestrator import construct_prompt
from savior.state_auditor.auditor import capture_evidence, cross_check
from savior.state_auditor.evidence_compiler import compile_t6_report, compile_t6_result, strip_structured_blocks, write_report_file, write_result_file
from savior.state_auditor.invariants import evaluate_invariants, get_task_config
from savior.state_auditor.verdict_parser import parse_output
from savior.utils.credentials import get_domain_name, get_secure_input


def show_menu():
    """Show the website selection menu."""
    websites = {
        "1": {"Name": "Zoom", "Url": "https://www.zoom.com"},
        "2": {"Name": "Adobe", "Url": "https://www.adobe.com"},
        "3": {"Name": "Pinterest", "Url": "https://www.pinterest.com"},
        "4": {"Name": "nytimes", "Url": "https://www.nytimes.com"},
        "5": {"Name": "Notion", "Url": "https://www.notion.so"},
        "6": {"Name": "Figma", "Url": "https://www.figma.com"},
        "7": {"Name": "Vimeo", "Url": "https://vimeo.com/"},
        "8": {"Name": "Sansung", "Url": "https://v3.account.samsung.com/dashboard/intro"},
        "9": {"Name": "Nginx", "Url": "https://community.nginx.org/"},
    }

    print("\n" + "=" * 40)
    print("OAuth Email Change Security Test - T6")
    print("=" * 40)
    print("\nPlease select a website to test:")

    for key in sorted(websites.keys()):
        site = websites[key]
        print(f"{key}. {site['Name']} ({site['Url']})")

    print("0. Custom URL")
    print("q. Quit")
    print("=" * 40)
    return websites


def _resolve_url() -> str:
    if len(sys.argv) >= 2:
        return sys.argv[1]

    websites = show_menu()
    while True:
        choice = input("\nEnter your choice: ").strip()
        if choice.lower() == "q":
            print("Exiting program")
            sys.exit(0)
        if choice == "0":
            custom_url = input("Enter custom URL: ").strip()
            if custom_url:
                return custom_url
        elif choice in websites:
            url = websites[choice]["Url"]
            print(f"Selected: {websites[choice]['Name']} - {url}")
            return url
        else:
            print("Invalid choice, please try again")


def _extract_vuln_analysis(evidence_text: str | None, raw_output: str) -> str:
    if evidence_text and evidence_text.strip() and evidence_text.strip().lower() != "none":
        match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", evidence_text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return evidence_text.strip()

    match = re.search(r"VULN_ANALYSIS_START(.*?)VULN_ANALYSIS_END", raw_output, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return "No vulnerability analysis provided"


def _format_duration(start_time: datetime, end_time: datetime) -> str:
    duration = end_time - start_time
    total_seconds = int(duration.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def main() -> None:
    url = _resolve_url()
    if not url:
        print("Error: No URL provided", file=sys.stderr)
        print("Usage: python t6.py <URL>", file=sys.stderr)
        print("Example: python t6.py https://www.zoom.com", file=sys.stderr)
        sys.exit(1)

    domain = get_domain_name(url)

    print("\nPlease enter credentials for T6 test:")
    print("Account A (original):")
    email_a = input("Email A: ")
    password_a = get_secure_input("Password A")
    print("\nAccount B (new email):")
    email_b = input("Email B: ")
    password_b = get_secure_input("Password B")

    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

    variables = {
        "url": url,
        "email_a": email_a,
        "password_a": password_a,
        "email_b": email_b,
        "password_b": password_b,
    }
    prompt = construct_prompt("T6", variables)

    print("\n" + "=" * 40)
    print("Test - T6")
    print("=" * 40)
    print(f"Target URL: {url}")
    print(f"Email A: {email_a}")
    print(f"Email B: {email_b}")
    print(f"Start Time: {start_time_str}")
    print("=" * 40)
    print()

    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"[{current_time}] Executing test task...")
    print()

    try:
        result = run_claude(prompt, timeout_seconds=1500)
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
    duration_str = _format_duration(start_time, end_time)

    parsed = parse_output("T6", output)
    rule_verdict = evaluate_invariants("T6", parsed["observations"])
    final_verdict = cross_check(get_task_config("T6"), rule_verdict, parsed["verdict"])
    evidence = capture_evidence("T6", output, parsed["observations"], final_verdict)

    status = final_verdict["status"] or parsed["llm_status"] or "UNKNOWN"
    clean_output = strip_structured_blocks(output)
    result_content = compile_t6_result(
        url=url,
        domain=domain,
        start_time_str=start_time_str,
        end_time_str=end_time_str,
        email_a=email_a,
        email_b=email_b,
        output=clean_output,
        status=status,
        test_date=end_time.strftime("%Y-%m-%d"),
        duration_str=duration_str,
        cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
        observations=parsed["observations"],
    )
    result_file = write_result_file("T6", domain, result_content)

    report_file = None
    if status == "T6_VULN":
        report_content = compile_t6_report(
            url=url,
            domain=domain,
            start_time_str=start_time_str,
            end_time_str=end_time_str,
            email_a=email_a,
            email_b=email_b,
            output=clean_output,
            status=status,
            duration_str=duration_str,
            vuln_analysis=_extract_vuln_analysis(parsed["evidence_text"], output),
            cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
            observations=parsed["observations"],
        )
        report_file = write_report_file("T6", domain, report_content)
        print(f"Vulnerability report saved to: {report_file}")

    print("\n" + "=" * 40)
    print("Test Summary")
    print("=" * 40)
    print(f"Status: {status}")
    print(f"Duration: {duration_str}")
    print(f"Result saved to: {result_file}")
    print("=" * 40)
    sys.exit(0)


if __name__ == "__main__":
    main()
