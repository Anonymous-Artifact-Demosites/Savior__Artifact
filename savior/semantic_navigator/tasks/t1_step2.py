#!/usr/bin/env python3
"""T1 Step 2 - Implicit Pre-hijacking (OAuth Login Phase) entry point."""

from __future__ import annotations

import re
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from savior.browser_interactor.claude_runner import run_claude
from savior.semantic_navigator.task_orchestrator import construct_prompt
from savior.state_auditor.auditor import capture_evidence, cross_check
from savior.state_auditor.evidence_compiler import compile_t1s2_result, write_result_file
from savior.state_auditor.invariants import evaluate_invariants, get_task_config
from savior.state_auditor.verdict_parser import parse_output
from savior.utils.credentials import get_domain_name, get_t1_credentials


def main():
    if len(sys.argv) < 2:
        print("Usage: python t1_step2.py <URL>", file=sys.stderr)
        print("Example: python t1_step2.py https://zoom.us", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]

    # Get credentials (Gmail password for OAuth login)
    creds = get_t1_credentials(url, step=2)
    email = creds["Email"]
    password = creds["Password"]  # Gmail password for OAuth

    # Extract domain name from URL
    domain = get_domain_name(url)

    # Get current directory absolute path
    current_dir = Path.cwd()

    # Create folder structure
    screenshot_folder = current_dir / "T1_step2_Screenshots" / domain
    result_folder = current_dir / "T1_step2_results"
    success_folder = result_folder / "success"
    fail_folder = result_folder / "fail"

    for folder in [screenshot_folder, result_folder, success_folder, fail_folder]:
        folder.mkdir(parents=True, exist_ok=True)

    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    stopwatch_start = time.time()

    # Build prompt via Semantic Navigator
    domain_screenshot_folder = screenshot_folder.resolve()
    variables = {
        "url": url,
        "email": email,
        "password": password,
        "screenshot_path": str(domain_screenshot_folder),
    }
    prompt = construct_prompt("T1_STEP2", variables)

    print("=" * 40)
    print("Test - T1")
    print("=" * 40)
    print(f"Target URL: {url}")
    print(f"Start Time: {start_time_str}")
    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"[{current_time}] Executing test task...")
    print()
    print("=" * 40)
    print()

    print(f"[{current_time}] Starting OAuth login...")

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

    output = result["output"]
    print(output)
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Completed in {duration_seconds:.1f}s")

    # --- State Auditor: parse + evaluate ---
    parsed = parse_output("T1_STEP2", output)
    rule_verdict = evaluate_invariants("T1_STEP2", parsed["observations"])
    final_verdict = cross_check(get_task_config("T1_STEP2"), rule_verdict, parsed["verdict"])
    evidence = capture_evidence("T1_STEP2", output, parsed["observations"], final_verdict)

    # Parse results while tolerating markdown asterisks.
    status = "UNKNOWN"
    idps = ""
    account_info = ""
    fail_reason = ""

    print("\n" + "=" * 40)
    print("Parsing results...")

    # Parse STATUS (ignore markdown asterisks)
    status_match = re.search(r"\*{0,2}STATUS:\*{0,2}\s*(SUCCESS|FAIL)", output, re.IGNORECASE)
    if status_match:
        status = status_match.group(1).upper()
        print(f"STATUS: {status}")
    else:
        print("STATUS not found in output")

    # Parse OAuth IdPs (ignore asterisks)
    idps_match = re.search(r"\*{0,2}OAUTH_IDPS:\*{0,2}\s*(.+?)(?:\r?\n|$)", output, re.IGNORECASE)
    if idps_match:
        idps = re.sub(r"^\*+|\*+$", "", idps_match.group(1).strip())
        print(f"OAuth IdPs: {idps}")

    # Parse account info (ignore asterisks)
    account_info_match = re.search(
        r"(?s)\*{0,2}ACCOUNT_INFO_START\*{0,2}(.*?)\*{0,2}ACCOUNT_INFO_END\*{0,2}", output, re.IGNORECASE
    )
    if account_info_match:
        account_info = account_info_match.group(1).strip()
        print("Account info found")

    # Parse fail reason
    fail_reason_match = re.search(r"\*{0,2}REASON:\*{0,2}\s*(.+?)(?:\r?\n|$)", output, re.IGNORECASE)
    if fail_reason_match:
        fail_reason = re.sub(r"^\*+|\*+$", "", fail_reason_match.group(1).strip())

    # Build account info lines (filtered)
    account_info_lines = None
    if account_info:
        lines = [line.strip() for line in account_info.split("\n") if line.strip() and re.search(r":\s*\S", line)]
        if lines:
            account_info_lines = lines
            print(f"Extracted {len(lines)} account fields")

    # Check screenshots (dynamically count all .png files)
    screenshot_files = list(screenshot_folder.glob("*.png"))
    screenshot_count = len(screenshot_files)

    if screenshot_count > 0:
        print(f"Screenshots: {screenshot_count} saved")
    else:
        print("No screenshots found")

    # Build and save result file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_content = compile_t1s2_result(
        timestamp=timestamp,
        url=url,
        email=email,
        status=status,
        idps=idps,
        fail_reason=fail_reason,
        account_info_lines=account_info_lines,
        cross_check=final_verdict if final_verdict["source"] != "unavailable" else None,
        observations=parsed["observations"],
    )

    # Save to appropriate folder
    if status == "SUCCESS":
        target_file = success_folder / f"{domain}.txt"
    else:
        target_file = fail_folder / f"{domain}.txt"

    target_file.write_text(file_content, encoding="utf-8")

    # Summary
    duration_str = f"{int(duration_seconds // 3600):02d}:{int((duration_seconds % 3600) // 60):02d}:{int(duration_seconds % 60):02d}"
    print("\n" + "=" * 40)
    print(f"Start Time    : {start_time_str}")
    print(f"End Time      : {end_time_str}")
    print(f"Duration      : {duration_str}")
    print(f"Test Date     : {datetime.now().strftime('%Y-%m-%d')}")
    print(f"Result: {status}")
    print(f"Saved to: {target_file}")
    print("=" * 40)

    exit_code = 0 if status == "SUCCESS" else (1 if status == "FAIL" else 2)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
