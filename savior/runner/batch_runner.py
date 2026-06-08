"""Batch URL scanning runner for SAVIOR real-world evaluation.

This module sits ABOVE the three-layer core architecture. It orchestrates
batch testing of multiple URLs:
  Phase 1: OAuth support scanning (per-URL LLM call)
  Phase 2: Test script execution against OAuth-supported URLs

The savior/oauth_test_runner.py entry point delegates to this module.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from savior.browser_interactor.claude_runner import run_claude
from savior.browser_interactor.url_prefilter import format_url, read_url_list
from savior.utils.credentials import get_domain_name


def _safe_print(text: str, fallback: str | None = None) -> None:
    """Print text with an ASCII fallback for consoles that reject Unicode."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(fallback if fallback is not None else text.encode("ascii", errors="replace").decode("ascii"))


_SCRIPT_EXIST_FILES: dict[str, list[Path]] = {
    "t2.py": [Path("T2") / "exist.txt"],
    "t3_t4.py": [Path("T3_T4") / "T3_exist.txt", Path("T3_T4") / "T4_exist.txt"],
    "t7.py": [Path("T7") / "exist.txt"],
}


def _dedup_exist_entries(url: str, script_name: str) -> None:
    """After N iterations, deduplicate exist.txt entries for *url*.

    Only touches exist files belonging to *script_name* so that a T2 batch
    run cannot accidentally modify T3_T4 or T7 history files.

    Task scripts append a line per VULN iteration. We keep only the
    last line that contains *url* in each exist file.
    """
    exist_paths = _SCRIPT_EXIST_FILES.get(script_name, [])
    for exist_path in exist_paths:
        if not exist_path.exists():
            continue
        try:
            lines = exist_path.read_text(encoding="utf-8").splitlines()
            # Partition: lines NOT about this url + the last line about this url
            other_lines = []
            last_match = None
            for line in lines:
                if url in line.split():
                    last_match = line
                else:
                    other_lines.append(line)
            if last_match is not None:
                other_lines.append(last_match)
            # Only rewrite if we actually removed duplicates
            if len(other_lines) < len(lines):
                exist_path.write_text("\n".join(other_lines) + "\n" if other_lines else "", encoding="utf-8")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# OAuth support scanning (Phase 1)
# ---------------------------------------------------------------------------


def scan_oauth_support(url: str) -> dict:
    """Scan a single URL for OAuth support using Claude.

    Returns {Success, Url, Domain, Providers, Skipped}.
    """
    domain = get_domain_name(url)
    base_folder = Path("OAuth_support")
    success_folder = base_folder / "success"

    base_folder.mkdir(exist_ok=True)
    success_folder.mkdir(exist_ok=True)

    support_url_file = base_folder / "support_url.txt"
    result_file = success_folder / f"{domain}.txt"
    screenshot_path = success_folder / f"{domain}.png"

    # Check cache
    if result_file.exists():
        try:
            existing_content = result_file.read_text(encoding="utf-8")
            providers_match = re.search(r"Providers:\s*(.+)", existing_content)
            if providers_match:
                providers = [p.strip() for p in providers_match.group(1).strip().split(",")]
                print(f"  [Cached] {domain} - Result exists, skipping scan")
                return {"Success": True, "Url": url, "Domain": domain, "Providers": providers, "Skipped": True}
        except Exception:
            pass
        # Cache file exists but is malformed (no Providers line) - delete and rescan
        print(f"  [Cached] {domain} - Malformed cache, rescanning")
        try:
            result_file.unlink()
        except OSError:
            pass
        # Also remove stale entry from support_url.txt if present
        if support_url_file.exists():
            try:
                lines = support_url_file.read_text(encoding="utf-8").splitlines()
                cleaned = [ln for ln in lines if ln.strip() != url]
                if len(cleaned) != len(lines):
                    support_url_file.write_text("\n".join(cleaned) + "\n" if cleaned else "", encoding="utf-8")
            except OSError:
                pass

    # Build scanning prompt.
    prompt = f"""IMPORTANT: Use Playwright MCP tools directly to interact with the browser. DO NOT write any code files or scripts.

GOAL: Navigate to {url}, find the login/registration page, and verify that the website MUST support OAuth third-party login/registration. Identify all consumer OAuth providers (Google, Apple, Microsoft, Facebook, GitHub, Twitter/X, LinkedIn, etc.) if found. Apply strict filtering criteria to determine if this website should be included.

STRATEGY: Be thorough and flexible. Try every possible method to find the login/registration page - explore the entire site, try common URL patterns (/login, /signin, /register, /signup), click navigation menus, scroll pages, look for authentication buttons.

FILTERING REQUIREMENTS (MUST CHECK ALL):

1. ACCESSIBILITY CHECK:
   - The website MUST have a publicly accessible login/registration page that can be reached and viewed
   - EXCLUDE: Static resource acceleration/CDN nodes, DNS resolution nodes
   - EXCLUDE: Hidden backend SDK endpoints, ad tracking domains
   - EXCLUDE: Pages that cannot be accessed or require special authentication to view

2. OAUTH THIRD-PARTY LOGIN/REGISTRATION (CORE REQUIREMENT):
   - MUST support OAuth third-party login/registration - the website MUST allow users to login or register using third-party OAuth providers (Google, Apple, Microsoft, Facebook, GitHub, Twitter/X, LinkedIn, etc.)
   - This is the core requirement: the website must be a consumer-facing service that accepts OAuth authentication from third-party providers
   - EXCLUDE: OAuth service providers themselves (like Google.com, Facebook.com, Microsoft.com - these are identity providers, not websites that use OAuth)
   - EXCLUDE: SSO/SAML and enterprise-only authentication options
   - ONLY count consumer OAuth providers, not enterprise SSO solutions

3. REGISTRATION ACCESSIBILITY CHECK:
   - The website MUST allow public registration without high barriers
   - EXCLUDE: High-barrier commercial services requiring:
     * Enterprise email verification
     * Manual review/approval processes
     * Existing contracts or partnerships
     * Examples: B2B platforms like vungle.com and similar enterprise services

4. WEBSITE TYPE EXCLUSIONS:
   - EXCLUDE: Government websites (.gov domains, government services)
   - EXCLUDE: Academic institutions (.edu domains, university websites)
   - EXCLUDE: Pure information disclosure websites (news-only sites without user accounts or login functionality)

5. GEOGRAPHIC EXCLUSIONS:
   - EXCLUDE: Korean websites (.kr domains, Korean language sites)
   - EXCLUDE: Russian websites (.ru domains, Russian language sites)

6. DUPLICATE CHECK:
   - Ensure this is not a duplicate of an already tested website

TECHNICAL REQUIREMENTS:
- Do not attempt to actually login
- If OAuth providers are found AND all filtering criteria pass, take a screenshot of the login page showing the OAuth buttons and save it to: {screenshot_path}
- Verify that the login/registration page is functional and accessible

OUTPUT FORMAT:
If OAuth found AND all criteria pass: OAUTH_SUPPORT: YES and PROVIDERS: [comma-separated list]
If OAuth not found OR any exclusion criteria match: OAUTH_SUPPORT: NO
If excluded, also output: EXCLUSION_REASON: [brief reason why excluded - e.g., 'Government site', 'OAuth provider', 'High barrier', 'Korean site', 'Russian site', etc.]"""

    print(f"  [Scanning] {url}")

    try:
        result = run_claude(prompt, timeout_seconds=300, max_retries=1)
        output = result["output"]
    except Exception as e:
        print(f"    Error executing claude: {e}")
        return {"Success": False, "Url": url, "Domain": domain, "Providers": [], "Skipped": False}

    # Parse output
    oauth_support = "NO"
    providers = []
    exclusion_reason = ""

    oauth_match = re.search(r"OAUTH_SUPPORT:\s*(YES|NO)", output, re.IGNORECASE)
    if oauth_match:
        oauth_support = oauth_match.group(1).upper()

    providers_match = re.search(r"PROVIDERS:\s*(.+)", output, re.IGNORECASE)
    if providers_match:
        providers = [p.strip() for p in providers_match.group(1).strip().split(",")]

    exclusion_match = re.search(r"EXCLUSION_REASON:\s*(.+)", output, re.IGNORECASE)
    if exclusion_match:
        exclusion_reason = exclusion_match.group(1).strip()

    if oauth_support == "YES" and providers:
        print(f"    [OK] OAuth Support: {', '.join(providers)}")

        result_content = f"URL: {url}\nDomain: {domain}\nDate: {datetime.now()}\nProviders: {', '.join(providers)}\n\n{output}"
        result_file.write_text(result_content, encoding="utf-8")

        # Append to support_url.txt if not already there
        existing_urls = []
        if support_url_file.exists():
            existing_urls = [line.strip() for line in support_url_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        if url not in existing_urls:
            with support_url_file.open("a", encoding="utf-8") as f:
                f.write(f"{url}\n")

        return {"Success": True, "Url": url, "Domain": domain, "Providers": providers, "Skipped": False}
    else:
        if exclusion_reason:
            print(f"    [EXCLUDED] {exclusion_reason}")
        else:
            print(f"    [NO] No OAuth support")
        return {"Success": False, "Url": url, "Domain": domain, "Providers": [], "Skipped": False}


# ---------------------------------------------------------------------------
# Test script selection menu
# ---------------------------------------------------------------------------

def _find_available_scripts() -> list[dict]:
    """Find available test scripts (tasks/*.py)."""
    scripts = []
    base = Path(__file__).resolve()
    # Bundled: savior/runner/ -> savior/semantic_navigator/tasks/
    bundled = base.parents[1] / "semantic_navigator" / "tasks"
    if bundled.exists():
        task_dir = bundled
    else:
        # Alternate layout: repo/savior/runner/ -> repo/tasks/
        task_dir = base.parents[2] / "tasks"
    mapping = [
        ("T1 Step1", "t1_step1.py"),
        ("T1 Step2", "t1_step2.py"),
        ("T2", "t2.py"),
        ("T3/T4", "t3_t4.py"),
        ("T5", "t5.py"),
        ("T6", "t6.py"),
        ("T7", "t7.py"),
    ]
    for display_name, filename in mapping:
        if (task_dir / filename).exists():
            scripts.append({"name": display_name, "path": str(task_dir / filename), "filename": filename})
    return scripts


def select_test_script() -> dict | None:
    """Interactive menu to select a test script.

    Displays the task selection menu.
    """
    scripts = _find_available_scripts()
    if not scripts:
        print("\n  Error: No test scripts found!")
        return None

    print()
    print("=" * 60)
    print("  Select Test Script")
    print("=" * 60)
    print()

    for i, s in enumerate(scripts, 1):
        print(f"  [{i}] {s['name']}")

    print()
    print("=" * 60)

    while True:
        try:
            choice = input(f"\nEnter number (1-{len(scripts)}): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(scripts):
                return scripts[idx]
        except (ValueError, KeyboardInterrupt):
            print("  Cancelled.")
            return None


# ---------------------------------------------------------------------------
# Batch execution
# ---------------------------------------------------------------------------

def invoke_test_script(script_path: str, target_urls: list[str], *, iterations: int = 1) -> dict:
    """Execute a test script against a list of URLs.

    Each URL is tested via subprocess (preserving full task behavior:
    interactive credential collection, file writing, exit codes).

    When iterations > 1, runs ALL N iterations per URL. A URL is
    counted as success if at least one iteration succeeds (Section 6.2
    "at least one successful execution"). CLI reports M/N rate.

    Known side effects of iterations > 1:
    - Result/report files reflect the LAST iteration's output
    - exist.txt entries may be appended multiple times for the same URL
    These are inherent to subprocess-based iteration where each run
    executes the full task script independently.

    For per-iteration structured analysis with clean aggregation,
    use savior.semantic_navigator.iterative_executor as a Python API.

    Returns {total, success, failed}.
    """
    script_name = Path(script_path).name
    total = len(target_urls)
    success = 0
    failed = 0

    print()
    print("=" * 60)
    print(f"  Executing: {script_name}")
    print("=" * 60)
    print(f"  Target URLs: {total}")
    if iterations > 1:
        print(f"  Iterations per URL: {iterations}")

    for index, url in enumerate(target_urls, 1):
        url = url.strip()
        if not url:
            print("  Warning: Empty URL, skipping...")
            continue

        print()
        print("-" * 60)
        print(f"  [{index}/{total}] Testing: {url}")
        print("-" * 60)

        cmd = [sys.executable, script_path, url]

        # Run all N iterations. Disk files reflect the last run.
        # CLI only reports aggregated M/N success rate.
        # For per-iteration analysis, use iterative_executor Python API.
        iter_successes = 0
        for iter_num in range(1, iterations + 1):
            if iterations > 1:
                print(f"  [Iteration {iter_num}/{iterations}]")

            try:
                result = subprocess.run(cmd, timeout=900)
            except subprocess.TimeoutExpired:
                if iterations == 1:
                    _safe_print("  Result: \u2717 Failed (Timeout)", "  Result: Failed (Timeout)")
                else:
                    print(f"  Iteration {iter_num}: Timeout")
                continue
            except Exception as e:
                if iterations == 1:
                    _safe_print(f"  Result: \u2717 Exception - {e}", f"  Result: Exception - {e}")
                else:
                    print(f"  Iteration {iter_num}: Exception - {e}")
                continue

            if result.returncode == 0:
                iter_successes += 1
                if iterations == 1:
                    _safe_print("  Result: \u2713 Success", "  Result: Success")
                else:
                    _safe_print(
                        f"  Iteration {iter_num}: \u2713 Success (exit 0)",
                        f"  Iteration {iter_num}: Success (exit 0)",
                    )
            else:
                if iterations == 1:
                    _safe_print(
                        f"  Result: \u2717 Failed (Exit Code: {result.returncode})",
                        f"  Result: Failed (Exit Code: {result.returncode})",
                    )
                else:
                    print(f"  Iteration {iter_num}: exit {result.returncode}")

        if iterations > 1:
            print(f"  Iterations: {iter_successes}/{iterations} succeeded")
            # Deduplicate exist.txt entries for this URL.
            # Task scripts append on each VULN iteration; we keep only the last entry per URL.
            _dedup_exist_entries(url, script_name)

        if iter_successes > 0:
            success += 1
        else:
            failed += 1

        if index < total:
            print("  Waiting 2 seconds...")
            time.sleep(2)

    print()
    print("=" * 60)
    print("  Execution Completed")
    print("=" * 60)
    print(f"  Total: {total} | Success: {success} | Failed: {failed}")

    return {"total": total, "success": success, "failed": failed}


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def main(argv=None):
    """Main batch runner entry point.

    Replicates the full oauth_test_runner.py flow:
    Phase 1: OAuth support scanning (per-URL LLM call)
    Phase 2: Test script execution against supported URLs
    """
    import argparse

    parser = argparse.ArgumentParser(description="OAuth Security Test Runner")
    parser.add_argument("--urls", nargs="+", help="URLs to test")
    parser.add_argument("--url-file", help="File containing URLs")
    parser.add_argument("--skip-oauth-scan", action="store_true", help="Skip OAuth support scanning, use cached support_url.txt")
    parser.add_argument(
        "--iterations", type=int, default=1,
        help="Repeat each task N times per URL to observe execution stability "
             "(default: 1). Reports M/N success rate; files reflect last run. "
             "For structured verdict aggregation per Section 6.2, use "
             "savior.semantic_navigator.iterative_executor Python API.",
    )
    args = parser.parse_args(argv)

    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass

    print()
    print("=" * 60)
    print("  OAuth Security Test Runner")
    print("=" * 60)

    # Collect URLs
    input_urls = read_url_list(urls=args.urls, url_file=args.url_file)

    if not input_urls:
        print()
        print("  No URLs provided. Please enter URLs to test.")
        print("  You can enter:")
        print("    - Full URL: https://www.zoom.com")
        print("    - Domain: zoom.com")
        print("    - Multiple URLs (one per line, press Ctrl+Z then Enter when done)")
        print("  Or press Ctrl+C to exit")
        print()
        print("Enter URLs (one per line):")
        print("-" * 60)

        try:
            while True:
                line = input().strip()
                if not line:
                    continue
                formatted = format_url(line)
                if formatted:
                    input_urls.append(formatted)
                    print(f"  \u2713 Added: {formatted}")
        except (EOFError, KeyboardInterrupt):
            print("\n")

    if not input_urls:
        print("  No URLs to test. Exiting.")
        return 1

    print(f"\n  Input URLs: {len(input_urls)}")

    # Phase 1: OAuth support scanning
    if args.skip_oauth_scan:
        support_file = Path("OAuth_support") / "support_url.txt"
        if support_file.exists():
            target_urls = [line.strip() for line in support_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            print(f"  Using cached OAuth URLs: {len(target_urls)}")
        else:
            print("  Error: OAuth_support/support_url.txt not found.")
            print("  Run without --skip-oauth-scan first to generate it.")
            return 1
    else:
        # Real OAuth support scanning - per-URL LLM call
        print()
        print("-" * 60)
        print("  Phase 1: OAuth Support Filtering")
        print("-" * 60)
        print(f"  Starting scan of {len(input_urls)} URLs...")

        scan_results = []
        success_count = 0
        fail_count = 0
        skipped_count = 0

        for i, url in enumerate(input_urls, 1):
            print(f"[{i}/{len(input_urls)}] {url}")
            result = scan_oauth_support(url)
            scan_results.append(result)

            if result.get("Skipped"):
                skipped_count += 1
            if result.get("Success"):
                success_count += 1
            elif not result.get("Skipped"):
                fail_count += 1

            if i < len(input_urls):
                print("Waiting 2 seconds...")
                time.sleep(2)

        target_urls = [r["Url"] for r in scan_results if r.get("Success")]

        print()
        print("-" * 60)
        print("  OAuth Filtering Results")
        print("-" * 60)
        print(f"  Total Input URLs: {len(input_urls)}")
        print(f"  Total Scanned: {len(scan_results)}")
        print(f"  OAuth Supported: {success_count}")
        print(f"  No OAuth Support: {fail_count}")
        print(f"  Skipped (Cached): {skipped_count}")

        if target_urls:
            print("  OAuth-Supported Websites:")
            for r in scan_results:
                if r.get("Success"):
                    providers_str = ", ".join(r.get("Providers", []))
                    skip_label = " (cached)" if r.get("Skipped") else ""
                    print(f"    - {r['Url']} - {providers_str}{skip_label}")

    if not target_urls:
        print("  No URLs passed filtering. Exiting.")
        return 1

    backend_name = os.environ.get("CAPTCHA_BACKEND", "manual")
    if backend_name != "manual":
        print("[INFO] CAPTCHA_BACKEND is set to an automated backend.")
    else:
        print("[INFO] CAPTCHA_BACKEND is set to 'manual' (default).")
        print("[INFO] CAPTCHAs will pause for human intervention.")
        print("[INFO] For automated resolution, set CAPTCHA_BACKEND to your backend module path.")

    # Select test script
    script = select_test_script()
    if not script:
        print("  No script selected. Exiting.")
        return 1

    # Confirm
    print()
    try:
        confirm = input("Confirm execution? [Y/n]: ").strip()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"

    if confirm.lower() not in ("", "y", "yes"):
        print("  Cancelled.")
        return 1

    # Execute
    result = invoke_test_script(script["path"], target_urls, iterations=args.iterations)

    print()
    try:
        input("Press Enter to exit...")
    except EOFError:
        pass

    if result["failed"] > 0:
        return 1
    return 0
