#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAuth Test Suite - Main Launcher
Main entry point for all OAuth security tests (T1-T7)
"""

import sys
import os
import subprocess
from pathlib import Path


def show_menu():
    """Display main menu"""
    print("\n" + "=" * 60)
    print("OAuth Security Test Suite")
    print("=" * 60)
    print("\nAvailable Tests:")
    print("  1. T1 Step 1 - Implicit Pre-hijacking (Email Registration)")
    print("  2. T1 Step 2 - Implicit Pre-hijacking (OAuth Login)")
    print("  3. T2 - Unaligned First-party Verification Hijacking")
    print("  4. T3/T4 - Combined Test")
    print("  5. T5 - Unauthorized IdP Association Manipulation")
    print("  6. T6 - Test")
    print("  7. T7 - Test")
    print("  8. CAPTCHA Handler")
    print("\n  0. Exit")
    print("=" * 60)


def run_test(test_name, args=None):
    """Run a test script"""
    # Map test names to script files
    test_map = {
        't1_step1': 't1_step1.py',
        't1_step2': 't1_step2.py',
        't2': 't2.py',
        't3_t4': 't3_t4.py',
        't5': 't5.py',
        't6': 't6.py',
        't7': 't7.py',
        'handler': 'handler.py',
    }
    
    script_name = test_map.get(test_name.lower())
    if not script_name:
        print(f"Error: Unknown test '{test_name}'", file=sys.stderr)
        return 1
    
    script_base = script_name.replace('.py', '')
    is_frozen = getattr(sys, 'frozen', False)
    script_path = None

    if is_frozen:
        # Frozen application mode: look for an executable first, then .py.
        base_path = Path(sys.executable).parent
        exe_candidate = base_path / f"{script_base}.exe"
        py_candidate = base_path / script_name
        if exe_candidate.exists():
            script_path = exe_candidate
        elif py_candidate.exists():
            script_path = py_candidate
    else:
        # Python script mode: tasks/ first (except handler), then root
        base_path = Path(__file__).parent
        if script_name != 'handler.py':
            candidates = [
                base_path / "semantic_navigator" / "tasks" / script_name,
                base_path / "tasks" / script_name,
                base_path / script_name,
                Path("tasks") / script_name,
                Path(script_name),
            ]
        else:
            candidates = [base_path / script_name, Path(script_name)]
        for c in candidates:
            if c.exists():
                script_path = c
                break

    if script_path is None:
        print(f"Error: Script '{script_name}' not found", file=sys.stderr)
        return 1

    # Build command: .exe runs directly, .py runs with Python interpreter
    if str(script_path).endswith('.exe'):
        cmd = [str(script_path)]
    else:
        cmd = [sys.executable, str(script_path)]
    
    if args:
        cmd.extend(args)
    
    try:
        # Run the test script
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except Exception as e:
        print(f"Error running test: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point"""
    # If command line arguments provided, use them
    if len(sys.argv) > 1:
        test_name = sys.argv[1]
        test_args = sys.argv[2:] if len(sys.argv) > 2 else []
        
        # Special handling for help
        if test_name in ['-h', '--help', 'help']:
            print("OAuth Test Suite - Usage")
            print("\nInteractive mode:")
            print("  python savior/main_launcher.py")
            print("\nCommand line mode:")
            print("  python savior/main_launcher.py <test_name> [args...]")
            print("\nAvailable tests:")
            print("  t1_step1 <URL>")
            print("  t1_step2 <URL>")
            print("  t2 <URL>")
            print("  t3_t4 <URL>")
            print("  t5 <URL>")
            print("  t6 <URL>")
            print("  t7 <URL>")
            print("  handler [command]")
            print("\nExamples:")
            print("  python savior/main_launcher.py t1_step1 https://example.com")
            print("  python savior/main_launcher.py t2 https://zoom.com")
            print("  python savior/main_launcher.py handler balance")
            return 0
        
        # Run the specified test
        return run_test(test_name, test_args)
    
    # Interactive mode
    while True:
        show_menu()
        choice = input("\nSelect test (0-8): ").strip()
        
        if choice == '0':
            print("Exiting...")
            break
        elif choice == '1':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t1_step1', [url])
        elif choice == '2':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t1_step2', [url])
        elif choice == '3':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t2', [url])
        elif choice == '4':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t3_t4', [url])
        elif choice == '5':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t5', [url])
        elif choice == '6':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t6', [url])
        elif choice == '7':
            url = input("Enter URL: ").strip()
            if url:
                run_test('t7', [url])
        elif choice == '8':
            cmd = input("Enter handler command (or press Enter for menu): ").strip()
            if cmd:
                run_test('handler', [cmd])
            else:
                run_test('handler', [])
        else:
            print("Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    sys.exit(main())

