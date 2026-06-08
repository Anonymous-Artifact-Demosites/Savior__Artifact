"""Shared CAPTCHA resolution handler integration."""

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path


def _captcha_script_path():
    """Return the repository-local handler.py path, supporting both layouts."""
    base = Path(__file__).resolve()
    bundled = base.parents[1] / "handler.py"
    if bundled.exists():
        return bundled
    return base.parents[2] / "handler.py"


def _run_python_mode(args):
    """Execute handler.py via subprocess in normal Python mode."""
    captcha_script = _captcha_script_path()
    if not captcha_script.exists():
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": json.dumps(
                {
                    "success": False,
                    "error": f"handler.py not found at: {captcha_script}",
                }
            ),
        }

    command = [sys.executable, str(captcha_script)] + list(args)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _run_packaged_mode(args):
    """Execute the bundled handler module when running from a packaged executable."""
    saved_argv = sys.argv.copy()
    sys.argv = ["handler"] + list(args)
    try:
        captcha_module = importlib.import_module("handler")
        try:
            captcha_module.main()
            return {"exit_code": 0, "stdout": "", "stderr": ""}
        except SystemExit as exc:
            return {"exit_code": exc.code if exc.code is not None else 0, "stdout": "", "stderr": ""}
    except Exception as exc:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": json.dumps(
                {
                    "success": False,
                    "error": f"Exception in CAPTCHA handler: {str(exc)}",
                }
            ),
        }
    finally:
        sys.argv = saved_argv


def run_args(args, packaged=None):
    """Run the CAPTCHA handler with the provided argument vector and return stdout/stderr."""
    if packaged is None:
        packaged = getattr(sys, "frozen", False)
    if packaged:
        return _run_packaged_mode(args)
    return _run_python_mode(args)


def solve(captcha_type, site_key=None, url=None, extra_args=None, packaged=None):
    """Solve a captcha using the shared handler.py subprocess entry point."""
    args = [captcha_type]
    if site_key is not None:
        args.append(site_key)
    if url is not None:
        args.append(url)
    if extra_args:
        args.extend(extra_args)
    result = run_args(args, packaged=packaged)
    payload = result["stdout"].strip()
    if payload:
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return {
                "success": result["exit_code"] == 0,
                "raw_stdout": payload,
                "raw_stderr": result["stderr"],
            }
    return {
        "success": result["exit_code"] == 0,
        "raw_stdout": "",
        "raw_stderr": result["stderr"],
    }


def call_handler_entry(argv=None):
    """CLI-compatible implementation of the CAPTCHA handler wrapper."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        error_msg = {
            "success": False,
            "error": "No command provided. Usage: python handler.py <command> [args...]",
        }
        print(json.dumps(error_msg), file=sys.stderr)
        return 1

    result = run_args(args)
    if result["stdout"]:
        print(result["stdout"], end="")
    if result["stderr"]:
        print(result["stderr"], end="", file=sys.stderr)
    return result["exit_code"]

def captcha_wrapper_call(args):
    """Function-compatible implementation of the CAPTCHA wrapper."""
    result = run_args(args)
    if result["stdout"]:
        print(result["stdout"], end="")
    if result["stderr"]:
        print(result["stderr"], end="", file=sys.stderr)
    return result["exit_code"]


def captcha_wrapper_entry(argv=None):
    """CLI-compatible implementation of captcha_wrapper.py."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("Usage: python captcha_wrapper.py <handler_args...>")
        print("Example: python captcha_wrapper.py balance")
        return 1
    return captcha_wrapper_call(args)
