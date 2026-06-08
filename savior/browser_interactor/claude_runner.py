"""Claude subprocess runner for the Browser Interactor layer (Section 5.2)."""

from pathlib import Path
import shutil
import subprocess
import sys
import time


def _project_mcp_config_path() -> Path:
    """Return the repository-local MCP config used for browser automation."""
    return Path(__file__).resolve().parents[2] / ".mcp.json"


def _inject_project_mcp_config(command):
    """Explicitly load the repo MCP config when it exists."""
    mcp_config = _project_mcp_config_path()
    if not mcp_config.exists():
        return command

    if isinstance(command, str):
        return f'{command} --strict-mcp-config --mcp-config "{mcp_config}"'

    return [*command, "--strict-mcp-config", "--mcp-config", str(mcp_config)]


def _build_command():
    """Build the Claude CLI command while preserving Windows behavior."""
    claude_cmd = shutil.which("claude")
    if not claude_cmd and sys.platform != "win32":
        raise FileNotFoundError("claude command not found in PATH")
    if sys.platform == "win32":
        return _inject_project_mcp_config("claude -p --dangerously-skip-permissions"), True
    return _inject_project_mcp_config([claude_cmd, "-p", "--dangerously-skip-permissions"]), False


def run_claude(prompt, timeout_seconds=600, max_retries=2):
    """Run Claude with retry/timeout handling and stdin prompt delivery."""
    command, use_shell = _build_command()
    last_error = None

    for attempt in range(1, max_retries + 1):
        started = time.time()
        try:
            result = subprocess.run(
                command,
                input=prompt,
                shell=use_shell,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
            output = result.stdout + result.stderr

            # Non-zero exit with empty output: retry once (per LLMORACLE plan)
            if result.returncode != 0 and not output.strip() and attempt < max_retries:
                last_error = f"claude exited {result.returncode} with empty output"
                continue

            return {
                "output": output,
                "return_code": result.returncode,
                "duration_seconds": time.time() - started,
                "attempts": attempt,
            }
        except subprocess.TimeoutExpired:
            last_error = f"claude command timed out after {timeout_seconds} seconds"
        except Exception as exc:
            last_error = str(exc)

        if attempt == max_retries:
            raise RuntimeError(last_error)

    raise RuntimeError(last_error or "claude command failed")


