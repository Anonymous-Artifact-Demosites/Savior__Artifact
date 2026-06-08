#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OAuth Security Test Runner entry point.

Delegates to savior.runner.batch_runner for the actual implementation.
CLI interface: --urls, --url-file, --skip-oauth-scan, --iterations.
"""

import sys
from pathlib import Path

# Ensure savior package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from savior.runner.batch_runner import main


if __name__ == "__main__":
    sys.exit(main() or 0)
