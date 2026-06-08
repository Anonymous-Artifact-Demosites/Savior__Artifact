"""URL pre-filtering for SAVIOR (Section 6.3).

Two-stage filtering pipeline:
1. Infrastructure Pruning - exclude CDN, API, and infrastructure domains
2. Contextual Relevance Filtering - LLM-based classification to exclude
   IdP portals, enterprise auth, and regional identity services

This module contains URL filtering and normalization helpers used before
task execution.
"""

from __future__ import annotations

import re
import sys
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Stage 1: Infrastructure Pruning (pattern-based, no LLM)
# ---------------------------------------------------------------------------

INFRASTRUCTURE_PATTERNS = [
    # CDN and static content
    r".*\.googleapis\.com$",
    r".*\.gstatic\.com$",
    r".*\.cloudflare\.com$",
    r".*\.cloudfront\.net$",
    r".*\.akamai\.net$",
    r".*\.fastly\.net$",
    r".*cdn\.",
    r".*static\.",
    # API endpoints
    r".*\.api\.",
    r"api\..*",
    # OAuth/identity providers (as targets - not useful to test the IdP itself)
    r"accounts\.google\.com$",
    r"login\.microsoftonline\.com$",
    r".*\.facebook\.com$",
    r"appleid\.apple\.com$",
    r"github\.com/login/oauth$",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE) for p in INFRASTRUCTURE_PATTERNS]


def is_infrastructure(url: str) -> tuple[bool, str]:
    """Check if a URL belongs to infrastructure/CDN/IdP domains.

    Returns (excluded, reason). If excluded is True, the URL should be
    skipped and reason explains why.
    """
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return False, ""

    hostname = hostname.lower()

    for pattern in _compiled_patterns:
        if pattern.match(hostname):
            return True, f"Infrastructure domain: {hostname} matches {pattern.pattern}"

    return False, ""


def format_url(url_input: str) -> str | None:
    """Format and normalize URL input.

    Normalization behavior:
    - Takes LAST CSV column (not first)
    - Preserves explicit http:// (does NOT force https upgrade)
    - Only adds https:// for valid domain patterns
    - Returns None for invalid input
    """
    if not url_input or not url_input.strip():
        return None

    url = url_input.strip()

    if url.startswith("#"):
        return None

    # CSV: take LAST column.
    if "," in url:
        parts = url.split(",", 1)
        url = parts[-1].strip()

    # Already has protocol - keep as-is (including http://)
    if re.match(r"^https?://", url):
        return url

    # Match domain pattern: contains at least one dot and valid characters
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$", url):
        return f"https://{url}"

    return None


def read_url_list(urls=None, url_file=None) -> list[str]:
    """Read and deduplicate URLs from CLI args, file, or stdin.

    Supports CLI arguments, files, and stdin pipelines.
    """
    result = []

    # From command line arguments
    if urls:
        for u in urls:
            if u:
                normalized = format_url(u.strip())
                if normalized:
                    result.append(normalized)

    # From file
    if url_file:
        from pathlib import Path
        if Path(url_file).exists():
            with open(url_file, "r", encoding="utf-8") as f:
                for line in f:
                    normalized = format_url(line.strip())
                    if normalized:
                        result.append(normalized)

    # From stdin (pipeline)
    if not sys.stdin.isatty():
        for line in sys.stdin:
            normalized = format_url(line.strip())
            if normalized:
                result.append(normalized)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(result))


def filter_urls(urls: list[str]) -> tuple[list[str], list[dict]]:
    """Apply infrastructure pruning to a URL list.

    Returns (passed_urls, filter_log). Each entry in filter_log is
    {url, excluded, reason}.
    """
    passed = []
    log = []

    for url in urls:
        excluded, reason = is_infrastructure(url)
        log.append({"url": url, "excluded": excluded, "reason": reason})
        if not excluded:
            passed.append(url)

    return passed, log
