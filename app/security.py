"""Explicit trust-boundary checks for a local support-agent sandbox.

These are illustrative heuristics, not a comprehensive prompt-injection detector.
Enforcement uses identity/tenant/approval checks independent of these regexes.
"""
from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlparse

PROMPT_PATTERNS = [
    re.compile(x, re.I) for x in [
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
        r"(?:reveal|print|show)\s+(?:the\s+)?(?:system|developer)\s+prompt",
        r"(?:override|bypass|disable)\s+(?:the\s+)?(?:rules|policy|guardrails)",
        r"(?:you\s+are\s+now|act\s+as)\s+(?:the\s+)?(?:system|developer)",
        r"(?:execute|run)\s+(?:shell|command|terminal)",
        r"(?:send|forward|exfiltrate)\s+.*(?:secrets?|tokens?|api[ -]?keys?)",
    ]
]
SENSITIVE = re.compile(r"\b(?:password|private[ _-]?key|api[ _-]?key)\b|\bBearer\s+\S{8,}", re.I)
MAX_UNTRUSTED_LENGTH = 4000
ALLOWED_REFERENCE_HOSTS = frozenset({"docs.example.com", "support.example.com"})


def canonicalize(value: str) -> str:
    result = value
    for _ in range(3):
        expanded = html.unescape(unquote(result))
        if expanded == result:
            break
        result = expanded
    return unicodedata.normalize("NFKC", result)


def screen_untrusted(text: str) -> list[str]:
    if not isinstance(text, str):
        return ["invalid_content"]
    flags: list[str] = []
    if len(text) > MAX_UNTRUSTED_LENGTH:
        flags.append("oversized_content")
    normalized = canonicalize(text[:MAX_UNTRUSTED_LENGTH])
    if any(p.search(normalized) for p in PROMPT_PATTERNS):
        flags.append("prompt_injection_indicator")
    if SENSITIVE.search(normalized):
        flags.append("sensitive_content_indicator")
    return flags


def safe_reference_url(value: str) -> bool:
    """No HTTP request is made; all external URLs are untrusted by default."""
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlparse(value)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
            return False
        hostname = parsed.hostname
        if not hostname or hostname.rstrip(".").lower() not in ALLOWED_REFERENCE_HOSTS:
            return False
        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            return True
    except (ValueError, TypeError):
        return False