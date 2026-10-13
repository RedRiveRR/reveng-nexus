"""Secret redaction for logs, diagnostics and displayed configuration."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|apikey|auth(orization)?|credential|private[_-]?key|"
    r"session[_-]?id|cookie)",
    re.IGNORECASE,
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Bearer / basic authorization headers.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    # key=value or key: value pairs whose key looks sensitive.
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|apikey|"
            r"credential|private[_-]?key)[A-Za-z0-9_.-]*)\s*([=:])\s*(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1\2[REDACTED]",
    ),
    # Credentials embedded in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    # Common provider key shapes (OpenAI/Anthropic/GitHub/HF/AWS access keys).
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,})\b"), "[REDACTED_KEY]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,})\b"), "[REDACTED_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_KEY]"),
)


def redact_text(text: str) -> str:
    """Remove credential-like substrings from free text."""
    redacted = str(text)
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    """Redact values whose key looks sensitive; recurse into nested mappings."""
    out: dict[str, Any] = {}
    for key, value in values.items():
        if SENSITIVE_KEY.search(str(key)):
            out[key] = "[REDACTED]"
        elif isinstance(value, Mapping):
            out[key] = redact_mapping(value)
        elif isinstance(value, str):
            out[key] = redact_text(value)
        else:
            out[key] = value
    return out
