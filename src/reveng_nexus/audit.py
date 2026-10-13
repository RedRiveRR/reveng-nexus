"""Append-only, metadata-only audit log.

Records which operation/provider/tool ran, when, for how long, with which outcome and
which *argument keys* were supplied. Argument values, target bytes, decompiled source
and model output are never written here. Error text is redacted and bounded.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .redaction import redact_text

_ALLOWED_FIELDS = {
    "event",
    "provider_id",
    "tool_name",
    "operation",
    "outcome",
    "duration_ms",
    "argument_keys",
    "target_sha256",
    "case_id",
    "tool_class",
    "policy_reason",
    "error_code",
    "error",
    "attempt",
    "detail",
    "transport",
    "count",
}
_MAX_ERROR = 500


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self._lock = threading.Lock()
        self.write_failures = 0

    def write(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {"timestamp": round(time.time(), 3), "event": event}
        for key, value in fields.items():
            if key not in _ALLOWED_FIELDS or value is None:
                continue
            if key in {"error", "policy_reason", "detail"}:
                value = redact_text(str(value))[:_MAX_ERROR]
            elif key == "argument_keys":
                value = sorted(str(k) for k in value)[:64]
            record[key] = value
        line = json.dumps(record, ensure_ascii=False)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except OSError:
            # Never crash analysis because the audit disk is full; surfaced via nexus_status.
            self.write_failures += 1

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, min(limit, 1000)) :]
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out
