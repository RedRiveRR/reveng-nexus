"""Adapter for REA (morluto/rea, npm ``rea-agents``) as an internal, static-only Nexus provider.

REA advertises 207 tools in one catalogue, including process capture, debuggers, Frida, ADB,
browser automation, file extraction and deep-engine (Ghidra/Hopper/IDA) sessions. It has no
read-only mode and no path containment of its own. Nexus therefore:

* allowlists exactly two tools, reviewed at the pin as static parsers of one regular file that
  never execute the target: ``analyze_javascript_application`` (JavaScript/Electron ASAR parsed
  as inert text; REA copies the archive to a ``rea-asar-snapshot-*`` temp dir and spawns its own
  Node worker, in a REA-owned Job Object, cwd a private temp dir) and ``inspect_electron_fuses``
  (in-process byte reader);
* disables both operations when the live catalogue or server version differs from the pin;
* classifies every other tool, current or future, as ``blocked`` (not even ``tool_overrides``
  can reopen one), and
* is adapter-only: no raw passthrough, so REA only ever sees the hash-verified staged copy that
  Nexus passes, never a caller-chosen path.

Results are REA Evidence records (``structuredContent`` = the JSON text block). REA's own evidence
ids, digests, limitations and unknowns are kept; local paths are replaced by the target's display
name in the normalised result (the raw output keeps them).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..errors import NexusError, ProviderCallError
from .base import McpAdapter, UpstreamPin

_ALLOWED = ("analyze_javascript_application", "inspect_electron_fuses")
# Pinned catalogue size at rea-agents 6.5.0 (src/contracts/toolContracts.ts). A different
# catalogue (or server version) means the upstream differs from the pin: every unlisted tool stays
# blocked and both operations are reported unavailable (_drift).
CATALOGUE_SIZE = 207
# sha256 over the sorted tool names, newline-joined, of the real tools/list on 2026-10-15.
CATALOGUE_SHA256 = "821ff86b6022644383456368e470cb72c92db8471785c41821bd0c99eeecde99"
_JS_FORMATS = {".asar": "asar"}


class ReaAdapter(McpAdapter):
    def _binding_status(self, provider, required):
        # Fail closed on upstream drift: the two allowlisted tools were reviewed at this exact pin,
        # so a different catalogue or server version disables both operations (also for require()).
        drift = _drift(provider, self.pin.package_version)
        if drift:
            return {"available": False, "reason": drift, "tools": list(required)}
        return super()._binding_status(provider, required)

    async def perform(self, provider, operation, target, params):
        try:
            return await super().perform(provider, operation, target, params)
        except NexusError:
            raise
        except (AttributeError, TypeError, ValueError, KeyError) as exc:
            # A wrongly typed field in REA's Evidence must be a bounded provider error, not a crash.
            raise ProviderCallError(
                f"{provider.id}: REA returned a malformed {operation} Evidence record ({type(exc).__name__})"
            ) from exc

    async def op_js_application(self, provider, target, session, params):
        staged = target.staged_path(provider.id)
        # REA applies analysis_timeout_ms per JavaScript source, not per call
        # (javascriptAnalysisResourceControls.ts:72-79); the whole call stays bounded by Nexus's
        # timeout_seconds, whose expiry sends notifications/cancelled to REA.
        budget_ms = int(max(10.0, float(provider.config.timeout_seconds) - 10.0) * 1000)
        arguments = {
            "input_path": str(staged),
            "format": _JS_FORMATS.get(Path(target.display_name).suffix.lower(), "auto"),
            "integrity_policy": "record-and-continue",
            "detail": "summary",
            "analysis_timeout_ms": min(budget_ms, 300_000),
        }
        payload, _text, raw = await self.call(provider, target, "analyze_javascript_application", arguments)
        record, warnings = _evidence(payload, target, provider.id, "analyze_javascript_application", staged)
        view = record.get("normalized_result") or {}
        summary = view.get("summary") if isinstance(view.get("summary"), dict) else {}
        normalized = {
            "rea_evidence_id": record.get("evidence_id"),
            "rea_parent_evidence_id": view.get("parent_evidence_id"),
            "rea_operation": view.get("parent_operation") or record.get("operation"),
            "format": summary.get("format"),
            "statistics": summary.get("statistics") or {},
            "electron": summary.get("electron") or {},
            "coverage": summary.get("coverage") or view.get("coverage") or {},
            "unknowns": _strings(view.get("unknowns")),
            "limitations": list(dict.fromkeys(_strings(view.get("limitations")) + _strings(record.get("limitations")))),
            "confidence": record.get("confidence"),
        }
        if normalized["rea_operation"] != "analyze_javascript_application":
            warnings.append(f"REA answered with operation {normalized['rea_operation']!r}")
        return self._result(
            provider, target, "js.application", "analyze_javascript_application", normalized, raw, warnings
        )

    async def op_electron_fuses(self, provider, target, session, params):
        staged = target.staged_path(provider.id)
        payload, _text, raw = await self.call(provider, target, "inspect_electron_fuses", {"path": str(staged)})
        record, warnings = _evidence(payload, target, provider.id, "inspect_electron_fuses", staged)
        result = record.get("normalized_result") or {}
        fuses: list[dict[str, Any]] = []
        for sl in result.get("slices") or []:
            for sentinel in (sl.get("sentinels") or []) if isinstance(sl, dict) else []:
                for fuse in sentinel.get("fuses") or []:
                    if isinstance(fuse, dict):
                        fuses.append(
                            {
                                "slice": sl.get("index"),
                                "wire_version": sentinel.get("wire_version"),
                                "index": fuse.get("index"),
                                "name": fuse.get("name"),
                                "state": fuse.get("state"),
                            }
                        )
        if not fuses:
            warnings.append("no Electron fuse wire was found; fuse state is unknown, not disabled")
        normalized = {
            "rea_evidence_id": record.get("evidence_id"),
            "format": (result.get("artifact") or {}).get("format"),
            "fuses": fuses,
            "runtime_implications": [r for r in result.get("runtime_implications") or [] if isinstance(r, dict)],
            "limitations": _strings(result.get("limitations") or record.get("limitations")),
            "confidence": record.get("confidence"),
        }
        return self._result(provider, target, "electron.fuses", "inspect_electron_fuses", normalized, raw, warnings)

    def _result(self, provider, target, operation, tool, normalized, raw, warnings):
        version = provider.server_info.get("version")
        return self.result(
            provider,
            operation,
            tool,
            normalized,
            raw,
            subject_type="artifact",
            subject_name=target.display_name,
            engine_version=f"rea-agents {version} (server-reported)" if version else None,
            evidence_kind="engine_derived",
            claim=f"REA static {operation} of {target.display_name}",
            warnings=warnings,
        )


def _evidence(payload: Any, target, provider_id: str, tool: str, staged: Path) -> tuple[dict[str, Any], list[str]]:
    """Check the REA Evidence envelope and that it describes the staged copy of this target."""
    if not isinstance(payload, dict) or not isinstance(payload.get("normalized_result"), dict):
        raise ProviderCallError(f"{provider_id}/{tool} did not return an REA Evidence record")
    subject = payload.get("subject")
    digests = subject.get("digest") if isinstance(subject, dict) else None
    digest = digests.get("sha256") if isinstance(digests, dict) else None
    # Exact match only: REA's digestSchema is lowercase hex (src/domain/digests.ts:19), as is
    # target.sha256; a missing, other-algorithm or differently cased digest fails closed.
    if not isinstance(digest, str) or digest != target.sha256:
        raise ProviderCallError(
            f"{provider_id}/{tool} analysed a different file (sha256 {str(digest)[:16]}...), not the target"
        )
    warnings: list[str] = []
    if payload.get("raw_result") is None and tool == "analyze_javascript_application":
        warnings.append("REA retained the full analysis in its own session; only the summary view is stored")
    replacements = {str(staged): target.display_name, str(target.original_path): target.display_name}
    replacements[str(target.work_dir).rstrip("\\/")] = WORK_TOKEN
    return _scrub(payload, _local_path_pattern(replacements)), warnings


WORK_TOKEN = "<nexus-work>"


def _local_path_pattern(replacements: dict[str, str]) -> tuple[re.Pattern[str], dict[str, str]]:
    """One case-insensitive pattern for the local paths Nexus passed, in every form REA may echo.

    Each path matches as written, with forward slashes and as a ``file:///`` URL, and only up to a
    boundary (end, separator, quote, whitespace or ``:``), so a staged ``app.asar`` never matches
    inside ``app.asarx``. Everything after the match is kept.
    """
    forms: dict[str, str] = {}
    for path, replacement in replacements.items():
        if not path:
            continue
        slashed = path.replace("\\", "/")
        url = "file:///" + slashed.lstrip("/")
        # also percent-encoded (a space or non-ASCII in the work dir) and JSON-escaped (a path
        # inside a JSON-encoded string, where every backslash is doubled)
        encoded = "file:///" + quote(slashed.lstrip("/"), safe="/:")
        for form in (path, slashed, url, encoded, path.replace("\\", "\\\\")):
            forms[form.casefold()] = replacement
    alternation = "|".join(re.escape(f) for f in sorted(forms, key=len, reverse=True))
    pattern = re.compile(rf"(?:{alternation})(?=$|[\\/\s\"':;,)\]]|\.\w+(?:$|[\\/\s\"':;,)\]]))", re.IGNORECASE)
    return pattern, forms


def _scrub(value: Any, matcher: tuple[re.Pattern[str], dict[str, str]]) -> Any:
    """Replace the local paths REA echoes back (keys and values, also inside messages).

    Target-derived strings that merely look like paths (an IPC channel "/api/x", another drive, a
    module specifier) are kept verbatim; only the paths Nexus itself passed are rewritten.
    """
    if isinstance(value, dict):
        return {_scrub(k, matcher): _scrub(v, matcher) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, matcher) for v in value]
    if isinstance(value, str):
        pattern, forms = matcher
        return pattern.sub(lambda m: forms[m.group(0).casefold()], value)
    return value


def _drift(provider, package_version: str | None) -> str | None:
    """Why the connected server is not the reviewed pin (None when it matches or is not connected)."""
    if not provider.started or not provider._tools:
        return None
    names = sorted(provider._tools)
    digest = hashlib.sha256("\n".join(names).encode()).hexdigest()
    if len(names) != CATALOGUE_SIZE or digest != CATALOGUE_SHA256:
        return (
            f"REA tool catalogue differs from the pin ({len(names)} tools, sha256 {digest[:12]}; pinned "
            f"{CATALOGUE_SIZE}, {CATALOGUE_SHA256[:12]}): re-review the upstream before use"
        )
    version = provider.server_info.get("version")
    if version != package_version:
        return (
            f"REA server version {str(version)[:40]!r} differs from the pin ({package_version}): re-review before use"
        )
    return None


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)][:64] if isinstance(value, list) else []


REA = ReaAdapter(
    name="rea",
    engine="rea",
    engine_family="rea",
    pin=UpstreamPin(
        repository="https://github.com/morluto/rea",
        revision="3b79af28e80785afce9f5998d8f03289402a1847",
        package="rea-agents (npm)",
        package_version="6.5.0",
        verified="runtime",
        verified_on="2026-10-15",
        notes=(
            "npm integrity sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A== "
            "(tag rea-agents-6.5.0, SLSA provenance to this commit); run on Node 24.21.0, never via npx."
        ),
    ),
    manifest={tool: "read" for tool in _ALLOWED},
    bindings={
        "js.application": ("analyze_javascript_application",),
        "electron.fuses": ("inspect_electron_fuses",),
    },
    trust_annotations=False,
    protocol_mode="auto",
    unlisted_tool_class="blocked",
    adapter_only=True,
    limitations=(
        "Static only: two allowlisted tools; REA's other 205 tools (process capture, debuggers, Frida, "
        "ADB, browser, extraction, deep-engine sessions) are blocked.",
        "Adapter-only: no raw passthrough; REA receives only the hash-verified staged copy.",
        "REA's own engine (Babel-based JavaScript parsing, byte-level fuse reading); no Ghidra/IDA/Hopper.",
        "The JavaScript result is REA's summary view; the full Evidence stays in the REA session.",
    ),
)
