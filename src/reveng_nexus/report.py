"""Case report export (JSON and Markdown).

Reports keep evidence classes visibly separate (direct / engine-derived / AI-generated /
analyst notes), list every recorded disagreement, and never present AI output as source
code of the original program. Raw provider output is excluded unless requested.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .evidence import EvidenceStore

_KIND_TITLES = {
    "direct_observation": "Direct observations (parsed from the artifact)",
    "engine_derived": "Engine-derived analysis",
    "ai_generated": "AI-generated interpretations (unverified)",
    "analyst_note": "Analyst / agent notes",
}
_FENCE = re.compile(r"`{3,}")


def _md_escape(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _fence(text: str, lang: str = "") -> str:
    # Target-derived text is data: neutralise fence breakouts so it cannot restructure the report.
    safe = _FENCE.sub("ʼʼʼ", text)
    return f"```{lang}\n{safe}\n```"


def _hex(value: Any) -> str:
    return f"{value:#x}" if isinstance(value, int) else ("" if value is None else str(value))


def build_bundle(store: EvidenceStore, case_id: str, *, include_raw: bool = False) -> dict[str, Any]:
    bundle = store.case_bundle(case_id, include_raw=include_raw)
    bundle["generated_at"] = datetime.now(UTC).isoformat()
    bundle["generator"] = f"reveng-nexus {__version__}"
    bundle["disclaimer"] = (
        "Engine output is an interpretation of machine code. AI-generated reconstructions are not the "
        "original source code and are unverified unless a review says otherwise. Matching results from "
        "wrappers of the same engine are consistency, not independent confirmation."
    )
    return bundle


def render_markdown(bundle: dict[str, Any], *, code_excerpt_lines: int = 60) -> str:
    case = bundle["case"]
    lines: list[str] = [
        f"# RevEng Nexus report — {case['title']}",
        "",
        f"- Case: `{case['case_id']}`",
        f"- Generated: {bundle['generated_at']} by {bundle['generator']} (schema v{bundle['schema_version']})",
        "",
        f"> {bundle['disclaimer']}",
        "",
        "## Targets",
        "",
        "| SHA-256 | Name | Format | Kind | Size |",
        "|---|---|---|---|---|",
    ]
    for target in bundle["targets"]:
        lines.append(
            f"| `{target['target_id']}` | {_md_escape(target['display_name'])} | {target.get('format')} | "
            f"{target.get('kind')} | {target['size_bytes']} |"
        )
    lines.append("")

    findings = bundle["findings"]
    lines += ["## Findings", ""]
    if not findings:
        lines += ["_No findings recorded._", ""]
    for finding in findings:
        lines += [
            f"### {_md_escape(finding['title'])}",
            "",
            f"- ID: `{finding['finding_id']}` · severity **{finding['severity']}** · status **{finding['status']}** "
            f"· confidence **{finding['confidence']}**",
        ]
        if finding.get("confidence_rationale"):
            lines.append(f"- Confidence rationale: {_md_escape(finding['confidence_rationale'])}")
        lines += [
            "",
            finding["description"],
            "",
            "| Evidence | Role | Kind | Provider/tool | Status |",
            "|---|---|---|---|---|",
        ]
        for ev in finding["evidence"]:
            lines.append(
                f"| `{ev['evidence_id']}` | {ev['role']} | {ev['evidence_kind']} | "
                f"{ev['provider_id']} / {_md_escape(ev['tool_name'])} | {ev['status']} |"
            )
        if any(ev["evidence_kind"] == "ai_generated" for ev in finding["evidence"]):
            lines.append("")
            lines.append("> ⚠ This finding cites AI-generated evidence; treat those parts as hypotheses.")
        lines.append("")

    comparisons = bundle["comparisons"]
    lines += ["## Cross-engine comparisons", ""]
    if not comparisons:
        lines += ["_No comparisons recorded._", ""]
    for cmp_ in comparisons:
        details = cmp_.get("details") or {}
        lines += [
            f"### {_md_escape(cmp_['subject'])} — {cmp_['assessment']}",
            "",
            f"- Comparison `{cmp_['comparison_id']}` ({cmp_['operation']}); confidence: "
            f"**{details.get('confidence', 'n/a')}**; engine families: {details.get('engine_families')}",
        ]
        for reason in details.get("rationale", []):
            lines.append(f"- {_md_escape(reason)}")
        if details.get("disagreements"):
            lines += ["", "**Disagreements (preserved, not resolved automatically):**", ""]
            for item in details["disagreements"]:
                lines.append(
                    f"- [{item.get('severity')}] {item.get('aspect')}: {_md_escape(item.get('detail', ''))} — "
                    f"`{_md_escape(json.dumps(item.get('values'), default=str))[:400]}`"
                )
        if details.get("agreements"):
            lines += ["", "**Agreements:** " + ", ".join(sorted({a.get("aspect", "?") for a in details["agreements"]}))]
        for check in details.get("ai_checks", []):
            lines.append(f"- AI check ({check['provider_id']}): {_md_escape(check['interpretation'])}")
        for lim in details.get("limitations", []):
            lines.append(f"- Limitation: {_md_escape(lim)}")
        lines.append("")

    lines += ["## Evidence", ""]
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for ev in bundle["evidence"]:
        by_kind.setdefault(ev["evidence_kind"], []).append(ev)
    for kind in ("direct_observation", "engine_derived", "ai_generated", "analyst_note"):
        rows = by_kind.get(kind, [])
        if not rows:
            continue
        lines += [
            f"### {_KIND_TITLES[kind]}",
            "",
            "| ID | Operation | Subject | Provider | Engine | Status | Claim |",
            "|---|---|---|---|---|---|---|",
        ]
        for ev in rows:
            engine = f"{ev.get('engine') or ''} {ev.get('engine_version') or ''}".strip()
            lines.append(
                f"| `{ev['evidence_id']}` | {ev.get('operation')} | {_md_escape(ev['subject'])} | {ev['provider_id']} "
                f"| {_md_escape(engine)} | {ev['status']} | {_md_escape(ev['claim'])[:160]} |"
            )
        lines.append("")
        for ev in rows:
            norm = ev.get("normalized") or {}
            code = norm.get("code") if isinstance(norm, dict) else None
            if code:
                excerpt = "\n".join(str(code).splitlines()[:code_excerpt_lines])
                label = "AI-generated, unverified" if kind == "ai_generated" else "engine output"
                lines += [
                    f"<details><summary>{ev['evidence_id']} — {_md_escape(ev['subject'])} ({label})</summary>",
                    "",
                    _fence(excerpt, "c"),
                    "",
                    "</details>",
                    "",
                ]
            if ev.get("model"):
                model = ev["model"]
                lines.append(
                    f"- `{ev['evidence_id']}` model provenance: {model.get('model')} "
                    f"(variant {model.get('variant')}, input {model.get('input_kind')} from "
                    f"`{model.get('input_evidence_id')}`)"
                )
            for warning in ev.get("warnings") or []:
                lines.append(f"- `{ev['evidence_id']}` warning: {_md_escape(warning)}")
        lines.append("")

    if bundle.get("reviews"):
        lines += ["## Reviews", "", "| Subject | Status | Note | When |", "|---|---|---|---|"]
        for review in bundle["reviews"]:
            lines.append(
                f"| {review['subject_type']} `{review['subject_id']}` | {review['status']} | "
                f"{_md_escape(review['note'])[:200]} | {review['created_at']} |"
            )
        lines.append("")

    lines += [
        "## Limitations",
        "",
        "- Only evidence recorded in this case is included; absence of a finding is not evidence of absence.",
        "- Engine versions are as reported by each provider at analysis time.",
        "- Raw provider outputs are stored in the local evidence database (hash-addressed) and omitted here.",
        "",
    ]
    return "\n".join(lines)


def export_report(
    store: EvidenceStore,
    case_id: str,
    out_dir: Path,
    *,
    formats: tuple[str, ...] = ("md", "json"),
    include_raw: bool = False,
) -> dict[str, Any]:
    bundle = build_bundle(store, case_id, include_raw=include_raw)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_case = re.sub(r"[^A-Za-z0-9_-]", "_", case_id)
    written: dict[str, str] = {}
    if "json" in formats:
        path = out_dir / f"{safe_case}-{stamp}.json"
        path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        written["json"] = str(path)
    if "md" in formats:
        path = out_dir / f"{safe_case}-{stamp}.md"
        path.write_text(render_markdown(bundle), encoding="utf-8")
        written["md"] = str(path)
    return {
        "case_id": case_id,
        "files": written,
        "counts": {
            "targets": len(bundle["targets"]),
            "evidence": len(bundle["evidence"]),
            "findings": len(bundle["findings"]),
            "comparisons": len(bundle["comparisons"]),
        },
    }
