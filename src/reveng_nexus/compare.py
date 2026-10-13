"""Cross-engine comparison that preserves disagreements and accounts for independence.

Principles
----------
* Results are compared on *extracted features* (function identity, calls, constants,
  string literals, control-structure counts, instruction-level call targets), never on
  raw text equality: two decompilers legitimately print different C for the same code.
* Addresses are compared after rebasing on each provider's reported image base. If a
  provider's base is unknown the comparison says so instead of assuming.
* Agreement among wrappers of the same engine family (two Ghidra servers) is reported
  as *consistency*, not independent corroboration.
* AI-generated output never raises confidence; it is checked against engine evidence.
* The result is a qualitative assessment with explicit reasons — not a vote count.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

_C_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "do",
    "else",
    "case",
    "goto",
    "break",
    "continue",
    "default",
    "typedef",
    "struct",
    "union",
    "enum",
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "const",
    "volatile",
    "static",
    "extern",
    "register",
    "auto",
    "bool",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "code",
    "byte",
    "word",
    "dword",
    "qword",
    "ulong",
    "uint",
    "ushort",
    "uchar",
    "longlong",
    "ulonglong",
    "__int64",
    "__int32",
    "__int16",
    "__int8",
    "_BYTE",
    "_WORD",
    "_DWORD",
    "_QWORD",
    "LOBYTE",
    "HIBYTE",
    "LOWORD",
    "HIWORD",
    "CONCAT11",
    "CONCAT22",
    "CONCAT44",
    "SUB41",
    "SUB81",
    "ZEXT14",
    "ZEXT48",
    "SEXT48",
}
_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_@$.:]*)\s*\(")
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_HEXNUM = re.compile(r"\b0x[0-9a-fA-F]+\b")
_DECNUM = re.compile(r"(?<![\w.])\d+(?![\w.])")
# C integer-literal suffixes (2LL, 0x10u, 7ULL) differ between decompilers; strip them first.
_INT_SUFFIX = re.compile(r"\b(0x[0-9a-fA-F]+|\d+)(?:[uU][lL]{0,2}|[lL]{1,2}[uU]?)\b")
_CONTROL = ("if", "for", "while", "switch", "goto", "return")
_CALL_MNEMONICS = {"call", "bl", "blr", "jal", "jalr", "bl.w", "blx"}
_TRIVIAL_CONSTANTS = {0, 1}
_DECOMPILE_ASPECTS = {"callees", "constants", "string_literals", "control_structure", "parameter_count"}
_DISASM_ASPECTS = {"instruction_call_targets", "instruction_count", "instruction_sequence"}
_IDENTITY_ASPECTS = {"function_start", "function_name", "function_size"}
# Weakest first: the overall verdict is the minimum over the content groups.
_VERDICT_RANK = {
    "disagreement": 0,
    "single_source": 1,
    "same_family_consistency": 2,
    "independent_partial_agreement": 3,
    "independent_agreement": 4,
}
_VERDICT_CONFIDENCE = {
    "disagreement": "low",
    "single_source": "low",
    "same_family_consistency": "medium",
    "independent_partial_agreement": "medium",
    "independent_agreement": "high",
    "insufficient_evidence": "none",
}


def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    return re.sub(r"//[^\n]*", " ", code)


def _first_line_signature(code: str) -> str:
    for line in code.splitlines():
        line = line.strip()
        if line and "(" in line and not line.startswith(("/", "*", "#")):
            return line
    return ""


def decompile_features(code: str, own_name: str | None = None) -> dict[str, Any]:
    body = _strip_comments(code)
    signature = _first_line_signature(body)
    sig_name = None
    match = _CALL.search(signature)
    if match:
        sig_name = match.group(1)
    names = {own_name, sig_name} - {None}
    calls = {m.group(1) for m in _CALL.finditer(body) if m.group(1) not in _C_KEYWORDS and m.group(1) not in names}
    strings = set(_STRING.findall(body))
    no_strings = _INT_SUFFIX.sub(r"\1", _STRING.sub('""', body))  # 2LL / 0x10u -> 2 / 0x10
    constants = {int(h, 16) for h in _HEXNUM.findall(no_strings)}
    constants |= {int(d) for d in _DECNUM.findall(_HEXNUM.sub(" ", no_strings)) if len(d) < 19}
    control = {kw: len(re.findall(rf"\b{kw}\b", no_strings)) for kw in _CONTROL}
    params = None
    if signature and "(" in signature and ")" in signature:
        inner = signature[signature.index("(") + 1 : signature.rindex(")")].strip()
        params = 0 if inner in {"", "void"} else inner.count(",") + 1
    return {
        "calls": calls,
        "strings": strings,
        "constants": constants - _TRIVIAL_CONSTANTS,
        "control": control,
        "param_count": params,
        "lines": sum(1 for line in body.splitlines() if line.strip()),
    }


def disassembly_features(instructions: list[dict[str, Any]], image_base: int | None = None) -> dict[str, Any]:
    """Features of an instruction listing; call targets are rebased when the base is known."""
    base = image_base or 0
    mnemonics = [str(i.get("mnemonic", "")).lower() for i in instructions]
    call_targets: set[int] = set()
    for insn in instructions:
        if str(insn.get("mnemonic", "")).lower() in _CALL_MNEMONICS:
            match = _HEXNUM.search(str(insn.get("op_str", "")))
            if match:
                call_targets.add(int(match.group(0), 16) - base)
    addresses: list[int] = [a for a in (i.get("address") for i in instructions) if isinstance(a, int)]
    return {
        "count": len(instructions),
        "mnemonics": mnemonics,
        "call_targets": call_targets,
        "first": min(addresses) if addresses else None,
        "last": max(addresses) if addresses else None,
    }


def _jaccard(a: set[Any], b: set[Any]) -> float | None:
    if not a and not b:
        return None
    return round(len(a & b) / len(a | b), 3)


@dataclass
class Observation:
    """One provider's result for the subject being compared."""

    evidence_id: str | None
    provider_id: str
    engine_family: str
    evidence_kind: str
    address: int | None
    name: str | None
    image_base: int | None
    size: int | None = None
    code: str | None = None
    instructions: list[dict[str, Any]] | None = None
    notes: list[str] = field(default_factory=list)

    def rebased(self) -> int | None:
        if self.address is None or self.image_base is None:
            return None
        return self.address - self.image_base


def _fmt(value: int | None) -> str:
    return "unknown" if value is None else f"{value:#x}"


def compare_observations(
    observations: list[Observation],
    *,
    reference_image_base: int | None,
    reference_bounds: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare engine observations of one function; return a structured assessment."""
    engines = [o for o in observations if o.evidence_kind != "ai_generated"]
    ai = [o for o in observations if o.evidence_kind == "ai_generated"]
    agreements: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    limitations: list[str] = []

    # --- identity: addresses (rebased) and names -----------------------------------
    identity: list[dict[str, Any]] = []
    for obs in engines:
        base = obs.image_base
        if base is None:
            limitations.append(
                f"{obs.provider_id}: image base unknown; address compared as reported "
                f"(assumed equal to the file's {_fmt(reference_image_base)})"
            )
            base = reference_image_base
        rel = None if obs.address is None or base is None else obs.address - base
        identity.append(
            {
                "provider_id": obs.provider_id,
                "address": obs.address,
                "image_base": base,
                "rva": rel,
                "name": obs.name,
                "size": obs.size,
            }
        )
    rvas = {row["rva"] for row in identity if row["rva"] is not None}
    if len(rvas) > 1:
        disagreements.append(
            {
                "aspect": "function_start",
                "severity": "high",
                "detail": "engines place the function at different addresses after rebasing",
                "values": {row["provider_id"]: _fmt(row["rva"]) for row in identity},
                "possible_causes": [
                    "different function-boundary recovery (thunks, tail calls, prologue detection)",
                    "different image base / load address conventions (e.g. PIE rebased to 0 vs 0x100000)",
                    "different symbol resolution for the requested name",
                ],
            }
        )
    elif len(rvas) == 1 and len(identity) > 1:
        agreements.append({"aspect": "function_start", "rva": _fmt(next(iter(rvas)))})
    names = {row["provider_id"]: row["name"] for row in identity if row["name"]}
    if len(set(names.values())) > 1:
        disagreements.append(
            {
                "aspect": "function_name",
                "severity": "low",
                "detail": "engines report different names (often auto-generated vs symbol names)",
                "values": names,
            }
        )

    sizes = {row["provider_id"]: row["size"] for row in identity if row["size"] is not None}
    if reference_bounds and reference_bounds.get("size") is not None:
        sizes.setdefault("file_symbol_table", reference_bounds["size"])
    if len(set(sizes.values())) > 1:
        disagreements.append(
            {
                "aspect": "function_size",
                "severity": "medium",
                "detail": "reported function sizes differ",
                "values": sizes,
                "possible_causes": [
                    "engine computes size from the body's address set vs. the symbol's st_size",
                    "non-contiguous function chunks or shared tails",
                    "incomplete auto-analysis in one engine",
                ],
            }
        )
    elif len(sizes) > 1:
        agreements.append({"aspect": "function_size", "size": next(iter(sizes.values()))})

    # --- decompiled code features ----------------------------------------------------
    feature_rows = {}
    for obs in engines:
        if obs.code:
            feature_rows[obs.provider_id] = decompile_features(obs.code, obs.name)
    pairwise = []
    ids = list(feature_rows)
    for i, left in enumerate(ids):
        for right in ids[i + 1 :]:
            fa, fb = feature_rows[left], feature_rows[right]
            pair = {
                "providers": [left, right],
                "calls_jaccard": _jaccard(fa["calls"], fb["calls"]),
                "constants_jaccard": _jaccard(fa["constants"], fb["constants"]),
                "strings_jaccard": _jaccard(fa["strings"], fb["strings"]),
                "control_equal": fa["control"] == fb["control"],
                "param_count": [fa["param_count"], fb["param_count"]],
            }
            pairwise.append(pair)
            only_a, only_b = fa["calls"] - fb["calls"], fb["calls"] - fa["calls"]
            if only_a or only_b:
                disagreements.append(
                    {
                        "aspect": "callees",
                        "severity": "high",
                        "detail": "decompiled bodies call different functions",
                        "values": {left: sorted(only_a), right: sorted(only_b)},
                        "possible_causes": [
                            "different callee naming (FUN_xxx vs symbol)",
                            "inlined/thunked calls",
                            "indirect calls resolved by only one engine",
                        ],
                    }
                )
            elif fa["calls"] or fb["calls"]:
                agreements.append({"aspect": "callees", "providers": [left, right], "calls": sorted(fa["calls"])})
            ca, cb = fa["constants"] - fb["constants"], fb["constants"] - fa["constants"]
            if ca or cb:
                disagreements.append(
                    {
                        "aspect": "constants",
                        "severity": "medium",
                        "detail": "numeric constants differ (may be representation, e.g. folded offsets)",
                        "values": {left: sorted(hex(c) for c in ca)[:20], right: sorted(hex(c) for c in cb)[:20]},
                    }
                )
            elif fa["constants"]:
                agreements.append(
                    {
                        "aspect": "constants",
                        "providers": [left, right],
                        "constants": sorted(hex(c) for c in fa["constants"])[:20],
                    }
                )
            sa, sb = fa["strings"] - fb["strings"], fb["strings"] - fa["strings"]
            if sa or sb:
                disagreements.append(
                    {
                        "aspect": "string_literals",
                        "severity": "medium",
                        "detail": "string literals differ",
                        "values": {left: sorted(sa)[:10], right: sorted(sb)[:10]},
                    }
                )
            if fa["control"] != fb["control"]:
                disagreements.append(
                    {
                        "aspect": "control_structure",
                        "severity": "low",
                        "detail": "different counts of control keywords (structuring differs)",
                        "values": {left: fa["control"], right: fb["control"]},
                    }
                )
            if None not in pair["param_count"] and fa["param_count"] != fb["param_count"]:
                disagreements.append(
                    {
                        "aspect": "parameter_count",
                        "severity": "medium",
                        "detail": "recovered signatures have different parameter counts",
                        "values": {left: fa["param_count"], right: fb["param_count"]},
                    }
                )

    # --- disassembly features ----------------------------------------------------------
    disasm_rows = {
        o.provider_id: disassembly_features(
            o.instructions, o.image_base if o.image_base is not None else reference_image_base
        )
        for o in engines
        if o.instructions
    }
    dids = list(disasm_rows)
    for i, left in enumerate(dids):
        for right in dids[i + 1 :]:
            da, db = disasm_rows[left], disasm_rows[right]
            ratio = difflib.SequenceMatcher(a=da["mnemonics"], b=db["mnemonics"], autojunk=False).ratio()
            pairwise.append(
                {
                    "providers": [left, right],
                    "mnemonic_similarity": round(ratio, 3),
                    "instruction_counts": [da["count"], db["count"]],
                }
            )
            if da["call_targets"] != db["call_targets"]:
                disagreements.append(
                    {
                        "aspect": "instruction_call_targets",
                        "severity": "high",
                        "detail": "direct call targets (as offsets from each engine's image base) differ",
                        "values": {
                            left: sorted(hex(t) for t in da["call_targets"]),
                            right: sorted(hex(t) for t in db["call_targets"]),
                        },
                    }
                )
            elif da["call_targets"]:
                agreements.append(
                    {
                        "aspect": "instruction_call_targets",
                        "providers": [left, right],
                        "targets": sorted(hex(t) for t in da["call_targets"]),
                    }
                )
            if da["count"] != db["count"]:
                disagreements.append(
                    {
                        "aspect": "instruction_count",
                        "severity": "medium",
                        "detail": "listings cover a different number of instructions (boundaries)",
                        "values": {left: da["count"], right: db["count"]},
                    }
                )
            elif ratio == 1.0:
                agreements.append({"aspect": "instruction_sequence", "providers": [left, right], "count": da["count"]})

    # --- AI output: checked against engines, never counted as corroboration ------------
    ai_checks = []
    engine_calls = set().union(*(f["calls"] for f in feature_rows.values())) if feature_rows else set()
    engine_consts = set().union(*(f["constants"] for f in feature_rows.values())) if feature_rows else set()
    for obs in ai:
        if not obs.code:
            continue
        fa = decompile_features(obs.code, obs.name)
        ai_checks.append(
            {
                "provider_id": obs.provider_id,
                "evidence_id": obs.evidence_id,
                "calls_not_seen_in_engines": sorted(fa["calls"] - engine_calls),
                "engine_calls_missing_from_ai": sorted(engine_calls - fa["calls"]),
                "constants_not_seen_in_engines": sorted(hex(c) for c in fa["constants"] - engine_consts)[:20],
                "interpretation": (
                    "AI reconstruction mentions calls/constants absent from engine output; treat those parts "
                    "as unsupported."
                    if (fa["calls"] - engine_calls or fa["constants"] - engine_consts)
                    else "AI reconstruction is consistent with engine-observed calls/constants (still unverified)."
                ),
            }
        )

    # --- assessment, per evidence group ----------------------------------------------------
    # Independence is judged separately for decompiled code, instruction listings and
    # identity (start/size/name): a Capstone listing that matches Ghidra's corroborates the
    # *instructions*, not Ghidra's pseudocode. The overall verdict is the weakest group's.
    families = sorted({o.engine_family for o in engines})
    groups = {
        "decompilation": ([o for o in engines if o.code], _DECOMPILE_ASPECTS),
        "disassembly": ([o for o in engines if o.instructions], _DISASM_ASPECTS),
        "identity": ([o for o in engines if o.address is not None or o.size is not None], _IDENTITY_ASPECTS),
    }
    by_group: dict[str, dict[str, Any]] = {}
    for group, (members, aspects) in groups.items():
        if not members:
            continue
        group_disagreements = [d for d in disagreements if d["aspect"] in aspects]
        fams = sorted({o.engine_family for o in members})
        if any(d["severity"] == "high" for d in group_disagreements):
            verdict = "disagreement"
        elif len(members) == 1:
            verdict = "single_source"
        elif len(fams) >= 2:
            verdict = "independent_partial_agreement" if group_disagreements else "independent_agreement"
        else:
            verdict = "same_family_consistency"
        by_group[group] = {
            "assessment": verdict,
            "engine_families": fams,
            "providers": [o.provider_id for o in members],
            "disagreements": sorted({d["aspect"] for d in group_disagreements}),
        }

    rationale: list[str] = []
    if not engines:
        assessment, confidence = "insufficient_evidence", "none"
        rationale.append("no engine-derived observation to compare")
    else:
        content_groups = {k: v for k, v in by_group.items() if k != "identity"} or by_group
        assessment = min((g["assessment"] for g in content_groups.values()), key=_VERDICT_RANK.__getitem__)
        if any(g["assessment"] == "disagreement" for g in by_group.values()):
            assessment = "disagreement"
        confidence = _VERDICT_CONFIDENCE[assessment]
        for name, summary in by_group.items():
            if summary["assessment"] == "disagreement":
                rationale.append(
                    f"{name}: high-severity disagreement in {summary['disagreements']} needs manual review"
                )
            elif summary["assessment"] == "single_source":
                rationale.append(f"{name}: only {summary['providers'][0]} produced this observation")
            elif summary["assessment"] == "same_family_consistency":
                rationale.append(
                    f"{name}: all observations come from one engine family ({summary['engine_families'][0]}); "
                    "agreement shows wrapper consistency, not independent confirmation"
                )
            else:
                rationale.append(
                    f"{name}: {len(summary['engine_families'])} independent engine families agree "
                    f"({summary['engine_families']})"
                    + (f"; lower-severity differences: {summary['disagreements']}" if summary["disagreements"] else "")
                )
    if ai:
        rationale.append("AI-generated observations were excluded from the confidence assessment")
    if any(o.code is None and o.instructions is None for o in engines):
        limitations.append("some providers contributed identity data only")

    return {
        "assessment": assessment,
        "confidence": confidence,
        "rationale": rationale,
        "engine_families": families,
        "by_group": by_group,
        "identity": identity,
        "agreements": agreements,
        "disagreements": disagreements,
        "pairwise": pairwise,
        "ai_checks": ai_checks,
        "limitations": limitations,
        "method": "feature comparison (calls, constants, strings, control counts, call targets) after rebasing",
    }
