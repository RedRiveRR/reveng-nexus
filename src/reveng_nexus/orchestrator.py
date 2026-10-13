"""Deterministic analysis workflows on top of the provider manager.

No LLM is needed for routing: providers are chosen by capability, configured
preference and priority (see ``registry.ProviderManager.rank``); functions are
prioritised by a documented keyword/shape score. Every step's output is recorded as
evidence with provenance; failures are reported per step instead of aborting.
"""

from __future__ import annotations

import re
from typing import Any

import anyio

from .compare import Observation, compare_observations
from .errors import ArgumentError, CapabilityUnavailable, NexusError, describe_exception
from .providers import TargetContext
from .registry import ProviderManager

DEPTH_LIMITS = {"quick": 0, "standard": 1, "deep": 2}
_INTEREST = (
    (re.compile(r"^(main|wmain|winmain|dllmain|_?start|entry|jni_onload)$", re.I), 50, "entry point"),
    (re.compile(r"crypt|cipher|aes|rsa|sha|md5|hash|hmac|key|xor", re.I), 30, "crypto/key handling"),
    (re.compile(r"auth|login|passw|token|licen[cs]e|serial|verify|check|valid", re.I), 30, "authentication/licensing"),
    (re.compile(r"parse|decode|deserial|unpack|read_|load|inflate", re.I), 20, "input parsing"),
    (re.compile(r"sock|connect|recv|send|http|url|download|upload", re.I), 20, "network"),
    (re.compile(r"exec|spawn|system|process|inject|thread", re.I), 15, "process control"),
    (re.compile(r"memcpy|strcpy|sprintf|alloc|free|copy", re.I), 10, "memory handling"),
)
_LIBRARY_NAME = re.compile(r"^(__|_?_imp_|\.|thunk_|j_|sub_[0-9a-f]+$)", re.I)


def prioritize_functions(functions: list[dict[str, Any]], entry_point: int | None, limit: int) -> list[dict[str, Any]]:
    scored = []
    for fn in functions:
        name = str(fn.get("name") or "")
        score, reasons = 0, []
        if entry_point is not None and fn.get("address") == entry_point:
            score += 40
            reasons.append("file entry point")
        for pattern, weight, reason in _INTEREST:
            if pattern.search(name):
                score += weight
                reasons.append(reason)
        size = fn.get("size")
        if isinstance(size, int):
            if size <= 2:
                score -= 10
                reasons.append("tiny body")
            elif size >= 64:
                score += 5
        if _LIBRARY_NAME.search(name):
            score -= 20
            reasons.append("library/thunk-like name")
        scored.append({**fn, "score": score, "reasons": reasons})
    scored.sort(key=lambda f: (-f["score"], f.get("address") or 0))
    return scored[:limit]


def translate_address(address: int, from_base: int | None, to_base: int | None) -> int:
    if from_base is None or to_base is None or from_base == to_base:
        return address
    return address - from_base + to_base


def _short(result: dict[str, Any]) -> dict[str, Any]:
    res = result["result"]
    ev = result.get("evidence") or {}
    return {
        "operation": res.operation,
        "provider_id": res.provider_id,
        "engine_family": res.engine_family,
        "evidence_id": ev.get("evidence_id"),
        "evidence_kind": res.evidence_kind,
        "claim": res.claim,
        "warnings": res.warnings,
        "attempts": result.get("attempts", []),
    }


class Orchestrator:
    def __init__(self, manager: ProviderManager) -> None:
        self.manager = manager
        self.config = manager.config

    async def _try(self, steps: list[dict[str, Any]], label: str, coro) -> dict[str, Any] | None:
        try:
            result = await coro
        except NexusError as exc:
            steps.append({"step": label, "ok": False, **exc.to_dict()})
            return None
        except Exception as exc:  # noqa: BLE001 - per-step isolation
            steps.append({"step": label, "ok": False, **describe_exception(exc)})
            return None
        steps.append({"step": label, "ok": True, **_short(result)})
        return result

    async def engine_image_base(self, target: TargetContext, provider_id: str) -> int | None:
        if provider_id == "builtin":
            return target.metadata.get("image_base")
        cached = await anyio.to_thread.run_sync(
            lambda: self.manager.evidence.query_evidence(
                target_id=target.sha256, operation="binary.metadata", limit=20, include_normalized=True
            )
        )
        for row in cached:
            if row["provider_id"] == provider_id and isinstance(row.get("normalized"), dict):
                base = row["normalized"].get("image_base")
                if base is not None:
                    return int(base)
        try:
            out = await self.manager.perform("binary.metadata", target, {}, provider_id=provider_id, max_failover=0)
        except NexusError:
            return None
        base = out["result"].normalized.get("image_base")
        return int(base) if base is not None else None

    # -- binary workflow ---------------------------------------------------------------
    async def analyze_binary(
        self,
        target: TargetContext,
        *,
        depth: str | None = None,
        provider_id: str | None = None,
        compare: bool | None = None,
        ai: bool | None = None,
        max_functions: int | None = None,
    ) -> dict[str, Any]:
        if target.kind != "native_binary":
            raise ArgumentError(f"nexus_analyze_binary expects a native binary; this target is {target.kind!r}")
        depth = depth or self.config.analysis.default_depth
        if depth not in DEPTH_LIMITS:
            raise ArgumentError("depth must be quick, standard or deep")
        steps: list[dict[str, Any]] = []
        mgr = self.manager

        await self._try(
            steps, "metadata (built-in parser)", mgr.perform("binary.metadata", target, {}, provider_id="builtin")
        )
        await self._try(steps, "imports", mgr.perform("binary.imports", target, {}, provider_id="builtin"))
        await self._try(steps, "exports", mgr.perform("binary.exports", target, {}, provider_id="builtin"))
        await self._try(steps, "strings", mgr.perform("binary.strings", target, {"limit": 200}, provider_id="builtin"))

        decompilers, rejected = mgr.rank("binary.decompile", target, provider_id)
        engine = next((p for p in decompilers if p.id != "builtin"), None)
        functions_result = None
        if engine is not None:
            functions_result = await self._try(
                steps,
                f"functions ({engine.id})",
                mgr.perform("binary.functions", target, {"limit": 2000}, provider_id=engine.id),
            )
            await self._try(
                steps,
                f"engine metadata ({engine.id})",
                mgr.perform("binary.metadata", target, {}, provider_id=engine.id, max_failover=0),
            )
        if functions_result is None:
            functions_result = await self._try(
                steps,
                "functions (symbol tables)",
                mgr.perform("binary.functions", target, {"limit": 2000}, provider_id="builtin"),
            )
        functions = functions_result["result"].normalized.get("functions", []) if functions_result else []

        limit = (
            max_functions
            if max_functions is not None
            else (self.config.analysis.max_functions_to_decompile * DEPTH_LIMITS[depth])
        )
        limit = max(0, min(int(limit), 200))
        priorities = prioritize_functions(functions, target.metadata.get("entry_point"), max(limit, 10))
        selected = [f for f in priorities if f.get("address") is not None or f.get("name")][:limit]

        decompiled = []
        for fn in selected:
            params = {"address": fn["address"]} if fn.get("address") is not None else {"name": fn["name"]}
            if engine is not None:
                out = await self._try(
                    steps,
                    f"decompile {fn.get('name') or fn.get('address')}",
                    mgr.perform("binary.decompile", target, params, provider_id=engine.id),
                )
            else:
                out = await self._try(
                    steps,
                    f"disassemble {fn.get('name')} (no decompiler available)",
                    mgr.perform("binary.disassemble", target, params, provider_id="builtin"),
                )
            if out:
                decompiled.append(
                    {
                        "function": fn,
                        "evidence_id": out["evidence"]["evidence_id"],
                        "provider_id": out["result"].provider_id,
                    }
                )

        comparisons = []
        do_compare = compare if compare is not None else self.config.analysis.cross_engine_comparison == "auto"
        if do_compare and selected:
            for fn in selected[: 1 if depth != "deep" else 3]:
                try:
                    comparisons.append(
                        await self.compare_function(
                            target, address=fn.get("address"), name=fn.get("name"), include_disassembly=True
                        )
                    )
                except NexusError as exc:
                    steps.append({"step": f"compare {fn.get('name')}", "ok": False, **exc.to_dict()})

        ai_results = []
        use_ai = ai if ai is not None else self.config.analysis.ai_enhancement
        if use_ai and decompiled:
            first = decompiled[0]
            try:
                ai_results.append(
                    await self.ai_decompile(
                        target, address=first["function"].get("address"), name=first["function"].get("name")
                    )
                )
            except NexusError as exc:
                steps.append({"step": "ai reconstruction", "ok": False, **exc.to_dict()})

        missing = []
        if engine is None:
            missing.append(
                {
                    "capability": "binary.decompile",
                    "detail": "no decompiler provider is running; only built-in metadata/strings/disassembly were used",
                    "rejected": rejected,
                }
            )
        return {
            "target": target.sha256,
            "case_id": target.case_id,
            "depth": depth,
            "primary_engine": engine.id if engine else None,
            "prioritized_functions": [
                {k: fn.get(k) for k in ("name", "address", "size", "score", "reasons")} for fn in priorities
            ],
            "decompiled": decompiled,
            "comparisons": comparisons,
            "ai": ai_results,
            "steps": steps,
            "missing_capabilities": missing,
            "notes": [
                "Function priority is a keyword/shape heuristic; it is a reading order, not a finding.",
                "Decompiled output is engine-derived evidence; verify important claims with a second engine "
                "or the instruction listing.",
            ],
        }

    # -- comparison --------------------------------------------------------------------
    async def compare_function(
        self,
        target: TargetContext,
        *,
        address: int | None = None,
        name: str | None = None,
        providers: list[str] | None = None,
        include_disassembly: bool = True,
        include_ai: bool = False,
    ) -> dict[str, Any]:
        if address is None and not name:
            raise ArgumentError("compare needs a function address or name")
        mgr = self.manager
        file_base = target.metadata.get("image_base")
        steps: list[dict[str, Any]] = []
        if providers:
            engine_ids = list(dict.fromkeys(providers))
        else:
            ranked, _rejected = mgr.rank("binary.decompile", target)
            engine_ids = [p.id for p in ranked][:4]
        if not engine_ids and not include_disassembly:
            raise CapabilityUnavailable("no decompiler providers are available for comparison")

        # Reference identity from the file's own symbol table (direct observation).
        symbols = target.metadata.get("functions", []) or []
        ref = None
        if address is not None:
            ref = next((f for f in symbols if f.get("address") == address), None)
        elif name:
            ref = next((f for f in symbols if f.get("name") == name), None)
        if ref and address is None:
            address = ref["address"]
        observations: list[Observation] = []
        evidence_ids: list[str] = []
        if ref is not None:
            observations.append(
                Observation(
                    evidence_id=None,
                    provider_id="file_symbol_table",
                    engine_family="nexus-formats",
                    evidence_kind="direct_observation",
                    address=ref["address"],
                    name=ref.get("name"),
                    image_base=file_base,
                    size=ref.get("size"),
                )
            )

        async def collect(provider_id: str) -> None:
            base = await self.engine_image_base(target, provider_id)
            params: dict[str, Any] = {}
            if address is not None:
                params["address"] = translate_address(address, file_base, base)
                if name:
                    params["name"] = name
            else:
                params["name"] = name
            out = await self._try(
                steps,
                f"decompile via {provider_id}",
                mgr.perform("binary.decompile", target, params, provider_id=provider_id, max_failover=0),
            )
            if out is None:
                return
            res = out["result"]
            evidence_ids.append(out["evidence"]["evidence_id"])
            observations.append(
                Observation(
                    evidence_id=out["evidence"]["evidence_id"],
                    provider_id=provider_id,
                    engine_family=res.engine_family,
                    evidence_kind=res.evidence_kind,
                    address=res.subject_address,
                    name=res.subject_name,
                    image_base=base,
                    code=res.normalized.get("code"),
                )
            )

        # Different providers run concurrently; locks inside the manager serialise conflicts.
        async with anyio.create_task_group() as tg:
            for pid in engine_ids:
                if pid == "builtin":
                    continue
                tg.start_soon(collect, pid)

        if include_disassembly:
            disasm_ids = [pid for pid in engine_ids if pid != "builtin"][:2]
            builtin = mgr.providers.get("builtin")
            if builtin is not None and builtin.list_capabilities().get("binary.disassemble", {}).get("available"):
                disasm_ids.append("builtin")
            for pid in disasm_ids:
                base = await self.engine_image_base(target, pid)
                params = (
                    {"address": translate_address(address, file_base, base)} if address is not None else {"name": name}
                )
                out = await self._try(
                    steps,
                    f"disassemble via {pid}",
                    mgr.perform("binary.disassemble", target, params, provider_id=pid, max_failover=0),
                )
                if out is None:
                    continue
                res = out["result"]
                evidence_ids.append(out["evidence"]["evidence_id"])
                observations.append(
                    Observation(
                        evidence_id=out["evidence"]["evidence_id"],
                        provider_id=f"{pid}:disasm",
                        engine_family=res.engine_family,
                        evidence_kind=res.evidence_kind,
                        address=res.subject_address,
                        name=res.subject_name,
                        image_base=base,
                        instructions=res.normalized.get("instructions"),
                    )
                )

        if include_ai:
            try:
                ai_out = await self.ai_decompile(target, address=address, name=name)
                evidence_ids.append(ai_out["evidence_id"])
                observations.append(
                    Observation(
                        evidence_id=ai_out["evidence_id"],
                        provider_id=ai_out["provider_id"],
                        engine_family="llm4decompile",
                        evidence_kind="ai_generated",
                        address=address,
                        name=name,
                        image_base=file_base,
                        code=ai_out["code"],
                    )
                )
            except NexusError as exc:
                steps.append({"step": "ai reconstruction", "ok": False, **exc.to_dict()})

        assessment = compare_observations(observations, reference_image_base=file_base, reference_bounds=ref)
        subject = name or (f"{address:#x}" if address is not None else "?")
        stored = await anyio.to_thread.run_sync(
            lambda: mgr.evidence.add_comparison(
                target_id=target.sha256,
                case_id=target.case_id,
                operation="function_comparison",
                subject=subject,
                assessment=assessment["assessment"],
                details=assessment,
                evidence_ids=evidence_ids,
            )
        )
        relation = (
            "contradicts"
            if assessment["assessment"] == "disagreement"
            else ("agrees_with" if assessment["assessment"].startswith("independent") else "same_subject")
        )
        engine_evidence = [o.evidence_id for o in observations if o.evidence_id and o.evidence_kind != "ai_generated"]

        def link_all() -> None:
            for i, left in enumerate(engine_evidence):
                for right in engine_evidence[i + 1 :]:
                    mgr.evidence.link(left, right, relation, note=stored["comparison_id"])

        await anyio.to_thread.run_sync(link_all)
        return {
            "comparison_id": stored["comparison_id"],
            "subject": subject,
            "providers": engine_ids,
            "evidence_ids": evidence_ids,
            **assessment,
            "steps": steps,
        }

    # -- AI enhancement -------------------------------------------------------------------
    async def ai_decompile(
        self,
        target: TargetContext,
        *,
        address: int | None = None,
        name: str | None = None,
        provider_id: str | None = None,
        source_provider: str | None = None,
    ) -> dict[str, Any]:
        mgr = self.manager
        ai_providers, rejected = mgr.rank("ai.decompile", target, provider_id)
        if not ai_providers:
            raise CapabilityUnavailable(
                "no AI decompilation provider is configured and healthy",
                details={"rejected": rejected},
                remediation="Configure an llm4decompile provider (see docs/PROVIDER_MATRIX.md).",
            )
        ai = ai_providers[0]
        variant = ai.config.model.variant
        file_base = target.metadata.get("image_base")
        if variant == "ref":
            ranked, _ = mgr.rank("binary.decompile", target, source_provider)
            ghidra_like = [p for p in ranked if p.engine_family == "ghidra"]
            if not ghidra_like:
                raise CapabilityUnavailable(
                    "LLM4Decompile-Ref models refine Ghidra pseudocode; no Ghidra provider is available"
                )
            source = ghidra_like[0]
            base = await self.engine_image_base(target, source.id)
            params = {"address": translate_address(address, file_base, base)} if address is not None else {"name": name}
            src = await mgr.perform("binary.decompile", target, params, provider_id=source.id, max_failover=0)
            input_text, input_kind = src["result"].normalized.get("code", ""), "pseudocode"
        else:
            params = {"address": address} if address is not None else {"name": name}
            src = await mgr.perform("binary.disassemble", target, params)
            from .providers.llm4decompile import render_assembly

            res = src["result"]
            input_text = render_assembly(res.subject_name or name or "func0", res.normalized.get("instructions", []))
            input_kind = "assembly"
        source_evidence = src["evidence"]["evidence_id"]
        out = await mgr.perform(
            "ai.decompile",
            target,
            {
                "input_text": input_text,
                "input_kind": input_kind,
                "address": address,
                "name": name,
                "input_evidence_id": source_evidence,
                "input_provider": src["result"].provider_id,
            },
            provider_id=ai.id,
            max_failover=0,
        )
        evidence_id = out["evidence"]["evidence_id"]
        await anyio.to_thread.run_sync(
            lambda: mgr.evidence.link(evidence_id, source_evidence, "derived_from", note="model input")
        )
        return {
            "provider_id": ai.id,
            "evidence_id": evidence_id,
            "input_evidence_id": source_evidence,
            "code": out["result"].normalized.get("code", ""),
            "model": out["result"].model,
            "warnings": out["result"].warnings,
            "verification": "unverified — AI-generated; compare with engine evidence before relying on it",
        }

    # -- Android ---------------------------------------------------------------------------
    async def analyze_apk(
        self, target: TargetContext, *, include_jadx: bool = True, class_limit: int = 200
    ) -> dict[str, Any]:
        if target.format != "apk":
            raise ArgumentError(f"nexus_analyze_apk expects an APK; this target is {target.format!r}")
        mgr = self.manager
        steps: list[dict[str, Any]] = []
        manifest = await self._try(
            steps, "manifest (built-in AXML parser)", mgr.perform("apk.manifest", target, {}, provider_id="builtin")
        )
        components = await self._try(
            steps, "components (built-in AXML parser)", mgr.perform("apk.components", target, {}, provider_id="builtin")
        )
        jadx_ids = [p.id for p in mgr.rank("apk.components", target)[0] if p.id != "builtin"]
        cross = None
        if include_jadx and jadx_ids:
            jid = jadx_ids[0]
            await self._try(steps, f"manifest ({jid})", mgr.perform("apk.manifest", target, {}, provider_id=jid))
            jadx_components = await self._try(
                steps, f"components ({jid})", mgr.perform("apk.components", target, {}, provider_id=jid)
            )
            await self._try(
                steps, f"classes ({jid})", mgr.perform("apk.classes", target, {"limit": class_limit}, provider_id=jid)
            )
            if components and jadx_components:
                cross = self._compare_components(components["result"].normalized, jadx_components["result"].normalized)
                ids = [components["evidence"]["evidence_id"], jadx_components["evidence"]["evidence_id"]]
                stored = await anyio.to_thread.run_sync(
                    lambda: mgr.evidence.add_comparison(
                        target_id=target.sha256,
                        case_id=target.case_id,
                        operation="exported_components",
                        subject="exported components",
                        assessment=cross["assessment"],
                        details=cross,
                        evidence_ids=ids,
                    )
                )
                cross["comparison_id"] = stored["comparison_id"]
        summary = {}
        if components:
            norm = components["result"].normalized
            summary = {
                "package": norm.get("package"),
                "target_sdk": norm.get("target_sdk"),
                "permissions_requested": norm.get("permissions_requested"),
                "exported_components": [
                    {"type": c["type"], "name": c["name"], "basis": c["exported_basis"], "permission": c["permission"]}
                    for c in norm.get("exported_components", [])
                ],
                "application_flags": norm.get("application"),
            }
        return {
            "target": target.sha256,
            "case_id": target.case_id,
            "summary": summary,
            "manifest_evidence_id": (manifest or {}).get("evidence", {}).get("evidence_id") if manifest else None,
            "cross_check": cross,
            "steps": steps,
            "missing_capabilities": []
            if jadx_ids
            else [
                {
                    "capability": "apk.class_source",
                    "detail": "no JADX provider running; Java decompilation unavailable (manifest/components still parsed)",
                }
            ],
        }

    @staticmethod
    def _compare_components(builtin: dict[str, Any], jadx: dict[str, Any]) -> dict[str, Any]:
        ours = {c["name"] for c in builtin.get("exported_components", []) if c.get("name")}
        theirs: set[str] = set()
        raw = jadx.get("exported_components")
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    nm = item.get("name") or item.get("className") or item.get("component")
                    if nm:
                        theirs.add(str(nm))
                elif isinstance(item, str):
                    theirs.add(item)
        elif isinstance(raw, str):
            theirs = {tok for tok in re.findall(r"[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)+", raw)}
        only_ours, only_theirs = sorted(ours - theirs), sorted(theirs - ours)
        assessment = "independent_agreement" if not (only_ours or only_theirs) else "disagreement"
        return {
            "assessment": assessment,
            "engine_families": ["nexus-formats", "jadx"],
            "agreements": sorted(ours & theirs),
            "disagreements": (
                [
                    {
                        "aspect": "exported_components",
                        "severity": "high",
                        "values": {"builtin": only_ours, "jadx": only_theirs},
                        "possible_causes": [
                            "implicit-export rules (targetSdk, intent filters) applied differently",
                            "activity-alias / disabled components",
                            "parser error",
                        ],
                    }
                ]
                if (only_ours or only_theirs)
                else []
            ),
        }
