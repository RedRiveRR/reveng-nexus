"""Agent D regressions: adapter normalisers against pinned upstream response shapes.

No server is launched: a fake provider answers each tool with the exact envelope the pinned
upstream builds (citations per test), and the real ``McpAdapter.perform``/``call`` path runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reveng_nexus.adapters import ADAPTERS
from reveng_nexus.errors import CapabilityUnavailable, ProviderCallError


def _result(payload: Any, *, structured: bool = True, text: str | None = None, is_error: bool = False):
    body = text if text is not None else (payload if isinstance(payload, str) else json.dumps(payload, indent=2))
    return SimpleNamespace(
        content=[SimpleNamespace(text=body)],
        structured_content=payload if structured and isinstance(payload, dict) else None,
        is_error=is_error,
    )


class FakeProvider:
    def __init__(self, pid: str, engine: str, answers: dict[str, Any]) -> None:
        self.id = pid
        self.engine = engine
        self.engine_family = engine
        self.started = True
        self.per_target = True  # capability check trusts the pin when no tools are listed
        self._tools: dict[str, Any] = {}
        self._owner = None
        self.adapter_state: dict[str, Any] = {}
        self.config = SimpleNamespace(startup_timeout_seconds=30)
        self.log_path = Path("fake.log")
        self.answers = answers
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_for_target(self, target, tool, arguments, **kw):
        self.calls.append((tool, dict(arguments)))
        answer = self.answers[tool]
        return answer(arguments) if callable(answer) else answer


class FakeTarget:
    def __init__(self, tmp_path: Path, fmt: str = "elf") -> None:
        self.sha256 = "ab" * 32
        self.format = fmt
        self._dir = tmp_path / "staged"
        self._dir.mkdir(exist_ok=True)

    def staged_path(self, provider_id: str) -> Path:
        return self._dir / ("sample.apk" if self.format == "apk" else "sample.elf")

    def provider_dir(self, provider_id: str) -> Path:
        return self._dir


def _remcp_ida(extra: dict[str, Any]) -> dict[str, Any]:
    answers: dict[str, Any] = {
        "open_database": _result({"status": "opening"}),
        "wait_for_analysis": _result({"status": "ready", "processor": "metapc", "bitness": 64}),
    }
    answers.update(extra)
    return answers


# -- re-mcp-ida (packages/re-mcp-ida/src/re_mcp_ida/tools/*.py at 7b38aa9) ----------------------------
async def test_remcp_ida_xrefs_from_keeps_both_ends(tmp_path):
    # xrefs.py:56-69,160-174: XrefFromResult {address, items[{to, to_name, type, is_code}], ...}
    page = {
        "address": "0x401000",
        "items": [{"to": "0x401040", "to_name": "add_numbers", "type": "Code_Near_Call", "is_code": True}],
        "total": 1,
        "offset": 0,
        "limit": 200,
        "has_more": False,
    }
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"get_xrefs_from": _result(page)}))
    res = await ADAPTERS["re_mcp"].perform(
        prov, "binary.xrefs", FakeTarget(tmp_path), {"address": 0x401000, "direction": "from"}
    )
    (ref,) = res.normalized["refs"]
    assert ref["from"] == 0x401000  # the queried end
    assert ref["to"] == 0x401040  # never the queried address relabelled as the target
    assert ref["type"] == "Code_Near_Call"


async def test_remcp_ida_xrefs_to_reads_from_key(tmp_path):
    # xrefs.py:38-52,122-135: XrefTo {from, from_name, type, is_code}
    page = {
        "address": "0x401040",
        "items": [{"from": "0x401008", "from_name": "main", "type": "Code_Near_Call", "is_code": True}],
        "total": 1,
        "offset": 0,
        "limit": 200,
        "has_more": False,
    }
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"get_xrefs_to": _result(page)}))
    res = await ADAPTERS["re_mcp"].perform(prov, "binary.xrefs", FakeTarget(tmp_path), {"address": 0x401040})
    (ref,) = res.normalized["refs"]
    assert (ref["from"], ref["to"], ref["from_function"]) == (0x401008, 0x401040, "main")


async def test_remcp_ghidra_xrefs_from_fills_the_queried_source(tmp_path):
    # re-mcp-ghidra tools/xrefs.py:31-35,94-98: XrefFrom {to_address, to_function, ref_type, is_call}
    page = {
        "items": [
            {"to_address": "0x400100", "to_function": "check_key", "ref_type": "UNCONDITIONAL_CALL", "is_call": True}
        ],
        "total": 1,
        "offset": 0,
        "limit": 200,
        "has_more": False,
    }
    prov = FakeProvider("ghidra_remcp", "ghidra", _remcp_ida({"get_xrefs_from": _result(page)}))
    res = await ADAPTERS["re_mcp"].perform(
        prov, "binary.xrefs", FakeTarget(tmp_path), {"address": 0x400127, "direction": "from"}
    )
    (ref,) = res.normalized["refs"]
    assert (ref["from"], ref["to"], ref["is_call"]) == (0x400127, 0x400100, True)


async def test_remcp_ida_decompile_reads_pseudocode_not_the_json_text(tmp_path):
    # functions.py:99-104: DecompilationResult {address, name, pseudocode}
    payload = {"address": "0x401000", "name": "main", "pseudocode": "int main(void)\n{\n  return 0;\n}"}
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"decompile_function": _result(payload)}))
    res = await ADAPTERS["re_mcp"].perform(prov, "binary.decompile", FakeTarget(tmp_path), {"address": 0x401000})
    assert res.normalized["code"] == payload["pseudocode"]
    assert res.normalized["function"] == {"name": "main", "address": 0x401000}


async def test_remcp_decompile_without_a_code_field_is_an_error(tmp_path):
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"decompile_function": _result({"address": "0x401000"})}))
    with pytest.raises(ProviderCallError):
        await ADAPTERS["re_mcp"].perform(prov, "binary.decompile", FakeTarget(tmp_path), {"address": 0x401000})


async def test_remcp_ida_disassembly_splits_the_disasm_text(tmp_path):
    # functions.py:107-120: DisassemblyResult {address, name, instruction_count, instructions[{address, disasm}]}
    payload = {
        "address": "0x401000",
        "name": "main",
        "instruction_count": 2,
        "instructions": [
            {"address": "0x401000", "disasm": "push    rbp"},
            {"address": "0x401001", "disasm": "mov     rbp, rsp"},
        ],
    }
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"disassemble_function": _result(payload)}))
    res = await ADAPTERS["re_mcp"].perform(prov, "binary.disassemble", FakeTarget(tmp_path), {"address": 0x401000})
    ins = res.normalized["instructions"]
    assert [(i["address"], i["mnemonic"], i["op_str"]) for i in ins] == [
        (0x401000, "push", "rbp"),
        (0x401001, "mov", "rbp, rsp"),
    ]
    assert res.normalized["function"]["name"] == "main"


async def test_remcp_ida_metadata_does_not_relabel_min_address_as_image_base(tmp_path):
    # database.py:67-80: IDA DatabaseInfoResult has min_address and entry_point, no image_base
    info = {
        "file_path": "x.i64",
        "processor": "metapc",
        "bitness": 64,
        "file_type": "ELF64",
        "min_address": "0x400000",
        "max_address": "0x403000",
        "entry_point": "0x401000",
        "function_count": 3,
        "segment_count": 4,
        "entry_point_count": 1,
        "trusted": True,
    }
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"get_database_info": _result(info)}))
    res = await ADAPTERS["re_mcp"].perform(prov, "binary.metadata", FakeTarget(tmp_path), {})
    assert res.normalized["image_base"] is None
    assert res.normalized["entry_point"] == 0x401000


async def test_remcp_unrecognised_page_shape_warns(tmp_path):
    prov = FakeProvider("re_mcp_ida", "ida", _remcp_ida({"get_strings": _result({"strings": []})}))
    res = await ADAPTERS["re_mcp"].perform(prov, "binary.strings", FakeTarget(tmp_path), {})
    assert res.normalized["strings"] == [] and any("unrecognised" in w for w in res.warnings)


async def test_partial_error_with_items_is_not_a_clean_success(tmp_path):
    page = {
        "items": [{"name": "main", "start": "0x401000", "end": "0x401030", "size": 48}],
        "has_more": False,
        "error": "worker crashed after page 1",
    }
    prov = FakeProvider("ghidra_remcp", "ghidra", _remcp_ida({"list_functions": _result(page)}))
    res = await ADAPTERS["re_mcp"].perform(prov, "binary.functions", FakeTarget(tmp_path), {})
    assert res.normalized["total"] == 1
    assert any("worker crashed" in w for w in res.warnings)


# -- ida-mcp-rs (blacktop/ida-mcp-rs 15d16ab) ------------------------------------------------------
def _db_info(auto_is_ok: bool) -> dict[str, Any]:
    # src/ida/types.rs:87-97 DbInfo (+ AnalysisStatus 132-139); server/mod.rs open_idb pretty JSON text
    return {
        "path": "sample.elf.i64",
        "file_type": "ELF",
        "loader": "ELF64 for x86-64",
        "processor": "metapc",
        "bits": 64,
        "function_count": 3,
        "debug_info": None,
        "analysis_status": {
            "auto_enabled": True,
            "auto_is_ok": auto_is_ok,
            "auto_state": "AU_NONE" if auto_is_ok else "AU_CODE",
            "auto_state_id": 0,
            "analysis_running": not auto_is_ok,
        },
    }


async def test_ida_rs_requests_auto_analysis_and_flags_an_incomplete_one(tmp_path):
    answers = {
        "open_idb": _result(_db_info(False), structured=False),
        "idb_meta": _result({"processor": "metapc", "bits": 64, "image_base": "0x400000"}, structured=False),
    }
    prov = FakeProvider("ida", "ida", answers)
    res = await ADAPTERS["ida_rs"].perform(prov, "binary.metadata", FakeTarget(tmp_path), {})
    open_args = dict(prov.calls)["open_idb"]
    assert open_args.get("auto_analyse") is True  # requests.rs:55-60 defaults to false
    assert any("auto-analysis" in w for w in res.warnings)


async def test_ida_rs_truncated_xrefs_are_flagged(tmp_path):
    # types.rs:390-396 XRefListResult {xrefs, truncated, next_offset}
    answers = {
        "open_idb": _result(_db_info(True), structured=False),
        "xrefs_to": _result(
            {
                "xrefs": [{"from": "0x401008", "to": "0x401040", "type": "Code_Near_Call", "is_code": True}],
                "truncated": True,
                "next_offset": 1,
            }
        ),
    }
    prov = FakeProvider("ida", "ida", answers)
    res = await ADAPTERS["ida_rs"].perform(prov, "binary.xrefs", FakeTarget(tmp_path), {"address": 0x401040})
    assert len(res.normalized["refs"]) == 1
    assert any("truncated" in w for w in res.warnings)


# -- jadx-mcp-server (Qtty 4e6d890) ------------------------------------------------------------------
def _apk_info(path: str) -> dict[str, Any]:
    # JadxAnalyzerCore.getApkInfo (core/JadxAnalyzerCore.java:509-519); jadx_mcp.py:288-290 json.dumps
    return {
        "apkPath": path,
        "packageName": "com.example.nexus",
        "totalClasses": 2,
        "exportedComponents": 1,
        "mainActivity": "com.example.nexus.MainActivity",
    }


def _jadx(value: Any):
    return _result(json.dumps(value), structured=False)


@pytest.mark.parametrize("reported", ["other", "missing"])
async def test_jadx_refuses_when_the_daemon_loaded_another_apk(tmp_path, reported):
    target = FakeTarget(tmp_path, "apk")
    info = _apk_info(str(tmp_path / "elsewhere" / "sample.apk"))
    if reported == "missing":
        info.pop("apkPath")
    prov = FakeProvider("jadx", "jadx", {"load_apk": _jadx(info), "get_all_classes": _jadx(["a.B"])})
    with pytest.raises(CapabilityUnavailable):
        await ADAPTERS["jadx"].perform(prov, "apk.classes", target, {})
    assert [c[0] for c in prov.calls] == ["load_apk"]


async def test_jadx_accepts_its_own_staged_copy(tmp_path):
    target = FakeTarget(tmp_path, "apk")
    info = _apk_info(str(target.staged_path("jadx")))
    prov = FakeProvider("jadx", "jadx", {"load_apk": _jadx(info), "get_all_classes": _jadx(["a.B"])})
    res = await ADAPTERS["jadx"].perform(prov, "apk.classes", target, {})
    assert res.normalized["classes"] == ["a.B"]
