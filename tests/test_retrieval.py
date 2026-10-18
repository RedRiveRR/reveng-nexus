"""Compact retrieval: keyset paging, summary view, batched findings and the case brief."""

import json
import sqlite3
from pathlib import Path

import pytest
from mcp import Client

from reveng_nexus.artifacts import identify
from reveng_nexus.errors import ArgumentError
from reveng_nexus.evidence import EvidenceStore
from reveng_nexus.registry import ProviderManager
from reveng_nexus.server import NexusServer


def _store(tmp_path: Path, root: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "data" / "evidence.sqlite3", (str(root),), max_target_size_mb=1)


@pytest.fixture
def case(tmp_path, elf_sample, workspace):
    store = _store(tmp_path, workspace)
    ident = identify(elf_sample)
    cid = store.create_case("Retrieval")["case_id"]
    store.upsert_target(ident, cid)
    return store, ident.sha256, cid


def _ev(store, sha, cid, i, **extra):
    fields = {
        "target_id": sha,
        "case_id": cid,
        "provider_id": "ghidra_remcp",
        "tool_name": "decompile_function",
        "operation": "binary.decompile",
        "evidence_kind": "engine_derived",
        "claim": f"claim {i}",
        "subject": f"fn{i}",
        "normalized": {"code": "x" * 50},
    }
    fields.update(extra)
    return store.add_evidence(**fields)["evidence_id"]


def _all_pages(store, **query):
    seen, cursor = [], None
    while True:
        page = store.page_evidence(cursor=cursor, **query)
        seen += [r["evidence_id"] for r in page["items"]]
        if not page["has_more"]:
            assert page["next_cursor"] is None
            return seen
        cursor = page["next_cursor"]


def test_pages_cover_every_record_once_in_the_listing_order(case):
    store, sha, cid = case
    for i in range(7):
        _ev(store, sha, cid, i)
    expected = [r["evidence_id"] for r in store.query_evidence(case_id=cid, limit=500)]
    assert _all_pages(store, case_id=cid, limit=3) == expected


def test_paging_is_stable_while_evidence_arrives(case):
    store, sha, cid = case
    ids = [_ev(store, sha, cid, i) for i in range(6)]
    first = store.page_evidence(case_id=cid, limit=3)
    late = _ev(store, sha, cid, 99)
    second = store.page_evidence(case_id=cid, limit=3, cursor=first["next_cursor"])
    got = [r["evidence_id"] for r in first["items"] + second["items"]]
    assert got == ids[::-1] and late not in got and second["has_more"] is False


def test_paging_with_identical_timestamps_neither_repeats_nor_skips(case):
    store, sha, cid = case
    ids = [_ev(store, sha, cid, i) for i in range(9)]
    with sqlite3.connect(store.database_path) as con:
        con.execute("UPDATE evidence SET created_at = '2026-10-17T00:00:00+00:00'")
    pages = _all_pages(store, case_id=cid, limit=2)
    assert sorted(pages) == sorted(ids) and len(pages) == len(set(pages)) == 9


def test_cursor_is_bound_to_its_filters_and_rejects_garbage(case):
    store, sha, cid = case
    for i in range(3):
        _ev(store, sha, cid, i)
    cursor = store.page_evidence(case_id=cid, limit=1)["next_cursor"]
    with pytest.raises(ArgumentError, match="different filters"):
        store.page_evidence(case_id=cid, operation="binary.metadata", limit=1, cursor=cursor)
    for bad in ("not-a-cursor", "e30", cursor[:-3] + "AAA"):
        with pytest.raises(ArgumentError):
            store.page_evidence(case_id=cid, limit=1, cursor=bad)


def test_summary_view_is_one_short_line_of_provenance(case):
    store, sha, cid = case
    _ev(store, sha, cid, 1, claim="c" * 1000, warnings=["w1", "w2"])
    item = store.page_evidence(case_id=cid, view="summary")["items"][0]
    assert set(item) >= {"evidence_id", "provider_id", "tool_name", "operation", "evidence_kind", "status"}
    assert "normalized" not in item and "model" not in item and len(item["claim"]) == 201
    assert item["warning_count"] == 2
    with pytest.raises(ArgumentError):
        store.page_evidence(case_id=cid, view="full")


def _count_selects(store, monkeypatch):
    counter = {"n": 0}
    original = store._connect

    def counting():
        connection = original()
        connection.set_trace_callback(
            lambda sql: counter.__setitem__("n", counter["n"] + sql.lstrip().upper().startswith("SELECT"))
        )
        return connection

    monkeypatch.setattr(store, "_connect", counting)
    return counter


def test_list_findings_matches_get_finding_without_a_query_per_finding(case, monkeypatch):
    store, sha, cid = case
    evs = [_ev(store, sha, cid, i) for i in range(4)]
    for i in range(12):
        store.record_finding(
            case_id=cid,
            title=f"finding {i}",
            description="d",
            evidence_ids=evs[: 1 + i % 3],
            contradicting_evidence_ids=[evs[3]] if i % 4 == 0 else [],
            status="needs_review",
        )
    expected = [store.get_finding(f["finding_id"]) for f in store.list_findings(case_id=cid, limit=500)]
    counter = _count_selects(store, monkeypatch)
    listed = store.list_findings(case_id=cid, limit=500)
    assert listed == expected and len(listed) == 12
    assert counter["n"] <= 2


def test_case_brief_lists_all_significant_findings_and_reports_omissions(case):
    store, sha, cid = case
    ev = _ev(store, sha, cid, 0)
    for i in range(3):
        store.record_finding(case_id=cid, title=f"high {i}", description="d", evidence_ids=[ev], severity="high")
    for i in range(4):
        store.record_finding(case_id=cid, title=f"info {i}", description="d", evidence_ids=[ev], severity="info")
    store.record_finding(
        case_id=cid, title="rejected critical", description="d", evidence_ids=[ev], severity="critical"
    )
    rejected = store.list_findings(case_id=cid, status="hypothesis")[0]["finding_id"]
    store.review("finding", rejected, "rejected", "false positive")
    for i in range(5):
        store.record_question(case_id=cid, target_id=sha, question=f"q{i}?")
    brief = store.case_brief(case_id=cid, limit=2)
    titles = [f["title"] for f in brief["findings"]["listed"]]
    assert titles[:3] == ["high 2", "high 1", "high 0"] and len(titles) == 3  # newest first
    assert brief["findings"]["total"] == 8 and brief["omitted"]["findings"] == 5
    assert brief["findings"]["by_severity"] == {"high": 3, "info": 4, "critical": 1}
    assert brief["evidence"]["total"] == 1 and brief["evidence"]["operations"][0]["operation"] == "binary.decompile"
    assert brief["questions"]["unresolved"] == 5 and len(brief["questions"]["unresolved_list"]) == 2
    assert brief["omitted"]["unresolved_questions"] == 3 and brief["questions"]["required_unresolved"] == 5
    assert len(json.dumps(brief)) < 8000


def test_case_brief_by_target_and_on_an_empty_case(case):
    store, sha, cid = case
    empty = store.case_brief(case_id=store.create_case("Empty")["case_id"])
    assert empty["evidence"]["total"] == 0 and empty["findings"]["listed"] == [] and empty["omitted"] == {}
    _ev(store, sha, cid, 1, status="contradicted")
    by_target = store.case_brief(target_id=sha)
    assert by_target["targets"][0]["target_id"] == sha and by_target["evidence"]["contradictions"] == 1
    with pytest.raises(ArgumentError):
        store.case_brief()


def _payload(result):
    return json.loads(result.content[0].text)


async def test_retrieval_tools_over_mcp(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            inspected = _payload(await client.call_tool("nexus_inspect_target", {"path": str(elf_sample)}))
            sha, cid = inspected["target"]["sha256"], inspected["target"]["case_id"]
            for tool in ("nexus_get_binary_metadata", "nexus_search_strings", "nexus_get_binary_metadata"):
                await client.call_tool(tool, {"target": sha, "refresh": True})  # three distinct records
            first = _payload(
                await client.call_tool("nexus_get_evidence", {"target": sha, "limit": 2, "view": "summary"})
            )
            assert (
                len(first["evidence"]) == 2 and first["has_more"] is True and "normalized" not in first["evidence"][0]
            )
            rest = _payload(
                await client.call_tool(
                    "nexus_get_evidence", {"target": sha, "limit": 2, "view": "summary", "cursor": first["next_cursor"]}
                )
            )
            ids = [e["evidence_id"] for e in first["evidence"] + rest["evidence"]]
            assert len(ids) == len(set(ids))
            raw_text = (await client.call_tool("nexus_get_evidence", {"target": sha, "limit": 1})).content[0].text
            assert raw_text.index('"next_cursor"') < raw_text.index('"evidence"')
            legacy = _payload(await client.call_tool("nexus_get_evidence", {"target": sha, "limit": 1000}))
            assert legacy["has_more"] is False and "comparisons" in legacy
            brief = _payload(await client.call_tool("nexus_case_brief", {"case_id": cid}))
            assert brief["case"]["case_id"] == cid and brief["evidence"]["total"] == len(legacy["evidence"])
            assert "untrusted_content_notice" in brief
            none = await client.call_tool("nexus_case_brief", {})
            assert none.is_error
    finally:
        await mgr.close()


# -- review findings ---------------------------------------------------------------------
def test_large_pages_stop_at_the_size_budget_and_keep_a_usable_cursor(case):
    store, sha, cid = case
    ids = [_ev(store, sha, cid, i, claim="c" * 4000) for i in range(60)]
    first = store.page_evidence(case_id=cid, limit=500)
    assert first["size_limited"] is True and first["has_more"] is True
    assert len(json.dumps(first)) < 160_000 and 0 < len(first["items"]) < 60
    assert sorted(_all_pages(store, case_id=cid, limit=500)) == sorted(ids)


def test_target_brief_includes_findings_citing_the_target_and_case_level_findings(case, workspace):
    store, sha, cid = case
    other_file = workspace / "second.bin"
    other_file.write_bytes(b"\x7fELF second target")
    other = identify(other_file)
    store.upsert_target(other, cid)
    on_first = _ev(store, sha, cid, 1)
    on_second = _ev(store, other.sha256, cid, 2)
    store.record_finding(
        case_id=cid, title="spans both", description="d", evidence_ids=[on_first, on_second], severity="critical"
    )
    store.record_finding(case_id=cid, title="case-level idea", description="d", evidence_ids=[], severity="high")
    brief = store.case_brief(target_id=other.sha256)
    titles = sorted(f["title"] for f in brief["findings"]["listed"])
    assert titles == ["case-level idea", "spans both"] and brief["findings"]["total"] == 2
    scoped = store.case_brief(case_id=cid, target_id=other.sha256)
    assert [t["target_id"] for t in scoped["targets"]] == [other.sha256]
    with pytest.raises(ArgumentError, match="not part of case"):
        store.case_brief(case_id=store.create_case("Unrelated")["case_id"], target_id=sha)


# -- PR #2 remediation: responses stay valid JSON under the output cap -------------------------
_CAP = 200_000  # server.MAX_RESPONSE_CHARS


async def _texts(client, tool: str, args: dict) -> tuple[str, dict]:
    result = await client.call_tool(tool, args)
    text = result.content[0].text
    assert len(text) <= _CAP, (tool, len(text))
    return text, json.loads(text)  # a cut response would not parse


async def test_evidence_pages_are_valid_json_within_the_cap_and_lose_no_record(config_factory, workspace, elf_sample):
    from reveng_nexus.artifacts import identify as _identify

    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        store = mgr.evidence
        ident = _identify(elf_sample)
        cid = store.create_case("Big pages")["case_id"]
        store.upsert_target(ident, cid)
        sha = ident.sha256
        expected = [
            _ev(
                store,
                sha,
                cid,
                i,
                normalized={"instructions": [{"address": i * 1000 + j, "op": "mov rax, rbx"} for j in range(120)]},
            )
            for i in range(80)
        ]
        huge = _ev(store, sha, cid, 999, normalized={"code": "y" * 400_000})  # larger than any page
        expected.append(huge)
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            # The old budget (compact JSON) let this first page render past the cap.
            first_text, first = await _texts(
                client, "nexus_get_evidence", {"case_id": cid, "limit": 500, "include_normalized": True}
            )
            assert "response_truncated" not in first and first_text.index('"next_cursor"') < first_text.index(
                '"evidence"'
            )
            seen, args, pages = [], {"case_id": cid, "limit": 500, "include_normalized": True}, 0
            while True:
                _text, page = await _texts(client, "nexus_get_evidence", args)
                assert "response_truncated" not in page  # pages fit by construction, nothing is shortened
                pages += 1
                for item in page["evidence"]:
                    seen.append(item["evidence_id"])
                    if item["evidence_id"] == huge:
                        # Returned (not skipped), with its bulky field elided and a way to get it all.
                        assert item["oversized"]["elided_fields"] == ["normalized"]
                        assert (
                            item["normalized"]["elided"] is True
                            and "nexus_export_report" in item["oversized"]["full_record"]
                        )
                if not page["has_more"]:
                    assert page["next_cursor"] is None
                    break
                # The cursor continues right after the last record this response contained.
                assert page["size_limited"] or len(page["evidence"]) == 500
                args = {**args, "cursor": page["next_cursor"]}
            assert pages > 1 and len(seen) == len(set(seen)) and sorted(seen) == sorted(expected)
            # The oversized record fetched alone is shortened into valid JSON, never cut mid-text.
            _text, alone = await _texts(client, "nexus_get_evidence", {"evidence_id": huge})
            assert alone["response_truncated"]["shortened_count"] >= 1
            assert alone["evidence"]["evidence_id"] == huge
    finally:
        await mgr.close()


async def test_large_question_listings_page_within_the_cap_and_keep_counts(config_factory, workspace, elf_sample):
    from reveng_nexus.artifacts import identify as _identify

    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        store = mgr.evidence
        ident = _identify(elf_sample)
        cid = store.create_case("Many questions")["case_id"]
        store.upsert_target(ident, cid)
        sha = ident.sha256
        cited = [_ev(store, sha, cid, i) for i in range(30)]
        long_text = "w" * 1500
        expected = [
            store.record_question(
                case_id=cid,
                target_id=sha,
                question=f"{i} {long_text}",
                needed_evidence=long_text,
                search_boundary=long_text,
                required=i % 3 == 0,
                evidence_ids=cited,
            )["question_id"]
            for i in range(150)
        ]
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            seen, offset, limited = [], 0, False
            while True:
                text, page = await _texts(
                    client, "nexus_list_questions", {"case_id": cid, "limit": 200, "offset": offset}
                )
                # Counts are complete on every page and come before the (bounded) list.
                assert page["counts"]["total"] == 150 and page["counts"]["required_unresolved"] == 50
                assert text.index('"counts"') < text.index('"questions"')
                limited = limited or page["size_limited"]
                seen += [q["question_id"] for q in page["questions"]]
                assert all(len(q["supporting_evidence_ids"]) <= 20 for q in page["questions"])
                if page["next_offset"] is None:
                    break
                assert page["next_offset"] == offset + page["returned"]
                offset = page["next_offset"]
            assert limited and seen == expected
    finally:
        await mgr.close()
