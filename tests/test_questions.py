"""Investigation questions (unknowns): revision checks, evidence gates, checklist and migration v2 -> v3."""

import json
import sqlite3
import threading
from pathlib import Path

import pytest
from mcp import Client

from reveng_nexus import evidence as evidence_module
from reveng_nexus.artifacts import identify
from reveng_nexus.errors import ArgumentError, NotFound, RevisionConflict
from reveng_nexus.evidence import SCHEMA_VERSION, EvidenceStore
from reveng_nexus.registry import ProviderManager
from reveng_nexus.report import build_bundle, render_markdown
from reveng_nexus.server import NexusServer


def _store(tmp_path: Path, root: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "data" / "evidence.sqlite3", (str(root),), max_target_size_mb=1)


def _evidence(store, sha, case_id, kind="engine_derived", **extra):
    fields = {
        "target_id": sha,
        "case_id": case_id,
        "provider_id": "ghidra_remcp",
        "tool_name": "decompile_function",
        "operation": "binary.decompile",
        "evidence_kind": kind,
        "claim": "pseudocode",
        "subject": "main",
    }
    if kind == "ai_generated":
        fields["model"] = {"id": "local-model"}
    fields.update(extra)
    return store.add_evidence(**fields)["evidence_id"]


@pytest.fixture
def case(tmp_path, elf_sample, workspace):
    store = _store(tmp_path, workspace)
    ident = identify(elf_sample)
    cid = store.create_case("Questions")["case_id"]
    store.upsert_target(ident, cid)
    return store, ident.sha256, cid


def test_new_question_is_open_with_missing_evidence_visible(case):
    store, sha, cid = case
    q = store.record_question(case_id=cid, target_id=sha, question="Where is the config parsed?")
    assert q["status"] == "open" and q["revision"] == 1 and q["required"] is True
    assert q["evidence_missing"] is True and q["supporting_evidence_ids"] == []
    assert "history" not in q and q["history_count"] == 1
    assert [h["revision"] for h in store.get_question(q["question_id"])["history"]] == [1]
    counts = store.question_counts(case_id=cid)
    assert counts["by_status"]["open"] == 1 and counts["required_unresolved"] == 1 and counts["complete"] is False


@pytest.mark.parametrize("status", ["resolved", "partial", "contradicted"])
def test_a_new_question_cannot_start_answered(case, status):
    store, sha, cid = case
    with pytest.raises(ArgumentError, match="starts as one of"):
        store.record_question(case_id=cid, target_id=sha, question="q?", status=status, answer="x")


def test_blocked_needs_a_reason(case):
    store, sha, cid = case
    with pytest.raises(ArgumentError, match="needs a reason"):
        store.record_question(case_id=cid, target_id=sha, question="Runtime key?", status="blocked")
    q = store.record_question(
        case_id=cid, target_id=sha, question="Runtime key?", status="blocked", answer="needs an authorised device"
    )
    assert q["status"] == "blocked"


def test_stale_revision_fails_without_overwriting(case):
    store, sha, cid = case
    ev = _evidence(store, sha, cid)
    q = store.record_question(case_id=cid, target_id=sha, question="What does main do?")
    first = store.update_question(q["question_id"], expected_revision=1, status="investigating", note="worker A")
    assert first["revision"] == 2
    with pytest.raises(RevisionConflict) as caught:
        store.update_question(q["question_id"], expected_revision=1, status="partial", answer="x", evidence_ids=[ev])
    assert caught.value.details["current_revision"] == 2 and caught.value.details["status"] == "investigating"
    current = store.get_question(q["question_id"])
    # The rejected write left nothing behind: status, revision and evidence links are unchanged.
    assert current["status"] == "investigating" and current["revision"] == 2 and current["evidence"] == []
    assert [h["status"] for h in current["history"]] == ["open", "investigating"]


def test_concurrent_writers_with_the_same_revision_one_wins(case):
    store, sha, cid = case
    q = store.record_question(case_id=cid, target_id=sha, question="Race?")
    results: list[str] = []

    def writer(name):
        try:
            store.update_question(q["question_id"], expected_revision=1, status="investigating", note=name)
            results.append("ok")
        except RevisionConflict:
            results.append("conflict")

    threads = [threading.Thread(target=writer, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["conflict", "conflict", "conflict", "ok"]
    assert store.get_question(q["question_id"])["revision"] == 2


def test_resolution_needs_answer_and_non_ai_support(case):
    store, sha, cid = case
    ai = _evidence(store, sha, cid, kind="ai_generated", operation="ai.decompile")
    engine = _evidence(store, sha, cid)
    q = store.record_question(case_id=cid, target_id=sha, question="Is input validated?")
    qid = q["question_id"]
    with pytest.raises(ArgumentError, match="needs an answer"):
        store.update_question(qid, expected_revision=1, status="resolved", evidence_ids=[engine])
    with pytest.raises(ArgumentError, match="supporting evidence"):
        store.update_question(qid, expected_revision=1, status="resolved", answer="yes")
    with pytest.raises(ArgumentError, match="never resolve"):
        store.update_question(qid, expected_revision=1, status="resolved", answer="yes", evidence_ids=[ai])
    # A failed gate rolls back the evidence links it would have added.
    assert store.get_question(qid)["evidence"] == []
    done = store.update_question(qid, expected_revision=1, status="resolved", answer="yes", evidence_ids=[ai, engine])
    assert done["status"] == "resolved" and done["evidence_missing"] is False
    assert "some supporting evidence is still unverified" in done["warnings"]
    assert store.question_counts(case_id=cid)["complete"] is True


def test_contradictions_need_evidence_and_block_resolution(case):
    store, sha, cid = case
    support = _evidence(store, sha, cid)
    contra = _evidence(store, sha, cid, provider_id="ida_rs", claim="different callee")
    q = store.record_question(case_id=cid, target_id=sha, question="Does main call parse()?")
    qid = q["question_id"]
    with pytest.raises(ArgumentError, match="contradicting evidence id"):
        store.update_question(qid, expected_revision=1, status="contradicted")
    q = store.update_question(qid, expected_revision=1, evidence_ids=[support], contradicting_evidence_ids=[contra])
    with pytest.raises(ArgumentError, match="contradicting evidence still stands"):
        store.update_question(qid, expected_revision=q["revision"], status="resolved", answer="yes")
    q = store.update_question(qid, expected_revision=q["revision"], status="contradicted", answer="engines disagree")
    assert q["status"] == "contradicted" and q["contradicting_evidence_ids"] == [contra]
    store.review("evidence", contra, "rejected", "IDA mis-identified the callee at this address")
    q = store.update_question(qid, expected_revision=q["revision"], status="resolved", answer="yes, verified")
    # The rejected contradiction was engine evidence and its dismissal is only an unauthenticated
    # review: the resolution is recorded but contested, and the case is not complete.
    assert q["status"] == "resolved" and q["contested"] is True and q["stale"] is False
    assert any(w.startswith("contested:") for w in q["warnings"])
    assert q["resolution_basis"]["dismissed_source_contradictions"] == [contra]
    counts = store.question_counts(case_id=cid)
    assert counts["contested"] == 1 and counts["required_unresolved"] == 1 and counts["complete"] is False


def test_partial_needs_support_and_rejected_support_does_not_count(case):
    store, sha, cid = case
    ev = _evidence(store, sha, cid)
    q = store.record_question(case_id=cid, target_id=sha, question="Which ciphers?")
    with pytest.raises(ArgumentError, match="partial needs"):
        store.update_question(q["question_id"], expected_revision=1, status="partial", answer="AES so far")
    q = store.update_question(
        q["question_id"], expected_revision=1, status="partial", answer="AES so far", evidence_ids=[ev]
    )
    assert q["status"] == "partial"
    store.review("evidence", ev, "rejected", "wrong function")
    # Missing evidence becomes visible again once the only support is rejected.
    assert store.get_question(q["question_id"])["evidence_missing"] is True


def test_cited_evidence_must_exist_and_match_the_question_scope(case, workspace):
    store, sha, cid = case
    with pytest.raises(NotFound, match="unknown evidence ids"):
        store.record_question(case_id=cid, target_id=sha, question="q?", evidence_ids=["ev_missing"])
    other_file = workspace / "other.bin"
    other_file.write_bytes(b"\x7fELF other target")
    other = identify(other_file)
    store.upsert_target(other, cid)
    foreign = _evidence(store, other.sha256, cid)
    with pytest.raises(ArgumentError, match="different target"):
        store.record_question(case_id=cid, target_id=sha, question="q?", evidence_ids=[foreign])
    other_case = store.create_case("Other")["case_id"]
    with pytest.raises(ArgumentError, match="not part of case"):
        store.record_question(case_id=other_case, target_id=sha, question="q?")
    with pytest.raises(ArgumentError, match="outside case"):
        store.record_question(case_id=other_case, question="q?", evidence_ids=[foreign])
    with pytest.raises(NotFound):
        store.update_question("q_missing", expected_revision=1, status="investigating")
    q = store.record_question(case_id=cid, target_id=sha, question="q?")
    with pytest.raises(ArgumentError, match="nothing to update"):
        store.update_question(q["question_id"], expected_revision=1)


def test_list_is_checklist_ordered_and_counts_are_not_limited(case):
    store, sha, cid = case
    ids = [store.record_question(case_id=cid, target_id=sha, question=f"q{i}?")["question_id"] for i in range(5)]
    store.record_question(case_id=cid, target_id=sha, question="optional?", required=False)
    listed = store.list_questions(case_id=cid, limit=3)
    assert [q["question_id"] for q in listed] == ids[:3]
    counts = store.question_counts(case_id=cid)
    assert counts["total"] == 6 and counts["required_unresolved"] == 5
    assert store.list_questions(case_id=cid, status="resolved") == []
    with pytest.raises(ArgumentError):
        store.list_questions(case_id=cid, status="done")


def test_report_marks_open_required_questions_and_missing_evidence(case):
    store, sha, cid = case
    store.record_question(case_id=cid, target_id=sha, question="Where is the key derived?")
    md = render_markdown(build_bundle(store, cid))
    assert "## Investigation questions" in md and "**Incomplete:** 1 required question(s)" in md
    assert "**missing**" in md


def test_report_without_questions_makes_no_completeness_claim(case):
    store, _sha, cid = case
    assert "makes no completeness claim" in render_markdown(build_bundle(store, cid))


def test_evidence_overview_groups_by_operation_with_latest_id(case):
    store, sha, cid = case
    _evidence(store, sha, cid)
    latest = _evidence(store, sha, cid, claim="second")
    meta = _evidence(store, sha, cid, operation="binary.metadata", evidence_kind="direct_observation")
    overview = {row["operation"]: row for row in store.evidence_overview(sha)}
    assert overview["binary.decompile"]["count"] == 2 and overview["binary.decompile"]["latest_evidence_id"] == latest
    assert overview["binary.metadata"]["latest_evidence_id"] == meta


# -- migration --------------------------------------------------------------------------
def _seed_v2(db: Path, sha: str) -> None:
    """Rows written the way a v2 database holds them (plain SQL, independent of today's code)."""
    con = sqlite3.connect(db)
    try:
        now = "2026-10-01T00:00:00+00:00"
        con.execute("INSERT INTO cases (case_id, title, created_at) VALUES ('case-old', 'Before upgrade', ?)", (now,))
        con.execute(
            "INSERT INTO targets (target_id, absolute_path, display_name, size_bytes, registered_at, format, kind) "
            "VALUES (?, '/x', 'x.elf', 3, ?, 'elf', 'native_binary')",
            (sha, now),
        )
        con.execute("INSERT INTO case_targets VALUES ('case-old', ?, ?)", (sha, now))
        con.execute("INSERT INTO raw_outputs VALUES ('r' || ?, 'raw text', 8, 0, ?)", (sha[:10], now))
        con.execute(
            "INSERT INTO evidence (evidence_id, case_id, target_id, provider_id, tool_name, operation, subject, claim, "
            "classification, evidence_kind, confidence, status, created_at, engine_family) VALUES ('ev_old', 'case-old', ?, "
            "'ghidra_remcp', 'decompile_function', 'binary.decompile', 'main', 'pseudocode', 'observation', "
            "'engine_derived', 'medium', 'corroborated', ?, 'ghidra')",
            (sha, now),
        )
        con.execute(
            "INSERT INTO findings VALUES ('fd_old', 'case-old', ?, 'Old finding', 'kept', 'info', 'needs_review', "
            "'low', '', ?, ?)",
            (sha, now, now),
        )
        con.execute("INSERT INTO finding_evidence VALUES ('fd_old', 'ev_old', 'supports')")
        con.execute("INSERT INTO reviews VALUES ('rv_old', 'evidence', 'ev_old', 'corroborated', 'agrees', ?)", (now,))
        con.commit()
    finally:
        con.close()


def _dump_columns(db: Path, tables: tuple[str, ...], columns: dict[str, list[str]]) -> dict[str, list[tuple]]:
    con = sqlite3.connect(db)
    try:
        return {t: sorted(con.execute(f"SELECT {', '.join(columns[t])} FROM {t}").fetchall()) for t in tables}
    finally:
        con.close()


def test_v2_database_migrates_to_current_without_touching_existing_rows(tmp_path, elf_sample, workspace, monkeypatch):
    db = tmp_path / "v2.sqlite3"
    v2_only = {v: sql for v, sql in evidence_module.MIGRATIONS.items() if v <= 2}
    monkeypatch.setattr(evidence_module, "MIGRATIONS", v2_only)
    assert EvidenceStore(db, (str(workspace),)).schema_version() == 2
    monkeypatch.undo()
    sha = identify(elf_sample).sha256
    _seed_v2(db, sha)
    tables = ("targets", "evidence", "cases", "case_targets", "raw_outputs", "findings", "finding_evidence", "reviews")
    con = sqlite3.connect(db)
    columns = {t: [r[1] for r in con.execute(f"PRAGMA table_info({t})")] for t in tables}
    con.close()
    before = _dump_columns(db, tables, columns)

    store = EvidenceStore(db, (str(workspace),))
    assert store.schema_version() == SCHEMA_VERSION == max(evidence_module.MIGRATIONS)
    assert _dump_columns(db, tables, columns) == before  # every v2 column of every v2 row is unchanged
    q = store.record_question(case_id="case-old", target_id=sha, question="Upgraded?", evidence_ids=["ev_old"])
    assert q["supporting_evidence_ids"] == ["ev_old"]
    assert store.get_finding("fd_old")["evidence"][0]["evidence_id"] == "ev_old"
    EvidenceStore(db, (str(workspace),))  # re-opening is idempotent
    con = sqlite3.connect(db)
    try:
        versions = [r[0] for r in con.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert versions == sorted(evidence_module.MIGRATIONS)
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        con.close()


# -- MCP surface -------------------------------------------------------------------------
def _payload(result):
    return json.loads(result.content[0].text)


async def test_question_tools_over_mcp(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert tools["nexus_list_questions"].annotations.read_only_hint is True
            assert tools["nexus_update_question"].annotations.read_only_hint is False
            inspected = _payload(
                await client.call_tool("nexus_inspect_target", {"path": str(elf_sample), "case_title": "Q over MCP"})
            )
            sha, cid = inspected["target"]["sha256"], inspected["target"]["case_id"]
            meta = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
            q = _payload(
                await client.call_tool("nexus_record_question", {"target": sha, "question": "What architecture is it?"})
            )
            assert q["case_id"] == cid and q["status"] == "open"
            plan = _payload(await client.call_tool("nexus_plan_analysis", {"target": sha}))
            assert plan["target_kind"] == "native_binary"
            checklist = plan["checklist"]
            assert checklist["questions"][0]["question_id"] == q["question_id"]
            assert checklist["question_counts"]["required_unresolved"] == 1
            ops = {row["operation"]: row for row in checklist["existing_evidence"]}
            assert ops["binary.metadata"]["latest_evidence_id"] == meta["evidence_id"]

            stale = await client.call_tool(
                "nexus_update_question",
                {"question_id": q["question_id"], "expected_revision": 2, "status": "investigating"},
            )
            assert stale.is_error and _payload(stale)["error"] == "revision_conflict"
            assert _payload(stale)["details"]["current_revision"] == 1
            done = _payload(
                await client.call_tool(
                    "nexus_update_question",
                    {
                        "question_id": q["question_id"],
                        "expected_revision": 1,
                        "status": "resolved",
                        "answer": "x86_64 ELF",
                        "evidence_ids": [meta["evidence_id"]],
                    },
                )
            )
            assert done["status"] == "resolved" and done["revision"] == 2
            listed = _payload(await client.call_tool("nexus_list_questions", {"case_id": cid}))
            assert listed["counts"]["complete"] is True and listed["returned"] == 1
            one = _payload(await client.call_tool("nexus_list_questions", {"question_id": q["question_id"]}))
            assert [h["status"] for h in one["question"]["history"]] == ["open", "resolved"]
            missing_scope = await client.call_tool("nexus_list_questions", {})
            assert missing_scope.is_error
            no_scope = await client.call_tool("nexus_record_question", {"question": "orphan?"})
            assert no_scope.is_error and _payload(no_scope)["error"] == "invalid_arguments"
            # The old plan call shape still works and has no checklist.
            legacy = _payload(await client.call_tool("nexus_plan_analysis", {"target_kind": "native_binary"}))
            assert "checklist" not in legacy and legacy["target_kind"] == "native_binary"
    finally:
        await mgr.close()


# -- review findings ---------------------------------------------------------------------
def test_resolved_question_turns_stale_when_its_support_is_rejected(case):
    store, sha, cid = case
    ev = _evidence(store, sha, cid)
    q = store.record_question(case_id=cid, target_id=sha, question="Entry point?")
    store.update_question(
        q["question_id"], expected_revision=1, status="resolved", answer="0x401000", evidence_ids=[ev]
    )
    assert store.question_counts(case_id=cid)["complete"] is True
    store.review("evidence", ev, "rejected", "address belonged to a thunk")
    view = store.get_question(q["question_id"])
    assert view["status"] == "resolved" and view["stale"] is True and view["evidence_missing"] is True
    counts = store.question_counts(case_id=cid)
    assert counts["stale"] == 1 and counts["required_unresolved"] == 1 and counts["complete"] is False


def test_self_approval_sequence_cannot_resolve_a_question(case):
    """An agent writes its own note, reviews it as verified, and tries to resolve with it."""
    store, sha, cid = case
    note = store.record_evidence(
        target_id=sha,
        provider_id="ghidra_remcp",
        tool_name="decompile_function",
        subject="main",
        claim="exits early",
        case_id=cid,
    )["evidence_id"]
    assert store.get_evidence_record(note)["evidence_kind"] == "analyst_note"  # a caller cannot pick the kind
    q = store.record_question(case_id=cid, target_id=sha, question="Does main exit early?")
    store.review("evidence", note, "verified", "I checked it myself")
    with pytest.raises(ArgumentError, match="never resolve one, even when reviewed"):
        store.update_question(
            q["question_id"], expected_revision=1, status="resolved", answer="yes", evidence_ids=[note]
        )
    ai = _evidence(store, sha, cid, kind="ai_generated", operation="ai.decompile")
    store.review("evidence", ai, "verified", "looks right")
    with pytest.raises(ArgumentError, match="never resolve one"):
        store.update_question(q["question_id"], expected_revision=1, status="resolved", answer="yes", evidence_ids=[ai])
    # Partial is allowed (the note is support, just not source evidence), so the work is not lost.
    partial = store.update_question(
        q["question_id"], expected_revision=1, status="partial", answer="likely yes", evidence_ids=[note]
    )
    assert partial["status"] == "partial" and store.question_counts(case_id=cid)["complete"] is False


def test_qualifying_source_evidence_resolves_and_records_its_basis(case):
    store, sha, cid = case
    note = store.record_evidence(
        target_id=sha, provider_id="analyst", tool_name="manual", subject="main", claim="see listing", case_id=cid
    )["evidence_id"]
    engine = _evidence(store, sha, cid)
    q = store.record_question(case_id=cid, target_id=sha, question="Does main exit early?", evidence_ids=[note])
    done = store.update_question(
        q["question_id"], expected_revision=1, status="resolved", answer="yes", evidence_ids=[engine]
    )
    assert done["status"] == "resolved" and done["contested"] is False and done["stale"] is False
    assert done["resolution_basis"] == {"source_evidence_ids": [engine]}
    history = store.get_question(q["question_id"])["history"]
    assert json.loads(history[-1]["basis_json"]) == {"source_evidence_ids": [engine]}
    assert store.question_counts(case_id=cid)["complete"] is True
    # Rejecting the only source evidence re-evaluates the stored state: stale, not complete.
    store.review("evidence", engine, "rejected", "wrong function")
    view = store.get_question(q["question_id"])
    assert view["stale"] is True and store.question_counts(case_id=cid)["complete"] is False


def test_evidence_from_another_case_of_the_same_target_is_allowed_with_a_warning(case):
    store, sha, cid = case
    other = store.create_case("Second look")["case_id"]
    with store._connection() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO case_targets VALUES (?, ?, '2026-10-17T00:00:00+00:00')", (other, sha)
        )
    ev = _evidence(store, sha, other)
    q = store.record_question(case_id=cid, target_id=sha, question="Reuse?", evidence_ids=[ev])
    assert any("recorded under case" in w for w in q["warnings"])


def test_contradictions_recorded_as_evidence_links_block_resolution(case):
    store, sha, cid = case
    support = _evidence(store, sha, cid)
    other = _evidence(store, sha, cid, provider_id="ida_rs")
    store.link(other, support, "contradicts", "IDA disagrees")
    q = store.record_question(case_id=cid, target_id=sha, question="Callee?")
    with pytest.raises(ArgumentError, match="contradicting evidence still stands"):
        store.update_question(
            q["question_id"], expected_revision=1, status="resolved", answer="x", evidence_ids=[support]
        )
    q = store.update_question(q["question_id"], expected_revision=1, evidence_ids=[support])
    assert q["linked_contradictions"][0]["evidence_id"] == other
    store.review("evidence", other, "rejected", "IDA used the wrong base")
    done = store.update_question(q["question_id"], expected_revision=2, status="resolved", answer="x")
    assert done["status"] == "resolved" and done["contested"] is True
    assert done["linked_contradictions"][0]["status"] == "rejected"
    # A contradiction that is only an agent note does not make the resolution contested.
    note = store.record_evidence(
        target_id=sha, provider_id="analyst", tool_name="manual", subject="x", claim="doubt", case_id=cid
    )["evidence_id"]
    fresh = _evidence(store, sha, cid, claim="second engine run")
    q2 = store.record_question(case_id=cid, target_id=sha, question="Callee 2?")
    q2 = store.update_question(
        q2["question_id"], expected_revision=1, evidence_ids=[fresh], contradicting_evidence_ids=[note]
    )
    store.review("evidence", note, "rejected", "my own doubt was wrong")
    done2 = store.update_question(q2["question_id"], expected_revision=2, status="resolved", answer="x")
    assert done2["status"] == "resolved" and done2["contested"] is False


def test_contradicted_on_ai_output_only_warns(case):
    store, sha, cid = case
    ai = _evidence(store, sha, cid, kind="ai_generated", operation="ai.decompile")
    q = store.record_question(case_id=cid, target_id=sha, question="Loop bound?")
    out = store.update_question(
        q["question_id"],
        expected_revision=1,
        status="contradicted",
        answer="AI says otherwise",
        contradicting_evidence_ids=[ai],
    )
    assert "the only contradicting evidence is AI-generated" in out["warnings"]


@pytest.mark.parametrize("bad", [None, "1", True, 1.0])
def test_expected_revision_must_be_an_integer(case, bad):
    store, sha, cid = case
    q = store.record_question(case_id=cid, target_id=sha, question="q?")
    with pytest.raises(ArgumentError, match="expected_revision"):
        store.update_question(q["question_id"], expected_revision=bad, status="investigating")


def test_concurrent_openers_of_an_old_database_apply_each_migration_once(tmp_path, workspace, monkeypatch):
    db = tmp_path / "race.sqlite3"
    v2_only = {v: sql for v, sql in evidence_module.MIGRATIONS.items() if v <= 2}
    monkeypatch.setattr(evidence_module, "MIGRATIONS", v2_only)
    EvidenceStore(db, (str(workspace),))
    monkeypatch.undo()
    errors: list[BaseException] = []

    def opener():
        try:
            EvidenceStore(db, (str(workspace),))
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=opener) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    con = sqlite3.connect(db)
    try:
        assert [r[0] for r in con.execute("SELECT version FROM schema_migrations ORDER BY version")] == sorted(
            evidence_module.MIGRATIONS
        )
    finally:
        con.close()


def test_a_failing_migration_leaves_no_partial_schema_or_ledger_row(tmp_path, workspace, monkeypatch):
    db = tmp_path / "atomic.sqlite3"
    EvidenceStore(db, (str(workspace),))
    broken = {
        **evidence_module.MIGRATIONS,
        99: "CREATE TABLE half_done (x INTEGER); INSERT INTO no_such_table VALUES (1);",
    }
    monkeypatch.setattr(evidence_module, "MIGRATIONS", broken)
    with pytest.raises(sqlite3.OperationalError):
        EvidenceStore(db, (str(workspace),))
    monkeypatch.undo()
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == SCHEMA_VERSION
        assert con.execute("SELECT 1 FROM sqlite_master WHERE name = 'half_done'").fetchone() is None
    finally:
        con.close()


# -- bounded output ------------------------------------------------------------------------
def test_listings_cap_ids_and_drop_link_detail(case):
    store, sha, cid = case
    ids = [_evidence(store, sha, cid, claim=f"c{i}") for i in range(30)]
    q = store.record_question(case_id=cid, target_id=sha, question="x" * 1500, evidence_ids=ids)
    row = store.list_questions(case_id=cid)[0]
    assert "evidence" not in row and row["supporting_evidence_count"] == 30
    assert row["supporting_evidence_ids"] == ids[:20]
    assert len(row["question"]) <= 501 and row["truncated_fields"] == ["question"]
    full = store.get_question(q["question_id"])
    assert len(full["evidence"]) == 30 and len(full["supporting_evidence_ids"]) == 30


def test_history_is_bounded_on_writes_and_reads(case):
    store, sha, cid = case
    q = store.record_question(case_id=cid, target_id=sha, question="Long-running?")
    rev = 1
    for _ in range(30):
        out = store.update_question(
            q["question_id"], expected_revision=rev, status="investigating", answer="a" * 3000, note="n" * 1500
        )
        rev = out["revision"]
        assert "history" not in out
    full = store.get_question(q["question_id"])
    assert [h["revision"] for h in full["history"]] == list(range(22, 32)) and full["history_count"] == 31
    assert len(json.dumps(out)) < 20_000
    assert "history" not in store.get_question(q["question_id"], history_limit=0)


def test_offset_paging_is_stable_while_questions_are_added(case):
    store, sha, cid = case
    ids = [store.record_question(case_id=cid, target_id=sha, question=f"q{i}?")["question_id"] for i in range(5)]
    first = [q["question_id"] for q in store.list_questions(case_id=cid, limit=2)]
    store.record_question(case_id=cid, target_id=sha, question="late?")
    second = [q["question_id"] for q in store.list_questions(case_id=cid, limit=2, offset=2)]
    assert first + second == ids[:4]


async def test_plan_checklist_is_bounded_and_lists_open_work_first(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            inspected = _payload(await client.call_tool("nexus_inspect_target", {"path": str(elf_sample)}))
            sha, cid = inspected["target"]["sha256"], inspected["target"]["case_id"]
            meta = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
            store = mgr.evidence
            done = store.record_question(case_id=cid, target_id=sha, question="resolved first?")
            store.update_question(
                done["question_id"],
                expected_revision=1,
                status="resolved",
                answer="y",
                evidence_ids=[meta["evidence_id"]],
            )
            for i in range(60):
                store.record_question(case_id=cid, target_id=sha, question=f"open {i} " + "z" * 600)
            plan = _payload(await client.call_tool("nexus_plan_analysis", {"case_id": cid, "target_kind": "unknown"}))
            checklist = plan["checklist"]
            assert len(checklist["questions"]) == 50 and checklist["questions_truncated"] is True
            assert all(q["status"] == "open" for q in checklist["questions"])
            assert all(len(q["question"]) <= 201 for q in checklist["questions"])
            assert checklist["question_counts"]["total"] == 61
            by_case = _payload(await client.call_tool("nexus_plan_analysis", {"case_id": cid}))
            assert by_case["target_kind"] == "unknown" and "checklist" in by_case
            page = _payload(await client.call_tool("nexus_list_questions", {"case_id": cid, "limit": 50}))
            assert page["returned"] == 50 and page["next_offset"] == 50
            rest = _payload(await client.call_tool("nexus_list_questions", {"case_id": cid, "offset": 50}))
            assert rest["returned"] == 11 and rest["next_offset"] is None
            empty = await client.call_tool("nexus_list_questions", {})
            assert empty.is_error and _payload(empty)["error"] == "invalid_arguments"
    finally:
        await mgr.close()


async def test_self_approval_over_mcp_is_refused_and_source_evidence_resolves(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            inspected = _payload(await client.call_tool("nexus_inspect_target", {"path": str(elf_sample)}))
            sha = inspected["target"]["sha256"]
            note = _payload(
                await client.call_tool(
                    "nexus_record_evidence",
                    {
                        "target": sha,
                        "subject": "binary",
                        "claim": "it is an x86_64 ELF",
                        "classification": "observation",
                    },
                )
            )
            reviewed = _payload(
                await client.call_tool(
                    "nexus_review",
                    {
                        "subject_type": "evidence",
                        "subject_id": note["evidence_id"],
                        "status": "verified",
                        "note": "mine",
                    },
                )
            )
            assert reviewed["status"] == "verified"
            q = _payload(await client.call_tool("nexus_record_question", {"target": sha, "question": "Architecture?"}))
            refused = await client.call_tool(
                "nexus_update_question",
                {
                    "question_id": q["question_id"],
                    "expected_revision": 1,
                    "status": "resolved",
                    "answer": "x86_64",
                    "evidence_ids": [note["evidence_id"]],
                },
            )
            assert refused.is_error and "never resolve" in _payload(refused)["message"]
            meta = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
            done = _payload(
                await client.call_tool(
                    "nexus_update_question",
                    {
                        "question_id": q["question_id"],
                        "expected_revision": 1,
                        "status": "resolved",
                        "answer": "x86_64",
                        "evidence_ids": [meta["evidence_id"]],
                    },
                )
            )
            assert done["status"] == "resolved" and done["resolution_basis"]["source_evidence_ids"] == [
                meta["evidence_id"]
            ]
    finally:
        await mgr.close()


# -- second authenticity review ------------------------------------------------------------------
def test_citing_both_sides_of_a_disagreement_does_not_hide_it(case):
    store, sha, cid = case
    ghidra = _evidence(store, sha, cid)
    ida = _evidence(store, sha, cid, provider_id="ida_rs", claim="different callee")
    store.link(ida, ghidra, "contradicts", "engines disagree")
    q = store.record_question(case_id=cid, target_id=sha, question="Callee?")
    with pytest.raises(ArgumentError, match="contradicting evidence still stands"):
        store.update_question(
            q["question_id"], expected_revision=1, status="resolved", answer="x", evidence_ids=[ghidra, ida]
        )
    store.review("evidence", ida, "contradicted", "IDA is wrong here")
    with pytest.raises(ArgumentError, match="contradicting evidence still stands"):
        store.update_question(
            q["question_id"], expected_revision=1, status="resolved", answer="x", evidence_ids=[ghidra, ida]
        )
    store.review("evidence", ida, "rejected", "IDA is wrong here")
    done = store.update_question(
        q["question_id"], expected_revision=1, status="resolved", answer="x", evidence_ids=[ghidra, ida]
    )
    assert done["contested"] is True and store.question_counts(case_id=cid)["complete"] is False


def test_a_required_question_can_never_be_made_optional(case):
    store, sha, cid = case
    q = store.record_question(case_id=cid, target_id=sha, question="Key derivation?")
    with pytest.raises(ArgumentError, match="cannot be made optional") as caught:
        store.update_question(q["question_id"], expected_revision=1, required=False)
    assert caught.value.details["rule"] == "required_is_monotonic"
    blocked = store.update_question(
        q["question_id"], expected_revision=1, status="blocked", answer="needs a runtime trace", note="out of scope"
    )
    assert blocked["required"] is True and store.question_counts(case_id=cid)["required_unresolved"] == 1
    engine = _evidence(store, sha, cid)
    done = store.update_question(
        q["question_id"], expected_revision=2, status="resolved", answer="PBKDF2", evidence_ids=[engine]
    )
    # Even once resolved, relaxing is refused; the refusal leaves revision and history untouched.
    with pytest.raises(ArgumentError, match="cannot be made optional"):
        store.update_question(q["question_id"], expected_revision=3, required=False)
    view = store.get_question(done["question_id"])
    assert view["revision"] == 3 and [h["required"] for h in view["history"]] == [1, 1, 1]


def test_resolve_optional_reopen_cannot_make_a_case_complete(case):
    store, sha, cid = case
    engine = _evidence(store, sha, cid)
    q = store.record_question(case_id=cid, target_id=sha, question="Entry point?")
    store.update_question(
        q["question_id"], expected_revision=1, status="resolved", answer="0x401000", evidence_ids=[engine]
    )
    assert store.question_counts(case_id=cid)["complete"] is True  # legitimate source resolution
    with pytest.raises(ArgumentError, match="cannot be made optional"):
        store.update_question(q["question_id"], expected_revision=2, required=False)
    reopened = store.update_question(q["question_id"], expected_revision=2, status="open", note="re-check")
    counts = store.question_counts(case_id=cid)
    assert reopened["required"] is True and counts["required_unresolved"] == 1 and counts["complete"] is False
    assert "**Incomplete:** 1 required question(s)" in render_markdown(build_bundle(store, cid))


def test_optional_questions_stay_optional_and_can_become_required(case):
    store, sha, cid = case
    opt = store.record_question(case_id=cid, target_id=sha, question="Nice to know?", required=False)
    req = store.record_question(case_id=cid, target_id=sha, question="Must know?")
    engine = _evidence(store, sha, cid)
    store.update_question(req["question_id"], expected_revision=1, status="resolved", answer="y", evidence_ids=[engine])
    counts = store.question_counts(case_id=cid)
    assert counts["complete"] is True and counts["unresolved"] == 1  # the open optional one does not block
    raised = store.update_question(opt["question_id"], expected_revision=1, required=True)
    assert raised["required"] is True and store.question_counts(case_id=cid)["complete"] is False


def test_a_question_ever_required_counts_as_required_even_if_stored_optional(case):
    """Defence in depth for databases written by an earlier build that allowed the flip."""
    store, sha, cid = case
    q = store.record_question(case_id=cid, target_id=sha, question="Legacy?")
    with store._connection() as connection:
        connection.execute("UPDATE questions SET required = 0 WHERE question_id = ?", (q["question_id"],))
    assert store.get_question(q["question_id"])["required"] is True
    assert store.question_counts(case_id=cid)["required_unresolved"] == 1


def test_report_lists_every_question_beyond_one_page(case):
    store, sha, cid = case
    for i in range(205):
        store.record_question(case_id=cid, target_id=sha, question=f"q{i}?")
    bundle = build_bundle(store, cid)
    assert len(bundle["questions"]) == 205 == bundle["question_counts"]["total"]


async def test_required_question_bypass_is_refused_over_mcp(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        app = NexusServer(mgr)
        async with Client(app.server) as client:
            inspected = _payload(await client.call_tool("nexus_inspect_target", {"path": str(elf_sample)}))
            sha, cid = inspected["target"]["sha256"], inspected["target"]["case_id"]
            meta = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
            q = _payload(await client.call_tool("nexus_record_question", {"target": sha, "question": "Arch?"}))
            qid = q["question_id"]
            resolved = _payload(
                await client.call_tool(
                    "nexus_update_question",
                    {
                        "question_id": qid,
                        "expected_revision": 1,
                        "status": "resolved",
                        "answer": "x86_64",
                        "evidence_ids": [meta["evidence_id"]],
                    },
                )
            )
            assert resolved["status"] == "resolved" and resolved["revision"] == 2
            relax = await client.call_tool(
                "nexus_update_question", {"question_id": qid, "expected_revision": 2, "required": False}
            )
            assert relax.is_error and _payload(relax)["details"]["rule"] == "required_is_monotonic"
            reopened = _payload(
                await client.call_tool(
                    "nexus_update_question", {"question_id": qid, "expected_revision": 2, "status": "open"}
                )
            )
            assert reopened["revision"] == 3 and reopened["required"] is True
            stale = await client.call_tool(
                "nexus_update_question", {"question_id": qid, "expected_revision": 2, "status": "investigating"}
            )
            assert stale.is_error and _payload(stale)["error"] == "revision_conflict"
            counts = _payload(await client.call_tool("nexus_list_questions", {"case_id": cid}))["counts"]
            brief = _payload(await client.call_tool("nexus_case_brief", {"case_id": cid}))["questions"]
            plan = _payload(await client.call_tool("nexus_plan_analysis", {"case_id": cid}))["checklist"]
            assert counts["complete"] is False and counts["required_unresolved"] == 1
            assert brief["complete"] is False and plan["question_counts"]["complete"] is False
            one = _payload(await client.call_tool("nexus_list_questions", {"question_id": qid}))["question"]
            assert [(h["revision"], h["status"], h["required"]) for h in one["history"]] == [
                (1, "open", 1),
                (2, "resolved", 1),
                (3, "open", 1),
            ]
    finally:
        await mgr.close()
