import sqlite3
from pathlib import Path

import pytest

from reveng_nexus.artifacts import identify
from reveng_nexus.errors import ArgumentError, NotFound
from reveng_nexus.evidence import SCHEMA_VERSION, EvidenceStore


def _store(tmp_path: Path, root: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "data" / "evidence.sqlite3", (str(root),), max_target_size_mb=1)


def test_target_registration_hashes_file_and_enforces_allowlist(tmp_path: Path):
    root = tmp_path / "samples"
    root.mkdir()
    sample = root / "sample.bin"
    sample.write_bytes(b"known sample bytes")
    store = _store(tmp_path, root)
    registered = store.register_target(str(sample), "test sample")
    assert len(registered["target_id"]) == 64
    assert registered["display_name"] == "sample.bin"
    assert store.list_targets()[0]["target_id"] == registered["target_id"]
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"not allowed")
    with pytest.raises(PermissionError, match="outside configured"):
        store.register_target(str(outside))


def test_registration_disabled_without_allowed_roots(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"bytes")
    store = EvidenceStore(tmp_path / "data.sqlite3")
    with pytest.raises(PermissionError, match="allowed_roots"):
        store.register_target(str(sample))


def test_evidence_provenance_and_cross_provider_candidates(tmp_path: Path):
    root = tmp_path / "samples"
    root.mkdir()
    sample = root / "sample.bin"
    sample.write_bytes(b"binary payload")
    store = EvidenceStore(tmp_path / "data.sqlite3", (str(root),))
    target = store.register_target(str(sample))
    first = store.record_evidence(
        target_id=target["target_id"],
        provider_id="ghidra",
        tool_name="decompile_function",
        subject="FUN_401000",
        claim="Function reads a configuration value.",
        excerpt="read_config();",
        classification="hypothesis",
    )
    store.record_evidence(
        target_id=target["target_id"],
        provider_id="ida_official",
        tool_name="decompile",
        subject="FUN_401000",
        claim="Function reads a configuration value.",
        classification="observation",
        confidence="high",
    )
    listed = store.list_evidence(target_id=target["target_id"])
    assert len(listed) == 2
    assert all("excerpt" not in row for row in listed)
    candidates = store.cross_check_candidates(target["target_id"])
    assert len(candidates) == 1
    assert candidates[0]["provider_count"] == 2
    assert candidates[0]["contains_contradiction"] is False
    assert store.update_status(first["evidence_id"], "corroborated")["status"] == "corroborated"


def test_evidence_requires_registered_sha256_target(tmp_path: Path):
    root = tmp_path / "samples"
    root.mkdir()
    (root / "sample.bin").write_bytes(b"binary payload")
    store = EvidenceStore(tmp_path / "data.sqlite3", (str(root),))
    store.register_target(str(root / "sample.bin"))
    with pytest.raises(ValueError, match="Unknown target_id"):
        store.record_evidence(
            target_id="0" * 64, provider_id="ghidra", tool_name="decompile", subject="FUN_401000", claim="Some claim"
        )


def test_migrates_a_0_1_database_in_place(tmp_path: Path):
    db = tmp_path / "old.sqlite3"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE targets (target_id TEXT PRIMARY KEY, absolute_path TEXT NOT NULL, display_name TEXT NOT NULL,
            label TEXT, size_bytes INTEGER NOT NULL, registered_at TEXT NOT NULL);
        CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(target_id)
            ON DELETE CASCADE, provider_id TEXT NOT NULL, tool_name TEXT NOT NULL, subject TEXT NOT NULL,
            claim TEXT NOT NULL, excerpt TEXT NOT NULL DEFAULT '', classification TEXT NOT NULL,
            confidence TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unverified', created_at TEXT NOT NULL);
    """)
    tid = "a" * 64
    con.execute("INSERT INTO targets VALUES (?, '/x', 'x.bin', '', 3, '2026-01-01T00:00:00+00:00')", (tid,))
    con.execute(
        "INSERT INTO evidence VALUES ('e1', ?, 'ghidra', 'decompile', 'main', 'old claim', 'code', "
        "'observation', 'high', 'unverified', '2026-01-01T00:00:00+00:00')",
        (tid,),
    )
    con.commit()
    con.close()
    store = EvidenceStore(db)
    assert store.schema_version() == SCHEMA_VERSION
    rows = store.list_evidence(target_id=tid, include_excerpt=True)
    assert rows[0]["claim"] == "old claim" and rows[0]["excerpt"] == "code"
    assert rows[0]["evidence_kind"] == "analyst_note" and rows[0]["case_id"] == "default"
    assert store.get_case("default")["targets"][0]["target_id"] == tid
    EvidenceStore(db)  # re-opening is idempotent
    assert store.schema_version() == SCHEMA_VERSION


@pytest.fixture
def populated(tmp_path, elf_sample, workspace):
    store = _store(tmp_path, workspace)
    ident = identify(elf_sample)
    case = store.create_case("Fixture case")
    store.upsert_target(ident, case["case_id"])
    engine = store.add_evidence(
        target_id=ident.sha256,
        case_id=case["case_id"],
        provider_id="ghidra_remcp",
        tool_name="decompile_function",
        operation="binary.decompile",
        evidence_kind="engine_derived",
        claim="pseudocode",
        subject="main@0x400119",
        subject_type="function",
        subject_address=0x400119,
        subject_name="main",
        normalized={"code": "int main(){}"},
        raw='{"decompiled_code": "int main(){}"}',
        engine="ghidra",
        engine_family="ghidra",
        engine_version="12.1.4",
    )
    return store, ident, case["case_id"], engine


def test_raw_output_is_hash_addressed_and_retrievable(populated):
    store, _ident, _case, engine = populated
    record = store.get_evidence_record(engine["evidence_id"], include_raw=True)
    assert record["raw"]["content"].startswith('{"decompiled_code"')
    assert len(record["raw_sha256"]) == 64 and record["engine_version"] == "12.1.4"


def test_raw_output_truncation_is_recorded(populated):
    store, ident, case, _ = populated
    big = store.add_evidence(
        target_id=ident.sha256,
        case_id=case,
        provider_id="p",
        tool_name="t",
        operation="o",
        evidence_kind="engine_derived",
        claim="c",
        raw="x" * 5000,
        raw_limit_bytes=100,
    )
    assert any("truncated" in w for w in big["warnings"])


def test_ai_evidence_requires_model_provenance_and_stays_unverified(populated):
    store, ident, case, _ = populated
    with pytest.raises(ArgumentError, match="model provenance"):
        store.add_evidence(
            target_id=ident.sha256,
            case_id=case,
            provider_id="llm",
            tool_name="t",
            operation="ai.decompile",
            evidence_kind="ai_generated",
            claim="c",
        )
    with pytest.raises(ArgumentError, match="unverified"):
        store.add_evidence(
            target_id=ident.sha256,
            case_id=case,
            provider_id="llm",
            tool_name="t",
            operation="ai.decompile",
            evidence_kind="ai_generated",
            claim="c",
            model={"model": "m"},
            status="verified",
        )


def test_findings_need_evidence_and_cannot_be_confirmed_by_ai_alone(populated):
    store, ident, case, engine = populated
    hypothesis = store.record_finding(case_id=case, title="Maybe a key check", description="hunch", evidence_ids=[])
    assert hypothesis["status"] == "hypothesis"
    with pytest.raises(ArgumentError, match="cite at least one"):
        store.record_finding(case_id=case, title="t", description="d", evidence_ids=[], status="confirmed")
    with pytest.raises(NotFound):
        store.record_finding(case_id=case, title="t", description="d", evidence_ids=["ev_missing"], status="confirmed")
    ai = store.add_evidence(
        target_id=ident.sha256,
        case_id=case,
        provider_id="llm",
        tool_name="completions",
        operation="ai.decompile",
        evidence_kind="ai_generated",
        claim="AI",
        model={"model": "m"},
    )
    with pytest.raises(ArgumentError, match="AI-generated evidence alone"):
        store.record_finding(
            case_id=case, title="t", description="d", evidence_ids=[ai["evidence_id"]], status="confirmed"
        )
    finding = store.record_finding(
        case_id=case,
        title="Key check",
        description="compares with 0x1337",
        evidence_ids=[engine["evidence_id"], ai["evidence_id"]],
        status="confirmed",
        confidence="medium",
        severity="low",
    )
    roles = {e["evidence_id"]: e["evidence_kind"] for e in finding["evidence"]}
    assert roles[ai["evidence_id"]] == "ai_generated"
    assert finding["target_id"] == ident.sha256


def test_reviews_are_the_only_path_to_verified(populated):
    store, _ident, _case, engine = populated
    with pytest.raises(ArgumentError, match="note"):
        store.review("evidence", engine["evidence_id"], "verified", "")
    store.review("evidence", engine["evidence_id"], "verified", "checked against the listing")
    record = store.get_evidence_record(engine["evidence_id"])
    assert record["status"] == "verified" and record["reviews"][0]["note"] == "checked against the listing"


def test_links_comparisons_and_bundle(populated):
    store, ident, case, engine = populated
    other = store.add_evidence(
        target_id=ident.sha256,
        case_id=case,
        provider_id="ida_rs",
        tool_name="decompile",
        operation="binary.decompile",
        evidence_kind="engine_derived",
        claim="pseudocode",
        subject_address=0x400119,
        engine_family="ida",
    )
    store.link(engine["evidence_id"], other["evidence_id"], "contradicts", note="different callees")
    cmp_ = store.add_comparison(
        target_id=ident.sha256,
        case_id=case,
        operation="function_comparison",
        subject="main",
        assessment="disagreement",
        details={"disagreements": [{"aspect": "callees"}]},
        evidence_ids=[engine["evidence_id"], other["evidence_id"]],
    )
    bundle = store.case_bundle(case)
    assert bundle["comparisons"][0]["comparison_id"] == cmp_["comparison_id"]
    assert set(bundle["comparisons"][0]["evidence_ids"]) == {engine["evidence_id"], other["evidence_id"]}
    assert bundle["links"][0]["relation"] == "contradicts"
    assert "absolute_path" not in bundle["targets"][0]
    with pytest.raises(ArgumentError):
        store.link(engine["evidence_id"], other["evidence_id"], "proves")
