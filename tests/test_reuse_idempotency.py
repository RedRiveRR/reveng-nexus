"""R2 initial slice: result reuse keyed on target/provider/operation/params/engine, and idempotent writes."""

import contextlib
import json
import sqlite3
import threading

import pytest
from conftest import mock_engine
from mcp import Client

from reveng_nexus import evidence as evidence_module
from reveng_nexus.errors import ArgumentError, CapabilityUnavailable, NotFound
from reveng_nexus.evidence import SCHEMA_VERSION, EvidenceStore, Idempotency
from reveng_nexus.registry import ProviderManager
from reveng_nexus.server import NexusServer


def _payload(result):
    return json.loads(result.content[0].text)


@pytest.fixture
async def gateway(config_factory, workspace):
    holder = {}

    async def factory(providers=None, **sections):
        mgr = ProviderManager(config_factory(workspace, providers or [], **sections))
        await mgr.start()
        holder["mgr"] = mgr
        return NexusServer(mgr), mgr

    yield factory
    if "mgr" in holder:
        await holder["mgr"].close()


async def _inspect(client, path, title=None):
    args = {"path": str(path)}
    if title:
        args["case_title"] = title
    out = _payload(await client.call_tool("nexus_inspect_target", args))
    return out["target"]["sha256"], out["target"]["case_id"]


# -- reuse ---------------------------------------------------------------------------------
async def test_identical_request_reuses_the_recorded_result(gateway, elf_sample):
    app, mgr = await gateway()
    async with Client(app.server) as client:
        sha, _cid = await _inspect(client, elf_sample)
        first = _payload(await client.call_tool("nexus_search_strings", {"target": sha, "limit": 20}))
        again = _payload(await client.call_tool("nexus_search_strings", {"target": sha, "limit": 20}))
        assert first["reused"] is False and again["reused"] is True
        assert again["evidence_id"] == first["evidence_id"] and again["result"] == first["result"]
        assert again["attempts"] == [
            {"provider_id": "builtin", "outcome": "reused", "evidence_id": first["evidence_id"]}
        ]
        assert again["provenance"]["provider_id"] == first["provenance"]["provider_id"]
        assert "reused_evidence_created_at" in again
        fresh = _payload(await client.call_tool("nexus_search_strings", {"target": sha, "limit": 20, "refresh": True}))
        assert fresh["reused"] is False and fresh["evidence_id"] != first["evidence_id"]
    audit = mgr.audit.path.read_text(encoding="utf-8")
    assert '"outcome": "reused"' in audit


async def test_different_parameters_targets_or_cases_are_not_reused(gateway, elf_sample, pe_sample):
    app, _mgr = await gateway()
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        base = _payload(await client.call_tool("nexus_search_strings", {"target": sha, "limit": 20}))
        other_params = _payload(await client.call_tool("nexus_search_strings", {"target": sha, "limit": 21}))
        assert other_params["reused"] is False and other_params["evidence_id"] != base["evidence_id"]
        pe_sha, _ = await _inspect(client, pe_sample)
        other_target = _payload(await client.call_tool("nexus_search_strings", {"target": pe_sha, "limit": 20}))
        assert other_target["reused"] is False
        _, second_case = await _inspect(client, elf_sample, title="Second case")
        other_case = _payload(
            await client.call_tool("nexus_search_strings", {"target": sha, "limit": 20, "case_id": second_case})
        )
        assert other_case["reused"] is False


async def test_rejected_evidence_is_not_reused(gateway, elf_sample):
    app, mgr = await gateway()
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        mgr.evidence.review("evidence", first["evidence_id"], "rejected", "parser bug")
        again = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        assert again["reused"] is False and again["evidence_id"] != first["evidence_id"]


async def test_code_change_is_part_of_the_engine_fingerprint(gateway, elf_sample, monkeypatch):
    from reveng_nexus import registry

    app, _mgr = await gateway()
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        monkeypatch.setattr(registry, "_code_fingerprint", lambda: "different-build")
        again = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        assert again["reused"] is False and again["evidence_id"] != first["evidence_id"]


async def test_workflows_still_run_fresh(gateway, elf_sample):
    app, mgr = await gateway([mock_engine("ghidra_a")])
    async with Client(app.server) as client:
        sha, cid = await _inspect(client, elf_sample)
        await client.call_tool("nexus_analyze_binary", {"target": sha, "max_functions": 1})
        before = len(mgr.evidence.query_evidence(case_id=cid, limit=500))
        await client.call_tool("nexus_analyze_binary", {"target": sha, "max_functions": 1})
        assert len(mgr.evidence.query_evidence(case_id=cid, limit=500)) > before


# -- idempotency ------------------------------------------------------------------------------
async def test_idempotent_writes_return_the_original_result(gateway, elf_sample):
    app, mgr = await gateway()
    async with Client(app.server) as client:
        sha, cid = await _inspect(client, elf_sample)
        meta = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        finding_args = {
            "target": sha,
            "title": "Entry point identified",
            "description": "From the ELF header.",
            "evidence_ids": [meta["evidence_id"]],
            "status": "needs_review",
            "idempotency_key": "finding-entry-0001",
        }
        first = _payload(await client.call_tool("nexus_record_finding", finding_args))
        again = _payload(await client.call_tool("nexus_record_finding", finding_args))
        assert again["finding_id"] == first["finding_id"] and again["idempotent_replay"] is True
        assert len(mgr.evidence.list_findings(case_id=cid)) == 1
        changed = await client.call_tool("nexus_record_finding", {**finding_args, "title": "Something else"})
        assert changed.is_error and "different arguments" in _payload(changed)["message"]

        note_args = {"target": sha, "subject": "main", "claim": "reads argv", "idempotency_key": "note-0001-abc"}
        n1 = _payload(await client.call_tool("nexus_record_evidence", note_args))
        n2 = _payload(await client.call_tool("nexus_record_evidence", note_args))
        assert n1["evidence_id"] == n2["evidence_id"] and n2["idempotent_replay"] is True

        review_args = {
            "subject_type": "finding",
            "subject_id": first["finding_id"],
            "status": "confirmed",
            "note": "checked the header bytes",
            "idempotency_key": "review-0001-x",
        }
        r1 = _payload(await client.call_tool("nexus_review", review_args))
        r2 = _payload(await client.call_tool("nexus_review", review_args))
        assert r1["review_id"] == r2["review_id"] and r2["idempotent_replay"] is True
        bundle = mgr.evidence.case_bundle(cid)
        assert len([r for r in bundle["reviews"] if r["subject_id"] == first["finding_id"]]) == 1

        q_args = {"target": sha, "question": "Is it stripped?", "idempotency_key": "question-0001"}
        q1 = _payload(await client.call_tool("nexus_record_question", q_args))
        q2 = _payload(await client.call_tool("nexus_record_question", q_args))
        assert q1["question_id"] == q2["question_id"] and q2["idempotent_replay"] is True
        upd = {
            "question_id": q1["question_id"],
            "expected_revision": 1,
            "status": "investigating",
            "idempotency_key": "update-0001-q",
        }
        u1 = _payload(await client.call_tool("nexus_update_question", upd))
        u2 = _payload(await client.call_tool("nexus_update_question", upd))  # lost-response retry
        assert u1["revision"] == 2 and u2["idempotent_replay"] is True and u2["revision"] == 2
        no_key_retry = await client.call_tool(
            "nexus_update_question", {k: v for k, v in upd.items() if k != "idempotency_key"}
        )
        assert no_key_retry.is_error and _payload(no_key_retry)["error"] == "revision_conflict"
        bad_key = await client.call_tool("nexus_record_question", {**q_args, "idempotency_key": "x"})
        assert bad_key.is_error and _payload(bad_key)["error"] == "invalid_arguments"


def test_a_failed_write_does_not_consume_the_key(tmp_path, workspace, elf_sample):
    from reveng_nexus.artifacts import identify

    store = EvidenceStore(tmp_path / "e.sqlite3", (str(workspace),))
    ident = identify(elf_sample)
    cid = store.create_case("Keys")["case_id"]
    store.upsert_target(ident, cid)
    key = Idempotency("nexus_record_finding", "finding-key-1", "h1")
    with pytest.raises(NotFound):
        store.record_finding(case_id=cid, title="t", description="d", evidence_ids=["ev_missing"], idempotency=key)
    ok = store.record_finding(case_id=cid, title="t", description="d", evidence_ids=[], idempotency=key)
    assert "idempotent_replay" not in ok
    with pytest.raises(ArgumentError, match="different arguments"):
        store.record_finding(
            case_id=cid, title="t", description="d", evidence_ids=[], idempotency=Idempotency(key.tool, key.key, "h2")
        )


def test_concurrent_retries_with_one_key_write_once(tmp_path, workspace, elf_sample):
    from reveng_nexus.artifacts import identify

    store = EvidenceStore(tmp_path / "e.sqlite3", (str(workspace),))
    ident = identify(elf_sample)
    cid = store.create_case("Race")["case_id"]
    store.upsert_target(ident, cid)
    key = Idempotency("nexus_record_question", "race-key-0001", "same")
    results: list[str] = []

    def writer():
        out = store.record_question(case_id=cid, target_id=ident.sha256, question="once?", idempotency=key)
        results.append(out["question_id"])

    threads = [threading.Thread(target=writer) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 6 and len(set(results)) == 1
    assert store.question_counts(case_id=cid)["total"] == 1


def test_v3_database_migrates_to_v4_without_touching_existing_rows(tmp_path, workspace, elf_sample, monkeypatch):
    from reveng_nexus.artifacts import identify

    db = tmp_path / "v3.sqlite3"
    monkeypatch.setattr(evidence_module, "MIGRATIONS", {v: q for v, q in evidence_module.MIGRATIONS.items() if v <= 3})
    old = EvidenceStore(db, (str(workspace),))
    ident = identify(elf_sample)
    cid = old.create_case("Before v4")["case_id"]
    old.upsert_target(ident, cid)
    with sqlite3.connect(db) as con:
        con.execute(
            "INSERT INTO evidence (evidence_id, case_id, target_id, provider_id, tool_name, operation, subject, claim, "
            "classification, evidence_kind, confidence, status, created_at) VALUES ('ev_old', ?, ?, 'builtin', 't', "
            "'binary.metadata', 'binary', 'old', 'observation', 'direct_observation', 'medium', 'unverified', "
            "'2026-10-01T00:00:00+00:00')",
            (cid, ident.sha256),
        )
        before = con.execute("SELECT * FROM evidence").fetchall()
    monkeypatch.undo()
    store = EvidenceStore(db, (str(workspace),))
    assert store.schema_version() == SCHEMA_VERSION == 4
    with sqlite3.connect(db) as con:
        after = con.execute(
            "SELECT evidence_id, case_id, target_id, provider_id, tool_name, subject, claim, excerpt, classification, "
            "confidence, status, created_at, operation, subject_type, subject_address, subject_name, evidence_kind, "
            "engine, engine_family, engine_version, raw_sha256, normalized_json, warnings_json, model_json, reuse_key "
            "FROM evidence"
        ).fetchall()
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert len(after) == len(before) == 1 and after[0][-1] is None  # old rows are never reused


async def test_access_profile_change_prevents_reuse(gateway, elf_sample):
    from dataclasses import replace

    app, mgr = await gateway()
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        profile = "restricted" if mgr.config.policy.access_profile != "restricted" else "balanced"
        mgr.config = replace(mgr.config, policy=replace(mgr.config.policy, access_profile=profile))
        again = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        assert again["reused"] is False and again["evidence_id"] != first["evidence_id"]


# -- review findings: engine identity -----------------------------------------------------------
async def test_builtin_library_version_change_prevents_reuse(gateway, elf_sample, monkeypatch):
    from reveng_nexus.providers import builtin

    app, _mgr = await gateway()
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        args = {"target": sha, "address": "0x400119"}
        first = _payload(await client.call_tool("nexus_disassemble_function", args))
        assert _payload(await client.call_tool("nexus_disassemble_function", args))["reused"] is True
        monkeypatch.setattr(builtin, "_capstone_version", lambda: "99.9.9")
        again = _payload(await client.call_tool("nexus_disassemble_function", args))
        assert again["reused"] is False and again["evidence_id"] != first["evidence_id"]


async def test_server_reported_framework_version_is_never_enough_for_reuse(gateway, elf_sample):
    app, _mgr = await gateway([mock_engine("ghidra_a")])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        args = {"target": sha, "address": "0x400119", "provider_id": "ghidra_a"}
        first = _payload(await client.call_tool("nexus_decompile_function", args))
        assert first["provenance"]["engine_version"].startswith("MCP server ")
        again = _payload(await client.call_tool("nexus_decompile_function", args))
        assert again["reused"] is False and again["evidence_id"] != first["evidence_id"]


def _ghidra_install(root, version="12.1.4", build="2026-Sep-21 1613 UTC", revision="8b6bbb85"):
    props = root / "Ghidra" / "application.properties"
    props.parent.mkdir(parents=True, exist_ok=True)
    props.write_text(
        "application.name=Ghidra\n"
        f"application.version={version}\n"
        "application.release.name=PUBLIC\n"
        f"application.build.date={build}\n"
        f"application.revision.ghidra={revision}\n",
        encoding="utf-8",
    )
    return root


async def _decompile(client, sha, refresh=False):
    args = {"target": sha, "address": "0x400119", "provider_id": "ghidra_a"}
    if refresh:
        args["refresh"] = True
    return _payload(await client.call_tool("nexus_decompile_function", args))


async def test_ghidra_reuse_follows_the_installation_identity(gateway, elf_sample, tmp_path):
    install = _ghidra_install(tmp_path / "ghidra_12.1.4_PUBLIC")
    log = tmp_path / "calls.log"
    env = {"GHIDRA_INSTALL_DIR": str(install), "MOCK_CALL_LOG": str(log)}
    app, mgr = await gateway([mock_engine("ghidra_a", env=env)])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = await _decompile(client, sha)
        calls_after_first = log.read_text(encoding="utf-8").count("\n")
        same = await _decompile(client, sha)  # 1. same engine identity: reused, engine not called
        assert same["reused"] is True and same["evidence_id"] == first["evidence_id"]
        assert same["reuse_status"]["identity_source"].startswith("Ghidra installation metadata")
        assert log.read_text(encoding="utf-8").count("\n") == calls_after_first

        # 3. a wrapper/framework version change alone is not a Ghidra identity change
        provider = mgr.providers["ghidra_a"]
        provider.server_info = {**provider.server_info, "version": "framework-9.9"}
        wrapper_only = await _decompile(client, sha)
        assert wrapper_only["reused"] is True and wrapper_only["evidence_id"] == first["evidence_id"]

        # 6. refresh runs the engine again
        fresh = await _decompile(client, sha, refresh=True)
        assert fresh["reused"] is False and fresh["evidence_id"] != first["evidence_id"]
        assert log.read_text(encoding="utf-8").count("\n") > calls_after_first

        # 2 + 5. in-place upgrade under the same path: the old results are not reused
        _ghidra_install(install, version="12.1.5", build="2026-Nov-02 0900 UTC", revision="aa11")
        upgraded = await _decompile(client, sha)
        assert upgraded["reused"] is False and upgraded["evidence_id"] not in {
            first["evidence_id"],
            fresh["evidence_id"],
        }
        assert upgraded["reuse_status"]["reason"] == "no stored result with this key"
        again = await _decompile(client, sha)
        assert again["reused"] is True and again["evidence_id"] == upgraded["evidence_id"]


async def test_unknown_ghidra_identity_disables_reuse_and_says_why(gateway, elf_sample, tmp_path):
    missing = tmp_path / "not-a-ghidra-dir"
    app, mgr = await gateway([mock_engine("ghidra_a", env={"GHIDRA_INSTALL_DIR": str(missing)})])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = await _decompile(client, sha)
        second = await _decompile(client, sha)
        assert first["reused"] is second["reused"] is False and second["evidence_id"] != first["evidence_id"]
        status = second["reuse_status"]
        assert status["eligible"] is False and "not a directory" in status["reason"]
        assert "engine_identity" in status["reason"]  # the opt-in is named
    # A directory without application.properties is not an identity either.
    (tmp_path / "empty_ghidra").mkdir()
    from reveng_nexus.registry import engine_identity

    provider = mgr.providers["ghidra_a"]
    provider.config.env["GHIDRA_INSTALL_DIR"] = str(tmp_path / "empty_ghidra")
    identity, reason = engine_identity(provider)
    assert identity is None and "application.properties is missing" in reason


async def test_unverifiable_engines_reuse_only_with_an_operator_attested_identity(gateway, elf_sample):
    plain = mock_engine("ida_b", engine="ida")
    attested = mock_engine("ida_c", engine="ida", settings={"engine_identity": "IDA 9.4 build 250912"})
    app, _mgr = await gateway([plain, attested])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        for pid, expect in (("ida_b", False), ("ida_c", True)):
            args = {"target": sha, "address": "0x400119", "provider_id": pid}
            await client.call_tool("nexus_decompile_function", args)
            second = _payload(await client.call_tool("nexus_decompile_function", args))
            assert second["reused"] is expect, pid
            if expect:
                assert second["reuse_status"]["identity_source"] == "operator-attested settings.engine_identity"
            else:
                assert "cannot be verified" in second["reuse_status"]["reason"]


async def test_rea_reuse_uses_its_pinned_server_version(config_factory, workspace, tmp_path):
    from fixtures.electron_builder import write_fuse_elf
    from test_rea_mocked import calls, rea_mock, started, target_of

    sample = write_fuse_elf(workspace / "fuses.elf")
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [rea_mock(env={"MOCK_CALL_LOG": str(log)})]))
    try:
        target = await target_of(mgr, sample)
        first = await mgr.perform("electron.fuses", target, {}, provider_id="rea", reuse=True)
        second = await mgr.perform("electron.fuses", target, {}, provider_id="rea", reuse=True)
        assert first["reused"] is False and second["reused"] is True and len(calls(log)) == 1
        provider = mgr.providers["rea"]
        provider.server_info = {**provider.server_info, "version": "6.6.0"}
        # A different REA version is drift from the reviewed pin: the operation is disabled before
        # reuse is considered, so no stored result is handed out either.
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("electron.fuses", target, {}, provider_id="rea", reuse=True)
        assert len(calls(log)) == 1
    finally:
        await mgr.close()


# -- review findings: idempotency ----------------------------------------------------------------
async def test_equivalent_retries_replay_and_keep_their_warnings(gateway, elf_sample):
    app, mgr = await gateway()
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        base = {"target": sha, "subject": "main", "claim": "c", "address": "0x10", "idempotency_key": "eq-retry-01"}
        first = _payload(await client.call_tool("nexus_record_evidence", base))
        variants = (
            {**base, "target": sha.upper()},
            {**base, "confidence": "low"},
            {**base, "address": "0x0010"},
            {**base, "address": 16},
        )
        for variant in variants:
            replay = _payload(await client.call_tool("nexus_record_evidence", variant))
            assert replay["evidence_id"] == first["evidence_id"] and replay["idempotent_replay"] is True
        meta = _payload(await client.call_tool("nexus_get_binary_metadata", {"target": sha}))
        mgr.evidence.review("evidence", meta["evidence_id"], "contradicted", "a second parser disagrees")
        finding = {
            "target": sha,
            "title": "Header parsed",
            "description": "From the ELF header.",
            "evidence_ids": [meta["evidence_id"]],
            "status": "confirmed",
            "idempotency_key": "warned-finding-1",
        }
        original = _payload(await client.call_tool("nexus_record_finding", finding))
        replay = _payload(await client.call_tool("nexus_record_finding", finding))
        assert original["warnings"] == replay["warnings"] == ["some supporting evidence is contradicted or rejected"]


async def test_ghidra_identity_covers_the_jdk_and_launch_properties(gateway, elf_sample, tmp_path):
    install = _ghidra_install(tmp_path / "ghidra")
    (install / "support").mkdir()
    (install / "support" / "launch.properties").write_text("JAVA_HOME_OVERRIDE=\n", encoding="utf-8")
    jdk = tmp_path / "jdk"
    jdk.mkdir()
    (jdk / "release").write_text('IMPLEMENTOR="Vendor"\nJAVA_RUNTIME_VERSION="21.0.12+1"\n', encoding="utf-8")
    env = {"GHIDRA_INSTALL_DIR": str(install), "JAVA_HOME": str(jdk)}
    app, _mgr = await gateway([mock_engine("ghidra_a", env=env)])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = await _decompile(client, sha)
        assert (await _decompile(client, sha))["evidence_id"] == first["evidence_id"]
        (jdk / "release").write_text('IMPLEMENTOR="Vendor"\nJAVA_RUNTIME_VERSION="21.0.13+2"\n', encoding="utf-8")
        new_jdk = await _decompile(client, sha)
        assert new_jdk["reused"] is False and new_jdk["evidence_id"] != first["evidence_id"]
        (install / "support" / "launch.properties").write_text("JAVA_HOME_OVERRIDE=C:\\other-jdk\n", encoding="utf-8")
        new_launch = await _decompile(client, sha)
        assert new_launch["reused"] is False and new_launch["evidence_id"] != new_jdk["evidence_id"]
        assert (await _decompile(client, sha))["evidence_id"] == new_launch["evidence_id"]


def test_unresolved_jdk_is_reported_in_the_identity_source(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from reveng_nexus.registry import engine_identity

    monkeypatch.delenv("JAVA_HOME", raising=False)
    install = _ghidra_install(tmp_path / "ghidra")
    cfg = SimpleNamespace(type="mcp_stdio", env={"GHIDRA_INSTALL_DIR": str(install)}, adapter="re_mcp", settings={})
    identity, source = engine_identity(SimpleNamespace(engine="ghidra", engine_family="ghidra", config=cfg))
    assert identity is not None and identity["jdk"] is None and "JDK not identified" in source


# -- second fingerprint review -------------------------------------------------------------------
def _ghidra_provider(env, type_="mcp_stdio"):
    from types import SimpleNamespace

    cfg = SimpleNamespace(type=type_, env=env, adapter="re_mcp", settings={})
    return SimpleNamespace(engine="ghidra", engine_family="ghidra", config=cfg)


def test_ghidra_identity_only_for_servers_nexus_launches(tmp_path, monkeypatch):
    from reveng_nexus.registry import engine_identity

    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(_ghidra_install(tmp_path / "local")))
    identity, reason = engine_identity(_ghidra_provider({}, type_="mcp_http"))
    assert identity is None and "not launched by Nexus" in reason
    assert engine_identity(_ghidra_provider({}, type_="mcp_launched_http"))[0] is not None


def test_relative_ghidra_dir_is_not_identified(tmp_path, monkeypatch):
    from reveng_nexus.registry import engine_identity

    _ghidra_install(tmp_path / "ghidra")
    monkeypatch.chdir(tmp_path)
    identity, reason = engine_identity(_ghidra_provider({"GHIDRA_INSTALL_DIR": "ghidra"}))
    assert identity is None and "relative" in reason


@pytest.mark.skipif(__import__("os").name != "nt", reason="case-insensitive environment is Windows behaviour")
def test_identity_follows_the_case_variant_the_child_sees(tmp_path, monkeypatch):
    from reveng_nexus.registry import engine_identity

    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(_ghidra_install(tmp_path / "a", version="11.0")))
    other = _ghidra_install(tmp_path / "b", version="12.1")
    identity, _ = engine_identity(_ghidra_provider({"ghidra_install_dir": str(other)}))
    assert identity is not None and identity["application.version"] == "12.1"


async def test_mutating_raw_calls_invalidate_stored_results(tmp_path, workspace, elf_sample):
    import asyncio
    from types import SimpleNamespace

    from reveng_nexus.artifacts import identify
    from reveng_nexus.errors import PolicyViolation
    from reveng_nexus.registry import ProviderManager

    store = EvidenceStore(tmp_path / "e.sqlite3", (str(workspace),))
    ident = identify(elf_sample)
    cid = store.create_case("Mutations")["case_id"]
    store.upsert_target(ident, cid)

    def stored():
        return store.add_evidence(
            target_id=ident.sha256,
            case_id=cid,
            provider_id="p",
            tool_name="t",
            operation="binary.decompile",
            evidence_kind="engine_derived",
            claim="c",
            reuse_key="k",
            params_hash="h",
        )["evidence_id"]

    outcome = {"raise": None}

    async def call_tool(name, arguments, **_):
        if outcome["raise"]:
            raise outcome["raise"]
        return {"ok": True}

    tools = {
        n: SimpleNamespace(classification=SimpleNamespace(tool_class=c))
        for n, c in (("read_x", "read"), ("rename", "mutate"))
    }
    provider = SimpleNamespace(id="p", started=True, per_target=False, _tools=tools, call_tool=call_tool)
    mgr = ProviderManager.__new__(ProviderManager)
    mgr.providers, mgr.evidence, mgr._provider_sems = {"p": provider}, store, {"p": asyncio.Semaphore(1)}

    stored()
    await mgr.call_provider_tool("p", "read_x", {})
    assert store.find_reusable("k", cid, ident.sha256) is not None  # a read changes nothing
    outcome["raise"] = PolicyViolation("blocked")
    with pytest.raises(PolicyViolation):
        await mgr.call_provider_tool("p", "rename", {})
    assert store.find_reusable("k", cid, ident.sha256) is not None  # refused before the engine
    outcome["raise"] = None
    await mgr.call_provider_tool("p", "rename", {})
    assert store.find_reusable("k", cid, ident.sha256) is None  # the engine state may have changed


# -- mutable analysis state (mocked stateful engine; not a real Ghidra reproduction) -----------
def _stateful_engine(provider):
    """Replace a mock provider's engine with one whose decompile output depends on mutable,
    unsaved analysis state that a restart discards (like an unsaved rename in Ghidra)."""
    from reveng_nexus.providers import OperationResult

    state = {"name": "FUN_00400119", "calls": 0}

    async def perform(operation, target, params):
        state["calls"] += 1
        return OperationResult(
            provider_id=provider.id,
            operation=operation,
            tool_name="decompile_function",
            engine="ghidra",
            engine_family="ghidra",
            evidence_kind="engine_derived",
            normalized={"name": state["name"]},
        )

    async def call_tool(name, arguments, **_):
        if name == "rename_function":
            state["name"] = arguments["new_name"]
        return {"ok": True}

    provider.perform = perform
    provider.call_tool = call_tool
    return state


async def test_results_after_a_state_mutation_are_not_reused_once_the_state_is_lost(gateway, elf_sample, tmp_path):
    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([mock_engine("ghidra_a", env={"GHIDRA_INSTALL_DIR": str(install)})])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        state = _stateful_engine(mgr.providers["ghidra_a"])
        target = mgr.target_context(sha)

        async def decompile():
            out = await mgr.perform(
                "binary.decompile", target, {"address": 0x400119}, provider_id="ghidra_a", reuse=True
            )
            return out["result"].normalized["name"], out["reused"]

        assert await decompile() == ("FUN_00400119", False)
        assert await decompile() == ("FUN_00400119", True)  # unmutated state: reused
        await mgr.call_provider_tool("ghidra_a", "rename_function", {"new_name": "parse_config"})
        assert await decompile() == ("parse_config", False)  # fresh after the mutation
        state["name"] = "FUN_00400119"  # the engine restarts and the unsaved rename is gone
        name, reused = await decompile()
        # A fresh call now says FUN_00400119; handing back "parse_config" would be stale.
        assert (name, reused) == ("FUN_00400119", False)
        status = (
            await mgr.perform("binary.decompile", target, {"address": 0x400119}, provider_id="ghidra_a", reuse=True)
        )["reuse_status"]
        assert status["eligible"] is False and "changed by a raw" in status["reason"]


async def test_a_read_in_flight_during_a_mutation_does_not_store_a_reusable_result(gateway, elf_sample, tmp_path):
    import asyncio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([mock_engine("ghidra_a", env={"GHIDRA_INSTALL_DIR": str(install)})])
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        provider = mgr.providers["ghidra_a"]
        state = _stateful_engine(provider)
        slow = provider.perform

        async def slow_perform(operation, target, params):
            out = await slow(operation, target, params)  # reads the pre-mutation state ...
            await asyncio.sleep(0.4)  # ... and records it after the mutation has finished
            return out

        provider.perform = slow_perform
        mgr._provider_sems["ghidra_a"] = asyncio.Semaphore(2)  # max_concurrency > 1
        target = mgr.target_context(sha)
        read = asyncio.create_task(
            mgr.perform("binary.decompile", target, {"address": 0x400119}, provider_id="ghidra_a", reuse=True)
        )
        await asyncio.sleep(0.1)
        await mgr.call_provider_tool("ghidra_a", "rename_function", {"new_name": "parse_config"})
        assert (await read)["result"].normalized["name"] == "FUN_00400119"
        provider.perform = slow
        again = await mgr.perform("binary.decompile", target, {"address": 0x400119}, provider_id="ghidra_a", reuse=True)
        assert again["reused"] is False and again["result"].normalized["name"] == state["name"] == "parse_config"


def test_reuse_block_persists_and_is_scoped(tmp_path, workspace, elf_sample, pe_sample):
    from reveng_nexus.artifacts import identify

    db = tmp_path / "e.sqlite3"
    store = EvidenceStore(db, (str(workspace),))
    cid = store.create_case("Blocks")["case_id"]
    elf, pe = identify(elf_sample), identify(pe_sample)
    for ident in (elf, pe):
        store.upsert_target(ident, cid)

    def stored(ident, provider="p"):
        return store.add_evidence(
            target_id=ident.sha256,
            case_id=cid,
            provider_id=provider,
            tool_name="t",
            operation="binary.decompile",
            evidence_kind="engine_derived",
            claim="c",
            reuse_key=f"k-{ident.sha256[:6]}-{provider}",
            params_hash="h",
        )

    stored(elf), stored(pe), stored(elf, provider="other")
    store.invalidate_reuse("p", elf.sha256, "renamed")
    reopened = EvidenceStore(db, (str(workspace),))  # a gateway restart keeps the block
    assert reopened.reuse_block("p", elf.sha256)["reason"] == "renamed"
    assert stored(elf)["evidence_id"] and reopened.find_reusable(f"k-{elf.sha256[:6]}-p", cid, elf.sha256, "p") is None
    assert reopened.find_reusable(f"k-{pe.sha256[:6]}-p", cid, pe.sha256, "p") is not None  # other target
    assert reopened.find_reusable(f"k-{elf.sha256[:6]}-other", cid, elf.sha256, "other") is not None  # other provider
    reopened.invalidate_reuse("p", None, "shared server mutated")  # all targets of a shared server
    assert reopened.find_reusable(f"k-{pe.sha256[:6]}-p", cid, pe.sha256, "p") is None


# -- follow-up fixes: unknown tool names, atomic store-time check ------------------------------
def _mutable_engine(install, **extra):
    return mock_engine(
        "ghidra_a", env={"GHIDRA_INSTALL_DIR": str(install)}, tool_overrides={"rename_function": "mutate"}, **extra
    )


async def _cached_decompile(client, sha):
    first = await _decompile(client, sha)
    assert (await _decompile(client, sha))["reused"] is True
    return first


def _rename_args():
    return {"address": "0x400119", "new_name": "x"}


@pytest.mark.parametrize("tool_mode", ["compact", "namespaced"])
async def test_unknown_tool_names_neither_block_nor_clear_reuse(gateway, elf_sample, tmp_path, tool_mode):
    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway(
        [_mutable_engine(install)], policy={"access_profile": "full_access"}, server={"tool_mode": tool_mode}
    )
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = await _cached_decompile(client, sha)
        typo = await client.call_tool(
            "nexus_call_provider_tool", {"provider_id": "ghidra_a", "tool_name": "renmae_function", "arguments": {}}
        )
        assert typo.is_error and "current catalogue" in _payload(typo)["message"]  # reached the provider
        if tool_mode == "namespaced":
            alias = await client.call_tool("ghidra_a__renmae_function", {})
            assert alias.is_error and _payload(alias)["error"] == "not_found"
        assert mgr.evidence.reuse_block("ghidra_a", sha) is None
        again = await _decompile(client, sha)
        assert again["reused"] is True and again["evidence_id"] == first["evidence_id"]  # keys intact


async def test_a_catalogue_that_cannot_confirm_the_tool_is_not_a_mutation(gateway, elf_sample, tmp_path):
    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        provider = mgr.providers["ghidra_a"]
        saved, provider._tools = provider._tools, {}  # discovery yielded nothing: existence unverifiable
        try:
            with pytest.raises(Exception, match="current catalogue"):
                await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
        finally:
            provider._tools = saved
        assert mgr.evidence.reuse_block("ghidra_a", sha) is None


@pytest.mark.parametrize("tool_mode", ["compact", "namespaced"])
async def test_a_real_mutating_call_still_blocks_on_both_caller_paths(gateway, elf_sample, tmp_path, tool_mode):
    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway(
        [_mutable_engine(install)], policy={"access_profile": "full_access"}, server={"tool_mode": tool_mode}
    )
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        if tool_mode == "namespaced":
            out = await client.call_tool("ghidra_a__rename_function", _rename_args())
        else:
            out = await client.call_tool(
                "nexus_call_provider_tool",
                {"provider_id": "ghidra_a", "tool_name": "rename_function", "arguments": _rename_args()},
            )
        assert not out.is_error, _payload(out)
        block = mgr.evidence.reuse_block("ghidra_a", sha)
        assert block is not None and "every target (one shared server)" in block["reason"]
        after = await _decompile(client, sha)
        assert after["reused"] is False and after["reuse_status"]["eligible"] is False


@pytest.mark.parametrize("failure", ["timeout", "provider_error", "cancelled"])
async def test_failed_or_timed_out_mutations_still_block(gateway, elf_sample, tmp_path, failure):
    import asyncio

    from reveng_nexus.errors import ProviderCallError, ProviderTimeout

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
    provider = mgr.providers["ghidra_a"]
    errors = {
        "timeout": ProviderTimeout("timed out after the request was sent"),
        "provider_error": ProviderCallError("engine failed half way"),
        "cancelled": asyncio.CancelledError(),
    }

    async def failing_raw_call(name, arguments, budget, *, target_sha256=None):
        raise errors[failure]

    provider._raw_call = failing_raw_call
    with pytest.raises(BaseException):  # noqa: B017 - the three failure kinds differ on purpose
        await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
    assert mgr.evidence.reuse_block("ghidra_a", sha) is not None


@pytest.mark.parametrize("tool_mode", ["compact", "namespaced"])
async def test_a_policy_refused_mutation_does_not_block(gateway, elf_sample, tmp_path, tool_mode):
    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], server={"tool_mode": tool_mode})  # default profile
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        first = await _cached_decompile(client, sha)
        refused = await client.call_tool(
            "nexus_call_provider_tool",
            {"provider_id": "ghidra_a", "tool_name": "rename_function", "arguments": _rename_args()},
        )
        assert refused.is_error and _payload(refused)["error"] == "policy_violation"
        assert mgr.evidence.reuse_block("ghidra_a", sha) is None
        assert (await _decompile(client, sha))["evidence_id"] == first["evidence_id"]


def test_store_time_block_check_is_atomic_with_the_insert(tmp_path, workspace, elf_sample, monkeypatch):
    """A block written by another connection while a result is being stored can neither slip in
    between the check and the insert nor leave the new row reusable."""
    import threading

    from reveng_nexus.artifacts import identify

    db = tmp_path / "e.sqlite3"
    store = EvidenceStore(db, (str(workspace),))
    ident = identify(elf_sample)
    cid = store.create_case("Atomic")["case_id"]
    store.upsert_target(ident, cid)
    original = EvidenceStore._blocked
    seen: dict[str, object] = {}

    def check_then_race(connection, provider_id, target_id):
        out = original(connection, provider_id, target_id)
        seen["in_transaction"] = connection.in_transaction
        other = EvidenceStore(db, (str(workspace),))  # an independent connection, like a concurrent mutation
        racer = threading.Thread(target=lambda: other.invalidate_reuse("p", ident.sha256, "mutated meanwhile"))
        racer.start()
        racer.join(timeout=1.0)  # without the write lock this commits right here, before our insert
        seen["racer_finished_before_insert"] = not racer.is_alive()
        seen["racer"] = racer
        return out

    monkeypatch.setattr(EvidenceStore, "_blocked", staticmethod(check_then_race))
    rec = store.add_evidence(
        target_id=ident.sha256,
        case_id=cid,
        provider_id="p",
        tool_name="t",
        operation="binary.decompile",
        evidence_kind="engine_derived",
        claim="read before the mutation",
        reuse_key="K",
        params_hash="h",
    )
    seen["racer"].join(timeout=15)
    monkeypatch.setattr(EvidenceStore, "_blocked", staticmethod(original))
    assert seen["in_transaction"] is True and seen["racer_finished_before_insert"] is False
    with sqlite3.connect(db) as con:
        key = con.execute("SELECT reuse_key FROM evidence WHERE evidence_id = ?", (rec["evidence_id"],)).fetchone()[0]
    assert key is None  # the block's transaction ran after ours and cleared the key
    assert store.reuse_block("p", ident.sha256)["reason"] == "mutated meanwhile"
    assert store.find_reusable("K", cid, ident.sha256, "p") is None  # read-time check still refuses
    assert store.find_reusable("K", cid, ident.sha256) is None  # and no reusable key was left behind


def test_storing_without_a_reuse_key_takes_no_early_write_lock(tmp_path, workspace, elf_sample, monkeypatch):
    from reveng_nexus.artifacts import identify

    store = EvidenceStore(tmp_path / "e.sqlite3", (str(workspace),))
    ident = identify(elf_sample)
    cid = store.create_case("Plain")["case_id"]
    store.upsert_target(ident, cid)
    calls = []
    original = EvidenceStore._blocked
    monkeypatch.setattr(EvidenceStore, "_blocked", staticmethod(lambda *a: calls.append(a) or original(*a)))
    store.add_evidence(
        target_id=ident.sha256,
        case_id=cid,
        provider_id="p",
        tool_name="t",
        operation="analyst.note",
        evidence_kind="analyst_note",
        claim="note",
    )
    assert calls == []  # no reuse key: no block check and no early BEGIN IMMEDIATE


# -- cancellation safety of the mutation block (genuine AnyIO cancellation) ---------------------
def _parked_engine(provider):
    """Replace the engine side of a provider: the request reaches it (``contacted``) and then
    waits until something outside cancels it (``cancelled``). It never raises on its own."""
    import anyio

    contacted, cancelled = anyio.Event(), anyio.Event()
    real = provider._raw_call

    async def raw_call(name, arguments, budget, *, target_sha256=None):
        if name != "rename_function":
            return await real(name, arguments, budget, target_sha256=target_sha256)
        contacted.set()
        try:
            await anyio.sleep_forever()
        except anyio.get_cancelled_exc_class():
            cancelled.set()
            raise

    provider._raw_call = raw_call
    return contacted, cancelled


def _watch_block_writes(mgr):
    """Signal when the (real) block write has finished, so tests wait on an event, not a delay."""
    import anyio

    done = anyio.Event()
    original = mgr._block_reuse_after_mutation

    async def watched(*args, **kwargs):
        try:
            await original(*args, **kwargs)
        finally:
            done.set()

    mgr._block_reuse_after_mutation = watched
    return done


async def _assert_blocked_and_not_reused(client, mgr, sha):
    assert mgr.evidence.reuse_block("ghidra_a", sha) is not None
    after = await _decompile(client, sha)
    assert after["reused"] is False and after["reuse_status"]["eligible"] is False


async def test_move_on_after_cancelling_a_mutation_still_blocks_reuse(gateway, elf_sample, tmp_path):
    import anyio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        contacted, cancelled = _parked_engine(mgr.providers["ghidra_a"])
        returned = False
        async with anyio.create_task_group() as tg:
            with anyio.move_on_after(60) as scope:

                async def expire_once_contacted():
                    await contacted.wait()
                    scope.deadline = anyio.current_time()  # the move_on_after deadline passes now

                tg.start_soon(expire_once_contacted)
                await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
                returned = True
        assert contacted.is_set() and cancelled.is_set()  # reached the engine, then cancelled from outside
        assert scope.cancelled_caught and not returned  # cancellation was not turned into success
        await _assert_blocked_and_not_reused(client, mgr, sha)


async def test_task_group_cancelling_a_mutation_still_blocks_reuse(gateway, elf_sample, tmp_path):
    import anyio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        contacted, cancelled = _parked_engine(mgr.providers["ghidra_a"])
        outcome: dict[str, bool] = {}

        async def mutate():
            try:
                await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
                outcome["returned"] = True
            except anyio.get_cancelled_exc_class():
                outcome["cancelled"] = True
                raise

        async with anyio.create_task_group() as tg:
            tg.start_soon(mutate)
            await contacted.wait()
            tg.cancel_scope.cancel()
        assert cancelled.is_set() and outcome == {"cancelled": True}  # still a cancellation, not success
        await _assert_blocked_and_not_reused(client, mgr, sha)


def _observe_protocol_cancels(monkeypatch):
    """Record every notifications/cancelled the server-side JSON-RPC dispatcher receives, and
    whether it named a request still in flight. Uses private names of the pinned MCP SDK (2.3)."""
    from mcp.shared import jsonrpc_dispatcher as jd

    seen: list[dict[str, object]] = []
    original = jd.JSONRPCDispatcher._dispatch_notification

    def spy(self, msg, *args, **kwargs):
        if msg.method == "notifications/cancelled":
            rid = jd.cancelled_request_id_from_params(msg.params)
            in_flight = rid is not None and jd.coerce_request_id(rid) in self._in_flight
            seen.append({"request_id": rid, "in_flight": in_flight})
        return original(self, msg, *args, **kwargs)

    monkeypatch.setattr(jd.JSONRPCDispatcher, "_dispatch_notification", spy)
    return seen


async def test_mcp_client_cancellation_of_a_mutation_still_blocks_reuse(gateway, elf_sample, tmp_path, monkeypatch):
    """Protocol level: the client abandons a running nexus_call_provider_tool request over JSON-RPC
    (legacy mode: in-memory streams, not the SDK's DirectDispatcher, which cancels the handler task
    directly); the SDK sends notifications/cancelled and the server cancels the handler's scope."""
    import anyio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    protocol_cancels = _observe_protocol_cancels(monkeypatch)
    async with Client(app.server, mode="legacy") as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        contacted, cancelled = _parked_engine(mgr.providers["ghidra_a"])
        block_written = _watch_block_writes(mgr)
        outcome: dict[str, object] = {}

        async def call():
            try:
                outcome["result"] = await client.call_tool(
                    "nexus_call_provider_tool",
                    {"provider_id": "ghidra_a", "tool_name": "rename_function", "arguments": _rename_args()},
                )
            except anyio.get_cancelled_exc_class():
                outcome["client_cancelled"] = True
                raise

        async with anyio.create_task_group() as tg:
            tg.start_soon(call)
            await contacted.wait()
            tg.cancel_scope.cancel()
        with anyio.fail_after(10):  # bounded waits for server-side signals, not ordering by sleep
            await cancelled.wait()  # the server handler was cancelled by the protocol message
            await block_written.wait()
        assert outcome == {"client_cancelled": True}
        # The handler was cancelled by a protocol notification for the request it was serving.
        assert len(protocol_cancels) == 1 and protocol_cancels[0]["in_flight"] is True, protocol_cancels
        await _assert_blocked_and_not_reused(client, mgr, sha)


async def test_a_failed_block_write_is_audited_and_not_reported_as_success(gateway, elf_sample, tmp_path):
    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)

        def broken(*args, **kwargs):
            raise sqlite3.OperationalError("database is locked")

        mgr.evidence.invalidate_reuse = broken
        out = await client.call_tool(
            "nexus_call_provider_tool",
            {"provider_id": "ghidra_a", "tool_name": "rename_function", "arguments": _rename_args()},
        )
        assert out.is_error and "could not be marked non-reusable" in _payload(out)["message"]
    audit = mgr.audit.path.read_text(encoding="utf-8")
    assert '"reuse_block_failed"' in audit


# -- native asyncio cancellation of the block write (on top of AnyIO cancellation above) --------
@contextlib.contextmanager
def _gated_block_write(mgr):
    """Hold the real block write inside its worker thread until released, so a test can deliver
    cancellations while the write has demonstrably started but not finished. Leaving the block
    always releases the write and wakes any waiter, so a failing assertion cannot park a worker."""
    from types import SimpleNamespace

    gate = SimpleNamespace(started=threading.Event(), release=threading.Event(), finished=threading.Event(), runs=0)
    real = mgr.evidence.invalidate_reuse

    def gated(*args, **kwargs):
        gate.runs += 1
        gate.started.set()
        gate.release.wait(10)
        try:
            return real(*args, **kwargs)
        finally:
            gate.finished.set()

    mgr.evidence.invalidate_reuse = gated
    try:
        yield gate
    finally:
        gate.release.set()
        gate.started.set()  # a test-side wait for the start must not outlive the test either


def _signal_block_requested(mgr):
    """Set an event when the cleanup asks for the block write. The test waiting on it resumes only
    after the cleanup has gone on to its first suspension inside the (real) write path."""
    import asyncio

    requested = asyncio.Event()
    original = mgr._block_reuse_after_mutation

    async def signalled(*args, **kwargs):
        requested.set()
        await original(*args, **kwargs)

    mgr._block_reuse_after_mutation = signalled
    return requested


async def _write_started_or_task_done(task, gate):
    """Wait (bounded) until the gated write has begun, or the task has ended without waiting for it."""
    import asyncio

    started = asyncio.get_running_loop().run_in_executor(None, gate.started.wait, 10)
    await asyncio.wait({task, started}, return_when=asyncio.FIRST_COMPLETED)


async def _mutation_task(mgr):
    import asyncio

    return asyncio.create_task(mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args()))


async def _turns(n=20):
    import asyncio

    for _ in range(n):  # event-loop turns, not wall-clock time
        await asyncio.sleep(0)


async def test_one_native_cancel_of_a_mutation_still_blocks_reuse(gateway, elf_sample, tmp_path):
    import asyncio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        contacted, cancelled = _parked_engine(mgr.providers["ghidra_a"])
        task = await _mutation_task(mgr)
        await contacted.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled.is_set()
        await _assert_blocked_and_not_reused(client, mgr, sha)


async def test_a_second_native_cancel_during_the_block_write_cannot_skip_it(gateway, elf_sample, tmp_path):
    import asyncio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        contacted, cancelled = _parked_engine(mgr.providers["ghidra_a"])
        with _gated_block_write(mgr) as gate:
            task = await _mutation_task(mgr)
            await contacted.wait()
            task.cancel()  # first native cancel: the engine call is cancelled, cleanup begins
            await _write_started_or_task_done(task, gate)
            assert gate.started.is_set() and not task.done()  # the block write is running
            task.cancel()  # second native cancel while the write is in progress
            await _turns()
            assert not task.done()  # the cleanup is still waiting for the write
            assert not gate.finished.is_set()
            gate.release.set()
            with pytest.raises(asyncio.CancelledError):  # still a cancellation, not a success
                await task
        assert cancelled.is_set() and gate.finished.is_set() and gate.runs == 1
        await _assert_blocked_and_not_reused(client, mgr, sha)


async def test_a_cancel_storm_from_the_moment_the_write_is_requested_cannot_skip_it(gateway, elf_sample, tmp_path):
    """The second cancel lands as soon as the cleanup has asked for the block write, before the
    worker is known to have started it (the original defect dropped the write there); more follow
    while the write is held. Every step is ordered by an event, not by counting loop turns."""
    import asyncio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        await _cached_decompile(client, sha)
        contacted, cancelled = _parked_engine(mgr.providers["ghidra_a"])
        requested = _signal_block_requested(mgr)
        with _gated_block_write(mgr) as gate:
            task = await _mutation_task(mgr)
            await contacted.wait()
            task.cancel()  # first native cancel: the engine call is cancelled, cleanup begins
            await requested.wait()  # the cleanup has requested the write and is suspended in it
            task.cancel()  # second native cancel while the write is pending
            await _write_started_or_task_done(task, gate)
            assert not task.done()  # the cleanup neither dropped nor gave up on the pending write
            for _ in range(5):  # more native cancels while the write is held: spacing is irrelevant
                task.cancel()
                await asyncio.sleep(0)
            assert not task.done() and not gate.finished.is_set()
            gate.release.set()
            with pytest.raises(asyncio.CancelledError):  # still a cancellation, not a success
                await task
        assert cancelled.is_set() and gate.finished.is_set() and gate.runs == 1  # run once, not dropped
        await _assert_blocked_and_not_reused(client, mgr, sha)


async def test_a_failed_block_write_under_cancellation_is_audited_and_stays_cancelled(gateway, elf_sample, tmp_path):
    import asyncio

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        contacted, _cancelled = _parked_engine(mgr.providers["ghidra_a"])

        def broken(*args, **kwargs):
            raise sqlite3.OperationalError("database is locked")

        mgr.evidence.invalidate_reuse = broken
        task = await _mutation_task(mgr)
        await contacted.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):  # not converted into ProviderCallError or success
            await task
    assert '"reuse_block_failed"' in mgr.audit.path.read_text(encoding="utf-8")


def _refuse_block_write_submission(mgr, monkeypatch):
    """Make the loop's executor refuse the block write, as after its shutdown, and record any run of
    the write itself. Only the registry's block write is refused; other executor users are unaffected."""
    import asyncio

    loop = asyncio.get_running_loop()
    submit = loop.run_in_executor
    runs = []
    real = mgr.evidence.invalidate_reuse
    mgr.evidence.invalidate_reuse = lambda *args, **kwargs: runs.append(args) or real(*args, **kwargs)

    def refuse(executor, func, *args):
        if getattr(func, "__module__", None) == "reveng_nexus.registry":
            raise RuntimeError("cannot schedule new futures after shutdown")
        return submit(executor, func, *args)

    monkeypatch.setattr(loop, "run_in_executor", refuse)
    return runs


@pytest.mark.parametrize("call_outcome", ["succeeded", "failed", "cancelled"])
async def test_a_block_write_that_cannot_be_started_is_audited_and_never_a_success(
    gateway, elf_sample, tmp_path, monkeypatch, call_outcome
):
    import asyncio

    from reveng_nexus.errors import ProviderCallError

    install = _ghidra_install(tmp_path / "ghidra")
    app, mgr = await gateway([_mutable_engine(install)], policy={"access_profile": "full_access"})
    async with Client(app.server) as client:
        sha, _ = await _inspect(client, elf_sample)
        provider = mgr.providers["ghidra_a"]
        if call_outcome == "failed":

            async def failing_raw_call(name, arguments, budget, *, target_sha256=None):
                raise ProviderCallError("engine failed half way")

            provider._raw_call = failing_raw_call
        elif call_outcome == "cancelled":
            contacted, _cancelled = _parked_engine(provider)
        runs = _refuse_block_write_submission(mgr, monkeypatch)
        task = await _mutation_task(mgr)
        if call_outcome == "cancelled":
            await contacted.wait()
            task.cancel()
        expected = {
            "succeeded": (ProviderCallError, "could not be marked non-reusable"),  # not reported as a success
            "failed": (ProviderCallError, "engine failed half way"),  # the original error, unchanged
            "cancelled": (asyncio.CancelledError, None),  # the cancellation, unchanged
        }[call_outcome]
        with pytest.raises(expected[0], match=expected[1]):
            await task
    assert runs == []  # the write never started ...
    assert mgr.evidence.reuse_block("ghidra_a", sha) is None  # ... and no block is claimed
    audit = mgr.audit.path.read_text(encoding="utf-8")
    assert '"reuse_block_failed"' in audit and "cannot schedule new futures after shutdown" in audit
