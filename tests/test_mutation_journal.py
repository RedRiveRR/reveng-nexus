"""Mutation journal: reuse protection that survives a failed block write and a process restart.

Every test uses a temporary data directory; the restart test starts a real child process on it.
"""

import json
import sqlite3
import sys
import textwrap

import anyio
import pytest
from test_reuse_idempotency import (
    _gated_block_write,
    _ghidra_install,
    _mutable_engine,
    _parked_engine,
    _rename_args,
    _write_started_or_task_done,
)

from reveng_nexus.config import parse_config
from reveng_nexus.errors import ProviderCallError
from reveng_nexus.mutation_journal import MutationJournal
from reveng_nexus.registry import ProviderManager

PARAMS = {"address": 0x400119}


@pytest.fixture
def raw_config(tmp_path, workspace):
    install = _ghidra_install(tmp_path / "ghidra")
    return {
        "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
        "providers": [_mutable_engine(install)],
        "policy": {"access_profile": "full_access"},
    }


@pytest.fixture
async def open_manager(tmp_path):
    managers = []

    async def factory(raw):
        mgr = ProviderManager(parse_config(raw, base_dir=tmp_path))
        await mgr.start()
        managers.append(mgr)
        return mgr

    yield factory
    for mgr in managers:
        await mgr.close()


async def _decompile(mgr, target):
    return await mgr.perform("binary.decompile", target, PARAMS, provider_id="ghidra_a", reuse=True)


async def _seeded(mgr, elf_sample):
    """A target with a stored, reusable decompilation."""
    intake = await mgr.intake(str(elf_sample))
    target = mgr.target_context(intake["target"]["sha256"])
    first = await _decompile(mgr, target)
    again = await _decompile(mgr, target)
    assert again["reused"] is True and again["evidence"]["evidence_id"] == first["evidence"]["evidence_id"]
    return target, first["evidence"]["evidence_id"]


def _failing_block_writes(mgr):
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    mgr.evidence.invalidate_reuse = broken


def _entries(mgr):
    return mgr.mutation_journal.pending()[0]


async def test_a_confirmed_block_removes_the_journal_entry(raw_config, open_manager, elf_sample):
    mgr = await open_manager(raw_config)
    target, _ = await _seeded(mgr, elf_sample)
    contacted, _cancelled = _parked_engine(mgr.providers["ghidra_a"])
    task = anyio.Event()

    async def mutate():
        try:
            await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
        except BaseException:
            pass
        finally:
            task.set()

    async with anyio.create_task_group() as tg:
        tg.start_soon(mutate)
        await contacted.wait()
        # The entry was durable before the engine saw the call.
        assert [(p, s) for p, s, _ in _entries(mgr)] == [("ghidra_a", "*")]
        tg.cancel_scope.cancel()
    assert _entries(mgr) == []  # removed once the block was confirmed
    assert mgr.evidence.reuse_block("ghidra_a", target.sha256) is not None


async def test_a_failed_block_write_leaves_durable_protection(raw_config, open_manager, elf_sample):
    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    _failing_block_writes(mgr)
    with pytest.raises(ProviderCallError, match="could not be marked non-reusable"):
        await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
    assert [(p, s) for p, s, _ in _entries(mgr)] == [("ghidra_a", "*")]
    entry = _entries(mgr)[0][2]
    content = json.loads(entry.read_text(encoding="utf-8"))
    assert set(content) == {"format", "provider_id", "target", "tool", "pid", "created_at"}  # no arguments
    after = await _decompile(mgr, target)
    assert after["reused"] is False and after["evidence"]["evidence_id"] != first


_CHILD = textwrap.dedent(
    """
    import asyncio, json, sys
    from pathlib import Path

    from reveng_nexus.config import parse_config
    from reveng_nexus.registry import ProviderManager

    async def main():
        raw, base, sha = json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]), sys.argv[3]
        mgr = ProviderManager(parse_config(raw, base_dir=base))
        await mgr.start()
        try:
            out = await mgr.perform(
                "binary.decompile", mgr.target_context(sha), {"address": 0x400119}, provider_id="ghidra_a", reuse=True
            )
            block = mgr.evidence.reuse_block("ghidra_a", sha)
            print(json.dumps({
                "reused": out["reused"],
                "evidence_id": out["evidence"]["evidence_id"],
                "block": block["reason"] if block else None,
                "entries": len(mgr.mutation_journal.pending()[0]) if hasattr(mgr, "mutation_journal") else None,
            }))
        finally:
            await mgr.close()

    asyncio.run(main())
    """
)


async def test_a_restarted_process_does_not_reuse_after_a_failed_block_write(
    raw_config, open_manager, elf_sample, tmp_path
):
    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    _failing_block_writes(mgr)
    with pytest.raises(ProviderCallError):
        await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
    await mgr.close()  # the first gateway stops; only the files in the data directory remain
    config_file, script = tmp_path / "config.json", tmp_path / "child.py"
    config_file.write_text(json.dumps(raw_config), encoding="utf-8")
    script.write_text(_CHILD, encoding="utf-8")
    done = await anyio.run_process(
        [sys.executable, str(script), str(config_file), str(tmp_path), target.sha256], check=False
    )
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-2000:]
    child = json.loads(done.stdout.decode().strip().splitlines()[-1])
    assert child["reused"] is False and child["evidence_id"] != first, child  # the stale result is not served
    assert child["block"] and "journalled" in child["block"]  # the new process persisted the block
    assert child["entries"] == 0  # and then resolved the entry


async def test_a_journal_that_cannot_be_written_stops_the_mutation(raw_config, open_manager, elf_sample):
    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    provider = mgr.providers["ghidra_a"]
    sent = []
    real_raw_call = provider._raw_call

    async def recording_raw_call(name, arguments, budget, *, target_sha256=None):
        sent.append(name)
        return await real_raw_call(name, arguments, budget, target_sha256=target_sha256)

    provider._raw_call = recording_raw_call

    def unwritable(*args, **kwargs):
        raise OSError("No space left on device")

    mgr.mutation_journal.record = unwritable
    with pytest.raises(ProviderCallError, match="was not sent"):
        await mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args())
    assert sent == []  # the engine never saw the call
    assert mgr._mutations_in_flight == {}
    assert (await _decompile(mgr, target))["reused"] is True  # nothing changed, so nothing is blocked
    assert '"mutation_journal_failed"' in mgr.audit.path.read_text(encoding="utf-8")


async def test_a_cancelled_mutation_whose_block_write_fails_stays_blocked_after_restart(
    raw_config, open_manager, elf_sample
):
    import asyncio

    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    contacted, _cancelled = _parked_engine(mgr.providers["ghidra_a"])
    _failing_block_writes(mgr)
    with _gated_block_write(mgr) as gate:
        task = asyncio.create_task(mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args()))
        await contacted.wait()
        task.cancel()
        await _write_started_or_task_done(task, gate)
        assert gate.started.is_set()
        gate.release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(_entries(mgr)) == 1
    assert (await _decompile(mgr, target))["evidence"]["evidence_id"] != first
    await mgr.close()
    fresh = await open_manager(raw_config)  # same data directory, healthy database
    again = await _decompile(fresh, fresh.target_context(target.sha256))
    assert again["reused"] is False and again["evidence"]["evidence_id"] != first
    assert _entries(fresh) == [] and fresh.evidence.reuse_block("ghidra_a", target.sha256) is not None


async def test_reads_during_a_mutation_store_nothing_reusable(raw_config, open_manager, elf_sample):
    import asyncio

    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    contacted, _cancelled = _parked_engine(mgr.providers["ghidra_a"])
    mutation = asyncio.create_task(mgr.call_provider_tool("ghidra_a", "rename_function", _rename_args()))
    await contacted.wait()
    read = asyncio.create_task(_decompile(mgr, target))  # cannot reuse; waits for the provider
    mutation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await mutation
    out = await read
    assert out["reused"] is False and out["evidence"]["evidence_id"] != first
    with sqlite3.connect(mgr.evidence.database_path) as con:
        key = con.execute(
            "SELECT reuse_key FROM evidence WHERE evidence_id = ?", (out["evidence"]["evidence_id"],)
        ).fetchone()[0]
    assert key is None  # stored, but never reusable


async def test_an_interrupted_journal_entry_blocks_conservatively_on_restart(
    raw_config, open_manager, elf_sample, tmp_path
):
    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    await mgr.close()
    journal = MutationJournal(tmp_path / "data" / "mutation-journal")
    # A stop after the intent was recorded: the call may or may not have reached the engine.
    journal.record("ghidra_a", "*", "rename_function")
    # A stop while recording: only a temporary file, so the call was never sent.
    (journal.directory / "ghidra_a@all-targets@0123456789abcdef0123456789abcdef.json.tmp").write_text("{")
    fresh = await open_manager(raw_config)
    out = await _decompile(fresh, fresh.target_context(target.sha256))
    assert out["reused"] is False and out["evidence"]["evidence_id"] != first
    assert "journalled" in fresh.evidence.reuse_block("ghidra_a", target.sha256)["reason"]
    assert _entries(fresh) == []


async def test_an_unreadable_journal_never_enables_reuse(raw_config, open_manager, elf_sample, tmp_path):
    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    await mgr.close()
    directory = tmp_path / "data" / "mutation-journal"
    directory.mkdir()
    # Damaged content under a valid name still blocks its provider and target (the name decides).
    (directory / f"ghidra_a@{target.sha256}@{'a' * 32}.json").write_bytes(b"\x00\xff not json")
    # A name that cannot be parsed could belong to anything: reuse is off everywhere.
    (directory / "garbage.json").write_text("?")
    fresh = await open_manager(raw_config)
    out = await _decompile(fresh, fresh.target_context(target.sha256))
    assert out["reused"] is False and "cannot be read" in out["reuse_status"]["reason"]
    assert (directory / "garbage.json").exists()  # kept for inspection
    await fresh.close()
    # A journal location that is not a directory cannot be listed: also off everywhere.
    (directory / "garbage.json").unlink()
    for leftover in directory.iterdir():
        leftover.unlink()
    directory.rmdir()
    directory.write_text("not a directory")
    blocked = await open_manager(raw_config)
    out = await _decompile(blocked, blocked.target_context(target.sha256))
    assert out["reused"] is False and "could not be read" in out["reuse_status"]["reason"]


async def test_a_block_that_still_cannot_be_written_at_start_keeps_the_entry(
    raw_config, open_manager, elf_sample, tmp_path, monkeypatch
):
    from reveng_nexus.evidence import EvidenceStore

    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    await mgr.close()
    MutationJournal(tmp_path / "data" / "mutation-journal").record("ghidra_a", "*", "rename_function")

    def still_locked(self, *args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(EvidenceStore, "invalidate_reuse", still_locked)
    fresh = await open_manager(raw_config)
    out = await _decompile(fresh, fresh.target_context(target.sha256))
    assert out["reused"] is False and out["evidence"]["evidence_id"] != first
    assert len(_entries(fresh)) == 1  # kept for the next start


async def test_entries_block_only_their_own_provider_and_target(raw_config, open_manager, elf_sample, tmp_path):
    mgr = await open_manager(raw_config)
    target, first = await _seeded(mgr, elf_sample)
    await mgr.close()
    journal = MutationJournal(tmp_path / "data" / "mutation-journal")
    journal.record("ghidra_a", "f" * 64, "rename_function")  # another target of this provider
    journal.record("other_engine", "*", "rename_function")  # another provider
    fresh = await open_manager(raw_config)
    out = await _decompile(fresh, fresh.target_context(target.sha256))
    assert out["reused"] is True and out["evidence"]["evidence_id"] == first
    assert fresh.evidence.reuse_block("ghidra_a", "f" * 64) is not None
    assert fresh.evidence.reuse_block("ghidra_a", target.sha256) is None
