"""Durable record of raw calls that may change an engine's analysis state.

A raw call that is not classified ``read`` can change what an engine returns later, so results
stored from that provider must stop being reusable (``EvidenceStore.invalidate_reuse`` writes a
persisted reuse block). That database write can fail, and the process can stop before it runs.
This journal makes the protection survive both: an entry is written durably *before* the call is
sent and removed only after the reuse block has been confirmed, or when the engine was provably
never contacted. At start the gateway re-applies the block for every entry left behind and keeps
reuse off for it until that succeeds.

The journal lives in its own directory, independent of the SQLite file whose write may fail. Each
entry is one small file; its name carries the provider id and scope, so even an entry whose
content was damaged still says what to block. Entries hold no arguments, credentials, environment
values or evidence: only the provider id, the target hash (or ``*`` for a shared server), the tool
name, the process id and a timestamp.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path

ALL_TARGETS = "*"
_ALL_TARGETS_NAME = "all-targets"
_ENTRY = re.compile(r"(?P<provider>[a-z0-9_-]{1,64})@(?P<scope>[0-9a-f]{64}|all-targets)@[0-9a-f]{32}\.json")


class MutationJournal:
    """Entries in ``directory``; every method does blocking file I/O (run it in a worker thread)."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def record(self, provider_id: str, scope: str, tool_name: str) -> Path:
        """Durably create an entry and return its path; raises OSError if that is not possible.

        The content is written to a temporary file, flushed and fsynced, then renamed into place,
        and the directory is synced where the platform allows it. A crash before the rename leaves
        only a ``.tmp`` file, which never stands for a dispatched call (the caller dispatches only
        after this returns) and is ignored.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        scope_name = _ALL_TARGETS_NAME if scope == ALL_TARGETS else scope.lower()
        final = self.directory / f"{provider_id}@{scope_name}@{uuid.uuid4().hex}.json"
        if not _ENTRY.fullmatch(final.name):
            raise OSError(f"cannot journal provider {provider_id!r} for scope {scope!r}")
        temporary = final.with_name(final.name + ".tmp")
        payload = {
            "format": 1,
            "provider_id": provider_id,
            "target": scope,
            "tool": tool_name,
            "pid": os.getpid(),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with open(temporary, "x", encoding="utf-8") as handle:
            handle.write(json.dumps(payload))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, final)
        _sync_directory(self.directory)
        return final

    def resolve(self, entry: Path) -> None:
        """Remove an entry whose reuse block is confirmed (or whose call never reached the engine).
        An entry another process already removed counts as resolved."""
        try:
            entry.unlink()
        except FileNotFoundError:
            return
        _sync_directory(self.directory)

    def pending(self) -> tuple[list[tuple[str, str, Path]], list[str]]:
        """Entries left behind: ``([(provider_id, scope, path)], [names that cannot be parsed])``.

        Raises OSError when the journal directory exists but cannot be listed. The file name is
        authoritative; the content is not needed to know what to block.
        """
        if not self.directory.exists():
            return [], []
        entries: list[tuple[str, str, Path]] = []
        unknown: list[str] = []
        for path in sorted(self.directory.iterdir()):
            if path.name.endswith(".tmp"):
                continue  # an interrupted record(): the call was never dispatched
            match = _ENTRY.fullmatch(path.name)
            if match is None:
                unknown.append(path.name)
                continue
            scope = match["scope"]
            entries.append((match["provider"], ALL_TARGETS if scope == _ALL_TARGETS_NAME else scope, path))
        return entries, unknown


def _sync_directory(directory: Path) -> None:
    """Make a create, rename or delete in ``directory`` durable where the platform supports it.
    Windows cannot open a directory for fsync; NTFS journals its metadata itself."""
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
