"""Local SQLite evidence store: cases, targets, provenance-backed evidence, comparisons,
findings and reviews. Schema changes go through numbered migrations.

Evidence kinds
--------------
``direct_observation``  parsed directly from the artifact bytes (headers, symbol tables)
``engine_derived``      produced by an analysis engine (decompiler, disassembler, xrefs)
``ai_generated``        produced by a model; always unverified until reviewed
``analyst_note``        submitted by the agent/analyst through nexus_record_evidence

Validation status: ``unverified`` → ``corroborated`` / ``contradicted`` / ``verified`` /
``rejected`` / ``resolved``. Only an explicit review sets ``verified`` or ``rejected``.

Questions (schema v3)
---------------------
An investigation question (an "unknown") stays visible until evidence answers it. Status:
``open`` (unanswered) · ``investigating`` · ``partial`` · ``blocked`` · ``contradicted`` ·
``resolved``. ``resolved`` needs an answer and supporting evidence that is not AI-generated
alone, with no contradicting evidence still standing; ``contradicted`` needs contradicting
evidence; ``partial`` needs some supporting evidence; ``blocked`` needs a reason. Every
update names the revision it read, so a stale writer gets a conflict instead of overwriting.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import ArgumentError, NotFound, RevisionConflict, WorkspaceViolation

_TARGET_ID = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
_CLASSIFICATIONS = {"observation", "hypothesis", "finding", "contradiction"}
_CONFIDENCE = {"low", "medium", "high"}
EVIDENCE_KINDS = {"direct_observation", "engine_derived", "ai_generated", "analyst_note"}
VALIDATION_STATUSES = {"unverified", "corroborated", "contradicted", "resolved", "verified", "rejected"}
_STATUSES = VALIDATION_STATUSES
LINK_RELATIONS = {"derived_from", "input_to", "agrees_with", "contradicts", "supports", "same_subject"}
FINDING_SEVERITIES = {"info", "low", "medium", "high", "critical"}
FINDING_STATUSES = {"hypothesis", "needs_review", "confirmed", "rejected"}
QUESTION_STATUSES = ("open", "investigating", "partial", "blocked", "contradicted", "resolved")
QUESTION_INITIAL_STATUSES = {"open", "investigating", "blocked"}
# Evidence produced from the artifact's bytes or by an analysis engine. Only this kind can resolve a
# question: agent notes and AI output are interpretation, and nexus_review cannot authenticate who
# reviews (any MCP caller, including the agent that wrote a note, can call it), so a review never
# turns interpretation into source evidence.
SOURCE_KINDS = frozenset({"direct_observation", "engine_derived"})
PAGE_CHAR_BUDGET = 150_000  # rendered characters per evidence page (see render_json; responses are capped below)
RESPONSE_CHAR_CAP = 200_000  # rendered characters in one tool response (the server's hard limit)
RESPONSE_MARGIN = 5_000  # headroom kept below the cap for the envelope around a measured list
BRIEF_HARD_CAP = 100  # critical/high findings a case brief always lists
QUESTION_LIST_IDS = 20  # evidence ids per role in listings; the full set is in nexus_list_questions(question_id)
DEFAULT_CASE = "default"
SCHEMA_VERSION = 4

_EVIDENCE_COLUMNS = (
    "evidence_id, case_id, target_id, provider_id, tool_name, operation, subject, subject_type, "
    "subject_address, subject_name, claim, classification, evidence_kind, confidence, status, "
    "engine, engine_family, engine_version, raw_sha256, normalized_json, warnings_json, "
    "model_json, created_at"
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def render_json(value: Any) -> str:
    """The exact rendering of a tool response (the server writes this); sizes are measured on it."""
    return json.dumps(value, ensure_ascii=False, indent=1, default=str)


def rendered_cost(value: Any, depth: int = 2) -> int:
    """Characters ``value`` adds to a response as a list item ``depth`` levels deep: its rendering,
    the extra indentation of each of its lines at that depth, and the separator."""
    text = render_json(value)
    return len(text) + (text.count("\n") + 1) * depth + 2


def _sql_statements(script: str) -> list[str]:
    """Split a migration script into complete statements (run one by one inside a transaction)."""
    statements: list[str] = []
    buffer = ""
    for part in script.split(";"):
        buffer += part + ";"
        if sqlite3.complete_statement(buffer):
            if buffer.strip(" \t\r\n;"):
                statements.append(buffer.strip())
            buffer = ""
    if buffer.strip(" \t\r\n;"):
        raise ValueError("migration script ends with an incomplete statement")
    return statements


def _count(values: Iterator[Any] | list[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def _loads(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except ValueError:
        return value


MIGRATIONS: dict[int, str] = {
    1: """
        CREATE TABLE IF NOT EXISTS targets (
            target_id TEXT PRIMARY KEY,
            absolute_path TEXT NOT NULL,
            display_name TEXT NOT NULL,
            label TEXT,
            size_bytes INTEGER NOT NULL,
            registered_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
            provider_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            subject TEXT NOT NULL,
            claim TEXT NOT NULL,
            excerpt TEXT NOT NULL DEFAULT '',
            classification TEXT NOT NULL,
            confidence TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unverified',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_evidence_subject ON evidence(target_id, subject);
    """,
    2: """
        ALTER TABLE targets ADD COLUMN md5 TEXT;
        ALTER TABLE targets ADD COLUMN format TEXT;
        ALTER TABLE targets ADD COLUMN kind TEXT;
        ALTER TABLE targets ADD COLUMN metadata_json TEXT;

        ALTER TABLE evidence ADD COLUMN case_id TEXT NOT NULL DEFAULT 'default';
        ALTER TABLE evidence ADD COLUMN operation TEXT;
        ALTER TABLE evidence ADD COLUMN subject_type TEXT;
        ALTER TABLE evidence ADD COLUMN subject_address INTEGER;
        ALTER TABLE evidence ADD COLUMN subject_name TEXT;
        ALTER TABLE evidence ADD COLUMN evidence_kind TEXT NOT NULL DEFAULT 'analyst_note';
        ALTER TABLE evidence ADD COLUMN engine TEXT;
        ALTER TABLE evidence ADD COLUMN engine_family TEXT;
        ALTER TABLE evidence ADD COLUMN engine_version TEXT;
        ALTER TABLE evidence ADD COLUMN raw_sha256 TEXT;
        ALTER TABLE evidence ADD COLUMN normalized_json TEXT;
        ALTER TABLE evidence ADD COLUMN warnings_json TEXT;
        ALTER TABLE evidence ADD COLUMN model_json TEXT;

        CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id, target_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_address ON evidence(target_id, subject_address);

        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        INSERT OR IGNORE INTO cases (case_id, title, created_at)
            VALUES ('default', 'Default case', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

        CREATE TABLE IF NOT EXISTS case_targets (
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
            added_at TEXT NOT NULL,
            PRIMARY KEY (case_id, target_id)
        );
        INSERT OR IGNORE INTO case_targets (case_id, target_id, added_at)
            SELECT 'default', target_id, registered_at FROM targets;

        CREATE TABLE IF NOT EXISTS raw_outputs (
            raw_sha256 TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            full_size INTEGER NOT NULL,
            truncated INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_links (
            src_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            dst_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            relation TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            PRIMARY KEY (src_id, dst_id, relation)
        );

        CREATE TABLE IF NOT EXISTS comparisons (
            comparison_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
            operation TEXT NOT NULL,
            subject TEXT NOT NULL,
            assessment TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comparison_members (
            comparison_id TEXT NOT NULL REFERENCES comparisons(comparison_id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            PRIMARY KEY (comparison_id, evidence_id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            target_id TEXT REFERENCES targets(target_id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence TEXT NOT NULL,
            confidence_rationale TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS finding_evidence (
            finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'supports',
            PRIMARY KEY (finding_id, evidence_id)
        );

        CREATE TABLE IF NOT EXISTS reviews (
            review_id TEXT PRIMARY KEY,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """,
    3: """
        CREATE TABLE IF NOT EXISTS questions (
            question_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            target_id TEXT REFERENCES targets(target_id) ON DELETE CASCADE,
            question TEXT NOT NULL,
            status TEXT NOT NULL,
            required INTEGER NOT NULL DEFAULT 1,
            needed_evidence TEXT NOT NULL DEFAULT '',
            search_boundary TEXT NOT NULL DEFAULT '',
            answer TEXT NOT NULL DEFAULT '',
            revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_questions_case ON questions(case_id, status);
        CREATE INDEX IF NOT EXISTS idx_questions_target ON questions(target_id, status);
        CREATE TABLE IF NOT EXISTS question_evidence (
            question_id TEXT NOT NULL REFERENCES questions(question_id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            added_revision INTEGER NOT NULL,
            PRIMARY KEY (question_id, evidence_id, role)
        );
        CREATE TABLE IF NOT EXISTS question_history (
            question_id TEXT NOT NULL REFERENCES questions(question_id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            status TEXT NOT NULL,
            answer TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            basis_json TEXT,
            required INTEGER,
            created_at TEXT NOT NULL,
            PRIMARY KEY (question_id, revision)
        );
    """,
    4: """
        ALTER TABLE evidence ADD COLUMN reuse_key TEXT;
        ALTER TABLE evidence ADD COLUMN params_hash TEXT;
        CREATE INDEX IF NOT EXISTS idx_evidence_reuse ON evidence(reuse_key, case_id);
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            tool TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            result_type TEXT NOT NULL,
            result_id TEXT NOT NULL,
            warnings_json TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tool, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS reuse_blocks (
            provider_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            PRIMARY KEY (provider_id, target_id)
        );
    """,
}


@dataclass(frozen=True)
class Idempotency:
    """A client-chosen key for one write. A retry with the same key and the same arguments
    writes nothing and returns the record's current state with the original warnings; the same
    key with different arguments is refused. The key row is written in the same transaction as
    the record."""

    tool: str
    key: str
    request_hash: str


class EvidenceStore:
    """Stores target identity and evidence; it never executes target files."""

    def __init__(
        self,
        database_path: str | Path,
        allowed_roots: tuple[str, ...] = (),
        max_target_size_mb: int = 250,
        follow_symlinks: bool = False,
    ) -> None:
        from .artifacts import WorkspaceGuard

        self.database_path = Path(database_path).expanduser().resolve()
        self.guard = WorkspaceGuard(allowed_roots, max_target_size_mb * 1024 * 1024, follow_symlinks)
        self.allowed_roots = self.guard.roots
        self.max_target_bytes = self.guard.max_bytes
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    # -- connection & migrations --------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        # Pending migrations run in one IMMEDIATE transaction that re-reads the ledger under the
        # write lock: two processes opening an old database at once cannot both apply a version,
        # and a failure leaves neither the schema change nor its ledger row behind.
        connection = self._connect()
        connection.isolation_level = None  # explicit BEGIN/COMMIT; executescript would commit implicitly
        try:
            if self._pending_migrations(connection):
                connection.execute("BEGIN IMMEDIATE")
                try:
                    for version in self._pending_migrations(connection):
                        for statement in _sql_statements(MIGRATIONS[version]):
                            connection.execute(statement)
                        connection.execute("INSERT INTO schema_migrations VALUES (?, ?)", (version, _now()))
                    connection.execute("COMMIT")
                except BaseException:
                    connection.execute("ROLLBACK")
                    raise
        finally:
            connection.close()
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _pending_migrations(connection: sqlite3.Connection) -> list[int]:
        ledger = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone()
        applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")} if ledger else set()
        if (
            not applied
            and connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence'").fetchone()
        ):
            # A 0.1 database has tables but no migration ledger: v1 is already in place.
            applied = {1}
        pending = [v for v in sorted(MIGRATIONS) if v not in applied]
        if pending and connection.in_transaction:
            # Inside the write transaction: create the ledger (and record a 0.1 database's v1).
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            if applied == {1} and not connection.execute("SELECT 1 FROM schema_migrations").fetchone():
                connection.execute("INSERT INTO schema_migrations VALUES (1, ?)", (_now(),))
        return pending

    def schema_version(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

    # -- idempotent writes -------------------------------------------------------------
    def _prior_write(self, idem: Idempotency | None) -> dict[str, Any] | None:
        if idem is None:
            return None
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM idempotency_keys WHERE tool = ? AND idempotency_key = ?", (idem.tool, idem.key)
            ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != idem.request_hash:
            raise ArgumentError(
                f"idempotency_key {idem.key!r} was already used for {idem.tool} with different arguments; "
                "use a new key for a different request"
            )
        return dict(row)

    @staticmethod
    def _store_warnings(connection: sqlite3.Connection, idem: Idempotency | None, warnings: list[str]) -> None:
        """Keep the warnings the original write returned, so a replay repeats them. Called inside
        the write's own transaction: a replay can never see the key without its warnings, and a
        failure here rolls the whole write back."""
        if idem is not None and warnings:
            connection.execute(
                "UPDATE idempotency_keys SET warnings_json = ? WHERE tool = ? AND idempotency_key = ?",
                (_json(warnings), idem.tool, idem.key),
            )

    @staticmethod
    def _claim_key(connection: sqlite3.Connection, idem: Idempotency | None, result_type: str, result_id: str) -> None:
        if idem is not None:
            connection.execute(
                "INSERT INTO idempotency_keys (tool, idempotency_key, request_hash, result_type, result_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (idem.tool, idem.key, idem.request_hash, result_type, result_id, _now()),
            )

    def _replay(self, prior: dict[str, Any]) -> dict[str, Any]:
        """The current state of the record an earlier write with this key produced."""
        kind, rid = prior["result_type"], prior["result_id"]
        if kind == "finding":
            out = self.get_finding(rid)
        elif kind == "evidence":
            out = self.get_evidence_record(rid)
            out.pop("excerpt", None)
        elif kind == "question":
            out = self.get_question(rid, history_limit=0)
        else:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT review_id, subject_type, subject_id, status FROM reviews WHERE review_id = ?", (rid,)
                ).fetchone()
            if row is None:
                raise NotFound(f"review {rid!r} not found")
            out = dict(row)
        out["idempotent_replay"] = True
        out["original_write_at"] = prior["created_at"]
        if prior.get("warnings_json"):
            out["warnings"] = _loads(prior["warnings_json"])
        return out

    def _after_race(self, idem: Idempotency | None) -> dict[str, Any] | None:
        """A concurrent write with the same key won the unique constraint: return its result."""
        prior = self._prior_write(idem)
        return self._replay(prior) if prior else None

    # -- cases ----------------------------------------------------------------
    def create_case(self, title: str, description: str = "", case_id: str | None = None) -> dict[str, Any]:
        title = (title or "").strip()
        if not title:
            raise ArgumentError("case title is required")
        cid = case_id or f"case-{uuid.uuid4().hex[:12]}"
        if not _CASE_ID.fullmatch(cid):
            raise ArgumentError("case_id must be 3-64 chars of lowercase letters, digits, '-' or '_'")
        now = _now()
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO cases (case_id, title, description, created_at) VALUES (?, ?, ?, ?)",
                (cid, title[:256], description[:4000], now),
            )
        return {"case_id": cid, "title": title[:256], "description": description[:4000], "created_at": now}

    def ensure_case(self, case_id: str | None) -> str:
        cid = case_id or DEFAULT_CASE
        with self._connection() as connection:
            row = connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (cid,)).fetchone()
        if row is None:
            raise NotFound(f"unknown case_id {cid!r}; create it with nexus_inspect_target(case_title=...)")
        return cid

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT c.case_id, c.title, c.created_at, COUNT(ct.target_id) AS target_count "
                "FROM cases c LEFT JOIN case_targets ct ON ct.case_id = c.case_id "
                "GROUP BY c.case_id ORDER BY c.created_at DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_case(self, case_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None:
                raise NotFound(f"unknown case_id {case_id!r}")
            targets = connection.execute(
                "SELECT t.target_id, t.display_name, t.format, t.kind, t.size_bytes, ct.added_at "
                "FROM case_targets ct JOIN targets t ON t.target_id = ct.target_id WHERE ct.case_id = ?",
                (case_id,),
            ).fetchall()
        return {**dict(row), "targets": [dict(t) for t in targets]}

    # -- targets --------------------------------------------------------------
    def _check_allowed_path(self, path: str | Path) -> Path:
        try:
            return self.guard.check(str(path))
        except WorkspaceViolation as exc:
            raise PermissionError(exc.message) from exc

    def upsert_target(self, identity: Any, case_id: str | None = None, label: str = "") -> dict[str, Any]:
        cid = self.ensure_case(case_id)
        now = _now()
        clean_label = label.strip()[:256] if label else ""
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO targets (target_id, absolute_path, display_name, label, size_bytes,
                       registered_at, md5, format, kind, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(target_id) DO UPDATE SET
                     absolute_path=excluded.absolute_path,
                     display_name=excluded.display_name,
                     label=CASE WHEN excluded.label != '' THEN excluded.label ELSE targets.label END,
                     size_bytes=excluded.size_bytes, md5=excluded.md5, format=excluded.format,
                     kind=excluded.kind, metadata_json=excluded.metadata_json""",
                (
                    identity.sha256,
                    identity.original_path,
                    identity.display_name,
                    clean_label,
                    identity.size_bytes,
                    now,
                    identity.md5,
                    identity.format,
                    identity.kind,
                    _json(identity.metadata),
                ),
            )
            connection.execute(
                "INSERT OR IGNORE INTO case_targets (case_id, target_id, added_at) VALUES (?, ?, ?)",
                (cid, identity.sha256, now),
            )
        return {**identity.summary(), "case_id": cid, "label": clean_label, "registered_at": now}

    def register_target(self, path: str, label: str = "", case_id: str | None = None) -> dict[str, Any]:
        from .artifacts import identify

        resolved = self._check_allowed_path(path)
        identity = identify(resolved)
        row = self.upsert_target(identity, case_id, label)
        return {
            "target_id": identity.sha256,
            "display_name": identity.display_name,
            "label": row["label"],
            "size_bytes": identity.size_bytes,
            "registered_at": row["registered_at"],
            "format": identity.format,
            "case_id": row["case_id"],
        }

    def get_target(self, target_id: str, *, include_path: bool = False) -> dict[str, Any]:
        tid = (target_id or "").lower()
        if not _TARGET_ID.fullmatch(tid):
            raise ArgumentError("target must be a SHA-256 hex digest returned by nexus_inspect_target")
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM targets WHERE target_id = ?", (tid,)).fetchone()
        if row is None:
            raise NotFound("unknown target; inspect the file first with nexus_inspect_target")
        out = dict(row)
        out["metadata"] = _loads(out.pop("metadata_json", None)) or {}
        if not include_path:
            out.pop("absolute_path", None)
        return out

    def target_cases(self, target_id: str) -> list[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT case_id FROM case_targets WHERE target_id = ? ORDER BY added_at", (target_id,)
            ).fetchall()
        return [r[0] for r in rows]

    def list_targets(self, limit: int = 50, case_id: str | None = None) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 200))
        with self._connection() as connection:
            if case_id:
                rows = connection.execute(
                    "SELECT t.target_id, t.display_name, t.label, t.size_bytes, t.registered_at, t.format, t.kind "
                    "FROM targets t JOIN case_targets ct ON ct.target_id = t.target_id WHERE ct.case_id = ? "
                    "ORDER BY t.registered_at DESC LIMIT ?",
                    (case_id, bounded_limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT target_id, display_name, label, size_bytes, registered_at, format, kind FROM targets "
                    "ORDER BY registered_at DESC LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    # -- raw outputs ------------------------------------------------------------
    def store_raw(self, content: str, limit_bytes: int) -> tuple[str, bool]:
        data = content.encode("utf-8", errors="replace")
        digest = hashlib.sha256(data).hexdigest()
        truncated = len(data) > limit_bytes
        stored = data[:limit_bytes].decode("utf-8", errors="ignore") if truncated else content
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO raw_outputs (raw_sha256, content, full_size, truncated, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (digest, stored, len(data), int(truncated), _now()),
            )
        return digest, truncated

    def get_raw(self, raw_sha256: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM raw_outputs WHERE raw_sha256 = ?", (raw_sha256,)).fetchone()
        return dict(row) if row else None

    # -- evidence -----------------------------------------------------------------
    def add_evidence(
        self,
        *,
        target_id: str,
        provider_id: str,
        tool_name: str,
        operation: str,
        evidence_kind: str,
        claim: str,
        case_id: str | None = None,
        subject: str = "binary",
        subject_type: str = "binary",
        subject_address: int | None = None,
        subject_name: str | None = None,
        normalized: Any = None,
        raw: str | None = None,
        raw_limit_bytes: int = 256 * 1024,
        engine: str | None = None,
        engine_family: str | None = None,
        engine_version: str | None = None,
        warnings: list[str] | None = None,
        model: dict[str, Any] | None = None,
        confidence: str = "medium",
        classification: str = "observation",
        status: str = "unverified",
        excerpt: str = "",
        reuse_key: str | None = None,
        params_hash: str | None = None,
        idempotency: Idempotency | None = None,
    ) -> dict[str, Any]:
        prior = self._prior_write(idempotency)
        if prior:
            return self._replay(prior)
        tid = target_id.lower()
        if not _TARGET_ID.fullmatch(tid):
            raise ArgumentError("target_id must be a SHA-256 hex digest")
        if evidence_kind not in EVIDENCE_KINDS:
            raise ArgumentError(f"evidence_kind must be one of {sorted(EVIDENCE_KINDS)}")
        if evidence_kind == "ai_generated" and not model:
            raise ArgumentError("AI-generated evidence must carry model provenance")
        if evidence_kind == "ai_generated" and status not in {"unverified"}:
            raise ArgumentError("AI-generated evidence starts unverified; review it explicitly")
        if confidence not in _CONFIDENCE:
            raise ArgumentError(f"confidence must be one of {sorted(_CONFIDENCE)}")
        if status not in VALIDATION_STATUSES:
            raise ArgumentError(f"status must be one of {sorted(VALIDATION_STATUSES)}")
        cid = self.ensure_case(case_id)
        raw_sha = None
        warns = list(warnings or [])
        if raw is not None:
            raw_sha, truncated = self.store_raw(raw, raw_limit_bytes)
            if truncated:
                warns.append(f"raw output truncated to {raw_limit_bytes} bytes for storage (hash covers full output)")
        evidence_id = _new_id("ev")
        now = _now()
        try:
            with self._connection() as connection:
                if reuse_key:
                    # Take the write lock before the block check, so a block committed by a concurrent
                    # raw mutation is either seen here or clears this row's key afterwards
                    # (invalidate_reuse writes the block and clears keys in one transaction).
                    connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT 1 FROM targets WHERE target_id = ?", (tid,)).fetchone() is None:
                    raise NotFound("Unknown target_id; register the file first.")
                self._claim_key(connection, idempotency, "evidence", evidence_id)
                if reuse_key and self._blocked(connection, provider_id, tid):
                    # The provider's analysis state for this target was changed by a raw call: a
                    # result derived from it may not be reproducible (unsaved state, restarts).
                    reuse_key = params_hash = None
                connection.execute(
                    """INSERT INTO evidence (evidence_id, case_id, target_id, provider_id, tool_name, operation,
                           subject, subject_type, subject_address, subject_name, claim, excerpt, classification,
                           evidence_kind, confidence, status, engine, engine_family, engine_version, raw_sha256,
                           normalized_json, warnings_json, model_json, created_at, reuse_key, params_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        evidence_id,
                        cid,
                        tid,
                        provider_id[:128],
                        tool_name[:256],
                        operation[:128],
                        subject[:512],
                        subject_type[:64],
                        subject_address,
                        (subject_name or None),
                        claim[:4000],
                        excerpt[:12000],
                        classification,
                        evidence_kind,
                        confidence,
                        status,
                        engine,
                        engine_family,
                        engine_version,
                        raw_sha,
                        _json(normalized) if normalized is not None else None,
                        _json(warns) if warns else None,
                        _json(model) if model else None,
                        now,
                        reuse_key,
                        params_hash,
                    ),
                )
        except sqlite3.IntegrityError:
            replay = self._after_race(idempotency)
            if replay is None:
                raise
            return replay
        return self.get_evidence_record(evidence_id)

    def invalidate_reuse(self, provider_id: str, target_id: str | None = None, reason: str = "") -> int:
        """A raw call changed (or may have changed) the provider's analysis state.

        Stored results of the provider (for one target, or all targets of a shared server) stop
        being handed out, and a persisted block keeps later results from becoming reusable: once
        the engine's state has been mutated, a result derived from it depends on state Nexus
        cannot identify (an unsaved change can be lost on a restart or rebuild). Only the reuse
        marker is cleared; the evidence records themselves are not changed.
        """
        tid = target_id.lower() if target_id else "*"
        sql = "UPDATE evidence SET reuse_key = NULL WHERE provider_id = ? AND reuse_key IS NOT NULL"
        values: list[Any] = [provider_id]
        if target_id:
            sql += " AND target_id = ?"
            values.append(tid)
        with self._connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reuse_blocks (provider_id, target_id, reason, created_at) VALUES (?, ?, ?, ?)",
                (provider_id, tid, reason[:500], _now()),
            )
            return connection.execute(sql, values).rowcount

    @staticmethod
    def _blocked(connection: sqlite3.Connection, provider_id: str, target_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT reason, created_at FROM reuse_blocks WHERE provider_id = ? AND target_id IN (?, '*') "
            "ORDER BY created_at DESC LIMIT 1",
            (provider_id, target_id.lower()),
        ).fetchone()

    def reuse_block(self, provider_id: str, target_id: str) -> dict[str, Any] | None:
        """Why results of this provider for this target are not reusable, if they are not."""
        with self._connection() as connection:
            row = self._blocked(connection, provider_id, target_id)
        return dict(row) if row else None

    def find_reusable(
        self, reuse_key: str, case_id: str, target_id: str, provider_id: str | None = None
    ) -> dict[str, Any] | None:
        """The newest evidence produced under this reuse key in this case, unless rejected or contradicted."""
        with self._connection() as connection:
            if provider_id and self._blocked(connection, provider_id, target_id):
                return None
            row = connection.execute(
                "SELECT evidence_id FROM evidence WHERE reuse_key = ? AND case_id = ? AND target_id = ? "
                "AND status NOT IN ('rejected', 'contradicted') ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (reuse_key, case_id, target_id.lower()),
            ).fetchone()
        return self.get_evidence_record(row[0]) if row else None

    def record_evidence(
        self,
        *,
        target_id: str,
        provider_id: str,
        tool_name: str,
        subject: str,
        claim: str,
        excerpt: str = "",
        classification: str = "observation",
        confidence: str = "medium",
        case_id: str | None = None,
        subject_address: int | None = None,
        idempotency: Idempotency | None = None,
    ) -> dict[str, Any]:
        """Agent/analyst-submitted note (kept compatible with the 0.1 API)."""
        if not _TARGET_ID.fullmatch(target_id.lower()):
            raise ValueError("target_id must be the SHA-256 hex digest returned by nexus_inspect_target.")
        if classification not in _CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {sorted(_CLASSIFICATIONS)}")
        if confidence not in _CONFIDENCE:
            raise ValueError(f"confidence must be one of {sorted(_CONFIDENCE)}")
        required = {"provider_id": provider_id, "tool_name": tool_name, "subject": subject, "claim": claim}
        missing = [name for name, value in required.items() if not str(value).strip()]
        if missing:
            raise ValueError(f"Required fields are blank: {', '.join(missing)}")
        if len(claim) > 4000 or len(excerpt) > 12000:
            raise ValueError("claim is limited to 4,000 characters and excerpt to 12,000 characters.")
        with self._connection() as connection:
            known = connection.execute("SELECT 1 FROM targets WHERE target_id = ?", (target_id.lower(),)).fetchone()
        if known is None:
            raise ValueError("Unknown target_id; register the file first.")
        record = self.add_evidence(
            target_id=target_id,
            case_id=case_id,
            provider_id=provider_id,
            tool_name=tool_name,
            operation="analyst.note",
            evidence_kind="analyst_note",
            claim=claim,
            subject=subject,
            subject_type="address" if subject_address is not None else "subject",
            subject_address=subject_address,
            classification=classification,
            confidence=confidence,
            excerpt=excerpt,
            idempotency=idempotency,
        )
        record.pop("excerpt", None)
        return record

    def get_evidence_record(self, evidence_id: str, *, include_raw: bool = False) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                f"SELECT {_EVIDENCE_COLUMNS}, excerpt FROM evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            if row is None:
                raise NotFound(f"evidence {evidence_id!r} not found")
            links = connection.execute(
                "SELECT src_id, dst_id, relation, note FROM evidence_links WHERE src_id = ? OR dst_id = ?",
                (evidence_id, evidence_id),
            ).fetchall()
            reviews = connection.execute(
                "SELECT status, note, created_at FROM reviews WHERE subject_type='evidence' AND subject_id = ? "
                "ORDER BY created_at",
                (evidence_id,),
            ).fetchall()
        record = self._decode_row(row)
        record["links"] = [dict(link) for link in links]
        record["reviews"] = [dict(r) for r in reviews]
        if include_raw and record.get("raw_sha256"):
            raw = self.get_raw(record["raw_sha256"])
            if raw:
                record["raw"] = {
                    "content": raw["content"],
                    "full_size": raw["full_size"],
                    "truncated": bool(raw["truncated"]),
                }
        return record

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        record["normalized"] = _loads(record.pop("normalized_json", None))
        record["warnings"] = _loads(record.pop("warnings_json", None)) or []
        record["model"] = _loads(record.pop("model_json", None))
        if not record.get("excerpt"):
            record.pop("excerpt", None)
        return record

    def query_evidence(
        self,
        *,
        target_id: str | None = None,
        case_id: str | None = None,
        status: str | None = None,
        evidence_kind: str | None = None,
        operation: str | None = None,
        subject_address: int | None = None,
        subject_name: str | None = None,
        limit: int = 50,
        include_normalized: bool = False,
    ) -> list[dict[str, Any]]:
        filters, values = self._evidence_filters(
            target_id, case_id, status, evidence_kind, operation, subject_address, subject_name
        )
        where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
        values.append(max(1, min(int(limit), 500)))
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT {_EVIDENCE_COLUMNS} FROM evidence {where_sql} ORDER BY created_at DESC, rowid DESC LIMIT ?",
                values,
            ).fetchall()
        out = []
        for row in rows:
            record = self._decode_row(row)
            if not include_normalized:
                record.pop("normalized", None)
            out.append(record)
        return out

    @staticmethod
    def _evidence_filters(
        target_id: str | None,
        case_id: str | None,
        status: str | None,
        evidence_kind: str | None,
        operation: str | None,
        subject_address: int | None,
        subject_name: str | None,
    ) -> tuple[list[str], list[Any]]:
        filters: list[str] = []
        values: list[Any] = []
        if target_id:
            if not _TARGET_ID.fullmatch(target_id.lower()):
                raise ArgumentError("target_id must be a SHA-256 hex digest.")
            filters.append("target_id = ?")
            values.append(target_id.lower())
        for column, value, allowed in (
            ("case_id", case_id, None),
            ("status", status, VALIDATION_STATUSES),
            ("evidence_kind", evidence_kind, EVIDENCE_KINDS),
            ("operation", operation, None),
        ):
            if value:
                if allowed is not None and value not in allowed:
                    raise ArgumentError(f"{column} must be one of {sorted(allowed)}")
                filters.append(f"{column} = ?")
                values.append(value)
        if subject_address is not None:
            filters.append("subject_address = ?")
            values.append(int(subject_address))
        if subject_name:
            filters.append("subject_name = ?")
            values.append(subject_name)
        return filters, values

    @staticmethod
    def _cursor(created_at: str, rowid: int, scope: str) -> str:
        payload = _json({"v": 1, "c": created_at, "r": rowid, "s": scope}).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _read_cursor(cursor: str, scope: str) -> tuple[str, int]:
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            data = json.loads(raw)
            created_at, rowid, cursor_scope = data["c"], data["r"], data["s"]
            if data.get("v") != 1 or not isinstance(created_at, str) or not isinstance(rowid, int):
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise ArgumentError("cursor is not a value returned by this tool") from exc
        if cursor_scope != scope:
            raise ArgumentError("cursor belongs to a query with different filters; restart without a cursor")
        return created_at, rowid

    @staticmethod
    def _evidence_summary(record: dict[str, Any]) -> dict[str, Any]:
        """One line of provenance per record; the full record is one nexus_get_evidence(evidence_id) away."""
        claim = record.get("claim") or ""
        return {
            "evidence_id": record["evidence_id"],
            "operation": record.get("operation"),
            "provider_id": record["provider_id"],
            "tool_name": record["tool_name"][:128],
            "engine_family": record.get("engine_family"),
            "evidence_kind": record["evidence_kind"],
            "classification": record["classification"],
            "status": record["status"],
            "confidence": record["confidence"],
            "subject": record["subject"][:160],
            "subject_address": record.get("subject_address"),
            "claim": claim[:200] + ("…" if len(claim) > 200 else ""),
            "warning_count": len(record.get("warnings") or []),
            "created_at": record["created_at"],
        }

    def page_evidence(
        self,
        *,
        target_id: str | None = None,
        case_id: str | None = None,
        status: str | None = None,
        evidence_kind: str | None = None,
        operation: str | None = None,
        subject_address: int | None = None,
        subject_name: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
        view: str = "standard",
        include_normalized: bool = False,
        budget: int = PAGE_CHAR_BUDGET,
    ) -> dict[str, Any]:
        """Newest-first evidence with a keyset cursor over (created_at, rowid).

        The order is total and evidence is never deleted, so pages neither repeat nor skip records
        while new evidence arrives (new records sort before the first page). This assumes one
        writer with a monotonic clock: a record committed late by a second process with an older
        timestamp can sort behind a cursor already handed out. ``created_at`` is compared as text
        (Nexus writes one ISO-8601 UTC format). A cursor is bound to the filters it was issued for.
        A page also stops at ``budget`` rendered characters (render_json, as the response is
        written; at least one record), so it fits a tool response; the cursor then continues after
        the last record returned. A record too large for any page is returned alone with its bulky
        fields elided and an ``oversized`` note, never skipped.
        """
        if view not in {"standard", "summary"}:
            raise ArgumentError("view must be 'standard' or 'summary'")
        filters, values = self._evidence_filters(
            target_id, case_id, status, evidence_kind, operation, subject_address, subject_name
        )
        scope = hashlib.sha256(_json([filters, values]).encode("utf-8")).hexdigest()[:16]
        if cursor:
            created_at, rowid = self._read_cursor(cursor, scope)
            filters.append("(created_at < ? OR (created_at = ? AND rowid < ?))")
            values += [created_at, created_at, rowid]
        size = max(1, min(int(limit), 500))
        where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT rowid AS row_key, {_EVIDENCE_COLUMNS} FROM evidence {where_sql} "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                [*values, size + 1],
            ).fetchall()
        more = len(rows) > size
        rows = rows[:size]
        items: list[dict[str, Any]] = []
        used = 0
        size_limited = False
        for row in rows:
            record = self._decode_row(row)
            record.pop("row_key", None)
            if view == "summary":
                item = self._evidence_summary(record)
            else:
                if not include_normalized:
                    record.pop("normalized", None)
                item = record
            cost = rendered_cost(item)
            if cost > budget:
                item = self._elide_oversized(item, budget)
                cost = rendered_cost(item)
            if items and used + cost > budget:
                size_limited = more = True
                break
            items.append(item)
            used += cost
        last = rows[len(items) - 1] if items else None
        next_cursor = self._cursor(last["created_at"], last["row_key"], scope) if more and last else None
        return {"items": items, "next_cursor": next_cursor, "has_more": more, "size_limited": size_limited}

    _OVERSIZED_KEEP = frozenset(
        {"evidence_id", "case_id", "target_id", "provider_id", "tool_name", "operation", "evidence_kind",
         "status", "created_at", "subject", "subject_type", "subject_address", "subject_name"}
    )  # fmt: skip

    @classmethod
    def _elide_oversized(cls, item: dict[str, Any], budget: int) -> dict[str, Any]:
        """A record too large for any page: keep its identity and provenance, replace its largest
        fields by size notes until it fits, and say how to get the full record."""
        out = dict(item)
        elided: list[str] = []
        bulky = sorted((k for k in out if k not in cls._OVERSIZED_KEEP), key=lambda k: -len(render_json(out[k])))
        for key in bulky:
            if rendered_cost(out) + 600 <= budget:
                break
            out[key] = {"elided": True, "chars": len(render_json(out[key]))}
            elided.append(key)
        out["oversized"] = {
            "elided_fields": elided,
            "full_record": "nexus_export_report(case_id, formats=['json'], include_raw=true) writes it "
            "to the data directory; nexus_get_evidence(evidence_id) returns it within the response limit",
        }
        return out

    def list_evidence(
        self,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        include_excerpt: bool = False,
    ) -> list[dict[str, Any]]:
        """0.1-compatible listing (excerpts only on request)."""
        if status and status not in _STATUSES:
            raise ValueError(f"status must be one of {sorted(_STATUSES)}")
        if target_id and not _TARGET_ID.fullmatch(target_id.lower()):
            raise ValueError("target_id must be a SHA-256 hex digest.")
        records = self.query_evidence(target_id=target_id, status=status, limit=limit)
        if include_excerpt:
            with self._connection() as connection:
                for record in records:
                    row = connection.execute(
                        "SELECT excerpt FROM evidence WHERE evidence_id = ?", (record["evidence_id"],)
                    ).fetchone()
                    record["excerpt"] = row[0] if row else ""
        return records

    def update_status(self, evidence_id: str, status: str) -> dict[str, Any]:
        if status not in _STATUSES:
            raise ValueError(f"status must be one of {sorted(_STATUSES)}")
        with self._connection() as connection:
            cursor = connection.execute("UPDATE evidence SET status = ? WHERE evidence_id = ?", (status, evidence_id))
            if cursor.rowcount == 0:
                raise ValueError("Evidence id not found.")
            row = connection.execute(
                "SELECT evidence_id, target_id, subject, status FROM evidence WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return dict(row)

    def review(
        self, subject_type: str, subject_id: str, status: str, note: str, *, idempotency: Idempotency | None = None
    ) -> dict[str, Any]:
        """Record an explicit human/agent review. This is the only path to 'verified'.

        The status change and the review row are written in one transaction.
        """
        prior = self._prior_write(idempotency)
        if prior:
            return self._replay(prior)
        note = (note or "").strip()
        if not note:
            raise ArgumentError("a review note explaining the basis of the decision is required")
        if subject_type == "evidence":
            if status not in VALIDATION_STATUSES - {"unverified"}:
                raise ArgumentError(
                    "evidence review status must be verified, rejected, corroborated, contradicted or resolved"
                )
            update: tuple[str, tuple[Any, ...]] = (
                "UPDATE evidence SET status = ? WHERE evidence_id = ?",
                (status, subject_id),
            )
            missing: Exception = ValueError("Evidence id not found.")
        elif subject_type == "finding":
            if status not in FINDING_STATUSES:
                raise ArgumentError(f"finding status must be one of {sorted(FINDING_STATUSES)}")
            update = (
                "UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?",
                (status, _now(), subject_id),
            )
            missing = NotFound(f"finding {subject_id!r} not found")
        else:
            raise ArgumentError("subject_type must be 'evidence' or 'finding'")
        review_id = _new_id("rv")
        now = _now()
        try:
            with self._connection() as connection:
                if connection.execute(*update).rowcount == 0:
                    raise missing
                self._claim_key(connection, idempotency, "review", review_id)
                connection.execute(
                    "INSERT INTO reviews (review_id, subject_type, subject_id, status, note, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (review_id, subject_type, subject_id, status, note[:4000], now),
                )
        except sqlite3.IntegrityError:
            replay = self._after_race(idempotency)
            if replay is None:
                raise
            return replay
        return {"review_id": review_id, "subject_type": subject_type, "subject_id": subject_id, "status": status}

    def link(self, src_id: str, dst_id: str, relation: str, note: str = "") -> None:
        if relation not in LINK_RELATIONS:
            raise ArgumentError(f"relation must be one of {sorted(LINK_RELATIONS)}")
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO evidence_links (src_id, dst_id, relation, note, created_at) VALUES (?, ?, ?, ?, ?)",
                (src_id, dst_id, relation, note[:1000], _now()),
            )

    # -- comparisons -----------------------------------------------------------------
    def add_comparison(
        self,
        *,
        target_id: str,
        case_id: str | None,
        operation: str,
        subject: str,
        assessment: str,
        details: dict[str, Any],
        evidence_ids: list[str],
    ) -> dict[str, Any]:
        cid = self.ensure_case(case_id)
        comparison_id = _new_id("cmp")
        now = _now()
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO comparisons (comparison_id, case_id, target_id, operation, subject, assessment, "
                "details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (comparison_id, cid, target_id, operation, subject[:512], assessment, _json(details), now),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO comparison_members (comparison_id, evidence_id) VALUES (?, ?)",
                [(comparison_id, eid) for eid in evidence_ids],
            )
        return {"comparison_id": comparison_id, "assessment": assessment, "created_at": now}

    def list_comparisons(
        self, *, target_id: str | None = None, case_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        filters: list[str] = []
        values: list[Any] = []
        if target_id:
            filters.append("target_id = ?")
            values.append(target_id.lower())
        if case_id:
            filters.append("case_id = ?")
            values.append(case_id)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        values.append(max(1, min(int(limit), 500)))
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM comparisons {where} ORDER BY created_at DESC LIMIT ?", values
            ).fetchall()
            out = []
            for row in rows:
                item = dict(row)
                item["details"] = _loads(item.pop("details_json"))
                item["evidence_ids"] = [
                    r[0]
                    for r in connection.execute(
                        "SELECT evidence_id FROM comparison_members WHERE comparison_id = ?", (item["comparison_id"],)
                    )
                ]
                out.append(item)
        return out

    # -- findings -------------------------------------------------------------------
    def record_finding(
        self,
        *,
        case_id: str | None,
        title: str,
        description: str,
        evidence_ids: list[str],
        target_id: str | None = None,
        severity: str = "info",
        status: str = "hypothesis",
        confidence: str = "low",
        confidence_rationale: str = "",
        contradicting_evidence_ids: list[str] | None = None,
        idempotency: Idempotency | None = None,
    ) -> dict[str, Any]:
        prior = self._prior_write(idempotency)
        if prior:
            return self._replay(prior)
        cid = self.ensure_case(case_id)
        title, description = (title or "").strip(), (description or "").strip()
        if not title or not description:
            raise ArgumentError("title and description are required")
        if severity not in FINDING_SEVERITIES:
            raise ArgumentError(f"severity must be one of {sorted(FINDING_SEVERITIES)}")
        if status not in FINDING_STATUSES - {"rejected"}:
            raise ArgumentError("new findings must be hypothesis, needs_review or confirmed")
        if confidence not in _CONFIDENCE:
            raise ArgumentError(f"confidence must be one of {sorted(_CONFIDENCE)}")
        contra = list(contradicting_evidence_ids or [])
        if status != "hypothesis" and not evidence_ids:
            raise ArgumentError("findings other than 'hypothesis' must cite at least one evidence_id")
        all_ids = [*evidence_ids, *contra]
        with self._connection() as connection:
            rows = (
                connection.execute(
                    f"SELECT evidence_id, target_id, evidence_kind, status FROM evidence WHERE evidence_id IN "
                    f"({','.join('?' * len(all_ids)) or 'NULL'})",
                    all_ids,
                ).fetchall()
                if all_ids
                else []
            )
        found = {r["evidence_id"]: dict(r) for r in rows}
        missing = [eid for eid in all_ids if eid not in found]
        if missing:
            raise NotFound(f"unknown evidence ids: {missing}")
        if target_id:
            target_id = target_id.lower()
        elif evidence_ids:
            target_id = found[evidence_ids[0]]["target_id"]
        warnings = []
        if status == "confirmed":
            support = [found[e] for e in evidence_ids]
            if all(s["evidence_kind"] == "ai_generated" for s in support):
                raise ArgumentError(
                    "a finding cannot be 'confirmed' on AI-generated evidence alone; cite engine or direct evidence"
                )
            if any(s["status"] in {"contradicted", "rejected"} for s in support):
                warnings.append("some supporting evidence is contradicted or rejected")
        finding_id = _new_id("fd")
        now = _now()
        try:
            self._write_finding(
                finding_id,
                cid,
                target_id,
                title,
                description,
                severity,
                status,
                confidence,
                confidence_rationale,
                now,
                evidence_ids,
                contra,
                idempotency,
                warnings,
            )
        except sqlite3.IntegrityError:
            replay = self._after_race(idempotency)
            if replay is None:
                raise
            return replay
        result = self.get_finding(finding_id)
        if warnings:
            result["warnings"] = warnings
        return result

    def _write_finding(
        self,
        finding_id: str,
        cid: str,
        target_id: str | None,
        title: str,
        description: str,
        severity: str,
        status: str,
        confidence: str,
        confidence_rationale: str,
        now: str,
        evidence_ids: list[str],
        contra: list[str],
        idempotency: Idempotency | None,
        warnings: list[str],
    ) -> None:
        with self._connection() as connection:
            self._claim_key(connection, idempotency, "finding", finding_id)
            self._store_warnings(connection, idempotency, warnings)
            connection.execute(
                "INSERT INTO findings (finding_id, case_id, target_id, title, description, severity, status, "
                "confidence, confidence_rationale, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    cid,
                    target_id,
                    title[:300],
                    description[:8000],
                    severity,
                    status,
                    confidence,
                    confidence_rationale[:2000],
                    now,
                    now,
                ),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id, role) VALUES (?, ?, ?)",
                [(finding_id, e, "supports") for e in evidence_ids] + [(finding_id, e, "contradicts") for e in contra],
            )

    @staticmethod
    def _finding_links(connection: sqlite3.Connection, finding_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
        """Evidence links of many findings in one query, in the order they were cited."""
        out: dict[str, list[dict[str, Any]]] = {fid: [] for fid in finding_ids}
        if not finding_ids:
            return out
        rows = connection.execute(
            "SELECT fe.finding_id, fe.evidence_id, fe.role, e.evidence_kind, e.provider_id, e.tool_name, e.status, "
            "e.subject FROM finding_evidence fe JOIN evidence e ON e.evidence_id = fe.evidence_id "
            f"WHERE fe.finding_id IN ({','.join('?' * len(finding_ids))}) ORDER BY fe.rowid",
            finding_ids,
        ).fetchall()
        for row in rows:
            link = dict(row)
            out[link.pop("finding_id")].append(link)
        return out

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            if row is None:
                raise NotFound(f"finding {finding_id!r} not found")
            links = self._finding_links(connection, [finding_id])[finding_id]
        return {**dict(row), "evidence": links}

    def list_findings(
        self, *, case_id: str | None = None, target_id: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        filters: list[str] = []
        values: list[Any] = []
        if case_id:
            filters.append("case_id = ?")
            values.append(case_id)
        if target_id:
            filters.append("target_id = ?")
            values.append(target_id.lower())
        if status:
            if status not in FINDING_STATUSES:
                raise ArgumentError(f"status must be one of {sorted(FINDING_STATUSES)}")
            filters.append("status = ?")
            values.append(status)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        values.append(max(1, min(int(limit), 500)))
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM findings {where} ORDER BY created_at DESC, rowid DESC LIMIT ?", values
            ).fetchall()
            links = self._finding_links(connection, [r["finding_id"] for r in rows])
        return [{**dict(r), "evidence": links[r["finding_id"]]} for r in rows]

    # -- questions (unknowns) ---------------------------------------------------------
    @staticmethod
    def _cited_evidence(connection: sqlite3.Connection, ids: list[str]) -> dict[str, dict[str, Any]]:
        rows = (
            connection.execute(
                f"SELECT evidence_id, case_id, target_id, evidence_kind, status FROM evidence WHERE evidence_id IN "
                f"({','.join('?' * len(ids))})",
                ids,
            ).fetchall()
            if ids
            else []
        )
        found = {r["evidence_id"]: dict(r) for r in rows}
        missing = [eid for eid in ids if eid not in found]
        if missing:
            raise NotFound(f"unknown evidence ids: {missing}")
        return found

    @staticmethod
    def _check_question_scope(
        connection: sqlite3.Connection, case_id: str, target_id: str | None, cited: dict[str, dict[str, Any]]
    ) -> list[str]:
        """Cited evidence must be about the question's target, or a target of its case.

        Evidence recorded under another case of the same target is allowed (it is reusable), but
        the caller is told, because that case's report holds the record, not this one.
        """
        case_targets = {
            r[0] for r in connection.execute("SELECT target_id FROM case_targets WHERE case_id = ?", (case_id,))
        }
        warnings: list[str] = []
        for eid, row in cited.items():
            if target_id and row["target_id"] != target_id:
                raise ArgumentError(f"evidence {eid} is about a different target than the question")
            if not target_id and row["target_id"] not in case_targets:
                raise ArgumentError(f"evidence {eid} is about a target outside case {case_id!r}")
            if row["case_id"] != case_id:
                warnings.append(f"evidence {eid} was recorded under case {row['case_id']!r}, not {case_id!r}")
        return warnings

    @staticmethod
    def _assess(
        status: str, links: list[dict[str, Any]], linked_contra: list[dict[str, Any]]
    ) -> tuple[list[str], list[str], dict[str, Any]]:
        """Return (problems, warnings, basis) for a question state given its evidence as it stands now.

        A problem means the evidence does not support the state: a write is refused, and a stored
        question in that state is reported as stale. Only source evidence (SOURCE_KINDS) can resolve
        a question; a review status never upgrades a note or AI output, because reviews are not
        authenticated. Contradicting evidence (cited, or linked as 'contradicts' against the
        support) blocks resolution until it is rejected; if it was source evidence, its rejection is
        itself only an unauthenticated review, so the resolution is marked contested (it is
        recorded, but does not count towards completion).
        """
        live = [link for link in links if link["status"] != "rejected"]
        supports = [link for link in live if link["role"] == "supports" and link["status"] != "contradicted"]
        all_contra = [link for link in links if link["role"] == "contradicts"] + linked_contra
        contradicts = [c for c in all_contra if c["status"] != "rejected"]
        dismissed = sorted(
            {c["evidence_id"] for c in all_contra if c["status"] == "rejected" and c["evidence_kind"] in SOURCE_KINDS}
        )
        problems: list[str] = []
        warnings: list[str] = []
        basis: dict[str, Any] = {}
        if status == "resolved":
            source = [link for link in supports if link["evidence_kind"] in SOURCE_KINDS]
            if not supports:
                problems.append("resolved needs supporting evidence that is not rejected or contradicted")
            elif not source:
                problems.append(
                    "a question can only be resolved by evidence parsed from the artifact or produced by an "
                    "engine; agent notes and AI output never resolve one, even when reviewed (nexus_review "
                    "cannot authenticate the reviewer)"
                )
            if contradicts:
                ids = sorted({c["evidence_id"] for c in contradicts})
                problems.append(
                    f"contradicting evidence still stands ({ids}); review it (nexus_review status 'rejected') "
                    "or mark the question 'contradicted'"
                )
            if any(link["status"] == "unverified" for link in source):
                warnings.append("some supporting evidence is still unverified")
            basis = {"source_evidence_ids": sorted({link["evidence_id"] for link in source})}
            if dismissed:
                basis["dismissed_source_contradictions"] = dismissed
                warnings.append(
                    f"contested: source evidence against this answer ({dismissed}) was dismissed only by "
                    "nexus_review, which cannot prove an independent reviewer; the question does not count "
                    "as resolved for completeness"
                )
        elif status == "contradicted":
            if not contradicts:
                problems.append("contradicted needs at least one contradicting evidence id that is not rejected")
            elif all(c["evidence_kind"] == "ai_generated" for c in contradicts):
                warnings.append("the only contradicting evidence is AI-generated")
        elif status == "partial" and not supports:
            problems.append("partial needs at least one supporting evidence id that is not rejected")
        return problems, warnings, basis

    def _gate(
        self, status: str, answer: str, links: list[dict[str, Any]], linked_contra: list[dict[str, Any]]
    ) -> tuple[list[str], dict[str, Any]]:
        """Refuse a question state its evidence does not support; return (warnings, basis) otherwise."""
        if status in {"resolved", "partial", "blocked"} and not answer.strip():
            what = "a reason" if status == "blocked" else "an answer"
            raise ArgumentError(f"a {status} question needs {what}")
        problems, warnings, basis = self._assess(status, links, linked_contra)
        if problems:
            raise ArgumentError("; ".join(problems))
        return warnings, basis

    @staticmethod
    def _question_links(connection: sqlite3.Connection, question_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {qid: [] for qid in question_ids}
        if not question_ids:
            return out
        rows = connection.execute(
            "SELECT qe.question_id, qe.evidence_id, qe.role, qe.added_revision, e.evidence_kind, e.status, "
            "e.provider_id, e.operation, e.subject FROM question_evidence qe "
            "JOIN evidence e ON e.evidence_id = qe.evidence_id "
            f"WHERE qe.question_id IN ({','.join('?' * len(question_ids))}) ORDER BY qe.added_revision, qe.rowid",
            question_ids,
        ).fetchall()
        for row in rows:
            link = dict(row)
            out[link.pop("question_id")].append(link)
        return out

    @staticmethod
    def _linked_contradictions(
        connection: sqlite3.Connection, links_by_question: dict[str, list[dict[str, Any]]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Evidence recorded elsewhere (evidence_links 'contradicts') against a question's support."""
        support_ids = sorted(
            {
                link["evidence_id"]
                for links in links_by_question.values()
                for link in links
                if link["role"] == "supports"
            }
        )
        out: dict[str, list[dict[str, Any]]] = {qid: [] for qid in links_by_question}
        if not support_ids:
            return out
        marks = ",".join("?" * len(support_ids))
        rows = connection.execute(
            "SELECT l.src_id, l.dst_id, s.evidence_kind AS src_kind, s.status AS src_status, "
            "d.evidence_kind AS dst_kind, d.status AS dst_status FROM evidence_links l "
            "JOIN evidence s ON s.evidence_id = l.src_id JOIN evidence d ON d.evidence_id = l.dst_id "
            f"WHERE l.relation = 'contradicts' AND (l.src_id IN ({marks}) OR l.dst_id IN ({marks})) "
            # A comparison compares records of one operation with each other. Older comparisons
            # linked every compared record pairwise, across operations too; such a link does not
            # show that the two operations disagreed, so it is not read as a contradiction.
            "AND NOT (s.operation IS NOT NULL AND d.operation IS NOT NULL AND s.operation <> d.operation)",
            [*support_ids, *support_ids],
        ).fetchall()
        against: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            for mine, other, kind, status in (
                (row["src_id"], row["dst_id"], row["dst_kind"], row["dst_status"]),
                (row["dst_id"], row["src_id"], row["src_kind"], row["src_status"]),
            ):
                against.setdefault(mine, []).append(
                    {"evidence_id": other, "against": mine, "evidence_kind": kind, "status": status}
                )
        for sid, inherited in EvidenceStore._inherited_contradictions(connection, support_ids).items():
            known = {c["evidence_id"] for c in against.get(sid, [])}
            against.setdefault(sid, []).extend(c for c in inherited if c["evidence_id"] not in known)
        for qid, links in links_by_question.items():
            supports = {
                link["evidence_id"] for link in links if link["role"] == "supports" and link["status"] != "rejected"
            }
            # Kept even when the opposing record is itself cited as support: citing both sides of a
            # disagreement must not hide it.
            out[qid] = [c for sid in sorted(supports) for c in against.get(sid, [])]
        return out

    @staticmethod
    def _subject_matches(a: Any, b: Any, name_addresses: dict[str, set[int]]) -> bool:
        """Whether two records of one provider describe the same subject (conservatively).

        Both have an address: the addresses decide (names are not compared). Otherwise the names
        must be equal and non-empty, and the provider must have reported that name at no more than
        one address on this target (its own name-to-address mapping); a name it placed at two
        addresses is ambiguous and never matches. Names are compared exactly, never fuzzily.
        """
        if (a["subject_type"] or "") != (b["subject_type"] or ""):
            return False
        if a["subject_address"] is not None and b["subject_address"] is not None:
            return bool(a["subject_address"] == b["subject_address"])
        name = a["subject_name"] or ""
        if not name or name != (b["subject_name"] or ""):
            return False
        addresses = name_addresses.get(name, set())
        known = {r["subject_address"] for r in (a, b) if r["subject_address"] is not None}
        return len(addresses) <= 1 and known <= addresses

    @staticmethod
    def _inherited_contradictions(
        connection: sqlite3.Connection, support_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """Disagreements recorded against an earlier run of the same result.

        A comparison links the records it compared (one operation, record pairs). A re-run of one
        side - same case, target, provider and operation, the same subject (see _subject_matches)
        and the same parameters where both runs recorded them - gets a new evidence id, but the
        disagreement still applies to it. For each opposing side (provider, operation, subject)
        only explicit comparison outcomes count, newest first: 'contradicts', or 'agrees_with'
        from a record with the same engine identity (engine and version) as the support. A
        'same_subject' link (single source, one engine family, or nothing to compare) is neutral
        and never clears a disagreement. Links between different operations (from older
        comparisons that linked every compared record) are ambiguous and are not used.
        """
        marks = ",".join("?" * len(support_ids))
        cols = (
            "evidence_id, case_id, target_id, provider_id, operation, subject_type, subject_address, "
            "subject_name, params_hash, engine, engine_version"
        )
        supports = connection.execute(
            f"SELECT {cols} FROM evidence WHERE evidence_id IN ({marks}) AND operation IS NOT NULL "
            "AND (subject_address IS NOT NULL OR COALESCE(subject_name, '') <> '')",
            support_ids,
        ).fetchall()
        out: dict[str, list[dict[str, Any]]] = {}
        for s in supports:
            mapping: dict[str, set[int]] = {}
            for row in connection.execute(
                "SELECT DISTINCT subject_name, subject_address FROM evidence WHERE target_id = ? "
                "AND provider_id = ? AND subject_name IS NOT NULL AND subject_address IS NOT NULL",
                (s["target_id"], s["provider_id"]),
            ):
                mapping.setdefault(row["subject_name"], set()).add(row["subject_address"])
            runs = [
                e
                for e in connection.execute(
                    f"SELECT {cols} FROM evidence WHERE case_id = ? AND target_id = ? AND provider_id = ? "
                    "AND operation = ?",
                    (s["case_id"], s["target_id"], s["provider_id"], s["operation"]),
                )
                if EvidenceStore._subject_matches(s, e, mapping)
                and (e["params_hash"] is None or s["params_hash"] is None or e["params_hash"] == s["params_hash"])
            ]
            if not runs:
                continue
            by_id = {e["evidence_id"]: e for e in runs}
            run_marks = ",".join("?" * len(by_id))
            links = connection.execute(
                "SELECT l.src_id, l.dst_id, l.relation, l.created_at, l.rowid AS link_row FROM evidence_links l "
                f"WHERE l.relation IN ('contradicts', 'agrees_with') AND (l.src_id IN ({run_marks}) "
                f"OR l.dst_id IN ({run_marks}))",
                [*by_id, *by_id],
            ).fetchall()
            other_ids = {link["dst_id"] if link["src_id"] in by_id else link["src_id"] for link in links}
            others = {
                o["evidence_id"]: o
                for o in connection.execute(
                    f"SELECT {cols}, evidence_kind, status FROM evidence WHERE evidence_id IN "
                    f"({','.join('?' * len(other_ids))})",
                    list(other_ids),
                )
            } if other_ids else {}  # fmt: skip
            latest: dict[tuple[Any, ...], tuple[Any, ...]] = {}
            for link in links:
                mine_id = link["src_id"] if link["src_id"] in by_id else link["dst_id"]
                other = others.get(link["dst_id"] if mine_id == link["src_id"] else link["src_id"])
                mine = by_id[mine_id]
                if other is None or other["evidence_id"] == s["evidence_id"] or other["operation"] != mine["operation"]:
                    continue
                if link["relation"] == "agrees_with" and (mine["engine"], mine["engine_version"]) != (
                    s["engine"],
                    s["engine_version"],
                ):
                    continue  # an agreement about another engine build says nothing about this output
                subject = (
                    f"a:{other['subject_address']}"
                    if other["subject_address"] is not None
                    else f"n:{other['subject_name']}"
                )
                side = (other["provider_id"], other["operation"], other["subject_type"] or "", subject)
                stamp = (link["created_at"], link["link_row"])
                if side not in latest or stamp > latest[side][0]:
                    latest[side] = (stamp, link["relation"], other, mine_id)
            for _stamp, relation, other, via in latest.values():
                if relation == "contradicts":
                    out.setdefault(s["evidence_id"], []).append(
                        {
                            "evidence_id": other["evidence_id"],
                            "against": s["evidence_id"],
                            "evidence_kind": other["evidence_kind"],
                            "status": other["status"],
                            "via": via,
                        }
                    )
        return out

    def _question_view(
        self, row: sqlite3.Row, links: list[dict[str, Any]], linked_contra: list[dict[str, Any]]
    ) -> dict[str, Any]:
        item = dict(row)
        item["required"] = bool(item["required"])
        item["evidence"] = links
        item["supporting_evidence_ids"] = [x["evidence_id"] for x in links if x["role"] == "supports"]
        item["contradicting_evidence_ids"] = [x["evidence_id"] for x in links if x["role"] == "contradicts"]
        if linked_contra:
            item["linked_contradictions"] = linked_contra
        # Missing evidence stays visible: no supporting evidence that still stands.
        item["evidence_missing"] = not any(
            x["role"] == "supports" and x["status"] not in {"rejected", "contradicted"} for x in links
        )
        # Re-check the stored state against the evidence as it stands now (reviews may have
        # rejected support since): a state its evidence no longer supports is reported as stale.
        problems, _, basis = self._assess(item["status"], links, linked_contra)
        item["stale"] = bool(problems)
        if problems:
            item["stale_reasons"] = problems
        item["contested"] = bool(item["status"] == "resolved" and basis.get("dismissed_source_contradictions"))
        if item["status"] == "resolved" and basis:
            item["resolution_basis"] = basis
        return item

    def _views(self, connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        ids = [r["question_id"] for r in rows]
        links = self._question_links(connection, ids)
        contra = self._linked_contradictions(connection, links)
        views = [self._question_view(r, links[r["question_id"]], contra[r["question_id"]]) for r in rows]
        # A question that was ever required stays required for every consumer (counts, checklist,
        # brief, report), even if a database written by an earlier build stored it as optional later.
        if ids:
            ever = {
                r[0]
                for r in connection.execute(
                    f"SELECT DISTINCT question_id FROM question_history WHERE required = 1 AND question_id IN "
                    f"({','.join('?' * len(ids))})",
                    ids,
                )
            }
            for view in views:
                view["required"] = view["required"] or view["question_id"] in ever
        return views

    @staticmethod
    def _compact_question(item: dict[str, Any], text_limit: int = 500) -> dict[str, Any]:
        """A bounded listing row: ids (capped) and counts instead of per-link detail."""
        out = {k: v for k, v in item.items() if k not in {"evidence", "linked_contradictions"}}
        for key in ("supporting_evidence_ids", "contradicting_evidence_ids"):
            ids = item[key]
            out[key.replace("_ids", "_count")] = len(ids)
            out[key] = ids[:QUESTION_LIST_IDS]
        if item.get("linked_contradictions"):
            out["linked_contradiction_ids"] = sorted({c["evidence_id"] for c in item["linked_contradictions"]})[
                :QUESTION_LIST_IDS
            ]
        for key in ("question", "answer", "needed_evidence", "search_boundary"):
            if len(out.get(key) or "") > text_limit:
                out[key] = out[key][:text_limit] + "…"
                out.setdefault("truncated_fields", []).append(key)
        # Id lists inside the resolution basis and stale reasons grow with the evidence; cap them too.
        if isinstance(out.get("resolution_basis"), dict):
            basis = dict(out["resolution_basis"])
            for key, value in list(basis.items()):
                if isinstance(value, list) and len(value) > QUESTION_LIST_IDS:
                    basis[key] = value[:QUESTION_LIST_IDS]
                    basis[f"{key}_count"] = len(value)
            out["resolution_basis"] = basis
        reasons = out.get("stale_reasons") or []
        if reasons and (len(reasons) > 5 or any(len(str(r)) > 300 for r in reasons)):
            out["stale_reasons"] = [str(r)[:300] + ("…" if len(str(r)) > 300 else "") for r in reasons[:5]]
            out["stale_reasons_count"] = len(reasons)
        return out

    def record_question(
        self,
        *,
        case_id: str | None,
        question: str,
        target_id: str | None = None,
        status: str = "open",
        required: bool = True,
        needed_evidence: str = "",
        search_boundary: str = "",
        answer: str = "",
        evidence_ids: list[str] | None = None,
        contradicting_evidence_ids: list[str] | None = None,
        note: str = "",
        idempotency: Idempotency | None = None,
    ) -> dict[str, Any]:
        prior = self._prior_write(idempotency)
        if prior:
            return self._replay(prior)
        cid = self.ensure_case(case_id)
        question = (question or "").strip()
        if not question:
            raise ArgumentError("question text is required")
        if status not in QUESTION_INITIAL_STATUSES:
            raise ArgumentError(
                f"a new question starts as one of {sorted(QUESTION_INITIAL_STATUSES)}; "
                "record evidence, then move it on with nexus_update_question"
            )
        if target_id:
            target_id = target_id.lower()
            if not _TARGET_ID.fullmatch(target_id):
                raise ArgumentError("target_id must be a SHA-256 hex digest")
        supports, contra = list(evidence_ids or []), list(contradicting_evidence_ids or [])
        question_id = _new_id("q")
        now = _now()
        try:
            warnings = self._write_question(
                question_id,
                cid,
                question,
                target_id,
                status,
                required,
                needed_evidence,
                search_boundary,
                answer,
                supports,
                contra,
                note,
                now,
                idempotency,
            )
        except sqlite3.IntegrityError:
            replay = self._after_race(idempotency)
            if replay is None:
                raise
            return replay
        result = self.get_question(question_id, history_limit=0)
        if warnings:
            result["warnings"] = warnings
        return result

    def _write_question(
        self,
        question_id: str,
        cid: str,
        question: str,
        target_id: str | None,
        status: str,
        required: bool,
        needed_evidence: str,
        search_boundary: str,
        answer: str,
        supports: list[str],
        contra: list[str],
        note: str,
        now: str,
        idempotency: Idempotency | None,
    ) -> list[str]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._claim_key(connection, idempotency, "question", question_id)
            if (
                target_id
                and not connection.execute(
                    "SELECT 1 FROM case_targets WHERE case_id = ? AND target_id = ?", (cid, target_id)
                ).fetchone()
            ):
                raise ArgumentError(f"target is not part of case {cid!r}")
            cited = self._cited_evidence(connection, [*supports, *contra])
            warnings = self._check_question_scope(connection, cid, target_id, cited)
            links = [{**cited[e], "role": "supports"} for e in supports] + [
                {**cited[e], "role": "contradicts"} for e in contra
            ]
            linked = self._linked_contradictions(connection, {question_id: links})[question_id]
            gate_warnings, basis = self._gate(status, answer, links, linked)
            warnings += gate_warnings
            connection.execute(
                "INSERT INTO questions (question_id, case_id, target_id, question, status, required, needed_evidence, "
                "search_boundary, answer, revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (
                    question_id,
                    cid,
                    target_id,
                    question[:2000],
                    status,
                    int(bool(required)),
                    needed_evidence[:2000],
                    search_boundary[:2000],
                    answer[:4000],
                    now,
                    now,
                ),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO question_evidence (question_id, evidence_id, role, added_revision) "
                "VALUES (?, ?, ?, 1)",
                [(question_id, link["evidence_id"], link["role"]) for link in links],
            )
            connection.execute(
                "INSERT INTO question_history (question_id, revision, status, answer, note, basis_json, required, "
                "created_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    question_id,
                    status,
                    answer[:4000],
                    note[:2000],
                    _json(basis) if basis else None,
                    int(bool(required)),
                    now,
                ),
            )
            self._store_warnings(connection, idempotency, warnings)
        return warnings

    def update_question(
        self,
        question_id: str,
        *,
        expected_revision: int,
        status: str | None = None,
        answer: str | None = None,
        evidence_ids: list[str] | None = None,
        contradicting_evidence_ids: list[str] | None = None,
        needed_evidence: str | None = None,
        search_boundary: str | None = None,
        required: bool | None = None,
        note: str = "",
        idempotency: Idempotency | None = None,
    ) -> dict[str, Any]:
        """Move a question on. Fails with a revision conflict if it changed since ``expected_revision``.

        With an idempotency key, a retry of an update that already went through returns the
        question as it is now (flagged) instead of a revision conflict.
        """
        prior = self._prior_write(idempotency)
        if prior:
            return self._replay(prior)
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
            raise ArgumentError("expected_revision must be the integer revision you last read")
        if status is not None and status not in QUESTION_STATUSES:
            raise ArgumentError(f"status must be one of {list(QUESTION_STATUSES)}")
        supports, contra = list(evidence_ids or []), list(contradicting_evidence_ids or [])
        changes = (status, answer, needed_evidence, search_boundary, required)
        if all(value is None for value in changes) and not supports and not contra:
            raise ArgumentError("nothing to update")
        now = _now()
        with self._connection() as connection:
            # Take the write lock before reading so the revision check and the write are one step.
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM questions WHERE question_id = ?", (question_id,)).fetchone()
            if row is None:
                raise NotFound(f"question {question_id!r} not found")
            if (
                idempotency is not None
                and connection.execute(
                    "SELECT 1 FROM idempotency_keys WHERE tool = ? AND idempotency_key = ?",
                    (idempotency.tool, idempotency.key),
                ).fetchone()
            ):
                # A concurrent retry with this key committed first: report its result.
                return self._replay(self._prior_write(idempotency) or {})
            self._claim_key(connection, idempotency, "question", question_id)
            if row["revision"] != expected_revision:
                raise RevisionConflict(
                    f"question {question_id!r} is at revision {row['revision']}, not {expected_revision}; "
                    "re-read it and apply your change to the current state",
                    details={
                        "current_revision": row["revision"],
                        "status": row["status"],
                        "updated_at": row["updated_at"],
                    },
                )
            cited = self._cited_evidence(connection, [*supports, *contra])
            warnings = self._check_question_scope(connection, row["case_id"], row["target_id"], cited)
            new_revision = row["revision"] + 1
            connection.executemany(
                "INSERT OR IGNORE INTO question_evidence (question_id, evidence_id, role, added_revision) "
                "VALUES (?, ?, ?, ?)",
                [(question_id, e, "supports", new_revision) for e in supports]
                + [(question_id, e, "contradicts", new_revision) for e in contra],
            )
            links = self._question_links(connection, [question_id])
            linked = self._linked_contradictions(connection, links)[question_id]
            new_status = status or row["status"]
            new_answer = row["answer"] if answer is None else answer[:4000]
            # The gate runs on the resulting state even when the status is unchanged, so new
            # contradicting evidence cannot be attached to a resolved question silently.
            gate_warnings, basis = self._gate(new_status, new_answer, links[question_id], linked)
            warnings += gate_warnings
            new_required = bool(row["required"]) if required is None else bool(required)
            if row["required"] and not new_required:
                # Requiredness only ever increases. Relaxing it could take the question out of the
                # completeness count (e.g. resolve -> optional -> reopen), and no caller of this
                # interface can be authenticated as an operator entitled to waive it.
                raise ArgumentError(
                    "a required question cannot be made optional (requiredness only increases through this "
                    "interface); mark it 'blocked' with a reason instead, which keeps it visible as incomplete",
                    details={"rule": "required_is_monotonic", "question_id": question_id},
                )
            cursor = connection.execute(
                "UPDATE questions SET status = ?, answer = ?, needed_evidence = ?, search_boundary = ?, required = ?, "
                "revision = ?, updated_at = ? WHERE question_id = ? AND revision = ?",
                (
                    new_status,
                    new_answer,
                    row["needed_evidence"] if needed_evidence is None else needed_evidence[:2000],
                    row["search_boundary"] if search_boundary is None else search_boundary[:2000],
                    int(new_required),
                    new_revision,
                    now,
                    question_id,
                    row["revision"],
                ),
            )
            if cursor.rowcount != 1:  # pragma: no cover - guarded by BEGIN IMMEDIATE
                raise RevisionConflict(f"question {question_id!r} changed during the update; re-read it")
            connection.execute(
                "INSERT INTO question_history (question_id, revision, status, answer, note, basis_json, required, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    question_id,
                    new_revision,
                    new_status,
                    new_answer,
                    note[:2000],
                    _json(basis) if basis else None,
                    int(new_required),
                    now,
                ),
            )
            self._store_warnings(connection, idempotency, warnings)
        result = self.get_question(question_id, history_limit=0)
        if warnings:
            result["warnings"] = warnings
        return result

    def get_question(self, question_id: str, *, history_limit: int = 10) -> dict[str, Any]:
        """One question with full link detail and its newest ``history_limit`` revisions (oldest first)."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM questions WHERE question_id = ?", (question_id,)).fetchone()
            if row is None:
                raise NotFound(f"question {question_id!r} not found")
            item = self._views(connection, [row])[0]
            item["history_count"] = row["revision"]
            limit = max(0, min(int(history_limit), 100))
            if limit:
                item["history"] = [
                    dict(r)
                    for r in connection.execute(
                        "SELECT revision, status, answer, note, basis_json, required, created_at FROM question_history "
                        "WHERE question_id = ? ORDER BY revision DESC LIMIT ?",
                        (question_id, limit),
                    )
                ][::-1]
        return item

    def list_questions(
        self,
        *,
        case_id: str | None = None,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Questions in creation order (a checklist): compact rows with capped evidence ids and counts.

        Questions are never deleted and new ones sort last, so ``offset`` paging is stable.
        """
        filters, values = self._question_filters(case_id, target_id)
        if status:
            if status not in QUESTION_STATUSES:
                raise ArgumentError(f"status must be one of {list(QUESTION_STATUSES)}")
            filters.append("status = ?")
            values.append(status)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        values += [max(1, min(int(limit), 200)), max(0, int(offset))]
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM questions {where} ORDER BY created_at, rowid LIMIT ? OFFSET ?", values
            ).fetchall()
            return [self._compact_question(view) for view in self._views(connection, rows)]

    def _all_questions(self, case_id: str) -> list[dict[str, Any]]:
        """Every question of a case (a report must not drop rows), read in pages of 200."""
        out: list[dict[str, Any]] = []
        while True:
            page = self.list_questions(case_id=case_id, limit=200, offset=len(out))
            out += page
            if len(page) < 200:
                return out

    @staticmethod
    def _question_filters(case_id: str | None, target_id: str | None) -> tuple[list[str], list[Any]]:
        """Filters for a question scope. A target scope also covers the case-level questions
        (no target) of the case(s) the target belongs to: they apply to every target of the case,
        so a target view must neither hide them nor call the work complete while one is open."""
        filters: list[str] = []
        values: list[Any] = []
        if case_id:
            filters.append("case_id = ?")
            values.append(case_id)
        if target_id:
            if not _TARGET_ID.fullmatch(target_id.lower()):
                raise ArgumentError("target_id must be a SHA-256 hex digest.")
            filters.append(
                "(target_id = ? OR (target_id IS NULL AND case_id IN "
                "(SELECT case_id FROM case_targets WHERE target_id = ?)))"
            )
            values += [target_id.lower(), target_id.lower()]
        return filters, values

    def question_counts(self, *, case_id: str | None = None, target_id: str | None = None) -> dict[str, Any]:
        """Counts by stored status over all matching questions (not limited).

        A question whose stored state its evidence no longer supports is counted as ``stale``, and
        a stale or unresolved required question keeps the investigation incomplete.
        """
        return self._question_totals(self._scoped_views(case_id, target_id))

    def _scoped_views(self, case_id: str | None, target_id: str | None) -> list[dict[str, Any]]:
        """Every question of a scope as full views, in creation order."""
        filters, values = self._question_filters(case_id, target_id)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        with self._connection() as connection:
            rows = connection.execute(f"SELECT * FROM questions {where} ORDER BY created_at, rowid", values).fetchall()
            return self._views(connection, rows)

    def prioritized_questions(
        self,
        *,
        case_id: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
        unresolved_only: bool = False,
    ) -> dict[str, Any]:
        """Questions ranked work-first, with counts over every question of the scope.

        Ranking happens before the limit: required questions that are not validly resolved come
        first, then other unresolved ones, then resolved ones; creation order breaks ties, so the
        result is deterministic. ``remaining`` says how many matching questions were left out
        (nexus_list_questions pages through all of them in creation order).
        """
        views = self._scoped_views(case_id, target_id)

        def rank(view: dict[str, Any]) -> int:
            unresolved = view["status"] != "resolved" or view["stale"] or view["contested"]
            return 0 if unresolved and view["required"] else (1 if unresolved else 2)

        ranked = sorted(enumerate(views), key=lambda item: (rank(item[1]), item[0]))
        matching = [view for _, view in ranked if not unresolved_only or rank(view) < 2]
        size = max(1, min(int(limit), 200))
        return {
            "counts": self._question_totals(views),
            "questions": [self._compact_question(view) for view in matching[:size]],
            "remaining": max(0, len(matching) - size),
        }

    @staticmethod
    def _question_totals(views: list[dict[str, Any]]) -> dict[str, Any]:
        by_status = dict.fromkeys(QUESTION_STATUSES, 0)
        for view in views:
            by_status[view["status"]] += 1
        unresolved = [v for v in views if v["status"] != "resolved" or v["stale"] or v["contested"]]
        required_unresolved = sum(1 for v in unresolved if v["required"])
        return {
            "total": len(views),
            "by_status": by_status,
            "stale": sum(1 for v in views if v["stale"]),
            "contested": sum(1 for v in views if v["contested"]),
            "unresolved": len(unresolved),
            "required_unresolved": required_unresolved,
            "complete": bool(views) and required_unresolved == 0,
        }

    def evidence_overview(self, target_id: str) -> list[dict[str, Any]]:
        """Per-operation evidence counts for one target, with the newest evidence id of each."""
        tid = target_id.lower()
        if not _TARGET_ID.fullmatch(tid):
            raise ArgumentError("target_id must be a SHA-256 hex digest.")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT operation, evidence_kind, provider_id, evidence_id, created_at, n FROM ("
                "  SELECT operation, evidence_kind, provider_id, evidence_id, created_at,"
                "         COUNT(*) OVER (PARTITION BY operation) AS n,"
                "         ROW_NUMBER() OVER (PARTITION BY operation ORDER BY created_at DESC, rowid DESC) AS rn"
                "  FROM evidence WHERE target_id = ?"
                ") WHERE rn = 1 ORDER BY operation",
                (tid,),
            ).fetchall()
        return [
            {
                "operation": r["operation"],
                "count": r["n"],
                "latest_evidence_id": r["evidence_id"],
                "latest_kind": r["evidence_kind"],
                "latest_provider_id": r["provider_id"],
                "latest_at": r["created_at"],
            }
            for r in rows
        ]

    # -- compact case brief ----------------------------------------------------------
    def case_brief(
        self, *, case_id: str | None = None, target_id: str | None = None, limit: int = 20
    ) -> dict[str, Any]:
        """A bounded summary to hand to a delegated agent: counts over everything, ids for detail.

        Counts always cover every matching record. Lists are capped at ``limit``, except that every
        critical/high finding that is not rejected is listed (up to BRIEF_HARD_CAP), and whatever a
        list leaves out is reported in ``omitted`` rather than dropped silently.
        """
        if not case_id and not target_id:
            raise ArgumentError("give case_id or target")
        size = max(1, min(int(limit), 100))
        brief: dict[str, Any] = {"scope": {"case_id": case_id, "target": target_id.lower() if target_id else None}}
        if case_id:
            case = self.get_case(case_id)
            brief["case"] = {"case_id": case["case_id"], "title": case["title"]}
            targets = case["targets"]
            if target_id:
                targets = [t for t in targets if t["target_id"] == target_id.lower()]
                if not targets:
                    raise ArgumentError(f"target is not part of case {case_id!r}")
        else:
            targets = [self.get_target(target_id or "")]
        brief["targets"] = [
            {k: t.get(k) for k in ("target_id", "display_name", "format", "kind")} for t in targets[:size]
        ]
        omitted: dict[str, int] = {}
        if len(targets) > size:
            omitted["targets"] = len(targets) - size
        ev_filters, ev_values = self._evidence_filters(target_id, case_id, None, None, None, None, None)
        ev_where = f"WHERE {' AND '.join(ev_filters)}" if ev_filters else ""
        # A finding belongs to a target if it names it, cites evidence about it, or is a case-level
        # finding without evidence in one of the target's cases (findings.target_id only holds the
        # target of the first cited evidence).
        fd_filters: list[str] = []
        fd_values: list[Any] = []
        if case_id:
            fd_filters.append("f.case_id = ?")
            fd_values.append(case_id)
        if target_id:
            tid = target_id.lower()
            fd_filters.append(
                "(f.target_id = ? OR EXISTS (SELECT 1 FROM finding_evidence x JOIN evidence e "
                "ON e.evidence_id = x.evidence_id WHERE x.finding_id = f.finding_id AND e.target_id = ?) "
                "OR (f.target_id IS NULL AND NOT EXISTS (SELECT 1 FROM finding_evidence y WHERE y.finding_id = "
                "f.finding_id) AND f.case_id IN (SELECT case_id FROM case_targets WHERE target_id = ?)))"
            )
            fd_values += [tid, tid, tid]
        fd_where = f"WHERE {' AND '.join(fd_filters)}" if fd_filters else ""
        with self._connection() as connection:
            kinds = connection.execute(
                f"SELECT evidence_kind, status, COUNT(*) AS n, MAX(created_at) AS last FROM evidence {ev_where} "
                "GROUP BY evidence_kind, status",
                ev_values,
            ).fetchall()
            operations = connection.execute(
                f"SELECT operation, COUNT(*) AS n, MAX(created_at) AS last FROM evidence {ev_where} "
                "GROUP BY operation ORDER BY n DESC, operation",
                ev_values,
            ).fetchall()
            contradiction_count = connection.execute(
                f"SELECT COUNT(*) FROM evidence {ev_where} {'AND' if ev_where else 'WHERE'} "
                "(status = 'contradicted' OR classification = 'contradiction')",
                ev_values,
            ).fetchone()[0]
            comparisons = connection.execute(
                f"SELECT assessment, COUNT(*) AS n FROM comparisons {ev_where} GROUP BY assessment", ev_values
            ).fetchall()
            findings = connection.execute(
                "SELECT f.finding_id, f.title, f.severity, f.status, f.confidence, f.target_id, f.created_at, "
                "SUM(fe.role = 'supports') AS supporting, SUM(fe.role = 'contradicts') AS contradicting "
                f"FROM findings f LEFT JOIN finding_evidence fe ON fe.finding_id = f.finding_id {fd_where} "
                "GROUP BY f.finding_id",
                fd_values,
            ).fetchall()
        by_kind: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for row in kinds:
            by_kind[row["evidence_kind"]] = by_kind.get(row["evidence_kind"], 0) + row["n"]
            by_status[row["status"]] = by_status.get(row["status"], 0) + row["n"]
        brief["evidence"] = {
            "total": sum(by_kind.values()),
            "by_kind": by_kind,
            "by_status": by_status,
            "contradictions": contradiction_count,
            "latest_at": max((row["last"] for row in kinds), default=None),
            "operations": [
                {"operation": r["operation"], "count": r["n"], "latest_at": r["last"]} for r in operations[:size]
            ],
            "comparisons_by_assessment": {r["assessment"]: r["n"] for r in comparisons},
        }
        if len(operations) > size:
            omitted["operations"] = len(operations) - size

        rank_sev = {s: i for i, s in enumerate(("critical", "high", "medium", "low", "info"))}
        rank_status = {s: i for i, s in enumerate(("confirmed", "needs_review", "hypothesis", "rejected"))}
        # Newest first within each severity/status rank (two stable sorts).
        ordered = sorted(findings, key=lambda f: f["created_at"], reverse=True)
        ordered.sort(key=lambda f: (rank_sev.get(f["severity"], 9), rank_status.get(f["status"], 9)))
        significant = [f for f in ordered if f["severity"] in {"critical", "high"} and f["status"] != "rejected"]
        significant_ids = {f["finding_id"] for f in significant}
        rest = [f for f in ordered if f["finding_id"] not in significant_ids]
        listed = significant[:BRIEF_HARD_CAP] + rest[: max(0, size - len(significant))]
        brief["findings"] = {
            "total": len(findings),
            "by_status": _count(f["status"] for f in findings),
            "by_severity": _count(f["severity"] for f in findings),
            "listed": [
                {
                    "finding_id": f["finding_id"],
                    "title": f["title"][:160] + ("…" if len(f["title"]) > 160 else ""),
                    "severity": f["severity"],
                    "status": f["status"],
                    "confidence": f["confidence"],
                    "supporting_evidence": int(f["supporting"] or 0),
                    "contradicting_evidence": int(f["contradicting"] or 0),
                }
                for f in listed
            ],
        }
        if len(findings) > len(listed):
            omitted["findings"] = len(findings) - len(listed)
        if len(significant) > BRIEF_HARD_CAP:
            omitted["significant_findings"] = len(significant) - BRIEF_HARD_CAP

        ranked = self.prioritized_questions(case_id=case_id, target_id=target_id, limit=size, unresolved_only=True)
        counts = ranked["counts"]
        open_rows = ranked["questions"]
        brief["questions"] = {
            **counts,
            "unresolved_list": [
                {
                    "question_id": q["question_id"],
                    "question": q["question"][:200] + ("…" if len(q["question"]) > 200 else ""),
                    "status": q["status"],
                    "required": q["required"],
                    "revision": q["revision"],
                    "evidence_missing": q["evidence_missing"],
                    "stale": q["stale"],
                    "contested": q["contested"],
                }
                for q in open_rows
            ],
        }
        if ranked["remaining"]:
            omitted["unresolved_questions"] = ranked["remaining"]
        brief["omitted"] = omitted
        brief["detail"] = (
            "Counts cover every record. For detail: nexus_get_findings, nexus_list_questions(question_id), "
            "nexus_get_evidence(view='summary', cursor=...) or nexus_get_evidence(evidence_id)."
        )
        return brief

    # -- 0.1 compatibility: cross-provider candidate grouping -----------------------
    def cross_check_candidates(self, target_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Group evidence on the same target/subject; candidates are not automatic proof."""
        records = self.list_evidence(target_id=target_id, limit=limit, include_excerpt=False)
        groups: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            key = (
                f"addr:{record['subject_address']:#x}"
                if record.get("subject_address") is not None
                else " ".join(str(record["subject"]).casefold().split())
            )
            groups.setdefault(key, []).append(record)
        candidates: list[dict[str, Any]] = []
        for key, rows in groups.items():
            providers = sorted({row["provider_id"] for row in rows})
            families = sorted({row.get("engine_family") or row["provider_id"] for row in rows})
            has_contradiction = any(
                row["classification"] == "contradiction" or row["status"] == "contradicted" for row in rows
            )
            if len(providers) > 1 or has_contradiction:
                candidates.append(
                    {
                        "subject_key": key,
                        "subjects": sorted({row["subject"] for row in rows}),
                        "providers": providers,
                        "provider_count": len(providers),
                        "engine_families": families,
                        "evidence_count": len(rows),
                        "contains_contradiction": has_contradiction,
                        "evidence": rows,
                        "interpretation": "Review source excerpts; matching subjects alone do not establish agreement.",
                    }
                )
        return candidates

    # -- export ---------------------------------------------------------------------
    def case_bundle(self, case_id: str, *, include_raw: bool = False, evidence_limit: int = 2000) -> dict[str, Any]:
        case = self.get_case(case_id)
        evidence = self.query_evidence(case_id=case_id, limit=min(evidence_limit, 500), include_normalized=True)
        if evidence_limit > 500:
            with self._connection() as connection:
                rows = connection.execute(
                    f"SELECT {_EVIDENCE_COLUMNS} FROM evidence WHERE case_id = ? ORDER BY created_at LIMIT ?",
                    (case_id, evidence_limit),
                ).fetchall()
            evidence = [self._decode_row(r) for r in rows]
        if include_raw:
            for record in evidence:
                raw = self.get_raw(record["raw_sha256"]) if record.get("raw_sha256") else None
                if raw:
                    record["raw"] = raw["content"]
        with self._connection() as connection:
            links = [
                dict(r)
                for r in connection.execute(
                    "SELECT l.* FROM evidence_links l JOIN evidence e ON e.evidence_id = l.src_id WHERE e.case_id = ?",
                    (case_id,),
                )
            ]
            reviews = [
                dict(r)
                for r in connection.execute(
                    "SELECT r.* FROM reviews r WHERE r.subject_id IN (SELECT evidence_id FROM evidence WHERE case_id = ?) "
                    "OR r.subject_id IN (SELECT finding_id FROM findings WHERE case_id = ?)",
                    (case_id, case_id),
                )
            ]
        targets = [self.get_target(t["target_id"]) for t in case["targets"]]
        return {
            "case": {k: v for k, v in case.items() if k != "targets"},
            "targets": targets,
            "evidence": evidence,
            "links": links,
            "comparisons": self.list_comparisons(case_id=case_id, limit=500),
            "findings": self.list_findings(case_id=case_id, limit=500),
            "questions": self._all_questions(case_id),
            "question_counts": self.question_counts(case_id=case_id),
            "reviews": reviews,
            "schema_version": self.schema_version(),
        }
