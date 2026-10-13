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
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import ArgumentError, NotFound, WorkspaceViolation

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
DEFAULT_CASE = "default"
SCHEMA_VERSION = 2

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
}


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
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
            if not applied:
                # A 0.1 database has tables but no migration ledger: treat v1 as applied.
                has_v1 = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence'"
                ).fetchone()
                if has_v1:
                    connection.execute("INSERT INTO schema_migrations VALUES (1, ?)", (_now(),))
                    applied = {1}
        for version in sorted(MIGRATIONS):
            if version in applied:
                continue
            connection = self._connect()
            try:
                connection.executescript("BEGIN;" + MIGRATIONS[version] + "COMMIT;")
                connection.execute("INSERT INTO schema_migrations VALUES (?, ?)", (version, _now()))
                connection.commit()
            except sqlite3.Error:
                connection.rollback()
                raise
            finally:
                connection.close()
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass

    def schema_version(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

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
    ) -> dict[str, Any]:
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
        with self._connection() as connection:
            if connection.execute("SELECT 1 FROM targets WHERE target_id = ?", (tid,)).fetchone() is None:
                raise NotFound("Unknown target_id; register the file first.")
            connection.execute(
                """INSERT INTO evidence (evidence_id, case_id, target_id, provider_id, tool_name, operation,
                       subject, subject_type, subject_address, subject_name, claim, excerpt, classification,
                       evidence_kind, confidence, status, engine, engine_family, engine_version, raw_sha256,
                       normalized_json, warnings_json, model_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                ),
            )
        return self.get_evidence_record(evidence_id)

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

    def review(self, subject_type: str, subject_id: str, status: str, note: str) -> dict[str, Any]:
        """Record an explicit human/agent review. This is the only path to 'verified'."""
        note = (note or "").strip()
        if not note:
            raise ArgumentError("a review note explaining the basis of the decision is required")
        now = _now()
        if subject_type == "evidence":
            if status not in VALIDATION_STATUSES - {"unverified"}:
                raise ArgumentError(
                    "evidence review status must be verified, rejected, corroborated, contradicted or resolved"
                )
            self.update_status(subject_id, status)
        elif subject_type == "finding":
            if status not in FINDING_STATUSES:
                raise ArgumentError(f"finding status must be one of {sorted(FINDING_STATUSES)}")
            with self._connection() as connection:
                cursor = connection.execute(
                    "UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?", (status, now, subject_id)
                )
                if cursor.rowcount == 0:
                    raise NotFound(f"finding {subject_id!r} not found")
        else:
            raise ArgumentError("subject_type must be 'evidence' or 'finding'")
        review_id = _new_id("rv")
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO reviews (review_id, subject_type, subject_id, status, note, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (review_id, subject_type, subject_id, status, note[:4000], now),
            )
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
    ) -> dict[str, Any]:
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
        with self._connection() as connection:
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
        result = self.get_finding(finding_id)
        if warnings:
            result["warnings"] = warnings
        return result

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            if row is None:
                raise NotFound(f"finding {finding_id!r} not found")
            links = connection.execute(
                "SELECT fe.evidence_id, fe.role, e.evidence_kind, e.provider_id, e.tool_name, e.status, e.subject "
                "FROM finding_evidence fe JOIN evidence e ON e.evidence_id = fe.evidence_id WHERE fe.finding_id = ?",
                (finding_id,),
            ).fetchall()
        return {**dict(row), "evidence": [dict(link) for link in links]}

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
            ids = [
                r[0]
                for r in connection.execute(
                    f"SELECT finding_id FROM findings {where} ORDER BY created_at DESC LIMIT ?", values
                )
            ]
        return [self.get_finding(fid) for fid in ids]

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
            "reviews": reviews,
            "schema_version": self.schema_version(),
        }
