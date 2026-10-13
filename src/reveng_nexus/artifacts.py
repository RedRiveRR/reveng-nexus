"""Artifact intake: workspace enforcement, hashing, identification and staging.

Targets are only ever read as bytes. Providers receive a per-provider *staged copy*
inside the Nexus data directory so engine databases (``.gpr``/``.i64`` …) never land
next to the operator's original sample and two engines never share one database.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ArgumentError, WorkspaceViolation
from .formats import inspect_file, sniff_format

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def is_sha256(value: str) -> bool:
    return bool(_SHA256.fullmatch(value or ""))


def _norm(path: Path) -> str:
    return os.path.normcase(str(path))


def _is_link_or_junction(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(os.path, "isjunction", None)
        return bool(is_junction and is_junction(path))
    except OSError:
        return True


class WorkspaceGuard:
    """Restricts which files Nexus will read, independently of the caller's cwd."""

    def __init__(self, allowed_roots: tuple[str, ...], max_bytes: int, follow_symlinks: bool = False):
        self.roots = tuple(Path(r).expanduser().resolve() for r in allowed_roots)
        self.max_bytes = max_bytes
        self.follow_symlinks = follow_symlinks

    @property
    def enabled(self) -> bool:
        return bool(self.roots)

    def check(self, raw_path: str) -> Path:
        if not self.roots:
            raise WorkspaceViolation(
                "Target intake is disabled until workspace.allowed_roots is configured.",
                remediation="Add the folder holding your authorised samples to workspace.allowed_roots.",
            )
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ArgumentError("path must be a non-empty string")
        if "\x00" in raw_path:
            raise ArgumentError("path contains a NUL byte")
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            raise ArgumentError("path must be absolute (relative paths depend on the server's cwd)")
        # Reject NTFS alternate data streams such as C:\x\file.exe:payload
        if os.name == "nt" and ":" in candidate.as_posix()[2:]:
            raise WorkspaceViolation("alternate data stream paths are not accepted")
        if any(part == ".." for part in candidate.parts):
            raise WorkspaceViolation("'..' path segments are not accepted")
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ArgumentError(f"path does not resolve to an existing file: {exc}") from exc

        root = next(
            (r for r in self.roots if _norm(resolved) == _norm(r) or _norm(resolved).startswith(_norm(r) + os.sep)),
            None,
        )
        if root is None:
            raise WorkspaceViolation("target is outside configured allowed_roots")
        if not self.follow_symlinks:
            # Walk the *unresolved* path below the root: any link/junction component is refused,
            # so a link inside the workspace cannot redirect reads elsewhere.
            probe = candidate
            while True:
                if _is_link_or_junction(probe):
                    raise WorkspaceViolation(
                        "symbolic links/junctions are not followed (workspace.follow_symlinks: false)"
                    )
                if _norm(probe.resolve()) == _norm(root) or probe.parent == probe:
                    break
                probe = probe.parent
        st = resolved.stat()
        if not stat.S_ISREG(st.st_mode):
            raise ArgumentError("target must be a regular file")
        if st.st_size > self.max_bytes:
            raise ArgumentError(f"target is {st.st_size} bytes; configured limit is {self.max_bytes} bytes")
        return resolved


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    sha256: str
    md5: str
    size_bytes: int
    original_path: str
    display_name: str
    format: str
    metadata: dict[str, Any]

    @property
    def kind(self) -> str:
        if self.format in {"apk"}:
            return "android_apk"
        if self.format == "dex":
            return "android_dex"
        if self.format in {"elf", "pe", "macho", "macho_universal"}:
            return "native_binary"
        return "unknown"

    def summary(self) -> dict[str, Any]:
        meta = self.metadata
        return {
            "sha256": self.sha256,
            "md5": self.md5,
            "size_bytes": self.size_bytes,
            "display_name": self.display_name,
            "format": self.format,
            "kind": self.kind,
            "format_detail": meta.get("format_detail"),
            "arch": meta.get("arch"),
            "bits": meta.get("bits"),
            "endianness": meta.get("endianness"),
            "entry_point": meta.get("entry_point"),
            "image_base": meta.get("image_base"),
            "is_pie": meta.get("is_pie"),
            "stripped": meta.get("stripped"),
        }


def hash_file(path: Path) -> tuple[str, str]:
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def identify(path: Path) -> ArtifactIdentity:
    """Hash and parse a workspace-checked file. Never executes or maps it."""
    sha256, md5 = hash_file(path)
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ArgumentError("file changed while it was being read; retry once it is stable")
    try:
        metadata = inspect_file(path, data)
    except Exception as exc:  # parsers face hostile input; report instead of crashing
        metadata = {"format": sniff_format(data[:8]), "error": f"parser failed: {type(exc).__name__}: {exc}"}
    return ArtifactIdentity(
        sha256=sha256,
        md5=md5,
        size_bytes=len(data),
        original_path=str(path),
        display_name=path.name,
        format=str(metadata.get("format", "unknown")),
        metadata=metadata,
    )


def stage_copy(work_dir: Path, sha256: str, provider_id: str, source: Path, display_name: str) -> Path:
    """Copy the target into ``work_dir/<sha16>/<provider>/`` and verify the copy's hash."""
    if not is_sha256(sha256):
        raise ArgumentError("invalid sha256")
    safe_provider = _SAFE_NAME.sub("_", provider_id)
    safe_name = _SAFE_NAME.sub("_", display_name)[:120] or "target.bin"
    dest_dir = work_dir / sha256[:16] / safe_provider
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name
    if dest.exists():
        if hash_file(dest)[0] == sha256:
            return dest
        dest.chmod(stat.S_IWRITE | stat.S_IREAD)
        dest.unlink()
    shutil.copyfile(source, dest)
    if hash_file(dest)[0] != sha256:
        dest.unlink(missing_ok=True)
        raise ArgumentError("staged copy hash mismatch; the original changed after intake")
    # The copy itself is read-only; engines still write their databases next to it.
    dest.chmod(stat.S_IREAD)
    return dest
