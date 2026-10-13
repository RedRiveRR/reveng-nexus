"""Static deployment diagnostics for ``--check-config`` (nothing is started or executed)."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import NexusConfig, expand_env

# Provider env values that name an installation directory which must exist.
_DIR_ENV = ("GHIDRA_INSTALL_DIR", "IDADIR", "JADX_MCP_HOME", "JAVA_HOME")


@dataclass(frozen=True, slots=True)
class Finding:
    level: str  # "error" (Nexus cannot work as configured) | "warning" (one provider/feature affected)
    subject: str
    message: str
    remediation: str = ""

    def render(self) -> str:
        text = f"{self.level}: [{self.subject}] {self.message}"
        return text + (f"\n    fix: {self.remediation}" if self.remediation else "")


def _writable_dir(path: Path) -> bool:
    """True if ``path`` (or, when it does not exist yet, its nearest existing ancestor) is writable.

    Never creates directories: a diagnostic must not change the machine it inspects.
    """
    probe = path
    while not probe.exists():
        if probe.parent == probe:
            return False
        probe = probe.parent
    if not probe.is_dir():
        return False
    try:
        with tempfile.NamedTemporaryFile(dir=probe, prefix=".nexus-write-test-", delete=True):
            pass
        return True
    except OSError:
        return False


def diagnose(config: NexusConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.allowed_roots:
        findings.append(
            Finding(
                "warning",
                "workspace",
                "no allowed_roots: target intake is disabled",
                "add your samples folder under workspace.allowed_roots",
            )
        )
    for root in config.allowed_roots:
        if not Path(root).is_dir():
            findings.append(
                Finding(
                    "error",
                    "workspace",
                    f"allowed root does not exist: {root}",
                    "create it, or rerun `reveng-nexus config init --create-dirs`",
                )
            )
    data_dir = Path(config.data_dir)
    if not _writable_dir(data_dir):
        findings.append(
            Finding(
                "error",
                "data_dir",
                f"data directory is not writable: {data_dir}",
                "choose a writable workspace.data_dir",
            )
        )
    elif "onedrive" in str(data_dir).lower() or "dropbox" in str(data_dir).lower():
        findings.append(
            Finding(
                "warning",
                "data_dir",
                f"data directory is inside a synced folder: {data_dir}",
                "sync clients can corrupt SQLite WAL files; prefer %LOCALAPPDATA%\\RevEngNexus\\data",
            )
        )

    for provider in config.providers:
        if not provider.enabled or provider.type == "builtin":
            continue
        subject = provider.id
        if provider.kind == "dynamic" and not config.policy.dynamic.enabled:
            findings.append(
                Finding("warning", subject, "enabled but dynamic analysis policy is off; it will not start")
            )
            continue
        if provider.command:
            command, missing = expand_env(provider.command)
            if missing:
                findings.append(
                    Finding(
                        "warning",
                        subject,
                        f"command references unset variables {missing}",
                        "set them or edit 'command'",
                    )
                )
            elif shutil.which(command) is None and not Path(command).is_file():
                findings.append(
                    Finding(
                        "warning",
                        subject,
                        f"executable not found: {command}",
                        "install the upstream tool or use an absolute path",
                    )
                )
        for key, raw in provider.env.items():
            value, missing = expand_env(raw)
            if missing:
                findings.append(
                    Finding(
                        "warning",
                        subject,
                        f"env {key} references unset variables {missing}",
                        f"set {', '.join(missing)} or write the path into providers.yaml",
                    )
                )
            elif key in _DIR_ENV and value and not Path(value).is_dir():
                findings.append(
                    Finding(
                        "warning",
                        subject,
                        f"env {key} points to a missing directory: {value}",
                        "fix the installation path",
                    )
                )
        if provider.type == "llm4decompile" and provider.model.api_key_env:
            if not os.environ.get(provider.model.api_key_env):
                findings.append(Finding("warning", subject, f"model.api_key_env {provider.model.api_key_env} is unset"))
    return findings
