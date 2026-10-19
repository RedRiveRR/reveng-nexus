"""Structured, bounded error types shared by the gateway, CLI and providers."""

from __future__ import annotations

from typing import Any

from .redaction import redact_text

_MAX_MESSAGE = 2000


class NexusError(Exception):
    """Base error with a stable machine-readable code and optional remediation."""

    code = "nexus_error"

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        remediation: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.remediation = remediation

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": self.code,
            "message": redact_text(self.message)[:_MAX_MESSAGE],
        }
        if self.details:
            payload["details"] = self.details
        if self.remediation:
            payload["remediation"] = self.remediation
        return payload


class ConfigError(NexusError, ValueError):
    code = "config_error"


class ArgumentError(NexusError, ValueError):
    code = "invalid_arguments"


class PolicyViolation(NexusError, PermissionError):
    code = "policy_violation"


class WorkspaceViolation(PolicyViolation):
    code = "workspace_violation"


class ProviderUnavailable(NexusError, RuntimeError):
    code = "provider_unavailable"


class ProviderCallError(NexusError, RuntimeError):
    code = "provider_error"


class ProviderTimeout(ProviderCallError):
    code = "provider_timeout"


class CapabilityUnavailable(NexusError, LookupError):
    """No enabled, healthy provider implements the requested operation."""

    code = "capability_unavailable"


class NotFound(NexusError, LookupError):
    code = "not_found"


class RevisionConflict(NexusError, ValueError):
    """A write named a revision that is no longer current (another writer got there first)."""

    code = "revision_conflict"


def describe_exception(exc: BaseException) -> dict[str, Any]:
    """Return a bounded, redacted diagnostic for any exception."""
    if isinstance(exc, NexusError):
        return exc.to_dict()
    return {
        "error": "internal_error"
        if not isinstance(exc, (ValueError, PermissionError))
        else ("invalid_arguments" if isinstance(exc, ValueError) else "policy_violation"),
        "message": redact_text(f"{type(exc).__name__}: {exc}")[:_MAX_MESSAGE],
    }
