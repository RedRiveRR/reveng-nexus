"""Compatibility shim: the 0.1 ``ProviderManager`` now lives in :mod:`reveng_nexus.registry`."""

from __future__ import annotations

from .registry import ProviderManager

__all__ = ["ProviderManager"]
