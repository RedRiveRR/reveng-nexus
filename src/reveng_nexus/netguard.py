"""Loopback checks for HTTP endpoints Nexus connects to (providers, AI endpoints).

The check is literal: ``localhost`` or an IP literal that is loopback. Host names are never
resolved, so ``localhost.evil``, ``127.0.0.1.nip.io`` or a hosts-file alias count as remote.
URLs are parsed with ``httpx2.URL``, the parser the HTTP client itself uses, so the checked
host is the host that is connected to.
"""

from __future__ import annotations

import ipaddress

import httpx2

LOOPBACK_NAMES = frozenset({"localhost"})


def is_loopback_host(host: str) -> bool:
    """True only for ``localhost`` or a loopback IP literal (127.0.0.0/8, ::1, ::ffff:127.x)."""
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False  # a name (never resolved) or a non-canonical form such as 2130706433
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def parse_http_url(url: str) -> httpx2.URL:
    """Parse an http(s) URL; refuse other schemes, empty hosts and embedded credentials."""
    try:
        parsed = httpx2.URL(url)
    except Exception as exc:  # noqa: BLE001 - httpx2 raises InvalidURL and friends
        raise ValueError(f"not a valid URL: {type(exc).__name__}") from None
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if not parsed.host:
        raise ValueError("URL has no host")
    if parsed.userinfo:
        raise ValueError("URL must not embed credentials (user:password@host)")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("URL port must be between 1 and 65535")
    return parsed


def url_is_loopback(url: str) -> bool:
    return is_loopback_host(parse_http_url(url).host)


def format_host(host: str) -> str:
    """Bracket an IPv6 literal for use in a URL authority."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host
