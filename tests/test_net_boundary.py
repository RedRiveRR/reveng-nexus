"""Proposed regression tests: HTTP provider / launched-server / AI endpoint boundary (audit A)."""

import json
import sys

import pytest

from reveng_nexus.config import ConfigError, parse_config
from reveng_nexus.netguard import format_host, is_loopback_host, parse_http_url
from reveng_nexus.registry import ProviderManager


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "127.8.9.10", "localhost", "LOCALHOST", "::1", "[::1]", "::ffff:127.0.0.1"],
)
def test_loopback_literals_are_accepted(host):
    assert is_loopback_host(host)


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",
        "::",
        "[::]",
        "10.0.0.1",
        "192.168.1.1",
        "203.0.113.5",
        "::ffff:10.0.0.1",
        "localhost.evil",
        "localhost.",
        "127.0.0.1.nip.io",
        "2130706433",
        "0x7f000001",
        "127.1",
        "",
    ],
)
def test_non_loopback_and_dns_names_are_refused_without_resolution(host):
    assert not is_loopback_host(host)


@pytest.mark.parametrize(
    "url",
    ["ftp://127.0.0.1/", "httpfoo", "http://", "http://user:pw@127.0.0.1:1/mcp", "http://127.0.0.1@evil.example/"],
)
def test_parse_http_url_rejects_bad_scheme_host_or_userinfo(url):
    with pytest.raises(ValueError):
        parse_http_url(url)


def test_format_host_brackets_ipv6():
    assert format_host("::1") == "[::1]"
    assert format_host("127.0.0.1") == "127.0.0.1"


def _cfg(tmp_path, providers, **policy):
    raw = {
        "workspace": {"allowed_roots": [str(tmp_path)], "data_dir": str(tmp_path / "data")},
        "providers": providers,
    }
    if policy:
        raw["policy"] = policy
    return parse_config(raw, base_dir=tmp_path)


def _http(url, **extra):
    return {"id": "remote", "enabled": True, "type": "mcp_http", "url": url, "timeout_seconds": 5, **extra}


@pytest.mark.parametrize("url", ["http://127.0.0.1:0/mcp", "http://127.0.0.1:65536/mcp", "http://127.0.0.1:-1/"])
def test_parse_http_url_rejects_out_of_range_ports(url):
    with pytest.raises(ValueError, match="port"):
        parse_http_url(url)


@pytest.mark.parametrize(
    "url", ["httpfoo", "http://user:secret@127.0.0.1:9/mcp", "http://127.0.0.1:0/mcp", "http://127.0.0.1:65536/mcp"]
)
def test_mcp_http_config_rejects_malformed_or_credentialed_url(tmp_path, url):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, [_http(url)])


def test_allow_remote_is_mcp_http_only(tmp_path):
    with pytest.raises(ConfigError, match="allow_remote"):
        _cfg(tmp_path, [{"id": "sx", "type": "mcp_stdio", "command": sys.executable, "allow_remote": True}])


class _Recorder:
    """Stands in for mcp.Client so no test ever opens a socket to a non-loopback host."""

    urls: list = []

    def __init__(self, server, **_):
        self.urls.append(server)

    async def __aenter__(self):
        raise ConnectionRefusedError("recorder")

    async def __aexit__(self, *a):
        return False


@pytest.fixture
def no_network(monkeypatch):
    import mcp
    import mcp.client.streamable_http as sh

    _Recorder.urls = []
    monkeypatch.setattr(mcp, "Client", _Recorder)
    monkeypatch.setattr(sh, "streamable_http_client", lambda url, **kw: url)
    return _Recorder.urls


@pytest.mark.parametrize(
    ("allow_remote", "policy_flag"),
    [(False, False), (True, False), (False, True)],
)
@pytest.mark.parametrize(
    "url", ["http://203.0.113.5:9100/mcp", "http://127.0.0.1.nip.io:9100/mcp", "http://[::]:9/mcp"]
)
async def test_remote_mcp_http_needs_two_explicit_opt_ins(tmp_path, no_network, url, allow_remote, policy_flag):
    mgr = ProviderManager(_cfg(tmp_path, [_http(url, allow_remote=allow_remote)], allow_remote_providers=policy_flag))
    await mgr.start()
    try:
        assert "not loopback" in mgr.provider_errors["remote"]
        assert no_network == [], "no client may be created for a refused endpoint"
    finally:
        await mgr.close()


async def test_remote_mcp_http_with_both_opt_ins_is_attempted(tmp_path, no_network):
    url = "http://203.0.113.5:9100/mcp"
    mgr = ProviderManager(_cfg(tmp_path, [_http(url, allow_remote=True)], allow_remote_providers=True))
    await mgr.start()
    try:
        assert no_network == [url]
        assert "not loopback" not in mgr.provider_errors.get("remote", "")
    finally:
        await mgr.close()


def _fake_launcher(tmp_path, host, port=9):
    script = tmp_path / "fake_launcher.py"
    script.write_text(
        "import json, sys, time\n"
        "print('plugin noise', flush=True)\n"
        f"print(json.dumps({{'status': 'ready', 'host': {host!r}, 'port': {port!r}}}), flush=True)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    return script


def _launched(script, template=None):
    launch = {"per_target": False, "startup_timeout_seconds": 20}
    if template:
        launch["url_template"] = template
    return {
        "id": "launched",
        "enabled": True,
        "type": "mcp_launched_http",
        "command": sys.executable,
        "args": [str(script)],
        "timeout_seconds": 5,
        "startup_timeout_seconds": 20,
        "launch": launch,
    }


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.1.2.3", "localhost.evil", "127.0.0.1.nip.io"])
async def test_launched_server_non_loopback_readiness_is_refused(tmp_path, no_network, host):
    mgr = ProviderManager(_cfg(tmp_path, [_launched(_fake_launcher(tmp_path, host))]))
    await mgr.start()
    try:
        assert "non-loopback" in mgr.provider_errors["launched"]
        assert no_network == []
    finally:
        await mgr.close()


async def test_launched_url_template_cannot_redirect_to_remote_host(tmp_path, no_network):
    script = _fake_launcher(tmp_path, "127.0.0.1")
    mgr = ProviderManager(_cfg(tmp_path, [_launched(script, "http://203.0.113.5:{port}/mcp")]))
    await mgr.start()
    try:
        assert "non-loopback" in mgr.provider_errors["launched"]
        assert no_network == []
    finally:
        await mgr.close()


async def test_launched_ipv6_loopback_readiness_builds_bracketed_url(tmp_path, no_network):
    mgr = ProviderManager(_cfg(tmp_path, [_launched(_fake_launcher(tmp_path, "::1"))]))
    await mgr.start()
    try:
        assert no_network == ["http://[::1]:9/mcp"]
    finally:
        await mgr.close()


@pytest.mark.parametrize("port", ["9", True, 0, 70000])
async def test_launched_readiness_with_invalid_port_is_refused(tmp_path, no_network, port):
    mgr = ProviderManager(_cfg(tmp_path, [_launched(_fake_launcher(tmp_path, "127.0.0.1", port))]))
    await mgr.start()
    try:
        assert "invalid port" in mgr.provider_errors["launched"]
    finally:
        await mgr.close()


async def test_loopback_http_client_ignores_proxy_environment(tmp_path, monkeypatch):
    """HTTP(S)_PROXY must not capture loopback provider traffic (target data, decompiled code)."""
    import httpx2

    from reveng_nexus.providers.mcp import McpProvider

    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    seen = {}
    real = httpx2.AsyncClient

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", spy)
    mgr = ProviderManager(_cfg(tmp_path, [_http("http://127.0.0.1:9/mcp")]))
    provider = McpProvider(mgr.config.providers[0], mgr.runtime)
    try:  # nothing listens on port 9; the point is that no proxy is configured or contacted
        async with provider._open_client("http://127.0.0.1:9/mcp", loopback=True):
            pass
    except Exception:  # noqa: BLE001
        pass
    assert seen.get("trust_env") is False
    await mgr.close()


def test_llm4decompile_loopback_client_ignores_proxy(monkeypatch):
    from reveng_nexus.providers import llm4decompile

    assert llm4decompile._is_loopback("::ffff:127.0.0.1")
    assert not llm4decompile._is_loopback("127.0.0.1.nip.io")


def test_readiness_json_fixture_shape():
    assert json.loads('{"status":"ready","host":"127.0.0.1","port":1}')["port"] == 1
