"""Dashboard, snapshot and tool-count semantics.

The dashboard server is exercised as a real uvicorn server on an ephemeral loopback port
(http.client, so forged Host/Origin headers can be sent). Providers are local mock MCP
servers; nothing touches a real engine, the permanent config or a real evidence database.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import re
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml
from conftest import mock_engine
from test_rea_mocked import rea_mock

from reveng_nexus import cli
from reveng_nexus.dashboard.app import build_server, create_app
from reveng_nexus.dashboard.data import DashboardData
from reveng_nexus.errors import NotFound, PolicyViolation
from reveng_nexus.registry import ProviderManager
from reveng_nexus.server import TOOL_SPECS, NexusServer
from reveng_nexus.snapshot import NEXUS_TOOL_OPERATIONS, SnapshotWriter, build_snapshot, sanitize
from reveng_nexus.verification import DOCUMENTED, STATES

ROOT = Path(__file__).resolve().parents[1]


async def started(config):
    mgr = ProviderManager(config)
    await mgr.start()
    return mgr


def provider(snapshot, pid):
    return next(p for p in snapshot["providers"] if p["id"] == pid)


# -- count semantics -------------------------------------------------------------------
async def test_snapshot_counts_are_distinct_and_match_the_gateway_decisions(config_factory, workspace):
    mgr = await started(config_factory(workspace, [mock_engine("eng")]))
    try:
        live = mgr.providers["eng"]
        snap = build_snapshot(mgr)
        entry = provider(snap, "eng")
        tools = list(live._tools.values())
        assert entry["counts"]["upstream_tools_discovered"] == len(tools)
        assert entry["counts"]["policy_allowed_tools"] == sum(t.decision.allowed for t in tools)
        assert entry["counts"]["callable_tools"] == sum(t.callable for t in tools)
        assert entry["counts"]["blocked_tools"] == sum(not t.decision.allowed for t in tools)
        # compact mode (default): raw tools are not listed to clients as their own tools
        assert entry["counts"]["exposed_tools"] == 0
        assert 0 < entry["counts"]["callable_tools"] < entry["counts"]["upstream_tools_discovered"]
        rows = {t["name"]: t for t in entry["tools"]}
        assert rows["patch_bytes"]["policy_allowed"] is False and rows["patch_bytes"]["tool_class"] == "mutate"
        assert rows["open_database"]["tool_class"] == "lifecycle" and rows["open_database"]["callable"] is False
        assert "binary.decompile" in rows["decompile_function"]["used_by_operations"]
        described = live.describe()
        assert described["tool_count"] == entry["counts"]["upstream_tools_discovered"]
        assert described["policy_allowed_tool_count"] == entry["counts"]["policy_allowed_tools"]
        assert described["callable_tool_count"] == entry["counts"]["callable_tools"]
        assert described["adapter_only"] is False
    finally:
        await mgr.close()


async def test_namespaced_mode_exposes_exactly_the_callable_tools(config_factory, workspace):
    mgr = await started(config_factory(workspace, [mock_engine("eng")], server={"tool_mode": "namespaced"}))
    try:
        app = NexusServer(mgr)
        listed = {t.name for t in (await app.list_tools()).tools} - set(TOOL_SPECS)
        entry = provider(build_snapshot(mgr), "eng")
        exposed = {t["public_name"] for t in entry["tools"] if t["exposed_to_clients"]}
        assert exposed == listed and entry["counts"]["exposed_tools"] == entry["counts"]["callable_tools"]
    finally:
        await mgr.close()


async def test_rea_is_allowed_for_its_adapter_but_never_callable_or_exposed(config_factory, workspace):
    mgr = await started(config_factory(workspace, [rea_mock()], server={"tool_mode": "namespaced"}))
    try:
        entry = provider(build_snapshot(mgr), "rea")
        allowed = sorted(t["name"] for t in entry["tools"] if t["policy_allowed"])
        assert allowed == ["analyze_javascript_application", "inspect_electron_fuses"]
        assert entry["counts"]["callable_tools"] == 0 and entry["counts"]["exposed_tools"] == 0
        assert entry["adapter_only"] is True
        ops = {t["name"]: t["used_by_operations"] for t in entry["tools"] if t["policy_allowed"]}
        assert ops == {
            "analyze_javascript_application": ["js.application"],
            "inspect_electron_fuses": ["electron.fuses"],
        }
        assert sorted(entry["usable_operations"]) == ["electron.fuses", "js.application"]
        described = mgr.providers["rea"].describe()
        assert (described["policy_allowed_tool_count"], described["callable_tool_count"]) == (2, 0)
        reasons = {t["name"]: t["policy_reason"] for t in entry["tools"] if t["policy_allowed"]}
        assert all("adapter-only" in r for r in reasons.values())
    finally:
        await mgr.close()


async def test_aliases_and_adapter_only_tools_cannot_bypass_policy(config_factory, workspace):
    mgr = await started(config_factory(workspace, [mock_engine("eng"), rea_mock()], server={"tool_mode": "namespaced"}))
    try:
        app = NexusServer(mgr)
        with pytest.raises(PolicyViolation):  # mutate tool through its namespaced alias
            await app.dispatch("eng__patch_bytes", {"address": "0x401000", "data": "90"})
        with pytest.raises(PolicyViolation):  # lifecycle tool through its alias
            await app.dispatch("eng__open_database", {"file_path": "C:/x"})
        with pytest.raises(PolicyViolation):  # an allowed REA tool is still adapter-only for callers
            await app.dispatch("rea__inspect_electron_fuses", {"path": "C:/x"})
        with pytest.raises(PolicyViolation):
            await app.dispatch(
                "nexus_call_provider_tool",
                {"provider_id": "rea", "tool_name": "analyze_javascript_application", "arguments": {}},
            )
        with pytest.raises(NotFound):  # discovery metadata cannot invent a tool
            await app.dispatch("eng__not_in_the_catalogue", {})
    finally:
        await mgr.close()


async def test_cancelled_provider_start_is_audited_as_cancelled_not_failed(config_factory, workspace):
    config = config_factory(workspace, [mock_engine("slow", env={"MOCK_STARTUP_DELAY": "30"})])
    mgr = ProviderManager(config)
    task = asyncio.create_task(mgr.start())
    await asyncio.sleep(1.5)
    task.cancel()
    with contextlib.suppress(BaseException):
        await task
    await mgr.close()
    rows = [json.loads(line) for line in Path(config.audit_log).read_text(encoding="utf-8").splitlines()]
    slow = [r for r in rows if r.get("provider_id") == "slow" and r["event"] == "provider_started"]
    assert slow and slow[-1]["outcome"] == "cancelled", slow


def test_providers_check_prints_explicit_counts(tmp_path, workspace, capsys):
    config = tmp_path / "providers.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
                "providers": [mock_engine("eng")],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--config", str(config), "providers", "check", "eng"])
    assert exit_info.value.code == 0
    report = json.loads(capsys.readouterr().out)["eng"]
    names = [n for n in report["tools_callable"] if not n.startswith("...")]
    assert report["tools_callable_count"] == len(names)  # under 40: the list is complete
    assert report["tools_policy_allowed_count"] >= report["tools_callable_count"]
    assert report["tools_total"] > report["tools_callable_count"]


# -- static mappings stay in sync -------------------------------------------------------
def test_every_nexus_tool_has_an_operation_mapping():
    assert set(NEXUS_TOOL_OPERATIONS) == set(TOOL_SPECS)


def test_documented_verification_matches_the_provider_matrix():
    matrix = (ROOT / "docs" / "PROVIDER_MATRIX.md").read_text(encoding="utf-8")
    for pid, entry in DOCUMENTED.items():
        assert entry["state"] in STATES
        row = next((line for line in matrix.splitlines() if line.startswith(f"| `{pid}` |")), None)
        assert row is not None, pid
        assert f"`{entry['state']}`" in row.split("|")[6], (pid, entry["state"])


# -- sanitisation and writer isolation ---------------------------------------------------
def test_sanitize_redacts_secrets_and_shortens_home(monkeypatch):
    home = str(Path.home())
    data = {
        "config_path": f"{home}\\AppData\\Local\\RevEngNexus\\config\\providers.yaml",
        "error": "upstream said token=abcdef123456 and Bearer abcdefghijklmnop",
        "api_key": "sk-should-not-appear",
        "nested": [{"password": "hunter2", "url": "https://user:pw@example.invalid/x"}],
        "dynamic_allowed_device_count": 3,
        "input_schema": {"properties": {"token": {"type": "string"}}},
    }
    out = sanitize(data)
    text = json.dumps(out)
    assert home.lower() not in text.lower() and out["config_path"].startswith("~")
    for secret in ("abcdef123456", "abcdefghijklmnop", "sk-should-not-appear", "hunter2", "user:pw"):
        assert secret not in text
    assert out["dynamic_allowed_device_count"] == 3
    assert out["input_schema"]["properties"]["token"] == {"type": "string"}  # schemas stay readable


async def test_snapshot_never_contains_provider_commands_or_environment(config_factory, workspace):
    engine = mock_engine("eng", env={"MOCK_FLAVOR": "a", "SECRET_SAUCE": "do-not-leak-me"})
    mgr = await started(config_factory(workspace, [engine]))
    try:
        text = json.dumps(build_snapshot(mgr))
        assert "do-not-leak-me" not in text and "SECRET_SAUCE" not in text
        assert "mock_engine.py" not in text and "log_file" not in text
    finally:
        await mgr.close()


async def test_disabled_provider_is_reported_without_live_data(config_factory, workspace):
    mgr = await started(config_factory(workspace, [mock_engine("eng", enabled=False)]))
    try:
        entry = provider(build_snapshot(mgr), "eng")
        assert entry["started"] is False and entry["tools"] == []
        assert entry["counts"]["callable_tools"] == 0 and entry["skipped"]
        assert entry["verification"]["state"] == "unrecorded"
    finally:
        await mgr.close()


async def test_snapshot_writer_failure_is_counted_not_raised(config_factory, workspace, monkeypatch, capsys):
    mgr = await started(config_factory(workspace, []))
    try:
        writer = SnapshotWriter(mgr)
        monkeypatch.setattr("reveng_nexus.snapshot.build_snapshot", lambda *a, **k: 1 / 0)
        assert writer.write() is False and writer.failures == 1
        assert capsys.readouterr().out == ""  # never on stdout (the MCP stdio channel)
    finally:
        await mgr.close()


def test_stdio_gateway_still_works_and_writes_a_snapshot(tmp_path, workspace):
    import anyio
    from mcp import Client, StdioServerParameters

    config = tmp_path / "providers.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
                "providers": [mock_engine("eng")],
            }
        ),
        encoding="utf-8",
    )
    snaps = tmp_path / "data" / "dashboard"

    async def run():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "reveng_nexus", "--config", str(config), "serve"]
        )
        async with Client(params, read_timeout_seconds=60) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert {"nexus_status", "nexus_list_providers"} <= names
            status = json.loads((await client.call_tool("nexus_status", {})).content[0].text)
            assert status["providers"]["eng"]["status"] == "ready"
            deadline = time.monotonic() + 30
            while not list(snaps.glob("gateway-*.json")) and time.monotonic() < deadline:
                await anyio.sleep(0.5)
            files = list(snaps.glob("gateway-*.json"))
            assert files, "the gateway wrote no snapshot"
            data = json.loads(files[0].read_text(encoding="utf-8"))
            assert provider(data, "eng")["counts"]["callable_tools"] > 0

    anyio.run(run)
    data = json.loads(next(snaps.glob("gateway-*.json")).read_text(encoding="utf-8"))
    assert data["gateway"].get("stopped_at"), "a clean shutdown marks the snapshot stopped"


# -- dashboard HTTP server ----------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def dashboard(config):
    port = _free_port()
    server = build_server(config, "127.0.0.1", port)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(10)


def request(port, method="GET", path="/", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, headers={"Host": f"127.0.0.1:{port}", **(headers or {})})
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


async def test_dashboard_serves_real_state_with_security_headers(config_factory, workspace):
    config = config_factory(workspace, [mock_engine("eng"), rea_mock(), mock_engine("off", enabled=False)])
    mgr = await started(config)
    try:
        assert SnapshotWriter(mgr).write()
        expected = build_snapshot(mgr)["totals"]
    finally:
        await mgr.close()
    with dashboard(config) as port:
        status, headers, body = await asyncio.to_thread(request, port, "GET", "/")
        assert status == 200 and b"/static/app.js" in body
        assert "script-src 'self'" in headers["content-security-policy"]
        assert headers["x-frame-options"] == "DENY" and headers["x-content-type-options"] == "nosniff"
        assert "access-control-allow-origin" not in headers and "server" not in headers
        status, headers, body = await asyncio.to_thread(request, port, "GET", "/api/state")
        assert status == 200 and headers["cache-control"] == "no-store"
        state = json.loads(body)
        assert state["primary"]["freshness"] == "live"
        assert state["primary"]["totals"] == expected
        assert {p["id"] for p in state["configured"]["providers"]} >= {"eng", "rea", "off"}
        assert provider(state["primary"], "rea")["counts"]["callable_tools"] == 0
        assert state["architecture"]["nodes"] and state["definitions"]["callable_tools"]
        for name in ("app.js", "app.css", "favicon.svg"):
            assert (await asyncio.to_thread(request, port, "GET", f"/static/{name}"))[0] == 200


async def test_dashboard_without_snapshot_or_audit_reports_unavailable(config_factory, workspace):
    config = config_factory(workspace, [mock_engine("eng")])
    with dashboard(config) as port:
        state = json.loads((await asyncio.to_thread(request, port, "GET", "/api/state"))[2])
        assert state["primary"] is None and state["instances"] == []
        activity = json.loads((await asyncio.to_thread(request, port, "GET", "/api/activity"))[2])
        assert activity["audit"]["available"] is False and activity["recent"] == []
        assert activity["evidence"]["available"] is False


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def test_dashboard_refuses_every_mutating_method(config_factory, workspace, method):
    with dashboard(config_factory(workspace, [])) as port:
        for path in ("/", "/api/state", "/api/activity", "/api/call"):
            status, headers, _ = await asyncio.to_thread(request, port, method, path)
            assert status == 405 and headers["allow"] == "GET, HEAD", (method, path)


async def test_dashboard_rejects_foreign_hosts_and_origins(config_factory, workspace):
    with dashboard(config_factory(workspace, [])) as port:
        assert (await asyncio.to_thread(request, port, "GET", "/api/state", {"Host": "evil.example"}))[0] == 421
        assert (await asyncio.to_thread(request, port, "GET", "/", {"Host": f"127.0.0.1:{port + 1}"}))[0] == 421
        assert (await asyncio.to_thread(request, port, "GET", "/api/state", {"Origin": "http://evil.example"}))[
            0
        ] == 403
        assert (await asyncio.to_thread(request, port, "GET", "/api/state", {"Sec-Fetch-Site": "cross-site"}))[0] == 403
        ok = await asyncio.to_thread(request, port, "GET", "/api/state", {"Origin": f"http://127.0.0.1:{port}"})
        assert ok[0] == 200 and "access-control-allow-origin" not in ok[1]
        local = await asyncio.to_thread(request, port, "GET", "/api/health", {"Host": f"localhost:{port}"})
        assert local[0] == 200


async def test_dashboard_has_no_file_or_tool_access_routes(config_factory, workspace):
    with dashboard(config_factory(workspace, [])) as port:
        for path in (
            "/static/../config/providers.yaml",
            "/static/..%2f..%2fpyproject.toml",
            "/static/providers.yaml",
            "/static/index.html.bak",
            "/api/call_tool",
            "/api/providers/eng/tools/patch_bytes",
            "/data/evidence.sqlite3",
        ):
            assert (await asyncio.to_thread(request, port, "GET", path))[0] == 404, path


def test_dashboard_route_surface_is_fixed_and_read_only(config_factory, workspace):
    app = create_app(config_factory(workspace, []), 8770)
    routes = app.app.routes
    assert sorted(r.path for r in routes) == ["/", "/api/activity", "/api/health", "/api/state", "/static/{name}"]
    for route in routes:
        assert route.methods <= {"GET", "HEAD"}, route.path


def test_dashboard_refuses_non_loopback_binds(config_factory, workspace, capsys):
    with pytest.raises(ValueError):
        build_server(config_factory(workspace, []), "0.0.0.0", 8770)
    assert cli.main.__module__ == "reveng_nexus.cli"
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["dashboard", "--host", "0.0.0.0"])
    assert exit_info.value.code == 2 and "loopback only" in capsys.readouterr().err


async def test_activity_is_sanitised_and_aggregated(config_factory, workspace):
    config = config_factory(workspace, [])
    log = Path(config.audit_log)
    log.parent.mkdir(parents=True, exist_ok=True)
    home = str(Path.home())
    rows = [
        {"timestamp": 1, "event": "provider_started", "provider_id": "eng", "outcome": "ok"},
        {"timestamp": 2, "event": "provider_started", "provider_id": "eng", "outcome": "cancelled"},
        {
            "timestamp": 3,
            "event": "tool_call_blocked",
            "provider_id": "eng",
            "tool_name": "patch_bytes",
            "outcome": "blocked",
            "policy_reason": "read-only policy blocks tools that modify analysis state",
            "target_sha256": "a" * 64,
        },
        {
            "timestamp": 4,
            "event": "tool_call",
            "provider_id": "eng",
            "outcome": "exception",
            "duration_ms": 9,
            "error": f"failed in {home}\\secret dir with password=letmein",
        },
    ]
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n", encoding="utf-8")
    act = DashboardData(config).activity()
    text = json.dumps(act)
    assert "letmein" not in text and home.lower() not in text.lower() and "a" * 64 not in text
    assert act["audit"]["records_read"] == 4
    assert [d["tool_name"] for d in act["policy_denials"]] == ["patch_bytes"]
    assert {(c["event"], c["outcome"]) for c in act["event_counts"]} >= {("provider_started", "cancelled")}
    assert act["calls_by_provider"]["eng"] == {"calls": 1, "errors": 1, "total_ms": 9}


def test_frontend_never_writes_html_from_data():
    """Upstream descriptions are untrusted: the client must build DOM nodes, not HTML strings."""
    js = (ROOT / "src" / "reveng_nexus" / "dashboard" / "static" / "app.js").read_text(encoding="utf-8")
    assert not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write\(|eval\(|new Function", js)
    assert not re.search(r"fetch\([^)]*method\s*:", js), "the client must only send GET requests"
    html = (ROOT / "src" / "reveng_nexus" / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    assert "<script>" not in html and "http://" not in html and "https://" not in html


# -- snapshot retention and atomicity ----------------------------------------------------
def _age(path: Path, seconds: float) -> None:
    import os

    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


def test_prune_is_bounded_owner_scoped_and_spares_active_files(tmp_path):
    from reveng_nexus import snapshot as snap

    d = tmp_path / "dashboard"
    d.mkdir()
    old = []
    for i in range(25):  # inactive snapshots, 1-25 hours old
        f = d / f"gateway-{1000 + i}.json"
        f.write_text("{}", encoding="utf-8")
        _age(f, 3600 * (i + 1))
        old.append(f)
    ancient = d / "gateway-99.json"
    ancient.write_text("{}", encoding="utf-8")
    _age(ancient, 8 * 86400)
    active = d / "gateway-5.json"  # touched recently: may be a running gateway
    active.write_text("{}", encoding="utf-8")
    own = d / "gateway-6.json"
    own.write_text("{}", encoding="utf-8")
    _age(own, 30 * 86400)
    torn = d / "gateway-7.json.tmp"  # an interrupted write
    torn.write_text("{partial", encoding="utf-8")
    _age(torn, 3600)
    fresh_tmp = d / "gateway-8.json.tmp"  # a write in progress
    fresh_tmp.write_text("{partial", encoding="utf-8")
    unrelated = [d / "notes.txt", d / "gateway-abc.json", d / "evidence.sqlite3", d / "gateway-1.json.bak"]
    for f in unrelated:
        f.write_text("keep", encoding="utf-8")
        _age(f, 30 * 86400)

    removed = set(snap.prune_snapshots(d, keep_path=own))

    survivors = {p.name for p in d.iterdir()}
    kept_inactive = [f for f in old if f.exists()]
    assert kept_inactive == old[: snap.KEEP_INACTIVE]  # the newest ones, exactly KEEP_INACTIVE
    assert not ancient.exists() and not torn.exists()
    assert {active.name, own.name, fresh_tmp.name} <= survivors
    assert all(f.exists() for f in unrelated)
    assert removed == {f.name for f in old[snap.KEEP_INACTIVE :]} | {ancient.name, torn.name}
    assert snap.prune_snapshots(d, keep_path=own) == []  # idempotent


async def test_snapshot_is_replaced_atomically_and_unchanged_heartbeats_only_touch(config_factory, workspace):
    mgr = await started(config_factory(workspace, [mock_engine("eng")]))
    try:
        writer = SnapshotWriter(mgr)
        assert writer.write() and writer.full_writes == 1
        first = writer.path.read_bytes()
        _age(writer.path, 60)
        before = writer.path.stat().st_mtime
        assert writer.write() and writer.full_writes == 1 and writer.touches == 1
        assert writer.path.read_bytes() == first  # not rewritten
        assert writer.path.stat().st_mtime > before  # but the heartbeat is visible
        assert not list(writer.path.parent.glob("*.tmp"))
        assert [p.name for p in writer.path.parent.iterdir()] == [writer.path.name]  # no per-heartbeat history
        assert writer.write(stopped=True) and writer.full_writes == 2
        assert json.loads(writer.path.read_text(encoding="utf-8"))["gateway"]["stopped_at"]
    finally:
        await mgr.close()


async def test_freshness_uses_heartbeat_mtime_and_marks_stale_and_stopped(config_factory, workspace):
    config = config_factory(workspace, [])
    mgr = await started(config)
    try:
        writer = SnapshotWriter(mgr)
        writer.write()
    finally:
        await mgr.close()
    data = json.loads(writer.path.read_text(encoding="utf-8"))
    data["written_at"] = time.time() - 3600  # old content, but a fresh heartbeat (mtime)
    writer.path.write_text(json.dumps(data), encoding="utf-8")
    assert DashboardData(config).snapshots()[0]["freshness"] == "live"
    _age(writer.path, 3600)
    assert DashboardData(config).snapshots()[0]["freshness"] == "stale"
    data["gateway"]["stopped_at"] = time.time()
    writer.path.write_text(json.dumps(data), encoding="utf-8")
    assert DashboardData(config).snapshots()[0]["freshness"] == "stopped"
    (writer.path.parent / "gateway-42.json").write_text("{torn", encoding="utf-8")
    (writer.path.parent / "gateway-43.json.tmp").write_text("{torn", encoding="utf-8")
    dash = DashboardData(config)
    assert len(dash.snapshots()) == 1 and dash.unreadable_snapshots == 1  # a .tmp is never read


async def test_concurrent_reader_never_sees_a_partial_snapshot(config_factory, workspace):
    config = config_factory(workspace, [mock_engine("eng")])
    mgr = await started(config)
    try:
        writer = SnapshotWriter(mgr)
        writer.write()
        stop = threading.Event()
        problems: list[str] = []
        partial: list[str] = []

        def read_loop():
            dash = DashboardData(config)
            while not stop.is_set():
                time.sleep(0.002)  # a dashboard polling far faster than its real 15 s
                snaps = dash.snapshots()
                if dash.unreadable_snapshots or len(snaps) != 1:
                    problems.append(f"unreadable={dash.unreadable_snapshots} count={len(snaps)}")
                # retried sharing violations are expected on Windows; partial JSON never is
                partial.extend(e for e in dash.read_errors if e in {"JSONDecodeError", "UnicodeDecodeError"})

        reader = threading.Thread(target=read_loop)
        reader.start()
        try:
            for i in range(40):
                writer._digest = f"forced {i}"  # treat as new content: a full rewrite each time
                assert writer.write(), writer.failures
        finally:
            stop.set()
            reader.join(10)
        assert problems == [] and partial == []
        # a replace that loses every retry to the reader is counted, never raised, and the next
        # heartbeat writes again; the file a reader sees is always complete
        assert writer.full_writes + writer.failures == 41 and writer.full_writes >= 30
        assert json.loads(writer.path.read_text(encoding="utf-8"))["gateway"]
    finally:
        await mgr.close()


async def test_snapshot_file_io_runs_off_the_event_loop(config_factory, workspace):
    mgr = await started(config_factory(workspace, []))
    try:
        writer = SnapshotWriter(mgr, heartbeat=0.05)
        loop_thread, io_threads = threading.get_ident(), []
        real = writer.persist

        def recording(*args, **kwargs):
            io_threads.append(threading.get_ident())
            return real(*args, **kwargs)

        writer.persist = recording  # type: ignore[method-assign]
        task = asyncio.create_task(writer.run())
        deadline = time.monotonic() + 10
        while len(io_threads) < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        heartbeat_threads = list(io_threads)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        # heartbeat writes run in a worker thread; only the final "stopped" write at shutdown is
        # synchronous (the loop is ending anyway)
        assert len(heartbeat_threads) >= 2 and loop_thread not in heartbeat_threads
        assert json.loads(writer.path.read_text(encoding="utf-8"))["gateway"].get("stopped_at")
    finally:
        await mgr.close()


def test_replace_retries_a_transient_sharing_violation(tmp_path, monkeypatch):
    import os

    from reveng_nexus import snapshot as snap

    src, dst = tmp_path / "a.tmp", tmp_path / "a.json"
    src.write_text("new", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")
    real, calls = os.replace, []

    def flaky(a, b):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError(32, "being used by another process")
        real(a, b)

    monkeypatch.setattr(snap.os, "replace", flaky)
    snap._replace_with_retry(src, dst)
    assert dst.read_text(encoding="utf-8") == "new" and len(calls) == 3


# -- history versus health ------------------------------------------------------------------
async def test_historical_failures_are_labelled_and_do_not_override_current_health(config_factory, workspace):
    config = config_factory(workspace, [mock_engine("eng")])
    log = Path(config.audit_log)
    log.parent.mkdir(parents=True, exist_ok=True)
    legacy = {
        "timestamp": 1000.0,
        "event": "provider_started",
        "provider_id": "eng",
        "outcome": "failed",
        "error": "CancelledError: ",
        "duration_ms": 78,
    }
    log.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    mgr = await started(config)  # appends a current, successful start
    try:
        await mgr.health()
        SnapshotWriter(mgr).write()
        dash = DashboardData(config)
        health = provider(dash.state()["primary"], "eng")["health"]["status"]
        act = dash.activity()
    finally:
        await mgr.close()
    assert health == "ready"
    starts = [r for r in act["recent"] if r["event"] == "provider_started" and r["provider_id"] == "eng"]
    old = next(r for r in starts if r["timestamp"] == 1000.0)
    new = next(r for r in starts if r["timestamp"] != 1000.0)
    assert old["outcome"] == "failed" and old["era"] == "historical" and "2026-10-16 fix" in old["note"]
    assert new["outcome"] == "ok" and new["era"] == "current" and "note" not in new
    assert act["legacy_cancel_records"] == 1 and act["current_gateway_since"]
    assert any("history" in n for n in act["telemetry_notes"])
    raw = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert raw == legacy  # the log itself is never rewritten


# -- test isolation from the permanent runtime --------------------------------------------
def test_test_configs_never_resolve_to_the_permanent_runtime(config_factory, workspace, tmp_path):
    from conftest import inside_permanent_runtime

    config = config_factory(workspace, [mock_engine("eng")])
    for path in (config.data_dir, config.audit_log, config.evidence_db):
        assert Path(path).resolve().is_relative_to(tmp_path.resolve()), path
        assert not inside_permanent_runtime(path)


def test_guard_refuses_permanent_runtime_paths(tmp_path):
    from conftest import PERMANENT_RUNTIME

    from reveng_nexus.audit import AuditLog
    from reveng_nexus.evidence import EvidenceStore

    with pytest.raises(AssertionError, match="permanent runtime"):
        AuditLog(PERMANENT_RUNTIME / "data" / "audit.jsonl")
    with pytest.raises(AssertionError, match="permanent runtime"):
        EvidenceStore(PERMANENT_RUNTIME / "data" / "evidence.sqlite3")
    AuditLog(tmp_path / "audit.jsonl")  # anything else is allowed


def test_misplaced_top_level_data_dir_is_reported(tmp_path):
    from reveng_nexus.config import parse_config

    config = parse_config(
        {"data_dir": str(tmp_path / "elsewhere"), "workspace": {"data_dir": str(tmp_path / "data")}},
        base_dir=tmp_path,
    )
    assert Path(config.data_dir) == (tmp_path / "data").resolve()
    assert any("'data_dir' is set both" in w for w in config.warnings)
    quiet = parse_config({"workspace": {"data_dir": str(tmp_path / "data")}}, base_dir=tmp_path)
    assert not any("set both" in w for w in quiet.warnings)
