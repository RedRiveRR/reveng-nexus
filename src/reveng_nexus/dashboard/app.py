"""Local, read-only dashboard server (Starlette + uvicorn, already dependencies of the MCP SDK).

Security model (docs/DASHBOARD.md):

* loopback only: the runner refuses any other bind address;
* GET/HEAD only: every other method is answered 405 before routing; no route changes state;
* Host must be the loopback address and port the server is bound to (DNS-rebinding defence);
* a request carrying an Origin must come from that same origin; API requests marked
  cross-site by the browser (Sec-Fetch-Site) are refused; no CORS headers are ever sent;
* a fixed set of static files, a fixed set of JSON endpoints, no path or URL parameters
  that reach the filesystem, a provider, a shell or the network;
* strict CSP: scripts and styles only from this origin, no inline code, no framing.
"""

from __future__ import annotations

import sys
from importlib import resources
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from ..config import NexusConfig
from .data import DashboardData

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
DEFAULT_PORT = 8770
_SAFE_METHODS = {"GET", "HEAD"}
_STATIC = {
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "favicon.svg": "image/svg+xml",
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
_SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), usb=()"),
]


def allowed_hosts(port: int) -> frozenset[str]:
    return frozenset({f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"})


def allowed_origins(port: int) -> frozenset[str]:
    return frozenset(f"http://{h}" for h in allowed_hosts(port))


class LocalOnlyMiddleware:
    """Refuses non-GET methods, foreign Host headers and cross-origin requests; adds security headers."""

    def __init__(self, app: Any, port: int) -> None:
        self.app = app
        self.hosts = allowed_hosts(port)
        self.origins = allowed_origins(port)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                await self.app(scope, receive, send)
            return  # websockets and anything else: not served
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        path = scope.get("path", "")
        refusal: tuple[int, str] | None = None
        if scope.get("method", "GET").upper() not in _SAFE_METHODS:
            refusal = (405, "read-only dashboard: only GET and HEAD are served")
        elif headers.get("host", "").lower() not in self.hosts:
            refusal = (421, "unexpected Host header: the dashboard answers only on its loopback address")
        elif "origin" in headers and headers["origin"].lower() not in self.origins:
            refusal = (403, "cross-origin request refused")
        elif path.startswith("/api/") and headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}:
            refusal = (403, "cross-site API request refused")
        if refusal is not None:
            status, message = refusal
            extra = [(b"allow", b"GET, HEAD")] if status == 405 else []
            await _send_plain(send, status, message, extra)
            return

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                names = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = [
                    *[(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"],
                    *[(k, v) for k, v in _SECURITY_HEADERS if k not in names],
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def _send_plain(send: Any, status: int, message: str, extra: list[tuple[bytes, bytes]]) -> None:
    body = message.encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
                *extra,
                *_SECURITY_HEADERS,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _asset(name: str) -> bytes:
    return resources.files("reveng_nexus.dashboard").joinpath("static", name).read_bytes()


def _json(value: Any) -> Response:
    return JSONResponse(value, headers={"cache-control": "no-store"})


def create_app(config: NexusConfig, port: int) -> Any:
    data = DashboardData(config)

    async def index(request: Request) -> Response:
        return Response(
            _asset("index.html"), media_type="text/html; charset=utf-8", headers={"cache-control": "no-store"}
        )

    async def static(request: Request) -> Response:
        name = request.path_params["name"]
        if name not in _STATIC:  # fixed allowlist: no directory access of any kind
            return PlainTextResponse("not found", status_code=404)
        return Response(_asset(name), media_type=_STATIC[name], headers={"cache-control": "no-cache"})

    async def state(request: Request) -> Response:
        return _json(data.state())

    async def activity(request: Request) -> Response:
        return _json(data.activity())

    async def health(request: Request) -> Response:
        return _json({"status": "ok", "read_only": True})

    async def not_found(request: Request, exc: Exception) -> Response:
        return PlainTextResponse("not found", status_code=404)

    app = Starlette(
        routes=[
            Route("/", index),
            Route("/static/{name}", static),
            Route("/api/state", state),
            Route("/api/activity", activity),
            Route("/api/health", health),
        ],
        exception_handlers={404: not_found},
    )
    return LocalOnlyMiddleware(app, port)


def build_server(config: NexusConfig, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> Any:
    import uvicorn

    if host not in LOOPBACK_HOSTS:
        raise ValueError(f"the dashboard binds loopback only ({', '.join(LOOPBACK_HOSTS)}), not {host!r}")
    uv_config = uvicorn.Config(
        create_app(config, port),
        host=host,
        port=port,
        log_level="warning",
        lifespan="off",
        server_header=False,
        proxy_headers=False,
        access_log=False,
    )
    return uvicorn.Server(uv_config)


def run(config: NexusConfig, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> int:
    server = build_server(config, host, port)
    shown = f"[{host}]" if ":" in host else host
    print(
        f"RevEng Nexus dashboard (read-only): http://{shown}:{port}/  - press Ctrl+C to stop",
        file=sys.stderr,
    )
    server.run()
    return 0


__all__ = ["DEFAULT_PORT", "build_server", "create_app", "run"]
