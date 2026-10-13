from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

TESTS = Path(__file__).parent
sys.path.insert(0, str(TESTS))

from fixtures.apk_builder import write_apk  # noqa: E402
from fixtures.elf_builder import write_elf  # noqa: E402
from fixtures.pe_builder import write_pe  # noqa: E402

from reveng_nexus.config import parse_config  # noqa: E402

MOCK_ENGINE = str(TESTS / "mock_servers" / "mock_engine.py")
MOCK_LAUNCHED = str(TESTS / "mock_servers" / "mock_launched.py")


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "samples"
    root.mkdir()
    return root


@pytest.fixture
def elf_sample(workspace: Path) -> Path:
    path = workspace / "nexus_fixture.elf"
    write_elf(path)
    return path


@pytest.fixture
def pe_sample(workspace: Path) -> Path:
    return write_pe(workspace / "nexus_fixture.exe")


@pytest.fixture
def apk_sample(workspace: Path) -> Path:
    return write_apk(workspace / "nexus_fixture.apk")


def mock_engine(
    provider_id: str,
    *,
    engine: str = "ghidra",
    flavor: str = "a",
    priority: int = 50,
    env: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "id": provider_id,
        "name": f"mock {provider_id}",
        "enabled": True,
        "type": "mcp_stdio",
        "adapter": "re_mcp",
        "engine": engine,
        "command": sys.executable,
        "args": [MOCK_ENGINE],
        "env": {"MOCK_FLAVOR": flavor, **(env or {})},
        "priority": priority,
        "timeout_seconds": extra.pop("timeout_seconds", 20),
        "startup_timeout_seconds": extra.pop("startup_timeout_seconds", 60),
        **extra,
    }


def mock_launched(provider_id: str, *, fail: bool = False, **extra: Any) -> dict[str, Any]:
    args = [MOCK_LAUNCHED, "{target}", "--port", "0", "--project-dir", "{workdir}"]
    if fail:
        args.append("--fail")
    return {
        "id": provider_id,
        "enabled": True,
        "type": "mcp_launched_http",
        "adapter": "mcpyghidra",
        "command": sys.executable,
        "args": args,
        "timeout_seconds": 20,
        "launch": {"startup_timeout_seconds": 60},
        **extra,
    }


def make_config(
    tmp_path: Path, workspace: Path | None = None, providers: list[dict[str, Any]] | None = None, **sections: Any
):
    raw: dict[str, Any] = {
        "workspace": {"allowed_roots": [str(workspace)] if workspace else [], "data_dir": str(tmp_path / "data")},
        "providers": providers or [],
    }
    raw.update(sections)
    return parse_config(raw, base_dir=tmp_path)


@pytest.fixture
def config_factory(tmp_path: Path):
    def factory(workspace: Path | None = None, providers: list[dict[str, Any]] | None = None, **sections: Any):
        return make_config(tmp_path, workspace, providers, **sections)

    return factory
