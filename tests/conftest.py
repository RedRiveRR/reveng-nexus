from __future__ import annotations

import os
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

# The permanent runtime layout (docs/DEPLOYMENT.md). Tests must never write there.
# pytest exports each test's node id as PYTEST_CURRENT_TEST, and Windows refuses environment
# variables longer than 32,767 characters: a parametrized id that embeds a large value then errors
# in setup and teardown (and the next test errors as a knock-on). Collection fails early instead.
MAX_NODE_ID_CHARS = 1000


def oversized_node_ids(node_ids: list[str], limit: int = MAX_NODE_ID_CHARS) -> list[str]:
    return [node_id for node_id in node_ids if len(node_id) > limit]


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    too_long = oversized_node_ids([item.nodeid for item in items])
    if too_long:
        raise pytest.UsageError(
            f"test node ids must stay under {MAX_NODE_ID_CHARS} characters (pass explicit ids= to "
            "parametrize):\n" + "\n".join(f"  {len(n)} chars: {n[:120]}..." for n in too_long)
        )


PERMANENT_RUNTIME = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "RevEngNexus"


def inside_permanent_runtime(path: str | Path) -> bool:
    resolved = str(Path(path).expanduser().resolve()).casefold()
    root = str(PERMANENT_RUNTIME.resolve()).casefold()
    return resolved == root or resolved.startswith(root.rstrip("\\/") + os.sep)


@pytest.fixture(autouse=True)
def _never_touch_permanent_runtime(monkeypatch):
    """Fail any test whose setup resolves the audit log or evidence store to the permanent runtime.

    Every ProviderManager opens both from its config's data_dir, so a test config that silently
    resolved to the real deployment would fail here before writing anything.
    """
    from reveng_nexus.audit import AuditLog
    from reveng_nexus.evidence import EvidenceStore

    monkeypatch.delenv("REVENG_NEXUS_CONFIG", raising=False)
    for cls in (AuditLog, EvidenceStore):
        original = cls.__init__

        def guarded(self, path, *args, __original=original, __name=cls.__name__, **kwargs):
            if inside_permanent_runtime(path):
                raise AssertionError(f"test tried to open the permanent runtime {__name}: {path}")
            __original(self, path, *args, **kwargs)

        monkeypatch.setattr(cls, "__init__", guarded)


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
