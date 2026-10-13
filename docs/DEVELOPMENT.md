# Development

## Environment (Windows PowerShell)

```powershell
# Python 3.11+ (tested with 3.12 from uv). Keep the venv outside OneDrive/Dropbox if possible.
uv venv C:\venvs\reveng-nexus --python 3.12        # or: py -3.12 -m venv .venv
$env:VIRTUAL_ENV = "C:\venvs\reveng-nexus"
uv pip install -e ".[dev]"                          # or: C:\venvs\reveng-nexus\Scripts\python -m pip install -e ".[dev]"
C:\venvs\reveng-nexus\Scripts\Activate.ps1
```

Linux/macOS: `python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`.

Runtime dependencies are bounded in `pyproject.toml` to the versions tested here
(`mcp 2.3.x`, `jsonschema 4.x`, `anyio 4.x`, `httpx2 2.x`, `uvicorn 0.x`, `pyelftools 0.32`,
`pefile 2024.8.26`). Capstone (`disasm` extra) enables built-in disassembly.

## Checks

```powershell
python -m pytest -q                          # unit + mock-provider integration tests
python -m compileall -q src tests
ruff check src tests
ruff format --check src tests
python -m mypy src --ignore-missing-imports
python -m reveng_nexus --config config/providers.example.yaml --check-config
```

Opt-in live Ghidra test (see `docs/TESTING.md`):

```powershell
$env:REVENG_NEXUS_LIVE_GHIDRA = "1"; $env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra_12.1.4_PUBLIC"
python -m pytest tests/integration -m integration -v
```

## Adding or updating a provider adapter

1. Clone the upstream at a specific commit or tag and read its tool definitions. Don't
   trust READMEs or old configs: the 0.1 example had the wrong transport for MCPyGhidra and
   the wrong environment variables for the official IDA server.
2. Write the adapter in `src/reveng_nexus/adapters/`:
   - an `UpstreamPin` (repository, revision, package version, verification level, date);
   - a `manifest` classifying every tool whose class the annotations don't settle
     (lifecycle, mutate, execute, dynamic, blocked);
   - `bindings` from Nexus operations to the tools they need, plus `op_*` normalisers that
     keep the raw output;
   - `trust_annotations` only when the upstream annotates every tool.
3. Register it in `adapters/__init__.py`, add an entry to `config/providers.example.yaml`
   (disabled), and update `docs/PROVIDER_MATRIX.md` and `THIRD_PARTY_NOTICES.md`.
4. Add a mock contract test (see `tests/mock_servers/`) and, where the engine is available,
   an opt-in live test under `tests/integration/`.
5. Run `reveng-nexus providers check <id> --verbose` against the real engine and record the
   result. Promote the verification level only after that.

## Conventions

- Provider/target-derived text is data. Never build commands from it.
- No new tool may be advertised without a real implementation and a JSON schema with
  `additionalProperties: false`.
- Errors raised to the agent are `NexusError` subclasses with a stable `code`, a bounded
  redacted message and, where useful, `remediation`.
- Don't print to stdout in server code: stdio MCP uses it.
- Don't commit sample binaries, model weights, `config/providers.yaml` or `data/`.
