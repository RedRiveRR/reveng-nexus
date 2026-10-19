import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import mock_engine

from reveng_nexus.errors import CapabilityUnavailable
from reveng_nexus.orchestrator import Orchestrator
from reveng_nexus.providers.llm4decompile import PROMPT_PREFIX, PROMPT_SUFFIX, build_prompt
from reveng_nexus.registry import ProviderManager

MODEL = "LLM4Binary/llm4decompile-6.7b-v2"


class FakeCompletions:
    """Minimal OpenAI-compatible server (GET /v1/models, POST /v1/completions)."""

    def __init__(self, served=(MODEL,), answer_model=None):
        self.prompts: list[dict] = []
        served_models, outer = list(served), self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, payload, status=200):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/v1/models":
                    self._send({"data": [{"id": m} for m in served_models]})
                else:
                    self._send({"error": "nope"}, 404)

            def do_POST(self):
                length = int(self.headers["Content-Length"])
                request = json.loads(self.rfile.read(length))
                outer.prompts.append(request)
                self._send(
                    {
                        "model": answer_model or request["model"],
                        "usage": {"completion_tokens": 20},
                        "choices": [
                            {
                                "text": "int main(void) {\n  int v = add_numbers(2, 3);\n  check_key(v);\n"
                                "  get_greeting();\n  launch_rocket();\n  return 0;\n}",
                                "finish_reason": "stop",
                            }
                        ],
                    }
                )

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def llm_provider(url, model=MODEL, **model_extra):
    return {
        "id": "llm4d",
        "enabled": True,
        "type": "llm4decompile",
        "timeout_seconds": 10,
        "model": {"endpoint": url, "model": model, "variant": "ref", **model_extra},
    }


@pytest.fixture
def fake():
    server = FakeCompletions()
    yield server
    server.close()


async def _setup(config_factory, workspace, elf_sample, providers):
    mgr = ProviderManager(config_factory(workspace, providers))
    await mgr.start()
    intake = await mgr.intake(str(elf_sample))
    return mgr, mgr.target_context(intake["target"]["sha256"])


def test_prompt_matches_upstream_template():
    assert build_prompt("  code  ") == "# This is the assembly code:\ncode\n# What is the source code?\n"
    assert PROMPT_PREFIX.startswith("# This is the assembly code") and PROMPT_SUFFIX.endswith("source code?\n")


async def test_ai_decompile_is_recorded_as_unverified_with_provenance(config_factory, workspace, elf_sample, fake):
    mgr, target = await _setup(config_factory, workspace, elf_sample, [mock_engine("ghidra_a"), llm_provider(fake.url)])
    try:
        assert (await mgr.health())["llm4d"]["status"] == "ready"
        out = await Orchestrator(mgr).ai_decompile(target, name="main")
        assert out["verification"].startswith("unverified")
        prompt = fake.prompts[0]["prompt"]
        assert prompt.startswith(PROMPT_PREFIX) and "add_numbers(2,3)" in prompt, "Ref models get Ghidra pseudocode"
        record = mgr.evidence.get_evidence_record(out["evidence_id"])
        assert record["evidence_kind"] == "ai_generated" and record["status"] == "unverified"
        assert record["model"]["model"] == MODEL and record["model"]["input_kind"] == "pseudocode"
        assert record["model"]["input_evidence_id"] == out["input_evidence_id"]
        assert any(
            link["relation"] == "derived_from" and link["dst_id"] == out["input_evidence_id"]
            for link in record["links"]
        )
        comparison = await Orchestrator(mgr).compare_function(
            target, name="main", include_ai=True, include_disassembly=False
        )
        check = comparison["ai_checks"][0]
        assert "launch_rocket" in check["calls_not_seen_in_engines"]
        assert comparison["assessment"] == "single_source", "AI output never counts as a second engine"
    finally:
        await mgr.close()


async def test_refuses_model_not_served(config_factory, workspace, elf_sample, fake):
    mgr, _ = await _setup(
        config_factory, workspace, elf_sample, [llm_provider(fake.url, model="LLM4Binary/llm4decompile-22b-v2")]
    )
    try:
        assert "not served" in mgr.provider_errors["llm4d"]
    finally:
        await mgr.close()


async def test_refuses_unrelated_model_id_unless_explicitly_allowed(config_factory, workspace, elf_sample):
    server = FakeCompletions(served=("qwen2.5-coder",))
    try:
        mgr, _ = await _setup(config_factory, workspace, elf_sample, [llm_provider(server.url, model="qwen2.5-coder")])
        assert "does not look like an LLM4Decompile" in mgr.provider_errors["llm4d"]
        await mgr.close()
        mgr, _ = await _setup(
            config_factory,
            workspace,
            elf_sample,
            [llm_provider(server.url, model="qwen2.5-coder", allow_unrecognized_model=True)],
        )
        assert "llm4d" not in mgr.provider_errors
        await mgr.close()
    finally:
        server.close()


async def test_rejects_substituted_model_in_response(config_factory, workspace, elf_sample):
    server = FakeCompletions(answer_model="some-other-model")
    try:
        mgr, target = await _setup(
            config_factory, workspace, elf_sample, [mock_engine("ghidra_a"), llm_provider(server.url)]
        )
        with pytest.raises(CapabilityUnavailable) as info:
            await Orchestrator(mgr).ai_decompile(target, name="main")
        assert "expected" in info.value.details["attempts"][-1]["message"]
        await mgr.close()
    finally:
        server.close()


async def test_remote_endpoint_needs_two_explicit_opt_ins(config_factory, workspace, elf_sample):
    mgr, _ = await _setup(config_factory, workspace, elf_sample, [llm_provider("http://inference.example.com:8000")])
    try:
        assert "not loopback" in mgr.provider_errors["llm4d"]
    finally:
        await mgr.close()


async def test_ai_unavailable_is_explained(config_factory, workspace, elf_sample):
    mgr, target = await _setup(config_factory, workspace, elf_sample, [])
    try:
        with pytest.raises(CapabilityUnavailable, match="no AI decompilation provider"):
            await Orchestrator(mgr).ai_decompile(target, name="main")
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("text", "match"),
    [("", "non-empty"), ("  \n\t ", "non-empty"), ("x" * 48_001, "exceeds 48000")],
    # Explicit ids: the default would embed the 48,001-character text in the node id, which pytest
    # exports as PYTEST_CURRENT_TEST and Windows refuses (environment variables are limited to 32,767).
    ids=["empty", "whitespace-only", "oversized-48001-chars"],
)
async def test_empty_or_oversized_input_is_refused_before_any_request(
    config_factory, workspace, elf_sample, fake, text, match
):
    from reveng_nexus.errors import ArgumentError

    mgr, target = await _setup(config_factory, workspace, elf_sample, [llm_provider(fake.url)])
    try:
        with pytest.raises(ArgumentError, match=match):
            await mgr.providers["llm4d"].perform(
                "ai.decompile", target, {"input_kind": "pseudocode", "input_text": text}
            )
        assert fake.prompts == []  # nothing was sent to the model endpoint
    finally:
        await mgr.close()
