"""Optional LLM4Decompile inference adapter (not an MCP server).

LLM4Decompile (albertan017/LLM4Decompile) publishes model weights on Hugging Face and
reference scripts that call ``transformers``/vLLM directly; it ships no server. Nexus
talks to a model the *operator* serves behind an OpenAI-compatible
``POST /v1/completions`` endpoint (e.g. ``vllm serve LLM4Binary/llm4decompile-6.7b-v2``
or llama.cpp's server). Nexus never downloads weights.

Prompt format (from the upstream README / ghidra/demo.py at the pinned revision)::

    # This is the assembly code:
    <input>
    # What is the source code?

``variant: ref`` (V2 models) expects Ghidra pseudocode as ``<input>``; ``variant: end``
(V1.5 models) expects objdump-style assembly. Nexus' assembly rendering is an
approximation of the objdump format the End models were trained on.

Model weights are under the DeepSeek License Agreement (LICENSE-MODEL), separate from
the MIT code licence, including use-based restrictions. Operators are responsible for
compliance.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx2 as httpx

from ..errors import ArgumentError, CapabilityUnavailable, PolicyViolation, ProviderCallError, ProviderUnavailable
from ..netguard import is_loopback_host, parse_http_url
from ..redaction import redact_text
from .base import AnalysisProvider, OperationResult, ProviderHealth, TargetContext

PROMPT_PREFIX = "# This is the assembly code:\n"
PROMPT_SUFFIX = "\n# What is the source code?\n"
UPSTREAM_REVISION = "85b364bf093eb2ee4f3687cfe38a203fca89f23e"
_MAX_INPUT_CHARS = 48_000


def build_prompt(text: str) -> str:
    return PROMPT_PREFIX + text.strip() + PROMPT_SUFFIX


def render_assembly(function_name: str, instructions: list[dict[str, Any]]) -> str:
    """Approximate the cleaned objdump format used by the upstream End-model scripts."""
    lines = [f"<{function_name}>:"]
    for insn in instructions:
        lines.append(f"{insn['mnemonic']} {insn.get('op_str', '')}".rstrip())
    return "\n".join(lines)


def _is_loopback(host: str) -> bool:
    return is_loopback_host(host)


class Llm4DecompileProvider(AnalysisProvider):
    engine = "llm4decompile"
    engine_family = "llm4decompile"

    def __init__(self, config, runtime) -> None:
        super().__init__(config, runtime)
        self.model_cfg = config.model
        try:
            # The HTTP client's own parser, so the checked host is the host connected to.
            self.host = parse_http_url(self.model_cfg.endpoint).host
        except ValueError:
            self.host = ""  # not loopback: refused unless both remote opt-ins are set
        self.base_url = self.model_cfg.endpoint.rstrip("/")
        if self.base_url.endswith("/v1"):
            self.base_url = self.base_url[:-3]
        self.served_models: list[str] = []
        self._client: httpx.AsyncClient | None = None

    def _check_remote_policy(self) -> None:
        if _is_loopback(self.host):
            return
        if not (self.model_cfg.allow_remote and self.runtime.config.policy.allow_remote_ai):
            raise PolicyViolation(
                f"{self.id}: endpoint host {self.host!r} is not loopback. Sending decompiled code to a remote "
                "service needs model.allow_remote: true AND policy.allow_remote_ai: true.",
            )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.model_cfg.api_key_env:
            key = os.environ.get(self.model_cfg.api_key_env)
            if not key:
                raise ProviderUnavailable(f"{self.id}: environment variable {self.model_cfg.api_key_env} is unset")
            headers["Authorization"] = f"Bearer {key}"
        return headers

    async def initialize(self) -> None:
        self._check_remote_policy()
        self._client = httpx.AsyncClient(
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
            trust_env=not _is_loopback(self.host),  # never route loopback inference through a proxy
        )
        await self._discover_models()
        self.started = True

    async def _discover_models(self) -> None:
        assert self._client is not None
        try:
            response = await self._client.get(f"{self.base_url}/v1/models", headers=self._headers())
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"{self.id}: inference endpoint unreachable: {redact_text(str(exc))}") from exc
        if response.status_code != 200:
            raise ProviderUnavailable(f"{self.id}: GET /v1/models returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderUnavailable(f"{self.id}: /v1/models did not return JSON") from exc
        self.served_models = [str(m.get("id")) for m in data.get("data", []) if isinstance(m, dict)]
        configured = self.model_cfg.model
        if configured not in self.served_models:
            raise ProviderUnavailable(
                f"{self.id}: configured model {configured!r} is not served by the endpoint "
                f"(served: {self.served_models[:10]}). Nexus will not substitute another model."
            )
        if "llm4decompile" not in configured.lower() and not self.model_cfg.allow_unrecognized_model:
            raise ProviderUnavailable(
                f"{self.id}: model id {configured!r} does not look like an LLM4Decompile checkpoint; set "
                "model.allow_unrecognized_model: true only if you deliberately serve a renamed checkpoint."
            )

    async def health_check(self) -> ProviderHealth:
        if self._client is None:
            return ProviderHealth("unavailable", "not initialised")
        try:
            await self._discover_models()
        except (ProviderUnavailable, PolicyViolation) as exc:
            return ProviderHealth("unavailable", exc.message)
        return ProviderHealth(
            "ready", f"serving {self.model_cfg.model} ({self.model_cfg.variant})", version=self.model_cfg.model
        )

    def list_capabilities(self) -> dict[str, dict[str, Any]]:
        expects = (
            "Ghidra pseudocode (LLM4Decompile-Ref/V2)"
            if self.model_cfg.variant == "ref"
            else ("objdump-style assembly (LLM4Decompile-End/V1.5)")
        )
        return {
            "ai.decompile": {
                "available": self.started,
                "input": expects,
                "engine_family": self.engine_family,
                "note": "output is AI-generated and unverified",
            }
        }

    async def shutdown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self.started = False

    async def perform(self, operation: str, target: TargetContext, params: dict[str, Any]) -> OperationResult:
        if operation != "ai.decompile":
            raise CapabilityUnavailable(f"{self.id} only implements ai.decompile")
        if self._client is None:
            raise ProviderUnavailable(f"{self.id} is not initialised")
        self._check_remote_policy()
        source_text = str(params.get("input_text") or "")
        input_kind = params.get("input_kind")
        expected = "pseudocode" if self.model_cfg.variant == "ref" else "assembly"
        if input_kind != expected:
            raise ArgumentError(f"{self.id} ({self.model_cfg.variant}) expects {expected} input, got {input_kind!r}")
        if not source_text.strip():
            raise ArgumentError("ai.decompile needs non-empty input text")
        if len(source_text) > _MAX_INPUT_CHARS:
            raise ArgumentError(f"input exceeds {_MAX_INPUT_CHARS} characters; pick a smaller function")
        prompt = build_prompt(source_text)
        body = {
            "model": self.model_cfg.model,
            "prompt": prompt,
            "max_tokens": self.model_cfg.max_tokens,
            "temperature": self.model_cfg.temperature,
        }
        started = time.monotonic()
        try:
            response = await self._client.post(
                f"{self.base_url}/v1/completions", headers=self._headers(), content=json.dumps(body)
            )
        except httpx.HTTPError as exc:
            raise ProviderCallError(f"{self.id}: inference request failed: {redact_text(str(exc))}") from exc
        finally:
            self.runtime.audit.write(
                "model_call",
                provider_id=self.id,
                operation=operation,
                duration_ms=round((time.monotonic() - started) * 1000),
                target_sha256=target.sha256,
                case_id=target.case_id,
            )
        if response.status_code != 200:
            raise ProviderCallError(f"{self.id}: /v1/completions returned HTTP {response.status_code}")
        try:
            data = response.json()
            choice = data["choices"][0]
            text = str(choice.get("text", ""))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderCallError(f"{self.id}: unexpected completion response shape") from exc
        served_model = str(data.get("model", ""))
        warnings = ["AI-generated reconstruction: not the original source and not verified."]
        if served_model and served_model != self.model_cfg.model:
            raise ProviderCallError(
                f"{self.id}: endpoint answered with model {served_model!r}, expected {self.model_cfg.model!r}"
            )
        if choice.get("finish_reason") == "length":
            warnings.append("generation hit max_tokens; output is truncated")
        model_provenance = {
            "model": self.model_cfg.model,
            "variant": self.model_cfg.variant,
            "endpoint_host": self.host,
            "api": self.model_cfg.api,
            "max_tokens": self.model_cfg.max_tokens,
            "temperature": self.model_cfg.temperature,
            "prompt_template": "llm4decompile:" + UPSTREAM_REVISION[:12],
            "input_kind": input_kind,
            "input_evidence_id": params.get("input_evidence_id"),
            "input_provider": params.get("input_provider"),
            "finish_reason": choice.get("finish_reason"),
            "usage": data.get("usage"),
        }
        address = params.get("address")
        return OperationResult(
            provider_id=self.id,
            operation=operation,
            tool_name="openai_completions",
            engine=self.engine,
            engine_family=self.engine_family,
            evidence_kind="ai_generated",
            normalized={
                "function": {"name": params.get("name"), "address": address},
                "code": text.strip(),
                "language": "C (model-generated)",
                "verification": "unverified",
            },
            raw={
                "request": {k: v for k, v in body.items() if k != "prompt"},
                "prompt_chars": len(prompt),
                "response": data,
            },
            subject_type="function",
            subject_address=address,
            subject_name=params.get("name"),
            engine_version=self.model_cfg.model,
            warnings=warnings,
            model=model_provenance,
            claim=f"AI reconstruction of {params.get('name') or address}",
        )
