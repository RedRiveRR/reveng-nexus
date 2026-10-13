# Third-party notices

RevEng Nexus's own code is MIT-licensed (see `LICENSE`). That licence covers only the
code in this repository. It grants no rights in, and claims no ownership of, any upstream
project, engine or model listed here.

**Nothing from the upstream projects below is vendored, copied or bundled in this
repository.** Nexus talks to them as separate processes or services over MCP or HTTP,
installed by the operator (usually by `uvx`/`npx` resolving a pinned package at run time).
Their licences apply to those installations.

Licences were checked at the pinned revisions on 2026-10-13. This is an integration record,
not legal advice; re-check the exact versions you deploy.

## Integration targets

| Project | Revision checked | Licence (as found) | How Nexus uses it |
|---|---|---|---|
| [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp) | `df6de7985b534a964c125d5a86e41b26b17b14f6`, PyPI `ida-mcp` 20261008.0.1 | MIT (© 2026 Hex-Rays SA). Requires a licensed IDA Pro 9.4+ with idalib. | optional child process |
| [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp) | `7b38aa92952bd0621e8c964dc859f1515fe26a10`, PyPI `re-mcp-ghidra` / `re-mcp-ida` 3.0.3 | MIT OR Apache-2.0 (REUSE layout, `LICENSES/`). Depends on FastMCP and RestrictedPython. | optional child process (default Ghidra path) |
| [nightwing-us/mcpyghidra](https://github.com/nightwing-us/mcpyghidra) | `f1e130cb12bca7fcbadbfa7ad86bb860c651dc3f` (v0.8.0), PyPI `mcpyghidra` 0.8.0 | Apache-2.0 (© 2026 Nightwing Group, LLC), with a NOTICE file attributing pyghidra-decaf, Ghidra, pyghidra, JPype, python-multipart and certifi. Redistributing it requires keeping that NOTICE. | optional child process |
| [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) | `15d16aba427bedc8a23c7a54d8adee06d427b740` (v9.5.0-beta.6) | MIT (© 2026 blacktop). Requires a licensed IDA Pro. | optional child process |
| [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) | `8c5134ee46e2bf44f9a4d846bd971c3e39b3e306`, npm `binary-ninja-mcp` 1.0.0 | **GPL-3.0**. Requires a Binary Ninja licence. | optional separate process over MCP (no linking or copying) |
| [Qtty/jadx-mcp-server](https://github.com/Qtty/jadx-mcp-server) | `4e6d890d1d3753d2bb47d492a9523ef98874df85` | **No licence file found**, so no redistribution or modification rights are granted. It builds on JADX (Apache-2.0). | optional child process from the operator's own checkout |
| [monkeywave/frida-mobile-mcp](https://github.com/monkeywave/frida-mobile-mcp) | `b2da55d6429438ed36e829e7478de42430cb4ef9`, npm `frida-mobile-mcp` 0.2.3 | MIT (© 2026 Daniel Baier). Depends on Frida (wxWindows Library Licence). | optional dynamic child process (off by default) |
| [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist) | `db0bb3da678adb453a499a13feea8ed659102bcb` | MIT (© 2025 Jason Tang) | not integrated as a provider; may be pointed at Nexus' loopback HTTP endpoint |
| [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | `85b364bf093eb2ee4f3687cfe38a203fca89f23e` | Code: MIT (© 2024 albertan017). **Model weights: DeepSeek License Agreement v1.0** (`LICENSE-MODEL`), including the use restrictions in Attachment A. | prompt template only; weights served by the operator; Nexus never downloads them |
| [ram-elgov/awesome-llm-reverse-engineering](https://github.com/ram-elgov/awesome-llm-reverse-engineering) | `55366aa3d44526ed0a9d3cb7fa01d4d8227d4631` | README states MIT | reading list only |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 12.1.4 (used for runtime verification) | Apache-2.0 | external engine; not distributed |

Prompt-format note: `providers/llm4decompile.py` reproduces the two-line prompt template
used in LLM4Decompile's README and `ghidra/demo.py` (`# This is the assembly code:` /
`# What is the source code?`). It is reimplemented here, not copied code; the attribution is
recorded for transparency.

## Python dependencies (installed from PyPI, not vendored)

| Package | Version tested | Licence |
|---|---|---|
| mcp / mcp-types | 2.3.0 | MIT |
| PyYAML | 6.0.3 | MIT |
| jsonschema | 4.26.0 | MIT |
| anyio | 4.15.1 | MIT |
| httpx2 | 2.13.1 | BSD-3-Clause |
| uvicorn | 0.54.0 | BSD-3-Clause |
| pyelftools | 0.32 | Public domain (Unlicense) |
| pefile | 2024.8.26 | MIT |
| capstone (optional `disasm`) | 5.0.9 | BSD-3-Clause |

Transitive dependencies (pydantic, starlette, pywin32, …) keep their own licences, which
travel with each installed package.
