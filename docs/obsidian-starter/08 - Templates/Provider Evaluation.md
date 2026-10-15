---
type: provider
state: reviewed_not_tested   # live_analysis_verified | connection_verified | mock_tested | unit_tested | reviewed_not_tested | blocked | not_integrated
last_verified: {{date}}
tags: [provider]
---
# <Provider name>

| Field | Value |
|---|---|
| Upstream | <url> |
| Pinned revision / package | <commit / version> |
| Licence | <as found; note if absent> |
| Integration method | <stdio / launched HTTP / HTTP / model endpoint / none> |
| Adapter | `src/reveng_nexus/adapters/<file>.py` |
| Verification state | <state from docs/PROVIDER_MATRIX.md, with date and command> |
| Blocked by | <licence / GUI / build tool / device / weights> |

**Observed contract:** <tools, required arguments, quirks — verified facts only>

**Policy:** <blocked/lifecycle/execute tools and why>

**Open questions:** <bullets>
