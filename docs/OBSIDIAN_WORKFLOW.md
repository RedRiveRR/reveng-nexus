# Obsidian knowledge-base workflow

RevEng Nexus keeps durable project memory (current state, decisions, provider research, next
actions) in a **private Obsidian vault outside this repository**. This saves AI sessions from
re-reading the whole repository and re-deriving past decisions.

| | Authoritative for |
|---|---|
| This repository | code, tests, release documentation (`README.md`, `docs/*.md`) |
| The private vault | working memory: current state, decision history, task continuity, lessons learned |

When they disagree, inspect the code and tests, decide which side is stale, and correct
it. Notes never override current behaviour.

## Location

On the integration machine the vault is the folder `reveng-nexus-obsidian` next to this
repository (inside the redirected Desktop). Its contents are **not** committed. The repo
ships only:

- `docs/obsidian-starter/`: the Token Optimization Protocol and note templates (sanitized);
- `scripts/init_obsidian_vault.py`: creates the folder skeleton and copies the starter files
  into a vault, **never overwriting** existing notes or Obsidian settings.

```powershell
python scripts/init_obsidian_vault.py "<vault path>" --dry-run
python scripts/init_obsidian_vault.py "<vault path>"
```

Structure: `00 - Home` (Start Here, Current State, Project Map, Token Optimization Protocol),
`01 - Project`, `02 - Architecture`, `03 - Providers`, `04 - Operations`, `05 - Decisions`
(Decision Log + ADRs), `06 - Tasks`, `07 - Session Notes`, `08 - Templates`, `99 - Archive`.

## Starting a Claude Code session

1. Read `00 - Home/Start Here.md` and `00 - Home/Current State.md`.
2. Follow `Project Map.md` to the 1–3 notes the task needs. If a context pack exists in
   `06 - Tasks/`, read that instead.
3. Open the source files and tests those notes name before trusting any status claim.
4. Do **not** read the vault recursively, every session note, or every ADR.

The full rules are in `docs/obsidian-starter/00 - Home/Token Optimization Protocol.md`.

## After meaningful work

- Update only the affected notes: usually `Current State`, one provider or architecture
  note, and `Next Actions`.
- Add a session summary in `07 - Session Notes/` (template: *Session Summary*) covering the
  objective, changed files or commits, **observed** test results, decisions, open issues, and
  the next action.
- Record consequential choices in `05 - Decisions/Decision Log.md`, with an ADR if the
  reasoning is long.
- For a multi-session task, keep a short *Task Context Pack* in `06 - Tasks/`.

## What goes where

| Repository | Private vault | Never anywhere |
|---|---|---|
| code, tests, fixtures builders, packaging | current state, next actions, open issues | secrets, tokens, keys, passwords |
| release docs, provider matrix, notices | decision history and rationale | conversation dumps, prompt transcripts |
| sanitized templates and protocol | session summaries, context packs | raw terminal output, copied source files |
| example config | local paths and machine layout | samples, evidence DBs, model weights |

Avoid duplication: a vault note summarises in a few lines and points to the canonical repo
document (e.g. `docs/PROVIDER_MATRIX.md`) instead of copying it.
