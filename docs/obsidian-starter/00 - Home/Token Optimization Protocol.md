---
type: protocol
tags: [moc, process]
---
# Token Optimization Protocol

Purpose: resume work without re-reading the whole repository, repeating research, or
reconstructing old decisions. The vault holds durable memory; the **source repository is
the authority** on what the code currently does.

## At the start of a task
1. Read [[Start Here]] and [[Current State]]. Nothing else yet.
2. Use [[Project Map]] to pick only the notes relevant to the task (typically 1–3).
3. If a task context pack exists in `06 - Tasks/`, read it instead of re-deriving context.
4. Before trusting any note about implementation status, open the corresponding source file
   and test named in the note. If they disagree, the code wins: fix the note.

## What not to read
5. Do not read the vault recursively, all session notes, all ADRs, or every architecture
   note. Session notes are history: read the latest one only when resuming its work.
6. Do not re-read repo docs that a note already summarises unless you are changing them.

## What to write (and not write)
7. Keep only durable knowledge: decisions, verified discoveries, important failures,
   reproducible fixes, current status, unresolved work.
8. Never store conversation dumps, prompt transcripts, unfiltered terminal output, copied
   source files, secrets, tokens, keys or passwords.
9. Keep [[Current State]] short (≤ 40 lines) and actionable: link to detail, don't copy it.
10. Mark every technical statement as **Verified** (with date and command/test), **Assumed**,
    **Proposed**, or **Untested**. A planned test is never recorded as a passed test.

## At the end of meaningful work
11. Update only the notes affected by the change: usually [[Current State]], one provider or
    architecture note, and [[Next Actions]].
12. Add a session summary in `07 - Session Notes/` from the *Session Summary* template:
    objective, changed files, tests run and results, decisions, open issues, next action.
13. Record consequential choices in [[Decision Log]] (and an ADR if the reasoning is long).
14. Use explicit dates (YYYY-MM-DD) and reproducible commands.

## Task context packs
For complex, multi-session tasks create one from the *Task Context Pack* template in
`06 - Tasks/`: objective, relevant files/notes, verified state, constraints and decisions,
required tests, open questions/failure modes, immediate next actions. Keep it under a page;
link to evidence instead of copying it. Delete or archive it when the task is done.

## Stale notes
An AI-written note is a lead, not proof. If the implementation changed since the note's
date, re-verify before acting on it, then update the note and keep the decision history.
