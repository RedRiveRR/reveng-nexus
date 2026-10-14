"""Create (or top up) a RevEng Nexus Obsidian vault from docs/obsidian-starter.

    python scripts/init_obsidian_vault.py "<path to vault>" [--dry-run]

Creates the standard folder skeleton and copies the starter notes/templates. Existing files
are never overwritten and existing Obsidian settings are left untouched; the script only
reports what it skipped. Project-state notes (Start Here, Current State, ...) are private and
are written by you or your agent, not shipped in the repository.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

FOLDERS = (
    "00 - Home",
    "01 - Project",
    "02 - Architecture",
    "03 - Providers",
    "04 - Operations",
    "05 - Decisions/ADRs",
    "06 - Tasks",
    "07 - Session Notes",
    "08 - Templates",
    "99 - Archive",
)
STARTER = Path(__file__).resolve().parents[1] / "docs" / "obsidian-starter"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("vault", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    vault: Path = args.vault.expanduser().resolve()
    created, skipped = [], []
    for folder in FOLDERS:
        target = vault / folder
        if not target.is_dir():
            created.append(f"{folder}/")
            if not args.dry_run:
                target.mkdir(parents=True, exist_ok=True)
    for source in sorted(STARTER.rglob("*.md")):
        rel = source.relative_to(STARTER)
        if rel.name == "README.md" and rel.parent == Path("."):
            continue
        target = vault / rel
        if target.exists():
            skipped.append(str(rel))
            continue
        created.append(str(rel))
        if not args.dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    templates_cfg = vault / ".obsidian" / "templates.json"
    if (vault / ".obsidian").is_dir() and not templates_cfg.exists():
        created.append(".obsidian/templates.json (core Templates plugin folder)")
        if not args.dry_run:
            templates_cfg.write_text('{\n  "folder": "08 - Templates"\n}\n', encoding="utf-8")
    prefix = "would create" if args.dry_run else "created"
    for item in created:
        print(f"{prefix}: {item}")
    for item in skipped:
        print(f"kept existing: {item}")
    print(f"vault: {vault}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
