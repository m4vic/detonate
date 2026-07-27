"""M1 — read a SKILL.md directory into the same ToolInfo shape the MCP driver
produces, so the pipeline after this point doesn't need to care which input
kind it's looking at.

A skill is a directory containing a SKILL.md (YAML frontmatter + Markdown body)
plus, usually, one or more bundled scripts the model is allowed to invoke. The
frontmatter's `description` field is exactly the kind of thing a supply-chain
attack poisons (Snyk's ToxicSkills research found injection in 36% of skills
tested) — enumerating it accurately is the whole point of this module.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .tool_info import ToolInfo

# Frontmatter is delimited by a line of exactly "---" at the top of the file,
# then closed by another "---". This is the standard convention SKILL.md and
# most static-site frontmatter formats share.
_FRONTMATTER_DELIM = "---"

# Common bundled-script extensions we treat as invokable — deliberately a
# short, explicit allowlist rather than "every file in the directory", so a
# stray README or image in the skill folder doesn't get treated as a tool.
_SCRIPT_EXTENSIONS = {".py", ".sh", ".js", ".ts"}


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split a SKILL.md's YAML frontmatter from its Markdown body.

    Returns (frontmatter_dict, body). If there's no frontmatter, returns an
    empty dict rather than raising — a skill without a description is still
    a real thing to report on (an empty/missing description is itself a
    finding worth surfacing later, not a crash).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_DELIM:
        return {}, text

    for i in range(1, len(lines)):
        if lines[i].strip() == _FRONTMATTER_DELIM:
            raw_frontmatter = "\n".join(lines[1:i])
            body = "\n".join(lines[i + 1:])
            try:
                parsed = yaml.safe_load(raw_frontmatter) or {}
            except yaml.YAMLError:
                # Malformed frontmatter is itself worth flagging later, not a
                # reason to crash the whole scan.
                parsed = {}
            return parsed, body

    # Opening delimiter with no closing one -> treat the whole thing as body.
    return {}, text


def find_bundled_scripts(skill_dir: Path) -> list[Path]:
    """Every script-like file in the skill directory (non-recursive at this
    milestone — deep/nested skills are a later refinement, not needed to
    prove the loader works)."""
    return sorted(
        p for p in skill_dir.iterdir()
        if p.is_file() and p.suffix.lower() in _SCRIPT_EXTENSIONS
    )


def load_skill(path: str) -> list[ToolInfo]:
    """Read a skill directory's SKILL.md and return it as ToolInfo entries.

    A skill's SKILL.md itself becomes one ToolInfo (name + description, the
    thing a poisoned frontmatter targets), plus one ToolInfo per bundled
    script (what actually executes when the skill is invoked).
    """
    skill_dir = Path(path).expanduser().resolve()
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"no SKILL.md found in {skill_dir}")

    frontmatter, body = _parse_frontmatter(skill_md.read_text(encoding="utf-8"))
    name = frontmatter.get("name", skill_dir.name)
    description = frontmatter.get("description", "") or body.strip()[:200]

    tools = [
        ToolInfo(
            name=name,
            description=description,
            source="skill",
            input_schema={},
            metadata={
                "path": str(skill_dir),
                "allowed_tools": frontmatter.get("allowed-tools", []),
            },
        )
    ]

    for script in find_bundled_scripts(skill_dir):
        tools.append(
            ToolInfo(
                name=f"{name}:{script.name}",
                description=f"bundled script: {script.name}",
                source="skill",
                input_schema={},
                metadata={"path": str(script), "parent_skill": name},
            )
        )

    return tools
