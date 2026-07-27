"""The shape both drivers (MCP, skill) normalize into.

Everything downstream (probes, monitor, verdict) works against ToolInfo, not
against MCP SDK types or SKILL.md's raw frontmatter. That keeps the pipeline
input-agnostic — a probe doesn't need to know whether a tool came from an MCP
server or a skill's bundled script, only that it has a name, a description
(the thing an attacker poisons), and enough info to invoke it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolInfo:
    """One invokable capability discovered on a Target."""

    name: str
    description: str
    source: str                    # "mcp" | "skill"
    input_schema: dict[str, Any] = field(default_factory=dict)
    # Free-form extra detail a probe MAY use later (e.g. a skill's script path,
    # an MCP tool's raw annotations). Never required for basic enumeration.
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        desc = self.description.strip().replace("\n", " ")
        if len(desc) > 80:
            desc = desc[:77] + "..."
        return f"[{self.source}] {self.name}: {desc}"
