"""What detonate scans: a Target.

v1 supports two input KINDS, and both execute — so both flow through the same
sandbox detonation pipeline:

  - mcp    : an MCP server launched over stdio (a command to run)
  - skill  : an agent skill directory (a SKILL.md plus bundled scripts)

Modelling the input as one small type with a `kind` keeps the rest of the
pipeline (sandbox, driver, probe, verdict) input-agnostic: it detonates a Target,
it doesn't care which flavour it is beyond the few points where they genuinely
differ. New executable input kinds (plugins, etc.) slot in here later without
touching the pipeline.

Text-only inputs (raw prompts) are intentionally NOT modelled here — they need no
sandbox, so they'd belong to a separate static path, deferred to phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

TargetKind = Literal["mcp", "skill"]


@dataclass
class Target:
    """A single thing to detonate."""

    kind: TargetKind
    # For kind="mcp": the command that launches the server over stdio.
    # For kind="skill": the path to the skill directory.
    reference: str

    @property
    def label(self) -> str:
        """Short human description for logs/reports."""
        return f"{self.kind}:{self.reference}"


def mcp_target(command: str) -> Target:
    return Target(kind="mcp", reference=command)


def skill_target(path: str) -> Target:
    # Normalise to an absolute path early so later stages get an unambiguous ref.
    return Target(kind="skill", reference=str(Path(path).expanduser().resolve()))
