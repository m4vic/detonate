"""Shared test setup.

detonate lives under src/, which isn't importable until the package is
installed. Tests should run straight from a fresh clone (`pytest`) with no
install step, so we put src/ on the path here rather than making every
contributor remember `pip install -e .` first.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def sample_skill_dir() -> Path:
    """The known-good skill fixture: frontmatter + one bundled script."""
    return FIXTURES / "sample_skill"


@pytest.fixture
def mock_server_command() -> str:
    """A launch command for the real MCP server fixture.

    sys.executable (not a bare "python") so the subprocess runs in the same
    interpreter as the test — otherwise the server can't import the mcp SDK
    when tests run inside a venv.
    """
    return f'"{sys.executable}" "{FIXTURES / "mock_mcp_server.py"}"'
