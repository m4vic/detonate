"""Tests for the CLI wiring.

The Docker pre-flight gate deliberately blocks every scan on a machine without
Docker, which means the enumeration path can't be exercised end-to-end there.
These tests stub the gate so the wiring itself is still proven anywhere —
including on the developer machine that has no Docker installed.

Stubbing the check is safe here precisely because it's the only thing being
stubbed: the fixtures underneath are a real MCP server and a real skill.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detonate import cli
from detonate.environment import DockerStatus


@pytest.fixture
def docker_ready(monkeypatch):
    """Pretend Docker is up. cli.py imported check_docker into its own
    namespace, so that's the name that has to be patched."""
    monkeypatch.setattr(
        cli, "check_docker",
        lambda *a, **kw: DockerStatus(installed=True, running=True, detail="stubbed"),
    )


@pytest.fixture
def docker_missing(monkeypatch):
    monkeypatch.setattr(
        cli, "check_docker",
        lambda *a, **kw: DockerStatus(installed=False, running=False,
                                      detail="docker binary not found on PATH"),
    )


class TestArgParsing:
    def test_requires_a_target(self):
        """`scan` with neither --mcp nor --skill is a usage error, not a no-op."""
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["scan"])

    def test_target_kinds_are_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["scan", "--mcp", "x", "--skill", "y"])

    def test_no_subcommand_prints_help(self, capsys):
        assert cli.main([]) == 0
        assert "usage" in capsys.readouterr().out.lower()


class TestDockerGate:
    def test_scan_blocked_without_docker(self, docker_missing, sample_skill_dir, capsys):
        """The gate is the tool's core safety promise: no sandbox, no scan.
        Exit 2 == environment problem, distinct from exit 1 == scan failure."""
        assert cli.main(["scan", "--skill", str(sample_skill_dir)]) == 2
        assert "requires Docker" in capsys.readouterr().err


class TestScanEndToEnd:
    def test_skill_scan(self, docker_ready, sample_skill_dir: Path, capsys):
        assert cli.main(["scan", "--skill", str(sample_skill_dir)]) == 0
        out = capsys.readouterr().out
        assert "discovered 2 tool(s)" in out
        assert "pdf-extractor" in out

    def test_mcp_scan_against_real_server(self, docker_ready, mock_server_command, capsys):
        assert cli.main(["scan", "--mcp", mock_server_command]) == 0
        out = capsys.readouterr().out
        assert "read_file" in out
        assert "echo" in out

    def test_mcp_scan_warns_it_is_unsandboxed(self, docker_ready, mock_server_command, capsys):
        """M1 runs the target on the host. That warning must not quietly
        disappear when M2 lands — if it does, this test is the tripwire."""
        cli.main(["scan", "--mcp", mock_server_command])
        assert "sandbox not yet implemented" in capsys.readouterr().out

    def test_enumeration_failure_exits_one(self, docker_ready, tmp_path, capsys):
        """A skill directory with no SKILL.md must fail the scan, not report a
        clean zero-tool result."""
        assert cli.main(["scan", "--skill", str(tmp_path)]) == 1
        assert "enumeration failed" in capsys.readouterr().err

    def test_output_is_ascii_safe(self, docker_ready, sample_skill_dir, capsys):
        """Windows consoles default to cp1252 and mangle non-ASCII. detonate is
        a CLI people run on Windows, so its own output stays ASCII."""
        out = capsys.readouterr()  # drain
        cli.main(["scan", "--skill", str(sample_skill_dir)])
        cli.build_parser().format_help().encode("ascii")
        capsys.readouterr().out.encode("ascii")
