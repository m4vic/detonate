"""Tests for the MCP driver.

These run against tests/fixtures/mock_mcp_server.py — a REAL MCP server built
on the official SDK, launched as a real stdio subprocess. Nothing about the
protocol is faked, so a passing test means the actual handshake works, not
just that we called the right function names.
"""

from __future__ import annotations

import pytest

from detonate.mcp_driver import enumerate_mcp_tools, parse_command


class TestParseCommand:
    def test_splits_command_and_args(self):
        params = parse_command("uvx some-mcp-server --flag")
        assert params.command == "uvx"
        assert params.args == ["some-mcp-server", "--flag"]

    def test_respects_quoted_paths(self):
        """Windows paths with spaces are the common case here — a naive
        .split() would shred 'C:/Program Files/...' into two arguments."""
        params = parse_command('"C:/Program Files/py.exe" server.py')
        assert params.command == "C:/Program Files/py.exe"
        assert params.args == ["server.py"]

    def test_empty_command_rejected(self):
        with pytest.raises(ValueError):
            parse_command("   ")


class TestEnumerateMcpTools:
    async def test_discovers_tools_from_real_server(self, mock_server_command: str):
        tools = await enumerate_mcp_tools(mock_server_command)
        assert {t.name for t in tools} == {"read_file", "echo"}

    async def test_captures_description_and_schema(self, mock_server_command: str):
        tools = await enumerate_mcp_tools(mock_server_command)
        read_file = next(t for t in tools if t.name == "read_file")
        assert read_file.source == "mcp"
        assert "Read the contents" in read_file.description
        # The schema is how a probe later knows what arguments to send.
        assert "path" in read_file.input_schema.get("properties", {})

    async def test_bad_command_raises(self):
        """A server that can't start must fail the scan, not silently report
        zero tools — 'no tools found' would read like a clean bill of health."""
        with pytest.raises(Exception):
            await enumerate_mcp_tools("definitely-not-a-real-binary-xyz", timeout_s=10)
