"""A minimal, real MCP server for testing detonate's driver against.

This is NOT a mock/stub in the sense of faking the protocol — it's a genuine
MCP server built with the official SDK's FastMCP, run as a real stdio
subprocess. Using a real (if trivial) server to test the real (if trivial)
client is what lets M1's smoke test prove the actual protocol works, not just
that our code calls the right function names.

Run directly: python mock_mcp_server.py
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("detonate-test-fixture")


@mcp.tool()
def read_file(path: str) -> str:
    """Read the contents of a file at the given path."""
    return f"(fixture) would read: {path}"


@mcp.tool()
def echo(text: str) -> str:
    """Echo back the given text."""
    return text


if __name__ == "__main__":
    mcp.run()
