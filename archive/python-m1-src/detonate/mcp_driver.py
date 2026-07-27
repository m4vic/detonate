"""M1 — connect to a real MCP server over stdio and enumerate its tools.

No sandbox yet (that's M2). This module proves detonate can speak the real MCP
protocol against a real server: launch it, initialize a session, list its
tools. That is the prerequisite for everything after it — you cannot detonate
a tool you cannot yet even discover.

Uses the official `mcp` SDK (`stdio_client` + `ClientSession`), not a
hand-rolled JSON-RPC client — the SDK IS the source of truth for the protocol.
"""

from __future__ import annotations

import shlex

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .tool_info import ToolInfo


def parse_command(command: str) -> StdioServerParameters:
    """Split a shell-style command string ("uvx some-server --flag") into the
    command + args StdioServerParameters needs. shlex handles quoting correctly
    (e.g. an arg containing a space), which naive str.split() would break."""
    parts = shlex.split(command)
    if not parts:
        raise ValueError(f"empty MCP command: {command!r}")
    return StdioServerParameters(command=parts[0], args=parts[1:])


async def enumerate_mcp_tools(command: str, timeout_s: float = 30.0) -> list[ToolInfo]:
    """Launch the MCP server over stdio, initialize a session, list its tools.

    Returns a plain list of ToolInfo — the server process is torn down again
    before this returns (the `async with` blocks close it), because M1 only
    discovers what a server offers; it does not yet run anything against it.
    """
    import anyio

    params = parse_command(command)

    with anyio.fail_after(timeout_s):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()

    return [
        ToolInfo(
            name=t.name,
            description=t.description or "",
            source="mcp",
            input_schema=t.inputSchema or {},
            metadata={"command": command},
        )
        for t in result.tools
    ]
