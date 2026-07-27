"""detonate — command-line entry point.

M0 scope (this milestone): the CLI skeleton, input handling for the two v1 target
kinds (MCP servers and agent skills), and the pre-flight environment check. The
detonation pipeline itself (sandbox -> driver -> probe -> verdict) arrives in
later milestones. Today, `scan` resolves the target, verifies the environment is
ready, and reports that detonation isn't wired in yet — so the command is fully
runnable and testable from day one, and each milestone lights up one more step.

We use argparse from the standard library on purpose: zero dependencies, and it
teaches cleanly on video. A richer CLI (typer/rich) is an easy upgrade later if
the output deserves it — but not before there's real output to dress up.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .environment import check_docker
from .mcp_driver import enumerate_mcp_tools
from .skill_loader import load_skill
from .target import Target, mcp_target, skill_target
from .tool_info import ToolInfo


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI. Kept in one place so every subcommand is visible."""
    parser = argparse.ArgumentParser(
        prog="detonate",
        description=(
            "Detonate untrusted AI-connected tools in a sandbox and report what "
            "they actually do, not what their manifest claims."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"detonate {__version__}"
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser(
        "scan", help="Detonate an AI-connected tool in a sandbox and report."
    )
    # v1 supports two executable input kinds. They are mutually exclusive: one
    # scan targets one thing. Both route into the same sandbox pipeline.
    group = scan.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--mcp",
        metavar="COMMAND",
        help="An MCP server launched over stdio (e.g. 'uvx some-mcp-server').",
    )
    group.add_argument(
        "--skill",
        metavar="PATH",
        help="An agent skill directory (a SKILL.md plus its bundled scripts).",
    )

    return parser


def resolve_target(args: argparse.Namespace) -> Target:
    """Turn parsed CLI args into a single Target. The mutually-exclusive,
    required group guarantees exactly one of these is set."""
    if args.mcp:
        return mcp_target(args.mcp)
    return skill_target(args.skill)


def _print_tools(tools: list[ToolInfo]) -> None:
    print(f"[detonate] discovered {len(tools)} tool(s):")
    for t in tools:
        print(f"    {t}")


async def _enumerate(target: Target) -> list[ToolInfo]:
    if target.kind == "mcp":
        return await enumerate_mcp_tools(target.reference)
    return load_skill(target.reference)  # kind == "skill"


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle `detonate scan`. Returns a process exit code."""
    target = resolve_target(args)

    # Pre-flight: the FINISHED pipeline requires a sandbox before executing
    # anything untrusted — detonate must never run untrusted code without one.
    # Docker is checked here so that requirement is enforced from day one, even
    # though M1 (below) doesn't route through a sandbox yet.
    status = check_docker()
    if not status.ready:
        print(f"[detonate] cannot scan: {status.detail}", file=sys.stderr)
        print(
            "[detonate] detonate requires Docker to sandbox untrusted code. "
            "Install Docker and make sure the daemon is running.",
            file=sys.stderr,
        )
        return 2  # exit code 2 == environment/usage problem, not a scan failure

    print(f"[detonate] docker: {status.detail}")
    print(f"[detonate] target: {target.label}")

    # M1: enumerate what the target offers. For kind="mcp" this LAUNCHES the
    # target's process to talk the protocol — that happens WITHOUT the sandbox
    # yet (M2 is what puts it in a disposable container). Say so loudly: M1 is
    # only safe to point at servers/skills you already trust, not arbitrary
    # untrusted input off the internet.
    if target.kind == "mcp":
        print("[detonate] WARNING: sandbox not yet implemented (M2). This will "
              "run the target's command directly on your machine to enumerate "
              "its tools. Only use --mcp against a server you already trust.")
    try:
        tools = asyncio.run(_enumerate(target))
    except Exception as exc:
        print(f"[detonate] enumeration failed: {exc}", file=sys.stderr)
        return 1

    _print_tools(tools)
    print("[detonate] detonation (sandbox + adversarial probes) not yet "
          "implemented (M2+). Enumeration complete.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Program entry point. `argv=None` means "read from sys.argv"."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)

    # No subcommand given -> show help rather than doing nothing.
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
