// Package cli is detonate's command-line surface.
//
// The whole CLI is an App with its dependencies as fields rather than a set of
// package-level functions calling os.Stdout and exec directly. That is what
// lets the tests drive real scans and assert on real output without a Docker
// daemon present, which matters because the Docker gate would otherwise make
// the interesting paths untestable on most developer machines.
//
// We use the standard library's flag package on purpose: zero dependencies,
// and it reads clearly on video. A richer CLI is an easy upgrade later, but
// not before there is real output worth dressing up.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/m4vic/detonate/internal/environment"
	"github.com/m4vic/detonate/internal/mcpdriver"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/toolinfo"
)

const Version = "0.0.1"

// Exit codes. Separating "your environment is wrong" from "the scan failed"
// matters for CI: one means fix the runner, the other means look at the tool
// you scanned. A single non-zero code would conflate them.
const (
	exitOK      = 0
	exitFailure = 1 // the scan itself failed
	exitUsage   = 2 // bad invocation, or the environment isn't ready
)

// App holds the CLI's dependencies so they can be substituted in tests.
type App struct {
	Stdout io.Writer
	Stderr io.Writer

	// CheckDocker is injected so tests can exercise the enumeration path on a
	// machine without Docker. Production always gets the real check.
	CheckDocker func(context.Context) environment.DockerStatus
}

// New returns an App wired to the real environment.
func New() *App {
	return &App{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		CheckDocker: environment.CheckDocker,
	}
}

const usage = `detonate %s

Detonate untrusted AI-connected tools in a sandbox and report what they
actually do, not what their manifest claims.

Usage:
  detonate scan --mcp <command>   Scan an MCP server launched over stdio
  detonate scan --skill <path>    Scan an agent skill directory
  detonate --version              Print the version

Examples:
  detonate scan --mcp "uvx some-mcp-server"
  detonate scan --skill ./skills/pdf-extractor
`

// Run executes one CLI invocation and returns a process exit code. It never
// calls os.Exit itself, so tests can call it directly.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printUsage()
		return exitOK
	}

	switch args[0] {
	case "scan":
		return a.scan(ctx, args[1:])
	case "--version", "-version", "version":
		fmt.Fprintf(a.Stdout, "detonate %s\n", Version)
		return exitOK
	case "help", "--help", "-h":
		a.printUsage()
		return exitOK
	default:
		fmt.Fprintf(a.Stderr, "detonate: unknown command %q\n", args[0])
		a.printUsage()
		return exitUsage
	}
}

func (a *App) printUsage() {
	fmt.Fprintf(a.Stdout, usage, Version)
}

func (a *App) scan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	mcpCmd := fs.String("mcp", "", "An MCP server launched over stdio (e.g. 'uvx some-mcp-server').")
	skillPath := fs.String("skill", "", "An agent skill directory (a SKILL.md plus its bundled scripts).")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	tgt, err := resolveTarget(*mcpCmd, *skillPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
		return exitUsage
	}

	// Pre-flight. The finished pipeline requires a sandbox before executing
	// anything untrusted, so the gate is enforced from day one even though M1
	// below does not route through a sandbox yet. Wiring it in later would
	// mean shipping a version whose safety promise is aspirational.
	status := a.CheckDocker(ctx)
	if !status.Ready() {
		fmt.Fprintf(a.Stderr, "detonate: cannot scan: %s\n", status.Detail)
		fmt.Fprintln(a.Stderr, "detonate: detonate requires Docker to sandbox untrusted code. "+
			"Install Docker and make sure the daemon is running.")
		return exitUsage
	}

	fmt.Fprintf(a.Stdout, "detonate: docker: %s\n", status.Detail)
	fmt.Fprintf(a.Stdout, "detonate: target: %s\n", tgt.Label())

	// Clear anything a previous run leaked. A scan that died hard (SIGKILL,
	// power loss, a panic of ours) leaves a container with no client attached,
	// and the whole promise of this tool is that untrusted code does not
	// outlive the scan.
	if n := sandbox.ReapOrphans(ctx); n > 0 {
		fmt.Fprintf(a.Stdout, "detonate: reaped %d orphaned container(s) from a previous run\n", n)
	}

	tools, err := a.enumerate(ctx, tgt)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: enumeration failed: %v\n", err)
		return exitFailure
	}

	a.printTools(tools)
	fmt.Fprintln(a.Stdout, "detonate: detonation (sandbox + adversarial probes) not yet "+
		"implemented (M2+). Enumeration complete.")
	return exitOK
}

func resolveTarget(mcpCmd, skillPath string) (target.Target, error) {
	switch {
	case mcpCmd != "" && skillPath != "":
		return target.Target{}, errors.New("--mcp and --skill are mutually exclusive; one scan targets one thing")
	case mcpCmd != "":
		return target.MCP(mcpCmd), nil
	case skillPath != "":
		return target.Skill(skillPath)
	default:
		return target.Target{}, errors.New("a target is required: pass --mcp <command> or --skill <path>")
	}
}

func (a *App) enumerate(ctx context.Context, tgt target.Target) ([]toolinfo.ToolInfo, error) {
	if tgt.Kind == target.KindMCP {
		// Always sandboxed. There is no host-execution path reachable from the
		// CLI: the unsandboxed EnumerateTools still exists for our own tests,
		// but shipping a flag that reaches it would recreate exactly the
		// --dangerously-run-mcp-servers hole that justifies this tool.
		fmt.Fprintln(a.Stdout, "detonate: launching target inside a sandbox "+
			"(network off, read-only root, no capabilities, non-root)")
		return mcpdriver.EnumerateSandboxed(ctx, tgt.Reference, sandbox.DefaultPolicy(), nil)
	}

	// A skill's SKILL.md is inert data, so reading it needs no container. Its
	// bundled SCRIPTS are not, and those only ever run sandboxed once probing
	// lands in M5.
	return skill.Load(tgt.Reference)
}

func (a *App) printTools(tools []toolinfo.ToolInfo) {
	fmt.Fprintf(a.Stdout, "detonate: discovered %d tool(s):\n", len(tools))
	for _, t := range tools {
		fmt.Fprintf(a.Stdout, "    %s\n", t)
	}
}
