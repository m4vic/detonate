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
	"path/filepath"
	"strings"

	"github.com/m4vic/detonate/internal/environment"
	"github.com/m4vic/detonate/internal/mcpdriver"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

const Version = "0.0.1"

// Exit codes. Separating "your environment is wrong" from "the scan failed"
// matters for CI: one means fix the runner, the other means look at the tool
// you scanned. A single non-zero code would conflate them.
const (
	exitOK      = 0
	exitFailure = 1 // the scan itself failed
	exitUsage   = 2 // bad invocation, or the environment isn't ready

	// exitFindings means the scan ran fine and found something. Distinct from
	// exitFailure because "the tool broke" and "the tool caught something" call
	// for opposite responses in CI, and a single non-zero code makes a pipeline
	// treat a crashed scanner as a security finding (or worse, the reverse).
	exitFindings = 3
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

Flags:
  --dir <path>   Host directory holding the server, mounted read-only
                 at /target inside the sandbox.

Examples:
  detonate scan --skill ./skills/pdf-extractor
  detonate scan --mcp "python /target/server.py" --dir ./my-server

Exit codes:
  0  clean    2  bad usage or environment
  1  error    3  behavioural findings
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
	mcpCmd := fs.String("mcp", "", "An MCP server launched over stdio (e.g. 'python /target/server.py').")
	skillPath := fs.String("skill", "", "An agent skill directory (a SKILL.md plus its bundled scripts).")
	mountDir := fs.String("dir", "", "Host directory holding the MCP server, mounted read-only at /target in the sandbox.")

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

	tools, tr, err := a.enumerate(ctx, tgt, *mountDir)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: enumeration failed: %v\n", err)
		return exitFailure
	}

	a.printTools(tools)
	return a.report(tr)
}

// report prints observed behaviour and picks the exit code.
//
// The exit code is the API for CI: a pipeline gates on it without parsing
// anything. That is why a critical finding must be non-zero — a scanner that
// exits 0 while reporting an exfiltration attempt is a scanner that gets
// ignored by the automation it was bought for.
func (a *App) report(tr *trace.Trace) int {
	if tr == nil {
		fmt.Fprintln(a.Stdout, "detonate: no behavioural trace collected "+
			"(this target kind is not executed yet)")
		return exitOK
	}

	var findings []trace.Event
	for _, e := range tr.Events {
		if e.Severity == trace.SeverityCritical || e.Severity == trace.SeverityNotable {
			findings = append(findings, e)
		}
	}

	if len(findings) == 0 {
		fmt.Fprintln(a.Stdout, "detonate: no suspicious behaviour observed during enumeration")
		fmt.Fprintln(a.Stdout, "detonate: NOTE: absence of findings is not proof of safety. "+
			"Enumeration only observes startup; adversarial probing lands in M5.")
		return exitOK
	}

	fmt.Fprintf(a.Stdout, "\ndetonate: %d BEHAVIOURAL FINDING(S):\n", len(findings))
	for _, e := range findings {
		fmt.Fprintf(a.Stdout, "  [%s] %s\n", strings.ToUpper(string(e.Severity)), e.Summary)
		if ev, ok := e.Detail["evidence"].(string); ok && ev != "" {
			fmt.Fprintf(a.Stdout, "      evidence: %s\n", ev)
		}
		fmt.Fprintf(a.Stdout, "      observed at +%dms during %s (source: %s)\n",
			e.Elapsed.Milliseconds(), orDash(e.During), e.Source)
	}

	if tr.HasSeverity(trace.SeverityCritical) {
		fmt.Fprintln(a.Stdout, "\ndetonate: VERDICT: dangerous")
		return exitFindings
	}
	fmt.Fprintln(a.Stdout, "\ndetonate: VERDICT: suspicious")
	return exitFindings
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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

func (a *App) enumerate(ctx context.Context, tgt target.Target, mountDir string) ([]toolinfo.ToolInfo, *trace.Trace, error) {
	if tgt.Kind == target.KindMCP {
		// Always sandboxed. There is no host-execution path reachable from the
		// CLI: the unsandboxed EnumerateTools still exists for our own tests,
		// but shipping a flag that reaches it would recreate exactly the
		// --dangerously-run-mcp-servers hole that justifies this tool.
		fmt.Fprintln(a.Stdout, "detonate: launching target inside a sandbox "+
			"(network off, read-only root, no capabilities, non-root)")

		var mounts []sandbox.Mount
		if mountDir != "" {
			abs, err := filepath.Abs(mountDir)
			if err != nil {
				return nil, nil, fmt.Errorf("resolving --dir: %w", err)
			}
			// Read-only, always. A target that can rewrite its own source
			// mid-scan makes the evidence disagree with the artifact, which
			// defeats the point of collecting evidence at all.
			mounts = append(mounts, sandbox.Mount{
				HostPath: abs, ContainerPath: "/target", ReadOnly: true,
			})
			fmt.Fprintf(a.Stdout, "detonate: mounting %s read-only at /target\n", abs)
		}

		res, err := mcpdriver.EnumerateSandboxedWithTrace(
			ctx, tgt.Reference, sandbox.DefaultPolicy(), mounts)
		if err != nil {
			return nil, nil, err
		}
		return res.Tools, res.Trace, nil
	}

	// A skill's SKILL.md is inert data, so reading it needs no container and
	// produces no behavioural trace. Its bundled SCRIPTS are not inert, and
	// those only ever run sandboxed once probing lands in M5.
	tools, err := skill.Load(tgt.Reference)
	return tools, nil, err
}

func (a *App) printTools(tools []toolinfo.ToolInfo) {
	fmt.Fprintf(a.Stdout, "detonate: discovered %d tool(s):\n", len(tools))
	for _, t := range tools {
		fmt.Fprintf(a.Stdout, "    %s\n", t)
	}
}
