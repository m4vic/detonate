package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/staticinv"
	"github.com/m4vic/detonate/internal/toolscan"
	"github.com/m4vic/detonate/internal/trace"
)

const modeUsage = `Usage:
  detonate static <file|folder|git-url>   Inspect without target execution
  detonate dynamic <file|folder>          Experimental sandboxed execution
  detonate report <bundle-dir>            Render a saved result offline
  detonate combined <target>               Not available in alpha
`

// modeArgs separates the one target from the options that follow it.
//
// The mode subcommands used to require exactly one argument, which meant any
// flag at all was rejected as bad usage: `detonate static ./skill --format
// json` printed usage and exited 2. That made the two documented CI outputs
// unreachable from the mode a CI job should be using, since static mode is the
// one that needs no Docker.
func (a *App) modeArgs(name string, args []string) (string, scanOptions, bool) {
	var opt scanOptions
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, modeUsage)
		return "", opt, false
	}

	// The target comes first so the flag parser sees only flags. Accepting it
	// anywhere would mean guessing which bare word is the target.
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	bindScanFlags(fs, &opt)
	if err := fs.Parse(args[1:]); err != nil {
		return "", opt, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(a.Stderr, "detonate: %s takes one target; put options after it\n\n", name)
		fmt.Fprint(a.Stderr, modeUsage)
		return "", opt, false
	}
	switch opt.format {
	case "", "text", "json", "sarif":
	default:
		fmt.Fprintf(a.Stderr, "detonate: unknown format %q; use text, json, or sarif\n", opt.format)
		return "", opt, false
	}
	return args[0], opt, true
}

func (a *App) runStatic(ctx context.Context, args []string) int {
	input, opt, ok := a.modeArgs("static", args)
	if !ok {
		return exitUsage
	}
	if err := a.configureColor(opt.color, opt.format); err != nil {
		fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
		return exitUsage
	}
	// Static mode reports through the same machine-readable contract as a
	// dynamic scan, so a CI job can gate on it without a container runtime.
	a.format = opt.format
	a.outFile = opt.out
	a.failIncomplete = opt.failIncomplete
	a.configureSave(opt.save, opt.saveDir)
	if (a.format == "json" || a.format == "sarif") && a.outFile == "" {
		a.docOut = a.Stdout
		a.Stdout = io.Discard
	}
	return a.scanStatic(ctx, input, opt.subPath)
}

func (a *App) runDynamic(ctx context.Context, args []string) int {
	input, opt, ok := a.modeArgs("dynamic", args)
	if !ok {
		return exitUsage
	}
	if err := a.configureColor(opt.color, opt.format); err != nil {
		fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
		return exitUsage
	}
	// The notice is decoration, and decoration on stdout corrupts a JSON or
	// SARIF stream. It has to be suppressed here rather than by RunTarget,
	// which cannot silence output that was already written before it was
	// called.
	if opt.format == "" || opt.format == "text" {
		fmt.Fprintln(a.Stdout, a.active("[DYNAMIC]")+" target code runs only in Docker")
		fmt.Fprintln(a.Stdout, a.muted("  Preflight a new setup with: detonate doctor"))
	}
	// RunTarget owns format selection and output redirection for this path,
	// so the parsed options are handed over whole rather than applied here.
	return a.RunTarget(ctx, input, opt)
}

func (a *App) runCombined(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(a.Stderr, modeUsage)
		return exitUsage
	}
	fmt.Fprintln(a.Stderr, "detonate: combined mode is not available in this alpha.")
	fmt.Fprintln(a.Stderr, "Use `detonate static <target>` or experimental `detonate dynamic <target>`.")
	return exitUsage
}

// scanStatic never starts Docker, installs dependencies, or invokes a target.
// A remote repository is cloned as data, then inspected exactly like a local
// path. Dynamic URL acquisition remains intentionally separate and explicit.
func (a *App) scanStatic(ctx context.Context, input, subPath string) int {
	a.scanScenarios = nil
	a.scanTools = nil
	a.scanFailures = nil
	a.scanTarget = input
	a.scanRepositoryURL = ""
	a.scanSubpath = ""
	a.scanRevision = ""
	a.scanSandboxImage = ""

	targetPath := input
	if fetch.IsURL(input) {
		fetched, err := fetch.Git(ctx, input)
		if err != nil {
			return a.failScan("fetch", "fetch_failed", assessment.OutcomeTargetError, true, err, exitFailure)
		}
		defer fetched.Cleanup()
		a.scanRepositoryURL = fetched.Source
		a.scanSubpath = filepath.ToSlash(subPath)
		a.scanRevision = fetched.Revision
		a.scanTarget = remoteTargetIdentity(fetched.Source, subPath)

		// A monorepo is reached with --path, so it has to be applied to the
		// clone here. Without it, --path parsed fine and then changed nothing,
		// which is worse than rejecting it.
		root, err := fetched.SubDir(subPath)
		if err != nil {
			fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
			return exitUsage
		}
		targetPath = root
		a.metadata("cloned", fetched.Source)
	} else if subPath != "" {
		targetPath = filepath.Join(input, subPath)
	}

	detected, err := Detect(targetPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: static scan: %v\n", err)
		return exitUsage
	}

	switch detected.Kind {
	case KindPrompt:
		return a.scanPrompt(detected.File)
	case KindSkill:
		return a.scanStaticSkill(detected)
	case KindMCP:
		return a.scanStaticMCP(detected)
	default:
		a.explainUnclassified(input, detected)
		return exitUsage
	}
}

// explainUnclassified turns a dead end into the next command to run.
//
// The most likely thing a person pastes is a repository that holds many
// servers rather than being one — github.com/modelcontextprotocol/servers is
// the best-known MCP repository and is exactly this shape. Reporting "no
// recognisable entry point" and stopping tells a new user the tool does not
// work on the first thing they tried.
func (a *App) explainUnclassified(input string, detected Detected) {
	fmt.Fprintf(a.Stderr, "detonate: cannot tell what %s is: %s\n", input, detected.Why)

	if len(detected.Packages) > 0 {
		fmt.Fprintln(a.Stderr, "\n  This looks like a repository of packages. Scan one with --path:")
		for _, pkg := range detected.Packages {
			fmt.Fprintf(a.Stderr, "    detonate static %s --path %s\n", input, pkg)
		}
		if len(detected.Packages) == maxSuggestedPackages {
			fmt.Fprintln(a.Stderr, "    ...and more; list the directory to see the rest")
		}
		return
	}

	fmt.Fprintln(a.Stderr, "\n  If it is an MCP server, give the command that starts it:")
	fmt.Fprintf(a.Stderr, "    detonate dynamic %s --cmd \"python /target/server.py\"\n", input)
	fmt.Fprintln(a.Stderr, "  Inside the sandbox the folder is mounted at /target.")
}

func (a *App) scanStaticSkill(detected Detected) int {
	sk, err := skill.LoadSkill(detected.Dir)
	if err != nil {
		return a.failScan("resolve", "skill_load_failed", assessment.OutcomeTargetError, false, err, exitFailure)
	}
	tr := &trace.Trace{Target: detected.Dir, Started: time.Now()}
	for _, event := range skill.Analyze(sk) {
		tr.Add(event)
	}
	outcome := assessment.OutcomePass
	if tr.HasSeverity(trace.SeverityNotable) {
		outcome = assessment.OutcomeFinding
	}
	if a.scanTarget == "" {
		a.scanTarget = detected.Dir
	}
	a.scanScenarios = []assessment.ScenarioResult{{
		ID: "skill.static", Required: true, Outcome: outcome,
	}}
	return a.report(tr)
}

func (a *App) scanStaticMCP(detected Detected) int {
	fmt.Fprintf(a.Stdout, "static: MCP server (%s)\n", detected.Why)
	tr := &trace.Trace{Target: detected.Dir, Started: time.Now()}
	detail := map[string]any{
		"entry_command": detected.Command,
		"manifest":      detected.Manifest,
		"needs_install": detected.NeedsInstall,
	}
	tr.Add(trace.Event{
		Kind: trace.KindProtocol, Severity: trace.SeverityInfo,
		Summary: "static MCP inventory completed; target code was not executed",
		During:  "static-inventory", Source: "static-scanner", Detail: detail,
	})
	if a.scanTarget == "" {
		a.scanTarget = detected.Dir
	}

	// Recover whatever inventory the target declares, then analyze it with the
	// same rules dynamic mode uses. Static mode previously returned
	// `unsupported` unconditionally, which meant the one path a user without
	// Docker can reach produced no verdict at all.
	inv := staticinv.Extract(detected.Dir)
	a.scanTools = inv.Tools

	if len(inv.Tools) == 0 {
		// Nothing to analyze. This stays `unsupported` — the honest outcome —
		// but now names the specific reason instead of claiming the analysis
		// does not exist.
		fmt.Fprintf(a.Stderr, "  no static tool inventory: %s\n", inv.Reason)
		a.scanScenarios = []assessment.ScenarioResult{{
			ID:       "mcp.static-inventory",
			Required: true,
			Outcome:  assessment.OutcomeUnsupported,
			Reason:   inv.Reason + "; run dynamic mode for the sandboxed probe path",
		}}
		return a.report(tr)
	}

	findings := toolscan.Analyze(inv.Tools)
	for _, ev := range findings {
		tr.Add(ev)
	}

	outcome := assessment.OutcomePass
	for _, ev := range findings {
		if ev.Severity == trace.SeverityCritical || ev.Severity == trace.SeverityNotable {
			outcome = assessment.OutcomeFinding
			break
		}
	}

	fmt.Fprintf(a.Stdout, "  analyzed %d declared tool(s) from %s\n",
		len(inv.Tools), inv.Source)

	scenarios := []assessment.ScenarioResult{{
		ID:       "mcp.static-inventory",
		Required: true,
		Outcome:  outcome,
	}}

	// An inventory the target admits is a lower bound cannot support a complete
	// verdict. Recorded as a separate unsupported scenario so risk and
	// completeness stay independent: the tools we DID see were genuinely
	// analyzed (above), and the ones we could not see reduce completeness here
	// rather than quietly downgrading the finding.
	if !inv.Complete {
		scenarios = append(scenarios, assessment.ScenarioResult{
			ID:       "mcp.static-inventory-coverage",
			Required: true,
			Outcome:  assessment.OutcomeUnsupported,
			Reason:   inv.Reason,
		})
	}

	a.scanScenarios = scenarios
	return a.report(tr)
}

func interactiveTarget(line, command string) string {
	return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, command)), `"'`)
}
