package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/trace"
)

const modeUsage = `Usage:
  detonate static <file|folder|git-url>   Inspect without target execution
  detonate dynamic <file|folder>          Experimental sandboxed execution
  detonate combined <target>               Not available in alpha
`

func (a *App) runStatic(ctx context.Context, args []string) int {
	if len(args) != 1 {
		fmt.Fprint(a.Stderr, modeUsage)
		return exitUsage
	}
	return a.scanStatic(ctx, args[0])
}

func (a *App) runDynamic(ctx context.Context, args []string) int {
	if len(args) != 1 {
		fmt.Fprint(a.Stderr, modeUsage)
		return exitUsage
	}
	fmt.Fprintln(a.Stdout, "dynamic mode is experimental: target code runs only in Docker when available")
	return a.RunTarget(ctx, args[0], scanOptions{})
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
func (a *App) scanStatic(ctx context.Context, input string) int {
	a.scanScenarios = nil
	a.scanTools = nil
	a.scanFailures = nil
	a.scanTarget = input

	targetPath := input
	if fetch.IsURL(input) {
		fetched, err := fetch.Git(ctx, input)
		if err != nil {
			return a.failScan("fetch", "fetch_failed", assessment.OutcomeTargetError, true, err, exitFailure)
		}
		defer fetched.Cleanup()
		targetPath = fetched.Dir
		fmt.Fprintf(a.Stdout, "static: cloned %s\n", fetched.Source)
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
		fmt.Fprintf(a.Stderr, "detonate: static scan cannot classify %q: %s\n", input, detected.Why)
		return exitUsage
	}
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
	a.scanTarget = detected.Dir
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
	a.scanTarget = detected.Dir
	a.scanScenarios = []assessment.ScenarioResult{{
		ID:       "mcp.static-inventory",
		Required: true,
		Outcome:  assessment.OutcomeUnsupported,
		Reason:   "MCP static source analysis is not implemented; run dynamic mode for the current sandboxed probe path",
	}}
	return a.report(tr)
}

func interactiveTarget(line, command string) string {
	return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, command)), `"'`)
}
