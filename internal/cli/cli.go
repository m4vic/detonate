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
	"runtime/debug"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/baseline"
	"github.com/m4vic/detonate/internal/environment"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/mcpdriver"
	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/probe"
	"github.com/m4vic/detonate/internal/report"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/scenario"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Version is overwritten at build time by release linker flags. For binaries
// installed with `go install`, the initialization fallback uses Go's module build
// metadata so the binary does not report the unhelpful "dev" value.
var Version = "dev"

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version = versionFromBuildInfo(Version, info.Main.Version)
	}
}

func versionFromBuildInfo(linkerVersion, moduleVersion string) string {
	if linkerVersion != "dev" {
		return linkerVersion
	}
	if moduleVersion != "" && moduleVersion != "(devel)" {
		return moduleVersion
	}
	return linkerVersion
}

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
	exitFindings   = 3
	exitIncomplete = 4
)

// App holds the CLI's dependencies so they can be substituted in tests.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	// CheckDocker is injected so tests can exercise the enumeration path on a
	// machine without Docker. Production always gets the real check.
	CheckDocker func(context.Context) environment.DockerStatus

	// format and outFile carry the machine-readable output selection through
	// to reporting. Fields rather than parameters because report() is called
	// from several paths (prompt, skill, MCP) and threading two more arguments
	// through each of them would obscure what those functions are for.
	format         string
	outFile        string
	failIncomplete bool

	// docOut is where the JSON or SARIF document goes once progress output has
	// been silenced. Without it the document would be written to the same
	// io.Discard that suppressed the chatter.
	docOut io.Writer

	// scanTarget and scanTools describe the current scan, needed to build a
	// complete document rather than just a list of findings.
	scanTarget    string
	scanTools     []toolinfo.ToolInfo
	scanScenarios []assessment.ScenarioResult
	scanFailures  []report.Failure

	// scanIdentity names the thing being scanned, for baseline purposes only.
	//
	// It exists because a start command does not identify a target. Every
	// TypeScript server in the MCP reference monorepo builds to dist/index.js,
	// so memory, sequentialthinking and everything all shared one baseline —
	// and scanning the second reported "9 tool(s) removed since the last
	// scan", a rug-pull finding invented entirely by the collision.
	//
	// The user's own argument plus --path is used rather than the resolved
	// directory: a clone lands in a fresh temp path every run, which would
	// never match a previous baseline.
	scanIdentity string
}

// New returns an App wired to the real environment.
func New() *App {
	return &App{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Stdin:       os.Stdin,
		CheckDocker: environment.CheckDocker,
	}
}

const usage = `detonate %s

Detonate untrusted AI-connected tools in a sandbox and report what they
actually do, not what their manifest claims.

Usage:
  detonate <target>     Scan a folder, a file, or a repository URL
  detonate              Guided scan
  detonate static <target>   Static-only inspection (alpha)
  detonate dynamic <target>  Sandboxed execution (experimental)

detonate works out what the target is: a folder with SKILL.md is a skill, a
folder with an entry point is an MCP server, a .txt or .md file is a prompt.

Scans attempt dynamic checks by default. Dependency and build hooks may execute
target-controlled code in the networked acquisition container; schema-reachable
tools are called with adversarial input, and skill scripts run in the sandbox.

Options:
  --cmd <command>    Command that starts the server, if detection got it wrong
  --path <sub>       Sub-directory to scan inside a cloned repository
  --quick            Skip install, probes and script execution
  --no-probe         Do not call tools with adversarial input
  --no-install       Do not install dependencies
  --no-scripts       Do not run a skill's bundled scripts
  --no-baseline      Do not compare against the previous scan
  --fail-incomplete  Exit 4 when required coverage is incomplete
  --format <format>  Output format: text, json, or sarif
  --out <file>       Write machine-readable output to a file

Examples:
  detonate ./my-server
  detonate github.com/owner/repo
  detonate ./skills/pdf-extractor
  detonate ./system-prompt.txt
  echo "ignore all previous instructions" | detonate -
  detonate ./weird-server --cmd "python /target/main.py"

Inside the sandbox your folder is mounted at /target, so --cmd uses paths
like /target/server.py rather than a host path.

A lone - reads a prompt from stdin, so a prompt can be piped in without
saving a file first.

Exit codes:
  0  completed without gated findings or coverage failure
  1  error    2  bad usage or environment
  3  findings 4  incomplete coverage (when --fail-incomplete is set)
`

// Run executes one CLI invocation and returns a process exit code. It never
// calls os.Exit itself, so tests can call it directly.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		// A person at a terminal gets the wizard; anything else gets usage.
		// The terminal check is what stops a CI job that ran `detonate` with
		// no arguments from blocking forever on a question nobody can answer.
		if stdinIsTerminal() {
			return a.runInteractive(ctx)
		}
		return a.printUsageAndExit()
	}

	switch args[0] {
	case "--version", "-version", "version":
		fmt.Fprintf(a.Stdout, "detonate %s\n", Version)
		return exitOK
	case "help", "--help", "-h":
		a.printUsage()
		return exitOK
	case "scan":
		// The explicit form, kept working. Anyone who scripted against it
		// should not have their pipeline broken by a UX improvement.
		a.scanScenarios = nil
		a.scanTools = nil
		a.scanFailures = nil
		a.scanTarget = ""
		return a.scan(ctx, args[1:])
	case "scenario":
		return a.runScenario(args[1:])
	case "static":
		return a.runStatic(ctx, args[1:])
	case "dynamic":
		return a.runDynamic(ctx, args[1:])
	case "combined":
		return a.runCombined(args[1:])
	}

	if args[0] != "-" && strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(a.Stderr, "detonate: unknown option %q\n\n", args[0])
		a.printUsage()
		return exitUsage
	}

	// The primary form: `detonate <target> [options]`. One argument, and
	// detonate works out what it is.
	fs := flag.NewFlagSet("detonate", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	var opt scanOptions
	bindScanFlags(fs, &opt)
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if args[0] == "-" {
		switch opt.format {
		case "", "text", "json", "sarif":
		default:
			fmt.Fprintf(a.Stderr, "  unknown format %q; use text, json, or sarif\n", opt.format)
			return exitUsage
		}
	}

	// The banner is decoration, and decoration on stdout corrupts a JSON or
	// SARIF stream. Printed before RunTarget can silence output, so the check
	// has to happen here.
	if opt.format == "" || opt.format == "text" {
		fmt.Fprint(a.Stdout, banner)
		fmt.Fprintln(a.Stdout)
	}
	if args[0] == "-" {
		// A lone dash is the Unix convention for "read from stdin". It still
		// goes through normal option parsing so --format/--out work in CI.
		a.format = opt.format
		a.outFile = opt.out
		a.failIncomplete = opt.failIncomplete
		a.scanTarget = "stdin"
		if (a.format == "json" || a.format == "sarif") && a.outFile == "" {
			a.docOut = a.Stdout
			a.Stdout = io.Discard
		}
		return a.scanStdinPrompt()
	}
	return a.RunTarget(ctx, args[0], opt)
}

func (a *App) printUsage() {
	fmt.Fprintf(a.Stdout, usage, Version)
}

// printUsageAndExit is the no-arguments path taken when nobody is at a
// terminal to answer the wizard. Separated from Run so a test can exercise it
// without depending on whether the test runner happens to own a TTY.
func (a *App) printUsageAndExit() int {
	a.printUsage()
	return exitOK
}

func (a *App) scan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	mcpCmd := fs.String("mcp", "", "An MCP server launched over stdio (e.g. 'python /target/server.py').")
	skillPath := fs.String("skill", "", "An agent skill directory (a SKILL.md plus its bundled scripts).")
	promptPath := fs.String("prompt", "", "A prompt or instruction file to analyse for injected instructions.")
	gitURL := fs.String("git", "", "Clone a repository and scan it (e.g. github.com/owner/repo).")
	subPath := fs.String("path", "", "Sub-directory inside the cloned repo to scan.")
	mountDir := fs.String("dir", "", "Host directory holding the MCP server, mounted read-only at /target in the sandbox.")
	install := fs.Bool("install", false, "Install the target's dependencies first, in a separate network-enabled container.")
	doProbe := fs.Bool("probe", false, "Call each discovered tool with adversarial arguments and watch what it does.")
	runScripts := fs.Bool("run-scripts", false, "Run a skill's bundled scripts in the sandbox and watch them.")
	noBaseline := fs.Bool("no-baseline", false, "Skip comparing against the previous scan of this target.")
	failIncomplete := fs.Bool("fail-incomplete", false, "Exit 4 when required coverage is partial or inconclusive.")
	defaultFormat := a.format
	if defaultFormat == "" {
		defaultFormat = "text"
	}
	outputFormat := fs.String("format", defaultFormat, "Output format: text, json, or sarif.")
	outputFile := fs.String("out", a.outFile, "Write machine-readable output to this file.")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	switch *outputFormat {
	case "", "text", "json", "sarif":
	default:
		fmt.Fprintf(a.Stderr, "detonate: unknown format %q; use text, json, or sarif\n",
			*outputFormat)
		return exitUsage
	}
	a.format = *outputFormat
	a.outFile = *outputFile
	a.failIncomplete = *failIncomplete || a.failIncomplete
	if a.scanTarget == "" {
		switch {
		case *gitURL != "":
			a.scanTarget = *gitURL
		case *skillPath != "":
			a.scanTarget = *skillPath
		case *promptPath != "":
			a.scanTarget = *promptPath
		case *mcpCmd != "":
			a.scanTarget = *mcpCmd
		}
	}
	if (a.format == "json" || a.format == "sarif") &&
		a.outFile == "" && a.docOut == nil {
		a.docOut = a.Stdout
		a.Stdout = io.Discard
	}

	// --prompt needs no Docker and no target: a prompt is inert text, and the
	// analysis is the same instruction check a skill body gets. Handled first
	// so it stays usable on a machine with no container runtime at all.
	if *promptPath != "" {
		return a.scanPrompt(*promptPath)
	}

	// --git clones first, then the rest of the scan proceeds against the
	// clone as if the user had passed --dir.
	dir := *mountDir
	skillDir := *skillPath
	if *gitURL != "" {
		fetched, err := fetch.Git(ctx, *gitURL)
		if err != nil {
			return a.failScan("fetch", "fetch_failed",
				assessment.OutcomeTargetError, true, err, exitFailure)
		}
		defer fetched.Cleanup()

		root, err := fetched.SubDir(*subPath)
		if err != nil {
			fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
			return exitUsage
		}
		fmt.Fprintf(a.Stdout, "  cloned %s\n", fetched.Source)

		if *skillPath != "" || fileExists(filepath.Join(root, "SKILL.md")) {
			skillDir = root
		} else {
			dir = root
		}
	}

	tgt, err := resolveTarget(*mcpCmd, skillDir)
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
		return a.failScan("runtime", "runtime_unavailable",
			assessment.OutcomeHarnessError, true,
			fmt.Errorf("%s; Docker is required to sandbox untrusted code",
				status.Detail), exitUsage)
	}

	// Clear anything a previous run leaked. A scan that died hard (SIGKILL,
	// power loss, a panic of ours) leaves a container with no client attached,
	// and the whole promise of this tool is that untrusted code does not
	// outlive the scan.
	if n := sandbox.ReapOrphans(ctx); n > 0 {
		fmt.Fprintf(a.Stdout, "  cleaned up %d orphaned container(s) from a previous run\n", n)
	}

	tools, tr, scenarios, err := a.enumerate(ctx, tgt, dir, *install, *doProbe, *runScripts)
	if err != nil {
		var pipelineErr *pipelineError
		if errors.As(err, &pipelineErr) {
			return a.failScan(pipelineErr.Phase, pipelineErr.Code,
				pipelineErr.Outcome, pipelineErr.Retryable,
				pipelineErr.Err, exitFailure)
		}
		return a.failScan("execute", "scan_failed",
			assessment.OutcomeHarnessError, false, err, exitFailure)
	}

	// Compare against the last scan of this target. Every other check here is
	// a snapshot, and a snapshot cannot detect a rug pull by definition — a
	// server that serves clean descriptions during review and swaps them
	// afterwards looks perfect every single time it is looked at once.
	if !*noBaseline && len(tools) > 0 && tr != nil {
		key := a.scanIdentity
		if key == "" {
			// The explicit `scan --mcp` form, which names a command directly.
			key = tgt.Label()
		}
		a.diffBaseline(key, tools, tr)
	}

	a.scanTools = tools
	a.scanScenarios = scenarios
	if a.scanTarget == "" {
		a.scanTarget = tgt.Reference
	}

	// Tool listing is decoration; suppress it when the caller wants a stream.
	if a.format != "json" && a.format != "sarif" {
		a.printTools(tools)
	}
	return a.report(tr)
}

// scanPrompt analyses a prompt or instruction file.
//
// No Docker, no container: a prompt is inert text that cannot be run, so the
// only thing to do is read it. Kept usable without a container runtime because
// the most likely user is someone checking a file they were sent.
func (a *App) scanPrompt(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: cannot read %s: %v\n", path, err)
		return exitUsage
	}
	return a.scanPromptText(string(data), path)
}

// scanPromptText analyses prompt text already in hand, so the caller can feed
// it from a file or from stdin. label names the source in the report.
func (a *App) scanPromptText(text, label string) int {
	tr := &trace.Trace{Target: label, Started: time.Now()}
	for _, ev := range skill.AnalyzePrompt(text) {
		tr.Add(ev)
	}
	outcome := assessment.OutcomePass
	if tr.HasSeverity(trace.SeverityNotable) {
		outcome = assessment.OutcomeFinding
	}
	a.scanScenarios = []assessment.ScenarioResult{{
		ID: "prompt.static", Required: true, Outcome: outcome,
	}}
	return a.report(tr)
}

// scanStdinPrompt reads a prompt from stdin, so a user can pipe or paste one
// without saving a file first: `echo "..." | detonate -` or
// `detonate - < prompt.txt`.
//
// Text-only by nature — no container, so this is the one scan that works
// without Docker, which matches the most likely user: someone checking a
// prompt they were just sent.
func (a *App) scanStdinPrompt() int {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: cannot read stdin: %v\n", err)
		return exitUsage
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		fmt.Fprintln(a.Stderr, "detonate: no prompt on stdin. "+
			"Pipe text in (echo \"...\" | detonate -) or give a file.")
		return exitUsage
	}
	return a.scanPromptText(string(data), "stdin")
}

// diffBaseline compares this scan against the previous one and records the
// result for next time.
//
// Failures here are reported but never fail the scan: a missing or unwritable
// baseline directory is a housekeeping problem, and refusing to report real
// findings because of it would be the wrong trade.
func (a *App) diffBaseline(target string, tools []toolinfo.ToolInfo, tr *trace.Trace) {
	current := baseline.Capture(target, tools)

	previous, existed, err := baseline.Load(target)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: could not read baseline: %v\n", err)
		return
	}

	if existed {
		for _, ev := range baseline.Compare(previous, current) {
			tr.Add(ev)
		}
	} else {
		fmt.Fprintln(a.Stdout, "  first scan of this target; recording a baseline "+
			"so the next run can detect changed tool descriptions")
	}

	if err := baseline.Save(current); err != nil {
		fmt.Fprintf(a.Stderr, "detonate: could not save baseline: %v\n", err)
	}
}

// report prints observed behaviour and picks the exit code.
//
// The exit code is the API for CI: a pipeline gates on it without parsing
// anything. That is why a critical finding must be non-zero — a scanner that
// exits 0 while reporting an exfiltration attempt is a scanner that gets
// ignored by the automation it was bought for.
func (a *App) report(tr *trace.Trace) int {
	if err := assessment.Validate(a.scanScenarios); err != nil {
		fmt.Fprintf(a.Stderr, "detonate: invalid scenario results: %v\n", err)
		return exitFailure
	}

	// Machine-readable output replaces the terminal report rather than adding
	// to it: a caller asking for JSON is piping it somewhere, and decorative
	// text mixed into the stream would break that.
	if a.format == "json" || a.format == "sarif" {
		return a.reportMachine(tr)
	}

	if tr == nil {
		fmt.Fprintln(a.Stdout, "  no behavioural trace collected "+
			"(this target kind is not executed yet)")
		return exitOK
	}
	summary := assessment.Summarize(tr.Events, a.scanScenarios)

	// Findings drive the verdict. Observations are context printed alongside
	// them and never change the outcome.
	//
	// The split exists because of a measured failure: an earlier version let
	// info-level capability signals ("uses an API key", "runs a script") count
	// as findings, and 11 of 12 real published skills came back "suspicious".
	// They legitimately do those things. A scanner where almost everything is
	// suspicious has said nothing, and the person reading it stops reading.
	var findings, observations []trace.Event
	for _, e := range tr.Events {
		switch e.Severity {
		case trace.SeverityCritical, trace.SeverityNotable:
			findings = append(findings, e)
		case trace.SeverityInfo:
			if e.Source != "sandbox" && e.Source != "acquire" { // lifecycle noise
				observations = append(observations, e)
			}
		}
	}

	const rule = "  ----------------------------------------------------------------"

	if len(findings) == 0 {
		fmt.Fprintf(a.Stdout, "\n%s\n", rule)
		fmt.Fprintf(a.Stdout, "  RISK: %s\n", summary.Risk)
		fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", summary.Completeness)
		fmt.Fprintln(a.Stdout, "  No findings were observed in the scenarios that completed.")
		fmt.Fprintf(a.Stdout, "%s\n", rule)
		a.printCoverage()
		a.printObservations(observations)
		// Say the limit out loud. A scanner that lets "we found nothing" be
		// read as "this is safe" is worse than no scanner, because it converts
		// ignorance into false confidence.
		fmt.Fprintln(a.Stdout, "  Note: no findings is not proof of safety; inspect completeness")
		fmt.Fprintln(a.Stdout, "  and the scenario outcomes before trusting this result.")
		return a.exitForSummary(summary)
	}

	verdict := "suspicious"
	if tr.HasSeverity(trace.SeverityCritical) {
		verdict = "dangerous"
	}

	fmt.Fprintf(a.Stdout, "\n%s\n", rule)
	fmt.Fprintf(a.Stdout, "  RISK: %s  (%d finding(s))\n", verdict, len(findings))
	fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", summary.Completeness)
	fmt.Fprintf(a.Stdout, "%s\n", rule)
	a.printCoverage()

	for i, e := range findings {
		fmt.Fprintf(a.Stdout, "\n  %d. [%s] %s\n", i+1, strings.ToUpper(string(e.Severity)), e.Summary)
		if ev, ok := e.Detail["evidence"].(string); ok && ev != "" {
			fmt.Fprintf(a.Stdout, "     evidence : %s\n", ev)
		}
		fmt.Fprintf(a.Stdout, "     observed : +%dms during %s\n", e.Elapsed.Milliseconds(), orDash(e.During))
		fmt.Fprintf(a.Stdout, "     source   : %s\n", e.Source)
	}
	a.printObservations(observations)
	fmt.Fprintf(a.Stdout, "\n%s\n", rule)
	return exitFindings
}

func (a *App) printCoverage() {
	var completed int
	for _, scenario := range a.scanScenarios {
		if scenario.Outcome == assessment.OutcomePass ||
			scenario.Outcome == assessment.OutcomeFinding {
			completed++
		}
	}
	fmt.Fprintf(a.Stdout, "  Coverage: %d/%d scenario(s) completed\n",
		completed, len(a.scanScenarios))
	for _, scenario := range a.scanScenarios {
		if scenario.Outcome == assessment.OutcomePass ||
			scenario.Outcome == assessment.OutcomeFinding {
			continue
		}
		fmt.Fprintf(a.Stdout, "    - %s: %s", scenario.ID, scenario.Outcome)
		if scenario.Reason != "" {
			fmt.Fprintf(a.Stdout, " (%s)", scenario.Reason)
		}
		fmt.Fprintln(a.Stdout)
	}
}

func (a *App) exitForSummary(summary assessment.Summary) int {
	if summary.Completeness == assessment.CompletenessFailed {
		return exitFailure
	}
	if a.failIncomplete && summary.Completeness != assessment.CompletenessComplete {
		return exitIncomplete
	}
	return exitOK
}

// reportMachine writes JSON or SARIF and returns the same exit code the
// terminal report would have.
//
// The exit code is deliberately computed the same way regardless of format: a
// pipeline that switches to --format sarif for annotations must not also
// change whether the build passes.
func (a *App) reportMachine(tr *trace.Trace) int {
	s := report.Build(tr, a.scanScenarios, a.scanTools, a.scanTarget, Version,
		a.scanFailures...)

	// docOut, not Stdout: when progress output was silenced to keep the stream
	// clean, Stdout is io.Discard and writing the document there would throw
	// away the entire report.
	w := a.docOut
	if w == nil {
		w = a.Stdout
	}
	if a.outFile != "" {
		f, err := os.Create(a.outFile)
		if err != nil {
			fmt.Fprintf(a.Stderr, "detonate: cannot write %s: %v\n", a.outFile, err)
			return exitFailure
		}
		defer f.Close()
		w = f
	}

	var err error
	if a.format == "sarif" {
		err = report.SARIF(w, tr, a.scanScenarios, a.sarifURI(), Version,
			a.scanFailures...)
	} else {
		err = report.JSON(w, s)
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: writing report: %v\n", err)
		return exitFailure
	}

	if a.outFile != "" {
		fmt.Fprintf(a.Stdout, "  wrote %s (%s)\n", a.outFile, a.format)
	}

	if s.Counts.Critical > 0 || s.Counts.Notable > 0 {
		return exitFindings
	}
	return a.exitForSummary(assessment.Summary{
		Risk: s.Risk, Completeness: s.Completeness,
	})
}

const maxFailureMessageBytes = 4096
const failureTruncationMarker = "...[truncated]"

// failScan finishes an interrupted pipeline with the same machine-readable
// contract as a successful scan. It always returns the caller-selected
// non-zero code, even when an inconclusive target failure would not normally
// trip --fail-incomplete.
func (a *App) failScan(
	phase, code string,
	outcome assessment.Outcome,
	retryable bool,
	err error,
	exitCode int,
) int {
	message := "unknown failure"
	if err != nil {
		message = err.Error()
	}
	// Error text can contain target-controlled stderr. Keep it on one line so
	// it cannot forge terminal log records, and repair invalid UTF-8 before
	// serializing it into JSON/SARIF.
	message = strings.Join(strings.Fields(strings.ToValidUTF8(message, "?")), " ")
	if len(message) > maxFailureMessageBytes {
		message = strings.ToValidUTF8(
			message[:maxFailureMessageBytes-len(failureTruncationMarker)], "",
		) + failureTruncationMarker
	}
	if a.scanTarget == "" {
		a.scanTarget = "unknown"
	}
	a.scanScenarios = append(a.scanScenarios, assessment.ScenarioResult{
		ID:       "pipeline." + phase,
		Required: true,
		Outcome:  outcome,
		Reason:   message,
	})
	a.scanFailures = append(a.scanFailures, report.Failure{
		Phase: phase, Code: code, Message: message, Retryable: retryable,
	})

	fmt.Fprintf(a.Stderr, "detonate: %s failed [%s]: %s\n", phase, code, message)
	if a.format == "json" || a.format == "sarif" {
		if code := a.reportMachine(nil); code == exitFailure {
			// reportMachine returning failure can mean either that it correctly
			// summarized a harness failure or that serialization failed. The
			// externally visible result is still the requested failure code.
		}
	} else {
		summary := assessment.Summarize(nil, a.scanScenarios)
		const rule = "  ----------------------------------------------------------------"
		fmt.Fprintf(a.Stdout, "\n%s\n", rule)
		fmt.Fprintf(a.Stdout, "  RISK: %s\n", summary.Risk)
		fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", summary.Completeness)
		fmt.Fprintf(a.Stdout, "  FAILURE: %s/%s\n", phase, code)
		fmt.Fprintf(a.Stdout, "%s\n", rule)
		a.printCoverage()
	}
	return exitCode
}

// pipelineError carries stable failure attribution through the execution
// layers without forcing low-level packages to depend on report formatting.
type pipelineError struct {
	Phase     string
	Code      string
	Outcome   assessment.Outcome
	Retryable bool
	Err       error
}

func (e *pipelineError) Error() string { return e.Err.Error() }
func (e *pipelineError) Unwrap() error { return e.Err }

func targetPipelineError(phase, code string, retryable bool, err error) error {
	return &pipelineError{
		Phase: phase, Code: code, Outcome: assessment.OutcomeTargetError,
		Retryable: retryable, Err: err,
	}
}

// sarifURI is what a finding gets attached to in a code-scanning UI.
//
// GitHub resolves this relative to the repository root, so a path outside the
// checkout cannot be annotated on a line. Falling back to the bare target name
// puts the finding on the run itself, which is visible, rather than silently
// attaching it to a file that does not exist.
func (a *App) sarifURI() string {
	if rel, err := filepath.Rel(mustWD(), a.scanTarget); err == nil &&
		!strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Base(a.scanTarget))
}

func mustWD() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// printObservations lists context that did not rise to a finding.
//
// Shown because a reviewer wants to know what a skill reaches for, withheld
// from the verdict because reaching for an API key is what a database skill
// does. Separating the two is what keeps the verdict worth reading.
func (a *App) printObservations(observations []trace.Event) {
	if len(observations) == 0 {
		return
	}
	fmt.Fprintf(a.Stdout, "\n  Observations (context, not findings):\n")
	for _, e := range observations {
		fmt.Fprintf(a.Stdout, "    - %s\n", e.Summary)
	}
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

func (a *App) enumerate(
	ctx context.Context,
	tgt target.Target,
	mountDir string,
	install, doProbe, runScripts bool,
) ([]toolinfo.ToolInfo, *trace.Trace, []assessment.ScenarioResult, error) {
	var scenarios []assessment.ScenarioResult
	if tgt.Kind == target.KindMCP {
		policy := sandbox.DefaultPolicy()

		var mounts []sandbox.Mount
		var absDir string
		if mountDir != "" {
			abs, err := filepath.Abs(mountDir)
			if err != nil {
				return nil, nil, scenarios, fmt.Errorf("resolving --dir: %w", err)
			}
			absDir = abs
			// Read-only, always. A target that can rewrite its own source
			// mid-scan makes the evidence disagree with the artifact, which
			// defeats the point of collecting evidence at all.
			mounts = append(mounts, sandbox.Mount{
				HostPath: abs, ContainerPath: "/target", ReadOnly: true,
			})
		}

		// Phase 1 runs the package manager with a network. Target-controlled
		// lifecycle and build hooks may execute here; the separate container
		// limits persistence but does not make acquisition inert.
		var installed *acquire.Result
		if install {
			if absDir == "" {
				return nil, nil, scenarios, errors.New("--install needs --dir: there is no target directory to read a manifest from")
			}
			m := acquire.Detect(absDir)
			if m.Ecosystem == acquire.EcosystemNone {
				fmt.Fprintln(a.Stdout, "  no dependency manifest found; skipping install")
			} else {
				fmt.Fprintf(a.Stdout, "  [1/2] installing %s deps from %s "+
					"(separate container, network ON, hooks may execute)\n", m.Ecosystem, m.File)
			}

			res, err := acquire.Install(ctx, absDir, policy)
			if err != nil {
				return nil, nil, scenarios,
					targetPipelineError("acquire", "acquisition_failed", true, err)
			}
			installed = res
			defer func() { _ = installed.Cleanup(context.Background()) }()

			mounts = append(mounts, installed.Mounts()...)
			policy.Env = installed.Env

			// Detonate on the runtime the dependencies were built for. A Node
			// package installed into a volume is useless inside a Python
			// image: the deps are present but `node` is not.
			if installed.Image != "" {
				policy.Image = installed.Image
			}

			// A project that had to be compiled now lives in the volume, not
			// at /target. Detection ran before the build and could only name
			// the entry point the package declares, which did not exist on
			// disk yet.
			if rewritten := installed.Command(tgt.Reference); rewritten != tgt.Reference {
				fmt.Fprintf(a.Stdout, "  built   running from %s\n", installed.Root)
				tgt.Reference = rewritten
			}
		}

		// Always sandboxed. There is no host-execution path reachable from the
		// CLI: the unsandboxed EnumerateTools still exists for our own tests,
		// but shipping a flag that reaches it would recreate exactly the
		// --dangerously-run-mcp-servers hole that justifies this tool.
		phase := ""
		if install {
			phase = "[2/2] "
		}
		fmt.Fprintf(a.Stdout, "  %slaunching target inside a sandbox "+
			"(network off, read-only root, no capabilities, non-root)\n", phase)

		if !doProbe {
			res, err := mcpdriver.EnumerateSandboxedWithTrace(ctx, tgt.Reference, policy, mounts)
			if err != nil {
				return nil, nil, scenarios,
					targetPipelineError("inventory", "mcp_inventory_failed", false, err)
			}
			// Fold install-time behaviour into the same trace. A postinstall
			// hook that phoned home is a finding about this target, and
			// splitting it into a separate report would let it be overlooked.
			if installed != nil && res.Trace != nil {
				res.Trace.Events = append(installed.Events, res.Trace.Events...)
			}
			scenarios = append(scenarios, assessment.ScenarioResult{
				ID: "mcp.inventory", Required: true, Outcome: assessment.OutcomePass,
			})
			for _, tool := range res.Tools {
				scenarios = append(scenarios, assessment.ScenarioResult{
					ID:       scenario.MCPToolID(tool.Name),
					Required: true,
					Outcome:  assessment.OutcomeSkipped,
					Reason:   "dynamic probes were disabled",
				})
			}
			return res.Tools, res.Trace, scenarios, nil
		}

		// Probing keeps the session open: a tool only reveals what it does
		// when it is called, so the container has to outlive tools/list.
		sess, err := mcpdriver.OpenSession(ctx, tgt.Reference, policy, mounts)
		if err != nil {
			return nil, nil, scenarios,
				targetPipelineError("start", "mcp_start_failed", false, err)
		}
		defer sess.Close()

		tools, err := sess.Tools(ctx)
		if err != nil {
			return nil, nil, scenarios,
				targetPipelineError("inventory", "mcp_inventory_failed", false, err)
		}
		scenarios = append(scenarios, assessment.ScenarioResult{
			ID: "mcp.inventory", Required: true, Outcome: assessment.OutcomePass,
		})

		tr := &trace.Trace{Target: tgt.Reference, Started: time.Now()}
		if installed != nil {
			for _, ev := range installed.Events {
				tr.Add(ev)
			}
		}

		// Enumeration-phase behaviour: what the server did just from being
		// launched and asked for its tool list, BEFORE any tool was called. A
		// network attempt here is unprovoked — nobody invoked anything — so it
		// is the real phone-home signal and stays a finding.
		//
		// Captured before probing on purpose. A tool that legitimately reaches
		// its own API when we call it must not be confused with the server
		// reaching out on its own; only the second is suspicious.
		for _, ev := range monitor.Analyze(sess.Stderr(), "enumeration") {
			tr.Add(ev)
		}

		fmt.Fprintf(a.Stdout, "  probing %d tool(s) with %d adversarial payload(s)...\n",
			len(tools), len(probe.Payloads()))

		// The engine attributes probe-phase behaviour to the specific payload
		// and tool that provoked it, and skips tools that need the network
		// (their egress is expected, not a finding). There is deliberately no
		// aggregate re-scan of the whole stderr buffer afterwards: it re-flagged
		// the expected, blocked network noise from every API-backed tool as a
		// critical finding, which turned a clean Notion server into "dangerous".
		probeResult := probe.RunWithResults(ctx, sess, tools, 0)
		for _, ev := range probeResult.Events {
			tr.Add(ev)
		}
		scenarios = append(scenarios, probeResult.Scenarios...)
		return tools, tr, scenarios, nil
	}

	// A skill is mostly a large prompt: its SKILL.md body is text an agent
	// reads and obeys, so the analysis is of the instructions rather than of
	// running code. Reading it needs no container.
	tools, err := skill.Load(tgt.Reference)
	if err != nil {
		return nil, nil, scenarios,
			targetPipelineError("resolve", "skill_load_failed", false, err)
	}

	sk, err := skill.LoadSkill(tgt.Reference)
	if err != nil {
		return nil, nil, scenarios,
			targetPipelineError("resolve", "skill_load_failed", false, err)
	}

	tr := &trace.Trace{Target: tgt.Reference, Started: time.Now()}
	staticEvents := skill.Analyze(sk)
	for _, ev := range staticEvents {
		tr.Add(ev)
	}
	staticOutcome := assessment.OutcomePass
	for _, event := range staticEvents {
		if event.Severity == trace.SeverityCritical ||
			event.Severity == trace.SeverityNotable {
			staticOutcome = assessment.OutcomeFinding
			break
		}
	}
	scenarios = append(scenarios, assessment.ScenarioResult{
		ID: "skill.static", Required: true, Outcome: staticOutcome,
	})

	// The dynamic half of skill analysis. SKILL.md is a prompt and can only be
	// read, but the bundled scripts are real programs an agent will execute on
	// the user's machine — and until they run, a script that phones home is
	// indistinguishable from one that formats a table.
	if runScripts && len(sk.Scripts) > 0 {
		fmt.Fprintf(a.Stdout, "  running %d bundled script(s) in the sandbox...\n",
			len(sk.Scripts))
		detonation := skill.DetonateScriptsWithResults(
			ctx, tgt.Reference, sk, sandbox.DefaultPolicy(),
		)
		for _, ev := range detonation.Events {
			tr.Add(ev)
		}
		scenarios = append(scenarios, detonation.Scenarios...)
	} else {
		for _, script := range sk.Scripts {
			scenarios = append(scenarios, assessment.ScenarioResult{
				ID:       scenario.SkillScriptID(script),
				Required: true,
				Outcome:  assessment.OutcomeSkipped,
				Reason:   "dynamic script execution was disabled",
			})
		}
	}
	return tools, tr, scenarios, nil
}

func (a *App) printTools(tools []toolinfo.ToolInfo) {
	fmt.Fprintf(a.Stdout, "\n  discovered %d tool(s):\n", len(tools))
	for _, t := range tools {
		fmt.Fprintf(a.Stdout, "    %s\n", t)
	}
}
