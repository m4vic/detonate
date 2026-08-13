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
	"github.com/m4vic/detonate/internal/bundle"
	"github.com/m4vic/detonate/internal/environment"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/report"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/scan"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Version is overwritten at build time by release linker flags. For binaries
// installed with `go install`, the initialization fallback uses Go's module build
// metadata so the binary does not report the unhelpful "dev" value.
var (
	Version       = "dev"
	Commit        = "unknown"
	BuildModified bool
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version = versionFromBuildInfo(Version, info.Main.Version)
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if Commit == "unknown" && setting.Value != "" {
					Commit = setting.Value
				}
			case "vcs.modified":
				BuildModified = setting.Value == "true"
			}
		}
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
	colorMode      string
	colorEnabled   bool
	saveRequested  bool
	saveDir        string
	saveFinalized  bool

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

	// Provenance is persisted only in opt-in bundles. A URL and subpath name
	// what the user requested; the revision and image name the immutable code
	// and runtime that actually produced the evidence.
	scanRepositoryURL string
	scanSubpath       string
	scanRevision      string
	scanSandboxImage  string

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
  detonate doctor       Check whether this machine can run a scan
  detonate report <dir> Render a saved report without rescanning
  detonate static <target>   Static-only inspection (alpha)
  detonate dynamic <target>  Sandboxed execution (experimental)

detonate works out what the target is: a folder with SKILL.md is a skill, a
folder with an entry point is an MCP server, a .txt or .md file is a prompt.

Scans attempt dynamic checks by default. Dependencies fetch with scripts
disabled; target-controlled install/build hooks run offline and non-root.
Schema-reachable tools receive adversarial input, and skill scripts run in the
sandbox.

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
  --color <mode>     Terminal color: auto, always, or never
  --save             Save a bounded report bundle after the scan
  --save-dir <dir>   Save the bundle at this directory (implies --save)

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
		a.scanRepositoryURL = ""
		a.scanSubpath = ""
		a.scanRevision = ""
		a.scanSandboxImage = ""
		return a.scan(ctx, args[1:])
	case "doctor":
		return a.doctor(ctx)
	case "report":
		return a.runSavedReport(args[1:])
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
	if err := a.configureColor(opt.color, opt.format); err != nil {
		fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
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
		a.configureSave(opt.save, opt.saveDir)
		if (a.format == "json" || a.format == "sarif") && a.outFile == "" {
			a.docOut = a.Stdout
			a.Stdout = io.Discard
		}
		return a.scanStdinPrompt()
	}
	return a.RunTarget(ctx, args[0], opt)
}

func (a *App) runSavedReport(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(a.Stderr, "detonate: report requires one saved bundle directory")
		return exitUsage
	}
	_, scan, err := bundle.Load(args[0])
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: cannot load report: %s\n", terminalSafe(err.Error()))
		return exitFailure
	}
	fmt.Fprint(a.Stdout, bundle.Text(scan))
	// Replay the stored scan's semantic exit — the same computation the live
	// report uses — so a saved report with findings or failed completeness never
	// replays as a clean exit 0 that a CI gate would accept.
	return a.exitForScan(scan)
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
	install := fs.Bool("install", false, "Fetch dependencies inertly, then install/build them offline and non-root.")
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
	colorMode := fs.String("color", colorAuto, "Terminal color: auto, always, or never.")
	save := fs.Bool("save", false, "Save a bounded report bundle after the scan.")
	saveDir := fs.String("save-dir", "", "Save the report bundle at this directory (implies --save).")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := a.configureColor(*colorMode, *outputFormat); err != nil {
		fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
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
	a.configureSave(*save, *saveDir)
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
		a.scanRepositoryURL = fetched.Source
		a.scanSubpath = filepath.ToSlash(*subPath)
		a.scanRevision = fetched.Revision
		a.scanTarget = remoteTargetIdentity(fetched.Source, *subPath)
		a.scanIdentity = a.scanTarget

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

	return a.execute(ctx, tgt, dir, scan.Stages{
		Install:    *install,
		Probe:      *doProbe,
		RunScripts: *runScripts,
	}, !*noBaseline)
}

// execute runs a scan whose target and stages are already decided, then
// reports it.
//
// Every path that scans something arrives here: the positional form, the
// explicit `scan` subcommand, and the interactive wizard. They differ only in
// how the user named the target, which is exactly the part that should not be
// duplicated into three pipelines.
//
// The options arrive as typed arguments. They used to arrive as a synthesized
// slice of command-line flags that this package handed back to its own flag
// parser, which meant the compiler could not check them and nothing but a
// terminal could start a scan.
func (a *App) execute(
	ctx context.Context,
	tgt target.Target,
	mountDir string,
	stages scan.Stages,
	useBaseline bool,
) int {
	requiresDocker := tgt.Kind == target.KindMCP || stages.Install ||
		stages.Probe || stages.RunScripts
	if requiresDocker {
		a.scanSandboxImage = sandbox.DefaultImage
		if stages.Install && mountDir != "" {
			manifest := acquire.Detect(mountDir)
			a.scanSandboxImage = acquire.ImageFor(manifest.Ecosystem, a.scanSandboxImage)
		}
		// Pre-flight only when a selected stage can execute target code. A skill
		// with no bundled scripts has no executable surface, so treating a
		// stopped Docker daemon as a harness failure would contradict reality.
		status := a.CheckDocker(ctx)
		if !status.Ready() {
			return a.failScan("runtime", "runtime_unavailable",
				assessment.OutcomeHarnessError, true,
				fmt.Errorf("%s; Docker is required to sandbox untrusted code; run 'detonate doctor' for setup details",
					status.Detail), exitUsage)
		}

		// Clear anything a previous run leaked. A scan that died hard (SIGKILL,
		// power loss, a panic of ours) leaves a container with no client attached.
		if n := sandbox.ReapOrphans(ctx); n > 0 {
			fmt.Fprintf(a.Stdout, "  cleaned up %d orphaned container(s) from a previous run\n", n)
		}
	}

	result, err := scan.Run(ctx, scan.Request{
		Target:   tgt,
		MountDir: mountDir,
		Stages:   stages,
	}, a.progress())
	if err != nil {
		return a.failPipeline(err)
	}
	tools, tr, scenarios := result.Tools, result.Trace, result.Scenarios
	a.recordScanFailures(result.Failures)

	// Compare against the last scan of this target. Every other check here is
	// a snapshot, and a snapshot cannot detect a rug pull by definition — a
	// server that serves clean descriptions during review and swaps them
	// afterwards looks perfect every single time it is looked at once.
	if useBaseline && len(tools) > 0 && tr != nil {
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

func (a *App) recordScanFailures(failures []scan.Failure) {
	for _, failure := range failures {
		a.scanFailures = append(a.scanFailures, report.Failure{
			Phase: failure.Phase, Code: failure.Code,
			Message:   normalizeFailureMessage(failure.Message),
			Retryable: failure.Retryable,
		})
	}
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
		return a.finalizeReport(tr, a.reportMachine(tr))
	}

	if tr == nil {
		if len(a.scanScenarios) == 0 && len(a.scanFailures) == 0 {
			fmt.Fprintln(a.Stdout, "  no behavioural trace collected "+
				"(this target kind is not executed yet)")
			return a.finalizeReport(tr, exitOK)
		}
		summary := assessment.Summarize(nil, a.scanScenarios)
		const rule = "  ----------------------------------------------------------------"
		fmt.Fprintf(a.Stdout, "\n%s\n", a.heading(rule))
		fmt.Fprintf(a.Stdout, "  RISK: %s\n", a.riskText(string(summary.Risk)))
		fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", a.completenessText(string(summary.Completeness)))
		for _, failure := range a.scanFailures {
			fmt.Fprintf(a.Stdout, "  FAILURE: %s\n",
				a.danger(failure.Phase+"/"+failure.Code))
		}
		fmt.Fprintf(a.Stdout, "%s\n", a.heading(rule))
		a.printCoverage()
		for _, failure := range a.scanFailures {
			fmt.Fprintf(a.Stdout, "  %s %s\n", a.warning("[LIMIT]"),
				terminalSafe(failure.Message))
		}
		return a.finalizeReport(tr, a.exitForSummary(summary))
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
		fmt.Fprintf(a.Stdout, "\n%s\n", a.heading(rule))
		fmt.Fprintf(a.Stdout, "  RISK: %s\n", a.riskText(string(summary.Risk)))
		fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", a.completenessText(string(summary.Completeness)))
		fmt.Fprintln(a.Stdout, "  No findings were observed in the scenarios that completed.")
		fmt.Fprintf(a.Stdout, "%s\n", a.heading(rule))
		a.printCoverage()
		a.printObservations(observations)
		// Say the limit out loud. A scanner that lets "we found nothing" be
		// read as "this is safe" is worse than no scanner, because it converts
		// ignorance into false confidence.
		fmt.Fprintln(a.Stdout, a.warning("  [NOTE]")+" no findings is not proof of safety; inspect completeness")
		fmt.Fprintln(a.Stdout, "  and the scenario outcomes before trusting this result.")
		return a.finalizeReport(tr, a.exitForSummary(summary))
	}

	verdict := "suspicious"
	if tr.HasSeverity(trace.SeverityCritical) {
		verdict = "dangerous"
	}

	fmt.Fprintf(a.Stdout, "\n%s\n", a.heading(rule))
	fmt.Fprintf(a.Stdout, "  RISK: %s  (%d finding(s))\n", a.riskText(verdict), len(findings))
	fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", a.completenessText(string(summary.Completeness)))
	fmt.Fprintf(a.Stdout, "%s\n", a.heading(rule))
	a.printCoverage()

	for i, e := range findings {
		findingLabel := a.warning("[FINDING]")
		if e.Severity == trace.SeverityCritical {
			findingLabel = a.danger("[FINDING]")
		}
		fmt.Fprintf(a.Stdout, "\n  %s %d  [%s] %s\n", findingLabel, i+1, strings.ToUpper(string(e.Severity)), terminalSafe(e.Summary))
		if ev, ok := e.Detail["evidence"].(string); ok && ev != "" {
			fmt.Fprintf(a.Stdout, "     %s %s\n", a.muted("evidence :"), terminalSafe(ev))
		}
		fmt.Fprintf(a.Stdout, "     observed : +%dms during %s\n", e.Elapsed.Milliseconds(), orDash(e.During))
		fmt.Fprintf(a.Stdout, "     source   : %s\n", e.Source)
	}
	a.printObservations(observations)
	fmt.Fprintf(a.Stdout, "\n%s\n", a.heading(rule))
	return a.finalizeReport(tr, exitFindings)
}

func (a *App) printCoverage() {
	var completed int
	for _, scenario := range a.scanScenarios {
		if scenario.Outcome == assessment.OutcomePass ||
			scenario.Outcome == assessment.OutcomeFinding {
			completed++
		}
	}
	fmt.Fprintf(a.Stdout, "  %s: %d/%d scenario(s) completed\n", a.heading("Coverage"),
		completed, len(a.scanScenarios))
	for _, scenario := range a.scanScenarios {
		if scenario.Outcome == assessment.OutcomePass ||
			scenario.Outcome == assessment.OutcomeFinding {
			continue
		}
		fmt.Fprintf(a.Stdout, "    - %s: %s", scenario.ID, scenario.Outcome)
		if scenario.Reason != "" {
			fmt.Fprintf(a.Stdout, " (%s)", terminalSafe(scenario.Reason))
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

// exitForScan maps a scan to the semantic exit code — findings first, then the
// completeness rule. It is the single source of truth shared by the live report
// (reportMachine) and the saved-bundle replay (runSavedReport), so replaying a
// stored result can never disagree with the live run about whether findings or
// incompleteness matter. A saved report full of findings must not exit 0.
func (a *App) exitForScan(s report.Scan) int {
	if s.Counts.Critical > 0 || s.Counts.Notable > 0 {
		return exitFindings
	}
	return a.exitForSummary(assessment.Summary{Risk: s.Risk, Completeness: s.Completeness})
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

	return a.exitForScan(s)
}

const maxFailureMessageBytes = 4096
const failureTruncationMarker = "...[truncated]"

func normalizeFailureMessage(message string) string {
	if message == "" {
		message = "unknown failure"
	}
	message = strings.Join(strings.Fields(strings.ToValidUTF8(message, "?")), " ")
	if len(message) > maxFailureMessageBytes {
		message = strings.ToValidUTF8(
			message[:maxFailureMessageBytes-len(failureTruncationMarker)], "",
		) + failureTruncationMarker
	}
	return message
}

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
	message := ""
	if err != nil {
		message = err.Error()
	}
	// Error text can contain target-controlled stderr. Keep it on one line so
	// it cannot forge terminal log records, and repair invalid UTF-8 before
	// serializing it into JSON/SARIF.
	message = normalizeFailureMessage(message)
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

	fmt.Fprintf(a.Stderr, "%s %s failed [%s]: %s\n", a.danger("[FAILED] detonate:"), phase, code, message)
	if a.format == "json" || a.format == "sarif" {
		if code := a.reportMachine(nil); code == exitFailure {
			// reportMachine returning failure can mean either that it correctly
			// summarized a harness failure or that serialization failed. The
			// externally visible result is still the requested failure code.
		}
	} else {
		summary := assessment.Summarize(nil, a.scanScenarios)
		const rule = "  ----------------------------------------------------------------"
		fmt.Fprintf(a.Stdout, "\n%s\n", a.heading(rule))
		fmt.Fprintf(a.Stdout, "  RISK: %s\n", a.riskText(string(summary.Risk)))
		fmt.Fprintf(a.Stdout, "  COMPLETENESS: %s\n", a.completenessText(string(summary.Completeness)))
		fmt.Fprintf(a.Stdout, "  FAILURE: %s\n", a.danger(phase+"/"+code))
		fmt.Fprintf(a.Stdout, "%s\n", a.heading(rule))
		a.printCoverage()
	}
	return a.finalizeReport(nil, exitCode)
}

// configureSave resets the per-run bundle state. An explicit directory is
// enough to opt in, so scripts need not repeat both flags.
func (a *App) configureSave(save bool, directory string) {
	a.saveRequested = save || directory != ""
	a.saveDir = directory
	a.saveFinalized = false
}

func (a *App) finalizeReport(tr *trace.Trace, exitCode int) int {
	if !a.saveRequested || a.saveFinalized {
		return exitCode
	}
	a.saveFinalized = true
	scan := report.Build(tr, a.scanScenarios, a.scanTools, a.scanTarget, Version,
		a.scanFailures...)
	path, err := bundle.Save(bundle.Options{
		Directory:        a.saveDir,
		Target:           a.scanTarget,
		Version:          Version,
		DetonateCommit:   Commit,
		DetonateModified: BuildModified,
		RepositoryURL:    a.scanRepositoryURL,
		Subpath:          a.scanSubpath,
		Revision:         a.scanRevision,
		SandboxImage:     a.scanSandboxImage,
		Report:           scan,
	})
	if err != nil {
		fmt.Fprintf(a.Stderr, "%s report failed [report_save_failed]: %s\n",
			a.danger("[FAILED] detonate:"), terminalSafe(err.Error()))
		return exitFailure
	}
	writer := a.Stdout
	if (a.format == "json" || a.format == "sarif") && a.outFile == "" {
		// Never append status text to a machine document on stdout.
		writer = a.Stderr
	}
	fmt.Fprintf(writer, "  %s %s\n", a.success("[SAVED]"), terminalSafe(path))
	return exitCode
}

// progress routes pipeline milestones to the terminal.
//
// The pipeline announces each step but does not know where output goes, which
// is what keeps it usable when the caller is a JSON stream, a test, or another
// program rather than a person watching a scan run.
func (a *App) progress() scan.Progress {
	return func(msg string) { fmt.Fprintln(a.Stdout, a.active("[SCAN]")+" "+strings.TrimSpace(msg)) }
}

// failPipeline turns a failed scan into the same structured report a
// successful one produces.
//
// A scan that died in acquisition and a scan that found nothing must never
// look alike, so the phase attribution the pipeline attached to the error is
// carried through to the report rather than flattened into "it broke".
func (a *App) failPipeline(err error) int {
	var scanErr *scan.Error
	if errors.As(err, &scanErr) {
		return a.failScan(scanErr.Phase, scanErr.Code, scanErr.Outcome,
			scanErr.Retryable, scanErr.Err, exitFailure)
	}
	return a.failScan("execute", "scan_failed",
		assessment.OutcomeHarnessError, false, err, exitFailure)
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
	fmt.Fprintf(a.Stdout, "\n  %s\n", a.warning("[OBSERVATIONS] context, not findings"))
	for _, e := range observations {
		fmt.Fprintf(a.Stdout, "    - %s\n", terminalSafe(e.Summary))
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

func (a *App) printTools(tools []toolinfo.ToolInfo) {
	fmt.Fprintf(a.Stdout, "\n  %s %d tool(s):\n", a.heading("discovered"), len(tools))
	for _, t := range tools {
		fmt.Fprintf(a.Stdout, "    %s\n", terminalSafe(t.String()))
	}
}
