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
	"time"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/baseline"
	"github.com/m4vic/detonate/internal/environment"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/mcpdriver"
	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/probe"
	"github.com/m4vic/detonate/internal/report"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Version is overwritten at build time by the release workflow's ldflags, so
// a downloaded binary reports the tag it was cut from rather than whatever
// string happened to be committed. A var, not a const: the linker cannot
// rewrite a constant.
var Version = "dev"

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

	// format and outFile carry the machine-readable output selection through
	// to reporting. Fields rather than parameters because report() is called
	// from several paths (prompt, skill, MCP) and threading two more arguments
	// through each of them would obscure what those functions are for.
	format  string
	outFile string

	// docOut is where the JSON or SARIF document goes once progress output has
	// been silenced. Without it the document would be written to the same
	// io.Discard that suppressed the chatter.
	docOut io.Writer

	// scanTarget and scanTools describe the current scan, needed to build a
	// complete document rather than just a list of findings.
	scanTarget string
	scanTools  []toolinfo.ToolInfo

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
		CheckDocker: environment.CheckDocker,
	}
}

const usage = `detonate %s

Detonate untrusted AI-connected tools in a sandbox and report what they
actually do, not what their manifest claims.

Usage:
  detonate <target>     Scan a folder, a file, or a repository URL
  detonate              Guided scan

detonate works out what the target is: a folder with SKILL.md is a skill, a
folder with an entry point is an MCP server, a .txt or .md file is a prompt.

Scans are thorough by default. Dependencies are installed in a separate
container that never runs the target, tools are called with adversarial
input, and a skill's bundled scripts are executed in the sandbox.

Options:
  --cmd <command>    Command that starts the server, if detection got it wrong
  --path <sub>       Sub-directory to scan inside a cloned repository
  --quick            Skip install, probes and script execution
  --no-probe         Do not call tools with adversarial input
  --no-install       Do not install dependencies
  --no-scripts       Do not run a skill's bundled scripts
  --no-baseline      Do not compare against the previous scan

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
  0  clean    2  bad usage or environment
  1  error    3  findings
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
		return a.scan(ctx, args[1:])
	case "-":
		// A lone dash is the Unix convention for "read from stdin". Lets a
		// user check a prompt they were just sent without saving a file:
		// `echo "..." | detonate -` or `detonate - < prompt.txt`.
		return a.scanStdinPrompt()
	}

	if strings.HasPrefix(args[0], "-") {
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

	// The banner is decoration, and decoration on stdout corrupts a JSON or
	// SARIF stream. Printed before RunTarget can silence output, so the check
	// has to happen here.
	if opt.format == "" || opt.format == "text" {
		fmt.Fprint(a.Stdout, banner)
		fmt.Fprintln(a.Stdout)
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

	if err := fs.Parse(args); err != nil {
		return exitUsage
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
			fmt.Fprintf(a.Stderr, "detonate: %v\n", err)
			return exitFailure
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
		fmt.Fprintf(a.Stderr, "detonate: cannot scan: %s\n", status.Detail)
		fmt.Fprintln(a.Stderr, "detonate: detonate requires Docker to sandbox untrusted code. "+
			"Install Docker and make sure the daemon is running.")
		return exitUsage
	}

	// Clear anything a previous run leaked. A scan that died hard (SIGKILL,
	// power loss, a panic of ours) leaves a container with no client attached,
	// and the whole promise of this tool is that untrusted code does not
	// outlive the scan.
	if n := sandbox.ReapOrphans(ctx); n > 0 {
		fmt.Fprintf(a.Stdout, "  cleaned up %d orphaned container(s) from a previous run\n", n)
	}

	tools, tr, err := a.enumerate(ctx, tgt, dir, *install, *doProbe, *runScripts)
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: enumeration failed: %v\n", err)
		return exitFailure
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
		fmt.Fprintln(a.Stdout, "  VERDICT: clean")
		fmt.Fprintln(a.Stdout, "  No suspicious behaviour observed while enumerating this target.")
		fmt.Fprintf(a.Stdout, "%s\n", rule)
		a.printObservations(observations)
		// Say the limit out loud. A scanner that lets "we found nothing" be
		// read as "this is safe" is worse than no scanner, because it converts
		// ignorance into false confidence.
		fmt.Fprintln(a.Stdout, "  Note: this is not proof of safety. Only startup behaviour was")
		fmt.Fprintln(a.Stdout, "  observed, and a target that hides its errors leaves no trace.")
		return exitOK
	}

	verdict := "suspicious"
	if tr.HasSeverity(trace.SeverityCritical) {
		verdict = "dangerous"
	}

	fmt.Fprintf(a.Stdout, "\n%s\n", rule)
	fmt.Fprintf(a.Stdout, "  VERDICT: %s  (%d finding(s))\n", verdict, len(findings))
	fmt.Fprintf(a.Stdout, "%s\n", rule)

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

// reportMachine writes JSON or SARIF and returns the same exit code the
// terminal report would have.
//
// The exit code is deliberately computed the same way regardless of format: a
// pipeline that switches to --format sarif for annotations must not also
// change whether the build passes.
func (a *App) reportMachine(tr *trace.Trace) int {
	s := report.Build(tr, a.scanTools, a.scanTarget, Version)

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
		err = report.SARIF(w, tr, a.sarifURI(), Version)
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
	return exitOK
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

func (a *App) enumerate(ctx context.Context, tgt target.Target, mountDir string, install, doProbe, runScripts bool) ([]toolinfo.ToolInfo, *trace.Trace, error) {
	if tgt.Kind == target.KindMCP {
		policy := sandbox.DefaultPolicy()

		var mounts []sandbox.Mount
		var absDir string
		if mountDir != "" {
			abs, err := filepath.Abs(mountDir)
			if err != nil {
				return nil, nil, fmt.Errorf("resolving --dir: %w", err)
			}
			absDir = abs
			// Read-only, always. A target that can rewrite its own source
			// mid-scan makes the evidence disagree with the artifact, which
			// defeats the point of collecting evidence at all.
			mounts = append(mounts, sandbox.Mount{
				HostPath: abs, ContainerPath: "/target", ReadOnly: true,
			})
		}

		// Phase 1. Runs the PACKAGE MANAGER with a network, never the target.
		// The target's own code only ever executes in phase 2, network off.
		var installed *acquire.Result
		if install {
			if absDir == "" {
				return nil, nil, errors.New("--install needs --dir: there is no target directory to read a manifest from")
			}
			m := acquire.Detect(absDir)
			if m.Ecosystem == acquire.EcosystemNone {
				fmt.Fprintln(a.Stdout, "  no dependency manifest found; skipping install")
			} else {
				fmt.Fprintf(a.Stdout, "  [1/2] installing %s deps from %s "+
					"(separate container, network ON, target NOT executed)\n", m.Ecosystem, m.File)
			}

			res, err := acquire.Install(ctx, absDir, policy)
			if err != nil {
				return nil, nil, err
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
				return nil, nil, err
			}
			// Fold install-time behaviour into the same trace. A postinstall
			// hook that phoned home is a finding about this target, and
			// splitting it into a separate report would let it be overlooked.
			if installed != nil && res.Trace != nil {
				res.Trace.Events = append(installed.Events, res.Trace.Events...)
			}
			return res.Tools, res.Trace, nil
		}

		// Probing keeps the session open: a tool only reveals what it does
		// when it is called, so the container has to outlive tools/list.
		sess, err := mcpdriver.OpenSession(ctx, tgt.Reference, policy, mounts)
		if err != nil {
			return nil, nil, err
		}
		defer sess.Close()

		tools, err := sess.Tools(ctx)
		if err != nil {
			return nil, nil, err
		}

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
		for _, ev := range probe.Run(ctx, sess, tools, 0) {
			tr.Add(ev)
		}
		return tools, tr, nil
	}

	// A skill is mostly a large prompt: its SKILL.md body is text an agent
	// reads and obeys, so the analysis is of the instructions rather than of
	// running code. Reading it needs no container.
	tools, err := skill.Load(tgt.Reference)
	if err != nil {
		return nil, nil, err
	}

	sk, err := skill.LoadSkill(tgt.Reference)
	if err != nil {
		return nil, nil, err
	}

	tr := &trace.Trace{Target: tgt.Reference, Started: time.Now()}
	for _, ev := range skill.Analyze(sk) {
		tr.Add(ev)
	}

	// The dynamic half of skill analysis. SKILL.md is a prompt and can only be
	// read, but the bundled scripts are real programs an agent will execute on
	// the user's machine — and until they run, a script that phones home is
	// indistinguishable from one that formats a table.
	if runScripts && len(sk.Scripts) > 0 {
		fmt.Fprintf(a.Stdout, "  running %d bundled script(s) in the sandbox...\n",
			len(sk.Scripts))
		for _, ev := range skill.DetonateScripts(ctx, tgt.Reference, sk, sandbox.DefaultPolicy()) {
			tr.Add(ev)
		}
	}
	return tools, tr, nil
}

func (a *App) printTools(tools []toolinfo.ToolInfo) {
	fmt.Fprintf(a.Stdout, "\n  discovered %d tool(s):\n", len(tools))
	for _, t := range tools {
		fmt.Fprintf(a.Stdout, "    %s\n", t)
	}
}
