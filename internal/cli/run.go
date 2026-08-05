package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/scan"
	"github.com/m4vic/detonate/internal/target"
)

// The primary CLI surface: `detonate <target>`.
//
// The redesign has two ideas behind it.
//
// First, ONE argument. The old form made the user declare the kind up front
// (--mcp, --skill, --prompt) and pass --dir separately for MCP because of the
// container mount path. Both are things detonate can work out by looking, and
// asking a person to classify their folder before the tool will examine it is
// asking them to do its job first.
//
// Second, THOROUGH BY DEFAULT. Dependency installation, adversarial probes and
// running a skill's bundled scripts were opt-in flags, which meant the default
// invocation was the least useful one — a scanner that finds nothing unless
// you already know which switches to throw is a scanner that reports clean to
// everyone who needed it most. Now the slow, complete scan is the default and
// --quick is how you opt out.

// scanOptions are the knobs, all with useful defaults.
type scanOptions struct {
	command        string // override the detected start command
	subPath        string // sub-directory inside a cloned repo
	quick          bool   // skip install, probes and script execution
	noBaseline     bool
	noProbe        bool
	noInstall      bool
	noScripts      bool
	failIncomplete bool

	// format is "text" (default), "json", or "sarif".
	format string
	// out writes machine-readable output to a file instead of stdout, which
	// is what CI needs: the human-readable log stays in the job output while
	// the artifact goes somewhere an upload step can find it.
	out string
}

// RunTarget scans one target, working out for itself what it is.
func (a *App) RunTarget(ctx context.Context, target string, opt scanOptions) int {
	switch opt.format {
	case "", "text", "json", "sarif":
	default:
		fmt.Fprintf(a.Stderr, "  unknown format %q; use text, json, or sarif\n", opt.format)
		return exitUsage
	}
	a.format = opt.format
	a.outFile = opt.out
	a.failIncomplete = opt.failIncomplete
	a.scanScenarios = nil
	a.scanTools = nil
	a.scanFailures = nil
	a.scanTarget = target
	a.scanIdentity = baselineIdentity(target, opt.subPath)

	// Progress chatter would corrupt a JSON stream on stdout. It stays only
	// when the output is for a person, or when the document is going to a file
	// and stdout is free.
	if (a.format == "json" || a.format == "sarif") && a.outFile == "" {
		a.docOut = a.Stdout // the document still needs somewhere real to go
		a.Stdout = io.Discard
	}

	// A remote target is cloned first, then re-detected on the clone: what
	// matters is what is inside the repository, not what the URL looked like.
	if fetch.IsURL(target) {
		fetched, err := fetch.Git(ctx, target)
		if err != nil {
			return a.failScan("fetch", "fetch_failed",
				assessment.OutcomeTargetError, true, err, exitFailure)
		}
		defer fetched.Cleanup()

		root, err := fetched.SubDir(opt.subPath)
		if err != nil {
			fmt.Fprintf(a.Stderr, "  %v\n", err)
			return exitUsage
		}
		fmt.Fprintf(a.Stdout, "  cloned  %s\n", fetched.Source)
		target = root
	}

	d, err := Detect(target)
	if err != nil {
		fmt.Fprintf(a.Stderr, "  %v\n", err)
		return exitUsage
	}
	if opt.command != "" {
		d.Command = opt.command
		d.Kind = KindMCP
	}

	switch d.Kind {
	case KindPrompt:
		fmt.Fprintf(a.Stdout, "  target  %s\n", shorten(d.File))
		fmt.Fprintf(a.Stdout, "  type    prompt (%s)\n\n", d.Why)
		return a.scanPrompt(d.File)

	case KindSkill:
		return a.runSkill(ctx, d, opt)

	case KindMCP:
		return a.runMCP(ctx, d, opt)

	default:
		a.explainUnclassified(shorten(d.Dir), d)
		return exitUsage
	}
}

func (a *App) runSkill(ctx context.Context, d Detected, opt scanOptions) int {
	fmt.Fprintf(a.Stdout, "  target  %s\n", shorten(d.Dir))
	fmt.Fprintf(a.Stdout, "  type    skill (%s)\n", d.Why)

	tgt, err := target.Skill(d.Dir)
	if err != nil {
		fmt.Fprintf(a.Stderr, "  %v\n", err)
		return exitUsage
	}

	// Bundled scripts are the only DYNAMIC part of a skill scan: SKILL.md can
	// only be read, but a script is a program an agent will actually execute.
	// Skipping it by default would leave the most dangerous part unexamined.
	runScripts := d.Scripts > 0 && !opt.quick && !opt.noScripts
	if runScripts {
		fmt.Fprintf(a.Stdout, "  plan    analyse instructions, run %d script(s) in the sandbox\n", d.Scripts)
	} else {
		fmt.Fprintln(a.Stdout, "  plan    analyse instructions only")
	}
	fmt.Fprintln(a.Stdout)

	return a.execute(ctx, tgt, "", scan.Stages{RunScripts: runScripts}, !opt.noBaseline)
}

func (a *App) runMCP(ctx context.Context, d Detected, opt scanOptions) int {
	fmt.Fprintf(a.Stdout, "  target  %s\n", shorten(d.Dir))
	fmt.Fprintf(a.Stdout, "  type    MCP server (%s)\n", d.Why)
	fmt.Fprintf(a.Stdout, "  start   %s\n", d.Command)

	install := d.NeedsInstall && !opt.quick && !opt.noInstall
	probe := !opt.quick && !opt.noProbe

	var plan []string
	if install {
		plan = append(plan, "install deps (network on, target hooks may run)")
	}
	plan = append(plan, "launch sandboxed (network off)")
	if probe {
		plan = append(plan, "probe tools with hostile input")
	}

	fmt.Fprintf(a.Stdout, "  plan    %s\n", strings.Join(plan, ", "))
	if d.NeedsInstall && !install {
		// Say so explicitly: a skipped install usually means the scan fails
		// on an import error, and a user who chose --quick should know why.
		fmt.Fprintf(a.Stdout, "  note    skipping %s; the server may fail to import\n", d.Manifest)
	}
	fmt.Fprintln(a.Stdout)

	return a.execute(ctx, target.MCP(d.Command), d.Dir,
		scan.Stages{Install: install, Probe: probe}, !opt.noBaseline)
}

// bindScanFlags defines the options shared by the positional form.
func bindScanFlags(fs *flag.FlagSet, opt *scanOptions) {
	fs.StringVar(&opt.command, "cmd", "", "Command that starts the server (overrides detection).")
	fs.StringVar(&opt.subPath, "path", "", "Sub-directory to scan inside a cloned repository.")
	fs.BoolVar(&opt.quick, "quick", false, "Skip dependency install, probes and script execution.")
	fs.BoolVar(&opt.noBaseline, "no-baseline", false, "Do not compare against the previous scan.")
	fs.BoolVar(&opt.noProbe, "no-probe", false, "Do not call tools with adversarial input.")
	fs.BoolVar(&opt.noInstall, "no-install", false, "Do not install the target's dependencies.")
	fs.BoolVar(&opt.noScripts, "no-scripts", false, "Do not run a skill's bundled scripts.")
	fs.BoolVar(&opt.failIncomplete, "fail-incomplete", false, "Exit 4 when required coverage is incomplete.")
	fs.StringVar(&opt.format, "format", "text", "Output format: text, json, or sarif.")
	fs.StringVar(&opt.out, "out", "", "Write machine-readable output to this file.")
}

// baselineIdentity names a target stably across runs.
//
// Built from what the user asked for rather than what it resolved to. A local
// path is made absolute so the same folder matches from any working directory;
// a URL is kept as-is because its clone lands somewhere different every run.
// --path is folded in because two packages in one repository are two targets,
// and without it they share a baseline and invent rug-pull findings about each
// other.
func baselineIdentity(target, subPath string) string {
	id := target
	if !fetch.IsURL(target) {
		if abs, err := filepath.Abs(target); err == nil {
			id = abs
		}
	}
	if subPath != "" {
		id += "#" + filepath.ToSlash(subPath)
	}
	return id
}

// shorten trims a long absolute path for display, keeping the tail because
// that is the part a reader recognises.
func shorten(p string) string {
	if len(p) <= 60 {
		return p
	}
	return "..." + string(filepath.Separator) +
		filepath.Join(filepath.Base(filepath.Dir(p)), filepath.Base(p))
}
