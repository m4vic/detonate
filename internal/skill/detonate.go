package skill

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/decoy"
	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/sandbox"
	scenariodef "github.com/m4vic/detonate/internal/scenario"
	"github.com/m4vic/detonate/internal/trace"
)

// DetonateScripts runs a skill's bundled scripts in the sandbox and reports
// what they do.
//
// This is what makes skill analysis dynamic rather than a text search. The
// SKILL.md is a prompt and can only be read, but the bundled scripts are real
// programs that an agent will execute on the user's machine — and until they
// are run, a script that phones home is indistinguishable from one that
// formats a table.
//
// Each script runs alone, with no arguments, in its own container: network
// off, read-only root, non-root, no capabilities. Running them separately
// costs a container per script but keeps attribution exact, which is the whole
// value of the result — "this skill did something" is far less useful than
// "extract.py tried to resolve a hostname".
//
// den is the decoy furnished into every script's home, if the caller planted
// one; nil disables the credential-leak check entirely rather than checking
// against nothing.
func DetonateScripts(ctx context.Context, dir string, sk Skill, policy sandbox.Policy, den *decoy.Environment) []trace.Event {
	return DetonateScriptsWithResults(ctx, dir, sk, policy, den).Events
}

// DetonationResult preserves both the evidence and whether each bundled
// script was actually executed. Unsupported interpreters and startup errors
// therefore reduce completeness instead of disappearing into an info line.
type DetonationResult struct {
	Events    []trace.Event
	Scenarios []assessment.ScenarioResult
}

// DetonateScriptsWithResults runs each script and records one terminal
// scenario outcome per script.
func DetonateScriptsWithResults(
	ctx context.Context,
	dir string,
	sk Skill,
	policy sandbox.Policy,
	den *decoy.Environment,
) DetonationResult {
	var events []trace.Event
	var scenarios []assessment.ScenarioResult

	// Keyed "script|token" so the same secret returned by two scripts is
	// still counted once per script, matching how the MCP probe path keys
	// leaks per tool.
	leaked := map[string]bool{}

	for _, script := range sk.Scripts {
		scenario := assessment.ScenarioResult{
			ID: scenariodef.SkillScriptID(script), Required: true,
		}
		cmd, ok := interpreterFor(script)
		if !ok {
			events = append(events, trace.Event{
				Kind: trace.KindProcess, Severity: trace.SeverityInfo, At: time.Now(),
				Summary: fmt.Sprintf("bundled script %q has no known interpreter; not run", script),
				During:  "skill-detonation", Source: "skill-runner",
			})
			scenario.Outcome = assessment.OutcomeUnsupported
			scenario.Reason = "no supported interpreter is available in the selected runtime profile"
			scenarios = append(scenarios, scenario)
			continue
		}
		scriptEvents, outcome, reason := runScriptWithOutcome(ctx, dir, script, cmd, policy, den, leaked)
		events = append(events, scriptEvents...)
		scenario.Outcome = outcome
		scenario.Reason = reason
		scenarios = append(scenarios, scenario)
	}

	// After every script has run, look for secrets staged to disk. A script
	// that copies a decoy into a file instead of printing it leaks nothing on
	// stdout, so this is the only place that catches it. Runs once over the
	// shared home rather than per script: attribution to one script is lost,
	// but the file and its planted nonce are the evidence that matters.
	events = append(events, fileLeakEvents(den, leaked)...)

	if ev, sc, ok := decoySummary(den, leaked); ok {
		events = append(events, ev)
		scenarios = append(scenarios, sc)
	}

	return DetonationResult{Events: events, Scenarios: scenarios}
}

// fileLeakEvents reports planted secrets found written into the sandbox home,
// registering each into leaked so the coverage summary counts it as returned.
func fileLeakEvents(den *decoy.Environment, leaked map[string]bool) []trace.Event {
	if den == nil {
		return nil
	}
	fileLeaks, err := den.FileLeaks()
	if err != nil || len(fileLeaks) == 0 {
		return nil
	}

	var events []trace.Event
	for _, fl := range fileLeaks {
		key := "file:" + fl.Path + "|" + fl.Hit.Token.Value
		if leaked[key] {
			continue
		}
		leaked[key] = true

		events = append(events, trace.Event{
			Kind: trace.KindFile, Severity: trace.SeverityCritical, At: time.Now(),
			Summary: fmt.Sprintf("a bundled script staged the contents of %s to %s",
				fl.Hit.Token.Path, fl.Path),
			During: "skill-detonation", Source: "decoy",
			Detail: map[string]any{
				"secret":   string(fl.Hit.Token.Kind),
				"path":     fl.Hit.Token.Path,
				"staged":   fl.Path,
				"encoding": fl.Hit.Encoding,
				"evidence": fmt.Sprintf("planted secret %s written to %s %s (nonce %s)",
					fl.Hit.Token.Path, fl.Path, encodingPhrase(fl.Hit.Encoding), fl.Hit.Token.Value),
				"nonce": fl.Hit.Token.Value,
			},
		})
	}
	return events
}

// scriptTimeout bounds one script. Short on purpose: a bundled helper that
// has not finished in this long is either waiting for input it will never get
// or doing something it was not asked to do, and both are results.
const scriptTimeout = 30 * time.Second

func runScript(ctx context.Context, dir, script string, argv []string, policy sandbox.Policy, den *decoy.Environment) []trace.Event {
	events, _, _ := runScriptWithOutcome(ctx, dir, script, argv, policy, den, map[string]bool{})
	return events
}

func runScriptWithOutcome(
	ctx context.Context,
	dir, script string,
	argv []string,
	policy sandbox.Policy,
	den *decoy.Environment,
	leaked map[string]bool,
) ([]trace.Event, assessment.Outcome, string) {
	p := policy
	p.Timeout = scriptTimeout

	name, err := sandbox.NewName()
	if err != nil {
		return nil, assessment.OutcomeHarnessError, err.Error()
	}

	mounts := []sandbox.Mount{{
		HostPath: dir, ContainerPath: "/skill",
		// Read-only: a script that rewrites its own skill mid-scan would make
		// the evidence disagree with the artifact on disk.
		ReadOnly: true,
	}}
	if den != nil {
		// Same mount point the MCP path uses: it replaces the empty tmpfs
		// home, so a script that reads ~/.ssh/id_rsa finds the planted decoy
		// instead of nothing.
		mounts = append(mounts, sandbox.Mount{
			HostPath:      den.HostDir,
			ContainerPath: den.ContainerHome,
			ReadOnly:      false,
		})
	}

	runCtx, cancel := context.WithTimeout(ctx, scriptTimeout+30*time.Second)
	defer cancel()

	c, err := sandbox.Start(runCtx, name, p, mounts, argv)
	if err != nil {
		return []trace.Event{{
			Kind: trace.KindProcess, Severity: trace.SeverityInfo, At: time.Now(),
			Summary: fmt.Sprintf("could not run bundled script %q", script),
			During:  "skill-detonation", Source: "skill-runner",
			Detail: map[string]any{"evidence": err.Error()},
		}}, assessment.OutcomeTargetError, err.Error()
	}
	// Drain stdout into a buffer instead of discarding it: a script that
	// returns a planted secret on stdout (its normal "result" channel, unlike
	// an MCP tool's structured response) has to be caught the same way a tool
	// response is.
	var stdout bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&stdout, c.Stdout()); close(done) }()
	timedOut := false
	select {
	case <-done:
	case <-time.After(scriptTimeout):
		timedOut = true
	}

	var exitErr error
	if !timedOut {
		exitErr = c.ExitError()
	}
	during := "skill-detonation:" + script
	stderr := c.Stderr()
	if err := c.Close(); err != nil {
		return monitor.Analyze(stderr, during), assessment.OutcomeTeardownError, err.Error()
	}
	// Close tears the container down, which closes the stdout pipe and lets
	// the drain goroutine above finish even when it timed out. Waiting here,
	// rather than reading the buffer immediately, is what makes that read
	// race-free.
	<-done

	events := monitor.Analyze(stderr, during)
	events = append(events, decoyLeakEvents(den, leaked, script, stdout.String()+stderr)...)

	// A script that merely EXISTS and runs is worth noting even when it
	// misbehaves in no detectable way, because a reader deciding whether to
	// trust a skill wants to know code executed at all.
	if len(events) == 0 {
		events = append(events, trace.Event{
			Kind: trace.KindProcess, Severity: trace.SeverityInfo, At: time.Now(),
			Summary: fmt.Sprintf("bundled script %q ran with no observable misbehaviour", script),
			During:  during, Source: "skill-runner",
		})
	}
	if timedOut {
		return events, assessment.OutcomeTimeout, "script exceeded its execution budget"
	}
	if exitErr != nil {
		return events, assessment.OutcomeTargetError, exitErr.Error()
	}
	for _, event := range events {
		if event.Severity == trace.SeverityCritical ||
			event.Severity == trace.SeverityNotable {
			return events, assessment.OutcomeFinding, "one or more dynamic findings were observed"
		}
	}
	return events, assessment.OutcomePass, ""
}

// decoyLeakEvents reports any planted secret found in a script's combined
// stdout and stderr, in the same shape probe's decoy check uses for MCP tool
// responses — critical severity, one event per token, keyed so the same
// secret is not reported twice for the same script.
func decoyLeakEvents(den *decoy.Environment, seen map[string]bool, script, output string) []trace.Event {
	if den == nil || output == "" {
		return nil
	}

	var events []trace.Event
	for _, hit := range den.Match(output) {
		key := script + "|" + hit.Token.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		events = append(events, trace.Event{
			Kind: trace.KindFile, Severity: trace.SeverityCritical, At: time.Now(),
			Summary: fmt.Sprintf("bundled script %q returned the contents of %s", script, hit.Token.Path),
			During:  "skill-detonation:" + script, Source: "decoy",
			Detail: map[string]any{
				"script": script,
				"secret": string(hit.Token.Kind),
				"path":   hit.Token.Path,
				// The renderers print "evidence", so the nonce has to live
				// there to be seen. A finding whose proof is buried in a field
				// nobody displays is a finding the reader has to take on trust,
				// which is the opposite of the point.
				"evidence": fmt.Sprintf("planted secret %s returned %s (nonce %s)",
					hit.Token.Path, encodingPhrase(hit.Encoding), hit.Token.Value),
				"encoding": hit.Encoding,
				"nonce":    hit.Token.Value,
			},
		})
	}
	return events
}

// decoySummary states what the credential check actually proved, mirroring
// probe's decoySummary for MCP tools. It always runs once per skill, not per
// script, so a skill with ten clean scripts and one thief reports exactly one
// coverage line rather than ten.
func decoySummary(den *decoy.Environment, leaked map[string]bool) (trace.Event, assessment.ScenarioResult, bool) {
	if den == nil || len(den.Tokens) == 0 {
		return trace.Event{}, assessment.ScenarioResult{}, false
	}

	seen := map[string]bool{}
	for key := range leaked {
		if i := strings.LastIndex(key, "|"); i >= 0 {
			seen[key[i+1:]] = true
		}
	}

	planted := len(den.Tokens)
	untouched := den.Untouched(seen)
	returned := planted - len(untouched)

	kinds := make([]string, 0, planted)
	for _, t := range den.Tokens {
		kinds = append(kinds, string(t.Kind))
	}
	sort.Strings(kinds)

	summary := fmt.Sprintf(
		"planted %d credential decoys in the sandbox; none were returned by any bundled script", planted)
	outcome := assessment.OutcomePass
	if returned > 0 {
		verb := "were"
		if returned == 1 {
			verb = "was"
		}
		summary = fmt.Sprintf(
			"planted %d credential decoys in the sandbox; %d %s returned by a bundled script",
			planted, returned, verb)
		outcome = assessment.OutcomeFinding
	}

	return trace.Event{
		Kind: trace.KindFile, Severity: trace.SeverityInfo, At: time.Now(),
		Summary: summary, During: "skill-detonation", Source: "decoy",
		Detail: map[string]any{
			"planted":  planted,
			"returned": returned,
			"secrets":  strings.Join(kinds, ", "),
		},
	}, assessment.ScenarioResult{
		ID:       "decoy.credential-exfiltration",
		Required: true,
		Outcome:  outcome,
	}, true
}

// encodingPhrase renders how a secret came back, for the evidence line. A
// secret returned base64-encoded was transformed on the way out, which is
// harder to explain away than one returned verbatim.
func encodingPhrase(encoding string) string {
	switch encoding {
	case "plain":
		return "verbatim"
	case "hex":
		return "hex-encoded"
	default:
		return encoding + "-encoded"
	}
}

// interpreterFor maps a script to the command that runs it inside the sandbox.
//
// Only interpreted languages the base image can actually run. A .sh is
// included because skills ship shell helpers constantly, and refusing to run
// the most common kind of bundled script would leave the biggest gap exactly
// where the risk is highest.
func interpreterFor(script string) ([]string, bool) {
	target := "/skill/" + filepath.ToSlash(script)
	switch filepath.Ext(script) {
	case ".py":
		return []string{"python", target}, true
	case ".sh":
		return []string{"sh", target}, true
	case ".js":
		return []string{"node", target}, true
	}
	return nil, false
}
