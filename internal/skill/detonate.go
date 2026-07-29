package skill

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/sandbox"
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
func DetonateScripts(ctx context.Context, dir string, sk Skill, policy sandbox.Policy) []trace.Event {
	var events []trace.Event

	for _, script := range sk.Scripts {
		cmd, ok := interpreterFor(script)
		if !ok {
			events = append(events, trace.Event{
				Kind: trace.KindProcess, Severity: trace.SeverityInfo, At: time.Now(),
				Summary: fmt.Sprintf("bundled script %q has no known interpreter; not run", script),
				During:  "skill-detonation", Source: "skill-runner",
			})
			continue
		}
		events = append(events, runScript(ctx, dir, script, cmd, policy)...)
	}
	return events
}

// scriptTimeout bounds one script. Short on purpose: a bundled helper that
// has not finished in this long is either waiting for input it will never get
// or doing something it was not asked to do, and both are results.
const scriptTimeout = 30 * time.Second

func runScript(ctx context.Context, dir, script string, argv []string, policy sandbox.Policy) []trace.Event {
	p := policy
	p.Timeout = scriptTimeout

	name, err := sandbox.NewName()
	if err != nil {
		return nil
	}

	mounts := []sandbox.Mount{{
		HostPath: dir, ContainerPath: "/skill",
		// Read-only: a script that rewrites its own skill mid-scan would make
		// the evidence disagree with the artifact on disk.
		ReadOnly: true,
	}}

	runCtx, cancel := context.WithTimeout(ctx, scriptTimeout+30*time.Second)
	defer cancel()

	c, err := sandbox.Start(runCtx, name, p, mounts, argv)
	if err != nil {
		return []trace.Event{{
			Kind: trace.KindProcess, Severity: trace.SeverityInfo, At: time.Now(),
			Summary: fmt.Sprintf("could not run bundled script %q", script),
			During:  "skill-detonation", Source: "skill-runner",
			Detail: map[string]any{"evidence": err.Error()},
		}}
	}
	defer c.Close()

	// Drain stdout so the script is not blocked writing into a full pipe, and
	// wait for it to finish or hit its budget.
	done := make(chan struct{})
	go func() { _, _ = io.ReadAll(c.Stdout()); close(done) }()
	select {
	case <-done:
	case <-time.After(scriptTimeout):
	}

	during := "skill-detonation:" + script
	events := monitor.Analyze(c.Stderr(), during)

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
	return events
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
