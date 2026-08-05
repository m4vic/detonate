// Package scan runs one target through the detonation pipeline.
//
// It acquires dependencies, launches the target in a sandbox, enumerates what
// it exposes, and provokes it with hostile input — returning everything it
// observed. It does no printing, reads no flags, and chooses no exit code.
// Those belong to whoever called it.
//
// The split exists because the pipeline used to live inside the CLI package,
// where the only way to run a scan was to build a slice of command-line flags
// and hand it back to the flag parser. Options crossed that boundary as
// strings the compiler could not check, and the engine could not be used by
// anything that was not a terminal.
package scan

import (
	"context"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Stages selects which parts of the pipeline run.
//
// Named for what they DO rather than what they skip, so a zero value is the
// safe, fast, static-only scan. A caller that forgets to set a field gets less
// execution, never more — which is the right direction for a package whose job
// is running untrusted code.
type Stages struct {
	// Install runs the target's package manager first, in a separate
	// container that has network access. Target-controlled lifecycle and
	// build hooks may execute there.
	Install bool

	// Probe calls every schema-reachable tool with adversarial arguments.
	Probe bool

	// RunScripts executes a skill's bundled scripts inside the sandbox.
	RunScripts bool
}

// Request is one scan.
//
// Target is already resolved: the caller has decided what this thing is and,
// for a remote target, has already cloned it. Detection and fetching are the
// caller's job because they are how a person names a target, and this package
// deals in targets that have been named.
type Request struct {
	Target target.Target

	// MountDir is the host directory holding an MCP server. It is mounted
	// read-only at /target inside the sandbox, which is why a caller's --cmd
	// refers to /target paths rather than host ones.
	MountDir string

	Stages Stages
}

// Report is everything one scan observed.
//
// Trace is the evidence and the only thing a verdict may be derived from.
// Scenarios record what was attempted, including what could not be completed,
// so that "nothing is wrong" stays distinguishable from "almost nothing was
// tested".
type Report struct {
	Tools     []toolinfo.ToolInfo
	Trace     *trace.Trace
	Scenarios []assessment.ScenarioResult

	// Reference is the start command actually used. Acquisition can rewrite
	// it: a TypeScript project's entry point does not exist on disk until its
	// build has run, so what finally launched is not always what was detected.
	Reference string
}

// Progress reports pipeline milestones as they happen.
//
// A scan can take minutes and spends most of it doing things the user should
// be told about — installing dependencies with the network on, launching
// untrusted code. Silence during that is alarming, so the pipeline announces
// each step and lets the caller decide whether a terminal, a log, or nothing
// at all is listening.
type Progress func(string)

func (p Progress) step(msg string) {
	if p != nil {
		p(msg)
	}
}

// Error attributes a failure to a pipeline phase.
//
// A scan that dies partway through still has to produce a report, or an early
// failure becomes indistinguishable from a clean result. Phase and Code are
// stable strings a CI consumer can match on; Outcome decides how the failure
// scores against completeness.
type Error struct {
	Phase     string
	Code      string
	Outcome   assessment.Outcome
	Retryable bool
	Err       error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// targetError attributes a failure to the target rather than to detonate.
// The distinction matters: a broken target is a result, a broken harness is a
// bug in this tool, and a report that confuses them sends the reader to the
// wrong place.
func targetError(phase, code string, retryable bool, err error) error {
	return &Error{
		Phase: phase, Code: code, Outcome: assessment.OutcomeTargetError,
		Retryable: retryable, Err: err,
	}
}

// Run executes one scan and returns what it observed.
//
// The returned error is a *Error whenever the pipeline reached a phase and
// failed inside it, so a caller can report which phase died without matching
// on error strings.
func Run(ctx context.Context, req Request, p Progress) (*Report, error) {
	if req.Target.Kind == target.KindMCP {
		return runMCP(ctx, req, p)
	}
	return runSkill(ctx, req, p)
}

// newTrace starts an evidence record for a target. Elapsed times in every
// event are relative to this moment, which is what makes two runs comparable.
func newTrace(reference string) *trace.Trace {
	return &trace.Trace{Target: reference, Started: time.Now()}
}
