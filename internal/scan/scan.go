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
	"errors"
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
	// Install fetches dependencies in a separate networked container with
	// scripts disabled, then runs target-controlled lifecycle/build hooks in an
	// offline non-root container.
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

	// Budget is the ceiling on the whole scan. Zero means DefaultBudget; a
	// negative value disables the ceiling, which is for interactive debugging
	// and should never be what CI runs.
	Budget time.Duration
}

// DefaultBudget bounds a whole scan.
//
// Per-phase timeouts already existed in about twenty places, and none of them
// bounded the total: a target that stalled just under every individual limit,
// or a pipeline that looped between phases, could run until something else
// killed it. In CI that is worse than a failure, because a job that hangs
// blocks a queue and gets the tool removed rather than debugged.
//
// Fifteen minutes is well past the slowest observed real scan — dependency
// acquisition plus probing on a fourteen-tool server runs in about thirty
// seconds — while staying under the default job timeout on common CI runners,
// so detonate reports the timeout itself instead of being killed and leaving no
// verdict at all.
const DefaultBudget = 15 * time.Minute

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
	Failures  []Failure

	// Reference is the start command actually used. Acquisition can rewrite
	// it: a TypeScript project's entry point does not exist on disk until its
	// build has run, so what finally launched is not always what was detected.
	Reference string
}

// Failure is a structured pipeline failure that occurred after enough of the
// scan completed to return a report. Keeping it beside the scenarios lets the
// CLI serialize teardown failures without turning them into findings or
// discarding the evidence already collected.
type Failure struct {
	Phase     string
	Code      string
	Message   string
	Retryable bool
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

func harnessError(phase, code string, retryable bool, err error) error {
	return &Error{
		Phase: phase, Code: code, Outcome: assessment.OutcomeHarnessError,
		Retryable: retryable, Err: err,
	}
}

// Run executes one scan and returns what it observed.
//
// The returned error is a *Error whenever the pipeline reached a phase and
// failed inside it, so a caller can report which phase died without matching
// on error strings.
func Run(ctx context.Context, req Request, p Progress) (*Report, error) {
	budget := req.Budget
	if budget == 0 {
		budget = DefaultBudget
	}
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	report, err := runKind(ctx, req, p)

	// A scan that did not finish under its own power must say so, and must not
	// look like a pass. Checked after the run rather than instead of it: the
	// pipeline may have produced real evidence before it was stopped, and
	// throwing that away would lose findings that were already proven.
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return withBudgetExceeded(report, req, budget), nil
	case errors.Is(ctx.Err(), context.Canceled):
		return withCancelled(report, req), nil
	}
	return report, err
}

func runKind(ctx context.Context, req Request, p Progress) (*Report, error) {
	if req.Target.Kind == target.KindMCP {
		return runMCP(ctx, req, p)
	}
	return runSkill(ctx, req, p)
}

// withBudgetExceeded records the ceiling as a failed required scenario, so
// completeness collapses and no exit path can report success.
func withBudgetExceeded(report *Report, req Request, budget time.Duration) *Report {
	if report == nil {
		report = &Report{Reference: req.Target.Reference}
	}
	reason := "scan exceeded its total budget of " + budget.String()

	report.Scenarios = append(report.Scenarios, assessment.ScenarioResult{
		ID:       "pipeline.budget",
		Required: true,
		Outcome:  assessment.OutcomeTimeout,
		Reason:   reason,
	})
	report.Failures = append(report.Failures, Failure{
		Phase: "budget", Code: "scan_budget_exceeded",
		Message: reason, Retryable: true,
	})
	return report
}

// withCancelled records an interrupted run the same way an overrun is
// recorded, so a scan stopped from outside cannot report success either.
//
// Cancellation reaches here after the pipeline has already unwound: the probe
// loop checks the context between payloads and returns what it had, marking
// the tool it was on as timed out and the rest as skipped. Those alone are
// indistinguishable from a slow target, so without this scenario a reader has
// to infer an interruption from the shape of the results.
//
// The outcome is timeout rather than skipped deliberately. Skipped only narrows
// coverage, and an interrupted scan has not narrowed the coverage question, it
// has abandoned it — which is the distinction completeness turns into
// inconclusive rather than partial.
func withCancelled(report *Report, req Request) *Report {
	if report == nil {
		report = &Report{Reference: req.Target.Reference}
	}
	const reason = "scan cancelled before it finished"

	report.Scenarios = append(report.Scenarios, assessment.ScenarioResult{
		ID:       "pipeline.cancelled",
		Required: true,
		Outcome:  assessment.OutcomeTimeout,
		Reason:   reason,
	})
	report.Failures = append(report.Failures, Failure{
		Phase: "cancelled", Code: "scan_cancelled",
		Message: reason, Retryable: true,
	})
	return report
}

// newTrace starts an evidence record for a target. Elapsed times in every
// event are relative to this moment, which is what makes two runs comparable.
func newTrace(reference string) *trace.Trace {
	return &trace.Trace{Target: reference, Started: time.Now()}
}
