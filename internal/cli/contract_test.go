package cli

import (
	"testing"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/report"
)

// The frozen contract.
//
// Exit codes are what a CI job actually gates on, and they are the one thing a
// consumer cannot adapt to after the fact: a pipeline that treats 3 as "found
// something" silently changes meaning if 3 ever becomes something else. Nothing
// else detonate exposes has that property — flags can be added, report fields
// can grow, output can be reformatted — so these five numbers are pinned here
// deliberately, and changing one is a breaking release, not a patch.
//
// This test exists to fail loudly during review rather than quietly in someone
// else's pipeline.
func TestExitCodesAreFrozen(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"clean", exitOK, 0},
		{"scan failed", exitFailure, 1},
		{"usage or environment", exitUsage, 2},
		{"findings", exitFindings, 3},
		{"incomplete coverage", exitIncomplete, 4},
	} {
		if tc.got != tc.want {
			t.Errorf("exit code for %s is %d, want %d — this is a breaking change "+
				"to the published contract, not an implementation detail",
				tc.name, tc.got, tc.want)
		}
	}
}

// The distinction the whole contract rests on: "the tool broke" and "the tool
// caught something" must never be the same number, or a pipeline cannot tell a
// detonate bug from a real finding in the target.
func TestFailureAndFindingsAreDistinct(t *testing.T) {
	if exitFailure == exitFindings {
		t.Fatal("a broken scan and a scan with findings share an exit code")
	}
	if exitIncomplete == exitOK {
		t.Fatal("incomplete coverage shares an exit code with a clean result")
	}
}

// A scan that assessed nothing must not exit 0.
//
// Measured on four real community MCP servers — blender-mcp, Gmail-MCP-Server,
// mcp-playwright, mcp-atlassian. None ships an MCPB manifest, so static mode
// had no inventory to read and every one returned not_assessed / inconclusive
// and exit 0. A CI job reads 0 as "safe to merge", so the tool was reporting
// green on four targets it had learned nothing about.
//
// Partial coverage is a different case and still exits 0: something was
// genuinely assessed and nothing was found. The line is "was anything examined
// at all", not "was everything examined".
func TestAnUnassessedTargetDoesNotExitClean(t *testing.T) {
	for _, tc := range []struct {
		name           string
		risk           assessment.Risk
		completeness   assessment.Completeness
		failIncomplete bool
		want           int
	}{
		{"nothing assessed", assessment.RiskNotAssessed, assessment.CompletenessInconclusive, false, exitIncomplete},
		{"nothing assessed, flag set", assessment.RiskNotAssessed, assessment.CompletenessInconclusive, true, exitIncomplete},
		{"partial coverage, nothing found", assessment.RiskNoFindings, assessment.CompletenessPartial, false, exitOK},
		{"partial coverage, flag set", assessment.RiskNoFindings, assessment.CompletenessPartial, true, exitIncomplete},
		{"complete and clean", assessment.RiskNoFindings, assessment.CompletenessComplete, false, exitOK},
		{"harness broke", assessment.RiskNotAssessed, assessment.CompletenessFailed, false, exitFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{failIncomplete: tc.failIncomplete}
			got := app.exitForSummary(assessment.Summary{
				Risk: tc.risk, Completeness: tc.completeness,
			})
			if got != tc.want {
				t.Errorf("exit = %d, want %d", got, tc.want)
			}
		})
	}
}

// Fault injection at every phase boundary.
//
// The rule this file exists to defend is "never exit 0 without a verdict", and
// the cases that broke it were never the obvious ones. Nothing was assessed is
// easy to catch. The dangerous shape is a scan that assessed something, formed
// a clean risk from it, and then fell apart — because risk stays no_findings
// while coverage quietly becomes unanswerable.
//
// Each case below builds the scenarios the pipeline genuinely produces at that
// boundary, summarizes them the way a live run does, and drives the result
// through exitForScan, the same function the live report and the saved-bundle
// replay both call. Asserting on exitForSummary alone would not prove the
// chain from scenarios to exit code.
func TestNoPhaseBoundaryExitsClean(t *testing.T) {
	// One tool was probed and behaved. This is what makes every case below
	// dangerous rather than trivially caught: risk is no_findings, not
	// not_assessed, so the pre-existing "nothing was assessed" guard does not
	// fire on any of them.
	probed := assessment.ScenarioResult{
		ID: "mcp.tool.read_file", Required: true, Outcome: assessment.OutcomePass,
	}
	unreached := assessment.ScenarioResult{
		ID: "mcp.tool.write_file", Required: true, Outcome: assessment.OutcomeSkipped,
		Reason: "the target process died before this tool was probed",
	}

	for _, tc := range []struct {
		name      string
		scenarios []assessment.ScenarioResult
		want      int
	}{
		{
			// Ctrl-C, or any caller abandoning the run. scan.withCancelled
			// records this scenario; without it the report carries only a
			// timeout and some skips, which reads as a slow target.
			name: "cancelled part-way through",
			scenarios: []assessment.ScenarioResult{probed, {
				ID: "pipeline.cancelled", Required: true,
				Outcome: assessment.OutcomeTimeout,
				Reason:  "scan cancelled before it finished",
			}, unreached},
			want: exitIncomplete,
		},
		{
			// The scan hit its own ceiling. Recorded by scan.withBudgetExceeded.
			name: "total budget exceeded",
			scenarios: []assessment.ScenarioResult{probed, {
				ID: "pipeline.budget", Required: true,
				Outcome: assessment.OutcomeTimeout,
				Reason:  "scan exceeded its total budget of 15m0s",
			}, unreached},
			want: exitIncomplete,
		},
		{
			// A payload killed the server and the remaining tools were never
			// reached. Measured on a real registry server in the v0.4.1 corpus
			// run, where it exited 0.
			name: "target died under a payload",
			scenarios: []assessment.ScenarioResult{probed, {
				ID: "mcp.tool.search", Required: true,
				Outcome: assessment.OutcomeTargetError,
				Reason:  "the target process died under this payload",
			}, unreached},
			want: exitIncomplete,
		},
		{
			// The sandbox outlived the scan. This one is exit 1, not 4: a
			// container we could not remove is detonate's failure, not a
			// statement about the target's coverage.
			name: "teardown failed",
			scenarios: []assessment.ScenarioResult{probed, {
				ID: "pipeline.teardown", Required: true,
				Outcome: assessment.OutcomeTeardownError,
				Reason:  "sandbox still exists",
			}},
			want: exitFailure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary := assessment.Summarize(nil, tc.scenarios)
			if summary.Risk != assessment.RiskNoFindings {
				t.Fatalf("risk = %q, want no_findings — this case is only "+
					"meaningful if the not_assessed guard does NOT catch it",
					summary.Risk)
			}

			app := &App{}
			got := app.exitForScan(report.Scan{
				Risk: summary.Risk, Completeness: summary.Completeness,
			})

			if got == exitOK {
				t.Fatalf("a scan that %s exited 0 with completeness %q — CI "+
					"reads 0 as safe to merge", tc.name, summary.Completeness)
			}
			if got != tc.want {
				t.Errorf("exit = %d, want %d (completeness %q)",
					got, tc.want, summary.Completeness)
			}
		})
	}
}

// The boundary the rule above must NOT cross.
//
// Partial coverage means the coverage question was answered and the answer was
// "some of it" — an unsupported tool, a scenario that could not apply. Failing
// those by default would fire on almost every real server and get the workflow
// deleted, which is the failure mode that ends adoption. --fail-incomplete
// exists for authors who want the stricter gate.
func TestPartialCoverageStillExitsClean(t *testing.T) {
	scenarios := []assessment.ScenarioResult{
		{ID: "mcp.tool.read_file", Required: true, Outcome: assessment.OutcomePass},
		{ID: "mcp.tool.no_args", Required: true, Outcome: assessment.OutcomeUnsupported,
			Reason: "tool takes no arguments, so there is nothing to probe"},
	}

	summary := assessment.Summarize(nil, scenarios)
	if summary.Completeness != assessment.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial", summary.Completeness)
	}

	app := &App{}
	if got := app.exitForScan(report.Scan{
		Risk: summary.Risk, Completeness: summary.Completeness,
	}); got != exitOK {
		t.Errorf("partial coverage with nothing found exited %d, want 0", got)
	}
}

// Fault injection at every phase boundary. None of them may exit 0.
//
// This is the check item 7 is actually about, and it runs the real assessment
// layer rather than hand-picked summaries: the scenario sets below are the
// shapes the pipeline genuinely produces, and completeness is computed from
// them. A change to how an outcome scores lands here as a failure, which is the
// point — the mapping from "something went wrong" to "the build fails" is the
// contract, not any one function along the way.
//
// The two clean cases at the end are load-bearing. A rule that fails everything
// is as useless as one that passes everything, and "partial coverage still
// exits 0" is a promise made in the README.
func TestNoFaultAtAnyPhaseBoundaryExitsClean(t *testing.T) {
	pass := func(id string) assessment.ScenarioResult {
		return assessment.ScenarioResult{ID: id, Required: true, Outcome: assessment.OutcomePass}
	}
	with := func(id string, outcome assessment.Outcome) assessment.ScenarioResult {
		return assessment.ScenarioResult{ID: id, Required: true, Outcome: outcome}
	}

	for _, tc := range []struct {
		name      string
		scenarios []assessment.ScenarioResult
		clean     bool
	}{{
		// Ctrl-C partway through probing: the tool in flight times out, the
		// ones behind it are never reached.
		name: "cancelled mid-probe",
		scenarios: []assessment.ScenarioResult{
			pass("mcp.tool.read"), with("mcp.tool.write", assessment.OutcomeTimeout),
			with("mcp.tool.list", assessment.OutcomeSkipped),
			with("pipeline.cancelled", assessment.OutcomeTimeout),
		},
	}, {
		// The whole-scan ceiling fired.
		name: "total budget exceeded",
		scenarios: []assessment.ScenarioResult{
			pass("mcp.tool.read"), with("pipeline.budget", assessment.OutcomeTimeout),
		},
	}, {
		// A payload killed the target and the remaining tools were never
		// probed. This is the v0.4.1 corpus case that exited 0.
		name: "target died under a payload",
		scenarios: []assessment.ScenarioResult{
			pass("mcp.tool.read"), with("mcp.tool.write", assessment.OutcomeTargetError),
			with("mcp.tool.list", assessment.OutcomeSkipped),
		},
	}, {
		// The scan itself completed; the sandbox could not be torn down.
		name: "teardown failed",
		scenarios: []assessment.ScenarioResult{
			pass("mcp.tool.read"), with("pipeline.teardown", assessment.OutcomeTeardownError),
		},
	}, {
		name:      "nothing ran at all",
		scenarios: []assessment.ScenarioResult{with("mcp.inventory", assessment.OutcomeUnsupported)},
	}, {
		name:      "everything passed",
		scenarios: []assessment.ScenarioResult{pass("mcp.tool.read"), pass("mcp.tool.write")},
		clean:     true,
	}, {
		name: "partial coverage, nothing found",
		scenarios: []assessment.ScenarioResult{
			pass("mcp.tool.read"), with("mcp.tool.write", assessment.OutcomeUnsupported),
		},
		clean: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			summary := assessment.Summarize(nil, tc.scenarios)
			got := (&App{}).exitForSummary(summary)

			if tc.clean && got != exitOK {
				t.Fatalf("exit = %d, want 0 — risk=%s completeness=%s",
					got, summary.Risk, summary.Completeness)
			}
			if !tc.clean && got == exitOK {
				t.Fatalf("a scan that hit %q exited 0 — risk=%s completeness=%s; "+
					"CI reads 0 as safe to merge", tc.name, summary.Risk, summary.Completeness)
			}
		})
	}
}
