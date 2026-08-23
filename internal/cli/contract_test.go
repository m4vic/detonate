package cli

import (
	"testing"

	"github.com/m4vic/detonate/internal/assessment"
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
