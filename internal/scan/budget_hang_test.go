package scan

import (
	"context"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/dockertest"
	"github.com/m4vic/detonate/internal/target"
)

// The half of the budget guarantee the nanosecond test cannot reach: a target
// that actually launches and then hangs is killed by the total budget, under a
// real deadline, and reported — not left to run until something else stops it.
//
// TestBudgetExceededIsReportedAndNeverLooksClean spends the budget before any
// phase runs, so it proves the reporting collapse but never exercises the
// interruption. This launches `sleep 600` as an MCP server — it accepts the
// container but never speaks the protocol — under a 5s budget, which is well
// below the 30s handshake timeout. So the thing that stops it can only be the
// budget, and the proof is in the clock: the call returns in seconds, not the
// 600 the target would otherwise sleep.
func TestHangingTargetIsKilledByTheBudgetAndReported(t *testing.T) {
	dockertest.Require(t)

	const budget = 5 * time.Second

	start := time.Now()
	report, err := Run(context.Background(), Request{
		Target: target.Target{Kind: target.KindMCP, Reference: "sleep 600"},
		Budget: budget,
		Stages: Stages{Probe: true},
	}, nil)
	elapsed := time.Since(start)

	// A budget overrun is a reported outcome, not an error return — same
	// contract as the already-spent-budget test.
	if err != nil {
		t.Fatalf("a budget overrun must be reported, not returned as an error: %v", err)
	}
	if report == nil {
		t.Fatal("no report produced")
	}

	// The clock is the real proof. Generous slack for image start and the 5s
	// teardown grace, but far under the 30s handshake timeout — so this bound
	// can only hold if the budget itself did the killing.
	if elapsed > 25*time.Second {
		t.Fatalf("scan took %s under a %s budget; it was not killed by the budget "+
			"but by something slower (or not at all)", elapsed, budget)
	}

	var found bool
	for _, s := range report.Scenarios {
		if s.ID == "pipeline.budget" {
			found = true
			if s.Outcome != assessment.OutcomeTimeout {
				t.Errorf("budget scenario outcome = %q, want timeout", s.Outcome)
			}
			if !s.Required {
				t.Error("the budget scenario must be required, or it cannot collapse completeness")
			}
		}
	}
	if !found {
		t.Fatalf("a target killed by the budget produced no pipeline.budget scenario: %+v",
			report.Scenarios)
	}

	// And it must not look like a pass: a scan stopped mid-flight has not
	// established coverage.
	summary := assessment.Summarize(nil, report.Scenarios)
	if summary.Completeness == assessment.CompletenessComplete {
		t.Fatalf("a target killed by the budget reported complete coverage")
	}
}
