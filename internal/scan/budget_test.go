package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/target"
)

// A scan that runs out of budget must say so and must not look like a pass.
//
// Per-phase timeouts existed in about twenty places and none bounded the total,
// so a target stalling just under every individual limit could run until
// something else killed it. In CI a hung job blocks a queue and gets the tool
// removed rather than debugged, which is worse than a failure.
func TestBudgetExceededIsReportedAndNeverLooksClean(t *testing.T) {
	// A budget already spent: the deadline fires before any phase can run, so
	// this needs no container and no target.
	report, err := Run(context.Background(), Request{
		Target: target.Target{Kind: target.KindMCP, Reference: "sleep 600"},
		Budget: time.Nanosecond,
	}, nil)
	if err != nil {
		t.Fatalf("a budget overrun must be reported, not returned as an error: %v", err)
	}
	if report == nil {
		t.Fatal("no report produced")
	}

	var found bool
	for _, s := range report.Scenarios {
		if s.ID == "pipeline.budget" {
			found = true
			if !s.Required {
				t.Error("the budget scenario is not required, so it cannot affect completeness")
			}
			if s.Outcome != assessment.OutcomeTimeout {
				t.Errorf("budget outcome = %q, want timeout", s.Outcome)
			}
			if !strings.Contains(s.Reason, "budget") {
				t.Errorf("reason does not name the cause: %q", s.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("no pipeline.budget scenario: %+v", report.Scenarios)
	}

	// The verdict layer must collapse: a required timeout means the scan
	// reached no conclusion, whatever else it managed to observe.
	got := assessment.Summarize(nil, report.Scenarios)
	if got.Completeness == assessment.CompletenessComplete {
		t.Fatalf("a scan killed by its own budget reported complete coverage")
	}
}

// Zero means "use the default", not "no ceiling". A caller that forgets to set
// a budget must still get one, since the whole point is that no path runs
// unbounded.
func TestZeroBudgetMeansTheDefault(t *testing.T) {
	if DefaultBudget <= 0 {
		t.Fatal("DefaultBudget must be positive")
	}
	if DefaultBudget > 30*time.Minute {
		t.Fatalf("DefaultBudget of %s is longer than a typical CI job timeout, "+
			"so the runner would kill the job before detonate reported anything",
			DefaultBudget)
	}
}
