package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/target"
)

// An interrupted scan must say it was interrupted, and must not look like a
// pass.
//
// Cancellation is quieter than every other failure: the probe loop checks the
// context between payloads and returns cleanly with what it had, so the
// pipeline unwinds without an error and the report reads as a scan that simply
// found less. Only the pipeline-level scenario distinguishes "stopped" from
// "finished quickly".
//
// The context is cancelled before Run is called, so this needs no container and
// no target — the pipeline exits at its first context check whatever phase that
// falls in.
func TestCancellationIsRecordedAndNeverLooksClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := Run(ctx, Request{
		Target: target.Target{Kind: target.KindMCP, Reference: "sleep 600"},
	}, nil)
	if err != nil {
		t.Fatalf("a cancelled scan must be reported, not returned as an error: %v", err)
	}
	if report == nil {
		t.Fatal("no report produced")
	}

	var found bool
	for _, s := range report.Scenarios {
		if s.ID != "pipeline.cancelled" {
			continue
		}
		found = true
		if !s.Required {
			t.Error("the cancellation scenario is not required, so it cannot affect completeness")
		}
		if s.Outcome != assessment.OutcomeTimeout {
			t.Errorf("cancellation outcome = %q, want timeout: a skipped outcome would "+
				"only narrow coverage, and an abandoned scan has no coverage to report",
				s.Outcome)
		}
		if !strings.Contains(s.Reason, "cancelled") {
			t.Errorf("reason does not name the cause: %q", s.Reason)
		}
	}
	if !found {
		t.Fatalf("no pipeline.cancelled scenario: %+v", report.Scenarios)
	}

	var failure bool
	for _, f := range report.Failures {
		if f.Code == "scan_cancelled" && f.Phase == "cancelled" {
			failure = true
		}
	}
	if !failure {
		t.Errorf("no structured cancellation failure: %+v", report.Failures)
	}

	// The verdict layer must collapse. Inconclusive, not partial: the question
	// was abandoned rather than answered narrowly.
	got := assessment.Summarize(nil, report.Scenarios)
	if got.Completeness != assessment.CompletenessInconclusive {
		t.Fatalf("completeness = %q, want inconclusive", got.Completeness)
	}
}
