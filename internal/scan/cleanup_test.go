package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/target"
)

func TestAddTeardownFailureMakesACompletedScanFailHonestly(t *testing.T) {
	report := &Report{Scenarios: []assessment.ScenarioResult{{
		ID: "mcp.inventory", Required: true, Outcome: assessment.OutcomePass,
	}}}

	addTeardownFailure(report, errors.New("sandbox still exists"))

	if len(report.Failures) != 1 {
		t.Fatalf("Failures = %+v, want one teardown failure", report.Failures)
	}
	if got := report.Failures[0]; got.Phase != "teardown" ||
		got.Code != "teardown_failed" || !got.Retryable {
		t.Fatalf("failure = %+v", got)
	}
	if len(report.Scenarios) != 2 ||
		report.Scenarios[1].Outcome != assessment.OutcomeTeardownError {
		t.Fatalf("Scenarios = %+v", report.Scenarios)
	}

	summary := assessment.Summarize(nil, report.Scenarios)
	if summary.Completeness != assessment.CompletenessFailed {
		t.Fatalf("completeness = %q, want %q", summary.Completeness, assessment.CompletenessFailed)
	}
}

func TestAddTeardownFailureIgnoresNil(t *testing.T) {
	report := &Report{}
	addTeardownFailure(report, nil)
	if len(report.Failures) != 0 || len(report.Scenarios) != 0 {
		t.Fatalf("nil teardown error changed report: %+v", report)
	}
}

func TestUnsafePythonAcquisitionBecomesExplicitUnsupportedOutcome(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"),
		[]byte("[project]\nname='fixture'\nversion='1.0.0'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := runMCP(context.Background(), Request{
		Target:   target.MCP("python /target/server.py"),
		MountDir: dir,
		Stages:   Stages{Install: true},
	}, nil)
	if err != nil {
		t.Fatalf("runMCP: %v", err)
	}
	if len(report.Scenarios) != 1 ||
		report.Scenarios[0].Outcome != assessment.OutcomeUnsupported {
		t.Fatalf("Scenarios = %+v", report.Scenarios)
	}
	if len(report.Failures) != 1 ||
		report.Failures[0].Code != "acquisition_unsupported" {
		t.Fatalf("Failures = %+v", report.Failures)
	}
}
