package assessment

import (
	"testing"

	"github.com/m4vic/detonate/internal/trace"
)

func TestSummarizeKeepsRiskAndCompletenessIndependent(t *testing.T) {
	got := Summarize(nil, []ScenarioResult{
		{ID: "mcp.inventory", Required: true, Outcome: OutcomePass},
		{ID: "mcp.tool/read", Required: true, Outcome: OutcomeUnsupported},
	})
	if got.Risk != RiskNoFindings || got.Completeness != CompletenessPartial {
		t.Fatalf("summary = %+v, want no_findings + partial", got)
	}
}

func TestSummarizeRiskLadder(t *testing.T) {
	scenarios := []ScenarioResult{{ID: "static", Required: true, Outcome: OutcomePass}}
	cases := []struct {
		name   string
		events []trace.Event
		want   Risk
	}{
		{"none", nil, RiskNoFindings},
		{"notable", []trace.Event{{Severity: trace.SeverityNotable}}, RiskSuspicious},
		{"critical", []trace.Event{{Severity: trace.SeverityCritical}}, RiskDangerous},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Summarize(tc.events, scenarios).Risk; got != tc.want {
				t.Fatalf("risk = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSummarizeCompletenessLadder(t *testing.T) {
	cases := []struct {
		name      string
		scenarios []ScenarioResult
		want      Completeness
	}{
		{"complete", []ScenarioResult{{ID: "a", Required: true, Outcome: OutcomePass}}, CompletenessComplete},
		{"partial", []ScenarioResult{
			{ID: "a", Required: true, Outcome: OutcomePass},
			{ID: "b", Required: true, Outcome: OutcomeSkipped},
		}, CompletenessPartial},
		{"inconclusive", []ScenarioResult{{ID: "a", Required: true, Outcome: OutcomeTimeout}}, CompletenessInconclusive},
		{"failed", []ScenarioResult{{ID: "a", Required: true, Outcome: OutcomeTeardownError}}, CompletenessFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Summarize(nil, tc.scenarios).Completeness; got != tc.want {
				t.Fatalf("completeness = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateRejectsDuplicatesAndUnknownOutcomes(t *testing.T) {
	if err := Validate([]ScenarioResult{
		{ID: "same", Outcome: OutcomePass},
		{ID: "same", Outcome: OutcomePass},
	}); err == nil {
		t.Fatal("duplicate IDs accepted")
	}
	if err := Validate([]ScenarioResult{{ID: "x", Outcome: Outcome("maybe")}}); err == nil {
		t.Fatal("unknown outcome accepted")
	}
}
