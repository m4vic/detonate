// Package assessment turns execution evidence into trustworthy scan outcomes.
//
// Risk and completeness are deliberately independent. "No findings" says
// what the enabled checks observed; it does not say that every required check
// ran. Keeping those facts separate prevents an unsupported or skipped probe
// from being rendered as a clean bill of health.
package assessment

import (
	"fmt"

	"github.com/m4vic/detonate/internal/trace"
)

// Outcome is the terminal state of one test scenario.
type Outcome string

const (
	OutcomePass          Outcome = "pass"
	OutcomeFinding       Outcome = "finding"
	OutcomeSkipped       Outcome = "skipped"
	OutcomeUnsupported   Outcome = "unsupported"
	OutcomeTimeout       Outcome = "timeout"
	OutcomeTargetError   Outcome = "target_error"
	OutcomeHarnessError  Outcome = "harness_error"
	OutcomeTeardownError Outcome = "teardown_error"
)

// ScenarioResult records exactly one terminal outcome for a stable scenario.
type ScenarioResult struct {
	ID       string  `json:"id"`
	Required bool    `json:"required"`
	Outcome  Outcome `json:"outcome"`
	Reason   string  `json:"reason,omitempty"`
}

// Risk is the security result derived from observed evidence.
type Risk string

const (
	RiskNotAssessed Risk = "not_assessed"
	RiskNoFindings  Risk = "no_findings"
	RiskSuspicious  Risk = "suspicious"
	RiskDangerous   Risk = "dangerous"
)

// Completeness says whether the selected scenario set actually ran.
type Completeness string

const (
	CompletenessComplete     Completeness = "complete"
	CompletenessPartial      Completeness = "partial"
	CompletenessInconclusive Completeness = "inconclusive"
	CompletenessFailed       Completeness = "failed"
)

// Summary is the pair consumers must use when deciding whether to trust a
// result. Neither field is meaningful enough to gate a deployment alone.
type Summary struct {
	Risk         Risk         `json:"risk"`
	Completeness Completeness `json:"completeness"`
}

// Summarize derives risk from evidence and completeness from scenario states.
func Summarize(events []trace.Event, scenarios []ScenarioResult) Summary {
	s := Summary{
		Risk:         risk(events, scenarios),
		Completeness: completeness(scenarios),
	}
	return s
}

func risk(events []trace.Event, scenarios []ScenarioResult) Risk {
	var assessed bool
	for _, scenario := range scenarios {
		if scenario.Outcome == OutcomePass || scenario.Outcome == OutcomeFinding {
			assessed = true
			break
		}
	}

	var notable bool
	for _, event := range events {
		switch event.Severity {
		case trace.SeverityCritical:
			return RiskDangerous
		case trace.SeverityNotable:
			notable = true
		}
	}
	if notable {
		return RiskSuspicious
	}
	if assessed {
		return RiskNoFindings
	}
	return RiskNotAssessed
}

func completeness(scenarios []ScenarioResult) Completeness {
	if len(scenarios) == 0 {
		return CompletenessInconclusive
	}

	var required, completed, unavailable, inconclusive int
	for _, scenario := range scenarios {
		if !scenario.Required {
			continue
		}
		required++
		switch scenario.Outcome {
		case OutcomePass, OutcomeFinding:
			completed++
		case OutcomeSkipped, OutcomeUnsupported:
			unavailable++
		case OutcomeTimeout, OutcomeTargetError:
			inconclusive++
		case OutcomeHarnessError, OutcomeTeardownError:
			return CompletenessFailed
		default:
			return CompletenessFailed
		}
	}

	if required == 0 || completed == required {
		return CompletenessComplete
	}
	if inconclusive > 0 || completed == 0 {
		return CompletenessInconclusive
	}
	if unavailable > 0 {
		return CompletenessPartial
	}
	return CompletenessFailed
}

// Validate rejects malformed or duplicate scenario results before they can be
// serialized as authoritative evidence.
func Validate(scenarios []ScenarioResult) error {
	seen := make(map[string]struct{}, len(scenarios))
	for i, scenario := range scenarios {
		if scenario.ID == "" {
			return fmt.Errorf("scenario %d has no ID", i)
		}
		if _, ok := seen[scenario.ID]; ok {
			return fmt.Errorf("duplicate scenario ID %q", scenario.ID)
		}
		seen[scenario.ID] = struct{}{}
		switch scenario.Outcome {
		case OutcomePass, OutcomeFinding, OutcomeSkipped, OutcomeUnsupported,
			OutcomeTimeout, OutcomeTargetError, OutcomeHarnessError, OutcomeTeardownError:
		default:
			return fmt.Errorf("scenario %q has invalid outcome %q", scenario.ID, scenario.Outcome)
		}
	}
	return nil
}
