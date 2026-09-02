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

// The outcomes are grouped by what they say about coverage, which is what
// completeness below scores them on:
//
//   - Pass and Finding are the only conclusive outcomes. Reaching either one
//     means the target was actually examined, which is also the precondition
//     for risk being anything other than not_assessed.
//   - Skipped and Unsupported never ran. They shrink coverage without casting
//     doubt on whatever else did run.
//   - Timeout and TargetError started and reached no conclusion, so the
//     coverage question itself is left unanswered rather than merely narrowed.
//   - HarnessError and TeardownError are detonate's own failures. They are
//     never attributable to the target, and they invalidate the run instead of
//     scoring against it.
//
// Adding an outcome means deciding which group it joins in completeness, whose
// default case rejects an unrecognized value rather than guessing at one.
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

// RiskNotAssessed is the only value here that is not a statement about the
// target. It means no scenario ever reached a conclusion, so reporting "no
// findings" would be describing the scanner's silence rather than the target's
// behavior. Keeping it distinct from RiskNoFindings is what stops an
// unexamined target from reading as a clean one.
//
// Which of these values may end in a zero exit is decided in exactly one
// place, exitForSummary in internal/cli. It is not restated here, so the two
// files cannot drift apart.
const (
	RiskNotAssessed Risk = "not_assessed"
	RiskNoFindings  Risk = "no_findings"
	RiskSuspicious  Risk = "suspicious"
	RiskDangerous   Risk = "dangerous"
)

// Completeness says whether the selected scenario set actually ran.
type Completeness string

// The values are ordered by how much doubt they cast on the accompanying risk.
// Complete and partial both mean something was genuinely examined and the
// result describes the target. Inconclusive means required scenarios began
// without finishing, so no coverage claim can be made either way. Failed means
// detonate itself broke, which says nothing about the target at all.
//
// Nothing here is a security verdict: a target can be complete and dangerous,
// or inconclusive and harmless. Consumers are required to read this alongside
// Risk, never instead of it.
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
