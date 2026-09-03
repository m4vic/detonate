package scan

import (
	"context"
	"fmt"
	"os"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/decoy"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/scenario"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/trace"
)

// runSkill analyses a skill's instructions and, when asked, runs its bundled
// scripts in the sandbox.
//
// A skill is mostly a large prompt: its SKILL.md body is text an agent reads
// and obeys, so most of the analysis is of instructions rather than of running
// code, and needs no container.
func runSkill(ctx context.Context, req Request, p Progress) (*Report, error) {
	dir := req.Target.Reference

	tools, err := skill.Load(dir)
	if err != nil {
		return nil, targetError("resolve", "skill_load_failed", false, err)
	}

	sk, err := skill.LoadSkill(dir)
	if err != nil {
		return nil, targetError("resolve", "skill_load_failed", false, err)
	}

	tr := newTrace(dir)
	staticEvents := skill.Analyze(sk)
	for _, ev := range staticEvents {
		tr.Add(ev)
	}

	staticOutcome := assessment.OutcomePass
	for _, event := range staticEvents {
		if event.Severity == trace.SeverityCritical ||
			event.Severity == trace.SeverityNotable {
			staticOutcome = assessment.OutcomeFinding
			break
		}
	}

	scenarios := []assessment.ScenarioResult{{
		ID: "skill.static", Required: true, Outcome: staticOutcome,
	}}

	// The dynamic half of skill analysis. SKILL.md is a prompt and can only be
	// read, but the bundled scripts are real programs an agent will execute on
	// the user's machine — and until they run, a script that phones home is
	// indistinguishable from one that formats a table.
	if req.Stages.RunScripts && len(sk.Scripts) > 0 {
		p.step(fmt.Sprintf("  running %d bundled script(s) in the sandbox...", len(sk.Scripts)))

		// Furnish the sandbox before any script runs, same reasoning as the
		// MCP path: an empty home cannot show a script reading things it
		// should not, and the decoy is writable so a script that writes
		// under ~ still behaves normally. Deleted with the scan.
		var den *decoy.Environment
		decoyDir, decoyErr := os.MkdirTemp("", "detonate-decoy-")
		if decoyErr == nil {
			defer os.RemoveAll(decoyDir)
			if planted, plantErr := decoy.Plant(decoyDir, sandbox.ContainerHome); plantErr == nil {
				den = planted
			} else {
				decoyErr = plantErr
			}
		}
		if decoyErr != nil {
			// Not fatal: a scan without a decoy is a weaker scan, not a
			// wrong one, but it must be visible rather than silent.
			p.step("  could not furnish the sandbox decoy; credential-leak checks are disabled")
		}

		detonation := skill.DetonateScriptsWithResults(ctx, dir, sk, sandbox.DefaultPolicy(), den)
		for _, ev := range detonation.Events {
			tr.Add(ev)
		}
		scenarios = append(scenarios, detonation.Scenarios...)
	} else if len(sk.Scripts) > 0 {
		for _, script := range sk.Scripts {
			scenarios = append(scenarios, assessment.ScenarioResult{
				ID:       scenario.SkillScriptID(script),
				Required: true,
				Outcome:  assessment.OutcomeSkipped,
				Reason:   "dynamic script execution was disabled",
			})
		}
	} else {
		tr.Add(trace.Event{
			Kind:     trace.KindLifecycle,
			Severity: trace.SeverityInfo,
			Summary:  "dynamic execution did not run because the skill has no bundled scripts",
			During:   "runtime-selection",
			Source:   "static-scanner",
		})
		scenarios = append(scenarios, assessment.ScenarioResult{
			ID:       "skill.runtime",
			Required: true,
			Outcome:  assessment.OutcomeSkipped,
			Reason:   "the skill contains no bundled scripts to execute",
		})
	}

	return &Report{
		Tools: tools, Trace: tr,
		Scenarios: scenarios, Reference: dir,
	}, nil
}
