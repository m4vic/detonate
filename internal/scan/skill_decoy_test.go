package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/dockertest"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/trace"
)

// The positive control for the decoy on the skill path.
//
// DetonateScripts used to discard a bundled script's stdout entirely, so a
// script that read a planted secret and printed it — the normal way a script
// reports its result, as opposed to an MCP tool's structured response — left
// no trace anywhere in the report. Only running a real thieving script
// through the real pipeline proves that gap is closed.
//
// testdata/evil-exfil-formatter reads ~/.ssh/id_rsa and prints it dressed up
// as formatted output.
func TestDecoyCatchesASkillScriptThatStealsTheSSHKey(t *testing.T) {
	dockertest.Require(t)

	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evil-exfil-formatter"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := Run(context.Background(), Request{
		Target: target.Target{Kind: target.KindSkill, Reference: dir},
		Stages: Stages{RunScripts: true},
	}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report == nil || report.Trace == nil {
		t.Fatal("no trace produced")
	}

	var leak *trace.Event
	var summary *trace.Event
	for i, ev := range report.Trace.Events {
		if ev.Source != "decoy" {
			continue
		}
		if _, hasNonce := ev.Detail["nonce"]; hasNonce {
			leak = &report.Trace.Events[i]
			break
		}
		summary = &report.Trace.Events[i]
	}
	if leak == nil {
		if summary != nil {
			t.Fatalf("a script that prints the decoy SSH key stole nothing; "+
				"the decoy was planted but never read: %q", summary.Summary)
		}
		t.Fatalf("a script that prints the decoy SSH key produced no decoy finding; events: %+v",
			report.Trace.Events)
	}

	if leak.Severity != trace.SeverityCritical {
		t.Fatalf("decoy finding severity = %q, want critical", leak.Severity)
	}
	if got, _ := leak.Detail["secret"].(string); got != "ssh-private-key" {
		t.Fatalf("finding names secret %q, want ssh-private-key", got)
	}
	if got, _ := leak.Detail["path"].(string); !strings.HasSuffix(got, "/.ssh/id_rsa") {
		t.Fatalf("finding names path %q, want the decoy key path", got)
	}

	nonce, _ := leak.Detail["nonce"].(string)
	if len(nonce) == 0 {
		t.Fatal("decoy finding carries no nonce, so nobody can verify it")
	}

	var decoyScenario *assessment.ScenarioResult
	for i, sc := range report.Scenarios {
		if sc.ID == "decoy.credential-exfiltration" {
			decoyScenario = &report.Scenarios[i]
			break
		}
	}
	if decoyScenario == nil {
		t.Fatal("no decoy.credential-exfiltration scenario in the report")
	}
	if decoyScenario.Outcome != assessment.OutcomeFinding {
		t.Fatalf("decoy.credential-exfiltration outcome = %q, want finding", decoyScenario.Outcome)
	}
}

// The negative control: a skill script that does exactly what it claims —
// format a table, nothing else — must not trip the decoy check. Without this,
// TestDecoyCatchesASkillScriptThatStealsTheSSHKey alone can't tell "the
// checker works" from "the checker flags everything".
//
// testdata/benign-formatter shares evil-exfil-formatter's SKILL.md almost
// verbatim; only its script differs, so this isolates the credential read as
// the thing that changes the verdict.
func TestDecoyStaysCleanForABenignSkillScript(t *testing.T) {
	dockertest.Require(t)

	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "benign-formatter"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := Run(context.Background(), Request{
		Target: target.Target{Kind: target.KindSkill, Reference: dir},
		Stages: Stages{RunScripts: true},
	}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report == nil || report.Trace == nil {
		t.Fatal("no trace produced")
	}

	for _, ev := range report.Trace.Events {
		if ev.Source == "decoy" {
			if _, hasNonce := ev.Detail["nonce"]; hasNonce {
				t.Fatalf("benign script triggered a decoy leak finding: %+v", ev)
			}
		}
	}

	var decoyScenario *assessment.ScenarioResult
	for i, sc := range report.Scenarios {
		if sc.ID == "decoy.credential-exfiltration" {
			decoyScenario = &report.Scenarios[i]
			break
		}
	}
	if decoyScenario == nil {
		t.Fatal("no decoy.credential-exfiltration scenario in the report")
	}
	if decoyScenario.Outcome != assessment.OutcomePass {
		t.Fatalf("decoy.credential-exfiltration outcome = %q, want pass", decoyScenario.Outcome)
	}
}
