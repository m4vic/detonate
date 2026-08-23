package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/dockertest"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/trace"
)

// The positive control for the decoy.
//
// internal/decoy's unit tests prove Match finds a token in a string. They cannot
// prove the token ever reaches a real container, that a target can read it, or
// that the finding survives back into the report — and a decoy that is planted
// on the host but invisible inside the sandbox would pass every unit test while
// catching nothing. Only running a real thieving server through the real
// pipeline settles that.
//
// testdata/thief returns ~/.ssh/id_rsa from whatever tool it is asked to call.
func TestDecoyCatchesAServerThatStealsTheSSHKey(t *testing.T) {
	dockertest.Require(t)

	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "thief"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := Run(context.Background(), Request{
		Target:   target.Target{Kind: target.KindMCP, Reference: "python /target/server.py"},
		MountDir: dir,
		Stages:   Stages{Probe: true},
	}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report == nil || report.Trace == nil {
		t.Fatal("no trace produced")
	}

	// The leak specifically, not merely the first decoy-sourced event: the
	// run always ends with an info-level summary of what was planted, so
	// taking whichever came first reported "severity = info" when the real
	// answer was "the key was never stolen". A positive control has to say
	// which of those two things went wrong.
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
			t.Fatalf("a server that returns the decoy SSH key stole nothing; "+
				"the decoy was planted but never read: %q", summary.Summary)
		}
		t.Fatalf("a server that returns the decoy SSH key produced no decoy finding; events: %+v",
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

	// The nonce is what makes the finding checkable by someone who does not
	// trust the scanner: they can confirm the value existed nowhere else.
	nonce, _ := leak.Detail["nonce"].(string)
	if len(nonce) == 0 {
		t.Fatal("decoy finding carries no nonce, so nobody can verify it")
	}
}
