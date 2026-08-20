package skill

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/dockertest"
	"github.com/m4vic/detonate/internal/sandbox"
)

func TestDetonateScriptsWithResultsRecordsUnsupportedInterpreter(t *testing.T) {
	sk := Skill{Scripts: []string{"scripts/helper.rb"}}
	result := DetonateScriptsWithResults(
		context.Background(), t.TempDir(), sk, sandbox.DefaultPolicy(),
	)

	if len(result.Scenarios) != 1 {
		t.Fatalf("got %d scenarios, want 1", len(result.Scenarios))
	}
	if got := result.Scenarios[0].Outcome; got != assessment.OutcomeUnsupported {
		t.Fatalf("outcome = %q, want unsupported", got)
	}
	if len(result.Events) != 1 {
		t.Fatalf("got %d events, want explicit not-run observation", len(result.Events))
	}
}

func TestDetonateScriptsWithResultsRecordsNonZeroExit(t *testing.T) {
	dockertest.Require(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dir := t.TempDir()
	script := filepath.Join("scripts", "fail.sh")
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, script), []byte("#!/bin/sh\nexit 7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := sandbox.DefaultPolicy()
	if err := sandbox.EnsureImage(ctx, policy.Image); err != nil {
		dockertest.Unavailable(t, "sandbox image unavailable: %v", err)
	}
	result := DetonateScriptsWithResults(
		ctx, dir, Skill{Scripts: []string{script}}, policy,
	)
	if got := result.Scenarios[0].Outcome; got != assessment.OutcomeTargetError {
		t.Fatalf("outcome = %q, want target_error (%+v)", got, result.Scenarios[0])
	}
}
