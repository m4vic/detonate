package cli

import (
	"context"
	"strings"
	"testing"
)

// Without Docker, doctor has to do two things: say so plainly, and point at
// the scans that still work. The second matters more than it looks — a user
// who reads "Docker is required" and concludes the tool is unusable never
// tries prompt or skill analysis, which needs no container and is the half
// most likely to help them today.
func TestDoctorWithoutDockerNamesWhatStillWorks(t *testing.T) {
	app, stdout, _ := newTestApp(false)

	if code := app.Run(context.Background(), []string{"doctor"}); code != exitUsage {
		t.Fatalf("exit = %d, want %d when Docker is unavailable", code, exitUsage)
	}

	out := stdout.String()
	for _, want := range []string{
		"[FAIL]",
		"docker binary not found",
		"install it",
		"detonate static",
		"detonate -",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
}

// A ready machine must exit 0, or a CI job that runs doctor as a setup gate
// fails on a working runner.
func TestDoctorReadyExitsZero(t *testing.T) {
	app, stdout, _ := newTestApp(true)

	if code := app.Run(context.Background(), []string{"doctor"}); code != exitOK {
		t.Fatalf("exit = %d, want %d when Docker is ready:\n%s",
			code, exitOK, stdout.String())
	}
	if out := stdout.String(); !strings.Contains(out, "Ready.") {
		t.Errorf("doctor did not report readiness:\n%s", out)
	}
}

// doctor reports an environment; it must never be mistaken for a scan result.
// Emitting a findings exit code from it would make a CI setup step look like a
// security failure.
func TestDoctorNeverReportsFindings(t *testing.T) {
	for _, ready := range []bool{true, false} {
		app, _, _ := newTestApp(ready)
		code := app.Run(context.Background(), []string{"doctor"})
		if code == exitFindings || code == exitIncomplete {
			t.Errorf("doctor(dockerReady=%v) returned scan exit code %d", ready, code)
		}
	}
}
