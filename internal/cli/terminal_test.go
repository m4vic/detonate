package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestColorPolicy(t *testing.T) {
	app, _, _ := newTestApp(false)
	if err := app.configureColor(colorAlways, "text"); err != nil {
		t.Fatal(err)
	}
	if got := app.heading("TARGET"); !strings.Contains(got, "\x1b[") {
		t.Fatalf("forced color produced no ANSI escape: %q", got)
	}

	if err := app.configureColor(colorNever, "text"); err != nil {
		t.Fatal(err)
	}
	if got := app.heading("TARGET"); strings.Contains(got, "\x1b[") {
		t.Fatalf("disabled color produced ANSI escape: %q", got)
	}
}

func TestNoColorOverridesForcedColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	app, _, _ := newTestApp(false)
	if err := app.configureColor(colorAlways, "text"); err != nil {
		t.Fatal(err)
	}
	if app.colorEnabled {
		t.Fatal("NO_COLOR did not disable terminal styling")
	}
}

func TestAutoColorIsOffForRedirectedWriter(t *testing.T) {
	app := &App{Stdout: &bytes.Buffer{}}
	if err := app.configureColor(colorAuto, "text"); err != nil {
		t.Fatal(err)
	}
	if app.colorEnabled {
		t.Fatal("auto color enabled for a non-terminal writer")
	}
}

func TestMachineOutputNeverContainsANSI(t *testing.T) {
	app, stdout, stderr := newTestApp(false)
	path := filepath.Join(t.TempDir(), "prompt.txt")
	if err := os.WriteFile(path, []byte("Summarise this document.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := app.Run(context.Background(), []string{
		path, "--format", "json", "--color", "always",
	})
	if code != exitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("JSON contains ANSI escapes: %q", stdout.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
}

func TestInvalidColorModeIsUsageError(t *testing.T) {
	app, _, stderr := newTestApp(false)
	code := app.Run(context.Background(), []string{
		"README.md", "--color", "ultraviolet",
	})
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "auto, always, or never") {
		t.Fatalf("error is not actionable: %q", stderr.String())
	}
}

func TestTerminalSafeRemovesTargetControlledEscapeSequences(t *testing.T) {
	input := "honest\x1b[2J\x1b[31mFAKE FAILURE\x1b[0m\r\nnext"
	got := terminalSafe(input)
	if strings.ContainsAny(got, "\x1b\r\n") {
		t.Fatalf("terminal controls survived sanitization: %q", got)
	}
	if !strings.Contains(got, "honest") || !strings.Contains(got, "FAKE FAILURE") {
		t.Fatalf("sanitization discarded readable evidence: %q", got)
	}
}
