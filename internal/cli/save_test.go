package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/report"
)

func TestStaticSaveBundleAndOfflineRerender(t *testing.T) {
	prompt := writeHostilePrompt(t)
	bundleDir := filepath.Join(t.TempDir(), "review")
	app, stdout, stderr := newTestApp(false)
	code := app.Run(context.Background(), []string{
		"static", prompt, "--save-dir", bundleDir, "--color", "always",
	})
	if code != exitFindings {
		t.Fatalf("exit = %d, want findings; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[SAVED]") {
		t.Fatalf("save confirmation missing:\n%s", stdout.String())
	}
	for _, name := range []string{"manifest.json", "report.txt", "report.json"} {
		if _, err := os.Stat(filepath.Join(bundleDir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	textData, err := os.ReadFile(filepath.Join(bundleDir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(textData), "\x1b[") {
		t.Fatalf("saved text contains ANSI escapes: %q", textData)
	}
	reportData, err := os.ReadFile(filepath.Join(bundleDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var scan report.Scan
	if err := json.Unmarshal(reportData, &scan); err != nil {
		t.Fatalf("invalid report.json: %v", err)
	}

	renderApp, rendered, renderErr := newTestApp(false)
	// The saved bundle has findings, so replaying it must reproduce the findings
	// exit (3), not a clean 0 — otherwise a CI gate consuming `detonate report`
	// would accept a stored result that actually found something.
	if code := renderApp.Run(context.Background(), []string{"report", bundleDir}); code != exitFindings {
		t.Fatalf("report exit = %d, want findings; stderr: %s", code, renderErr.String())
	}
	if rendered.String() != string(textData) {
		t.Fatalf("offline render differs from report.txt")
	}
}

func TestJSONSaveKeepsStdoutMachineReadable(t *testing.T) {
	prompt := writeHostilePrompt(t)
	bundleDir := filepath.Join(t.TempDir(), "review")
	app, stdout, stderr := newTestApp(false)
	code := app.Run(context.Background(), []string{
		"static", prompt, "--format", "json", "--save-dir", bundleDir,
	})
	if code != exitFindings {
		t.Fatalf("exit = %d, want findings; stderr: %s", code, stderr.String())
	}
	var scan report.Scan
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatalf("stdout is not a clean JSON document: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "[SAVED]") {
		t.Fatalf("save confirmation should be on stderr: %s", stderr.String())
	}
}

func TestSaveFailureIsNonZeroAndDoesNotOverwrite(t *testing.T) {
	prompt := writeHostilePrompt(t)
	existing := t.TempDir()
	marker := filepath.Join(existing, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, stderr := newTestApp(false)
	if code := app.Run(context.Background(), []string{
		"static", prompt, "--save-dir", existing,
	}); code != exitFailure {
		t.Fatalf("exit = %d, want save failure", code)
	}
	if !strings.Contains(stderr.String(), "report_save_failed") {
		t.Fatalf("structured save error missing: %s", stderr.String())
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "keep" {
		t.Fatalf("existing destination changed: data=%q err=%v", data, err)
	}
}
