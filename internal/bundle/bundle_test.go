package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/report"
)

func TestSaveWritesAtomicRedactedBundle(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "saved")
	scan := report.Scan{
		Schema: report.SchemaV1, Tool: "detonate", Version: "test",
		Target: "https://github.com/owner/example",
		Risk:   assessment.RiskNoFindings, Completeness: assessment.CompletenessComplete,
		Findings: []report.Finding{{Evidence: "api_key=super-secret-value"}},
	}
	got, err := Save(Options{
		Directory: destination, Target: scan.Target, Version: "test", Report: scan,
		DetonateCommit: "1111111111111111111111111111111111111111",
		RepositoryURL:  "https://github.com/owner/example",
		Subpath:        "examples/server",
		Revision:       "2222222222222222222222222222222222222222",
		SandboxImage:   "node:22-slim@sha256:" + strings.Repeat("a", 64),
		Now:            time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != destination {
		t.Fatalf("path = %q, want %q", got, destination)
	}
	for _, name := range []string{"manifest.json", "report.txt", "report.json"} {
		data, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "super-secret-value") ||
			strings.Contains(text, "\x1b[") {
			t.Fatalf("%s leaked secret or ANSI data: %q", name, text)
		}
	}
	data, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != SchemaV1 || manifest.Redactions["report.txt"] == 0 ||
		manifest.Redactions["report.json"] == 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if manifest.Provenance.Target == nil ||
		manifest.Provenance.Target.RepositoryURL != "https://github.com/owner/example" ||
		manifest.Provenance.Target.Subpath != "examples/server" ||
		manifest.Provenance.Target.Commit != "2222222222222222222222222222222222222222" ||
		manifest.Provenance.Detonate.Commit != "1111111111111111111111111111111111111111" ||
		manifest.Provenance.Sandbox == nil ||
		!strings.Contains(manifest.Provenance.Sandbox.Image, "@sha256:") {
		t.Fatalf("incomplete provenance: %+v", manifest.Provenance)
	}
	reportData, err := os.ReadFile(filepath.Join(destination, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved report.Scan
	if err := json.Unmarshal(reportData, &saved); err != nil {
		t.Fatalf("saved report is invalid JSON: %v", err)
	}
}

func TestSaveRefusesToOverwrite(t *testing.T) {
	destination := t.TempDir()
	_, err := Save(Options{Directory: destination})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v, want already exists", err)
	}
}

func TestSaveRejectsOversizedCanonicalReport(t *testing.T) {
	parent := t.TempDir()
	destination := filepath.Join(parent, "saved")
	scan := report.Scan{
		Schema:   report.SchemaV1,
		Findings: []report.Finding{{Summary: strings.Repeat("x", maxJSONReportBytes+1)}},
	}
	_, err := Save(Options{Directory: destination, Report: scan})
	if err == nil || !strings.Contains(err.Error(), "bundle limit") {
		t.Fatalf("error = %v, want bundle limit", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("incomplete destination exists: %v", err)
	}
	temps, err := filepath.Glob(filepath.Join(parent, ".detonate-bundle-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary bundles left behind: %v", temps)
	}
}

func TestLoadRerendersSavedCanonicalReport(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "saved")
	scan := report.Scan{
		Schema: report.SchemaV1, Tool: "detonate", Version: "test",
		Target: "example", Risk: assessment.RiskNoFindings,
		Completeness: assessment.CompletenessComplete,
	}
	if _, err := Save(Options{Directory: destination, Target: scan.Target, Report: scan}); err != nil {
		t.Fatal(err)
	}
	_, loaded, err := Load(destination)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(destination, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Text(loaded); got != string(want) {
		t.Fatalf("rerender differs from saved text\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestTargetSlug(t *testing.T) {
	if got := targetSlug("https://github.com/Owner/Some Repo.git"); got != "some-repo" {
		t.Fatalf("slug = %q", got)
	}
	if got := targetSlug("!!!"); got != "scan" {
		t.Fatalf("fallback slug = %q", got)
	}
}
