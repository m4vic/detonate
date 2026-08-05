package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMonorepo builds a repository that holds servers rather than being one,
// which is the shape of github.com/modelcontextprotocol/servers and the most
// likely thing a new user pastes.
func writeMonorepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// A root manifest with no entry point: enough to be a real project, not
	// enough to start anything.
	mustWrite(t, filepath.Join(root, "package.json"),
		`{"name":"servers","private":true,"workspaces":["src/*"]}`)

	for _, name := range []string{"memory", "fetch"} {
		dir := filepath.Join(root, "src", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		mustWrite(t, filepath.Join(dir, "package.json"),
			`{"name":"`+name+`","version":"1.0.0","bin":{"`+name+`":"index.js"}}`)
		mustWrite(t, filepath.Join(dir, "index.js"), "// server\n")
	}
	return root
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// An unclassifiable folder must name what IS scannable inside it.
//
// Reporting "no recognisable entry point" and stopping told a new user the
// tool did not work on the first thing they tried, when the truth was that
// they were one flag away from a scan.
func TestMonorepoSuggestsItsPackages(t *testing.T) {
	root := writeMonorepo(t)
	app, _, stderr := newTestApp(false)

	if code := app.Run(context.Background(), []string{"static", root}); code != exitUsage {
		t.Fatalf("exit = %d, want %d for an unclassifiable folder", code, exitUsage)
	}

	out := stderr.String()
	if !strings.Contains(out, "repository of packages") {
		t.Errorf("no monorepo explanation:\n%s", out)
	}
	for _, want := range []string{"--path src/memory", "--path src/fetch"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing suggestion %q:\n%s", want, out)
		}
	}
}

// The suggestion has to be a command that works. A hint the user follows into
// the same dead end is worse than no hint.
func TestSuggestedPathActuallyScans(t *testing.T) {
	root := writeMonorepo(t)
	app, stdout, stderr := newTestApp(false)

	code := app.Run(context.Background(), []string{"static", root, "--path", "src/memory"})

	if code == exitUsage {
		t.Fatalf("the suggested --path was itself rejected:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "MCP server") {
		t.Errorf("did not classify the package as an MCP server:\n%s", stdout.String())
	}
}

// A folder with nothing scannable inside it must not claim to be a monorepo.
// Offering package suggestions that do not exist would send the reader looking
// for directories that are not there.
func TestPlainUnknownFolderGetsCmdHint(t *testing.T) {
	app, _, stderr := newTestApp(false)

	if code := app.Run(context.Background(), []string{"static", t.TempDir()}); code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}

	out := stderr.String()
	if strings.Contains(out, "repository of packages") {
		t.Errorf("claimed to be a monorepo with no packages present:\n%s", out)
	}
	if !strings.Contains(out, "--cmd") {
		t.Errorf("no --cmd hint for an unclassifiable folder:\n%s", out)
	}
}

// findPackages must not descend into directories that are not package parents,
// or a repository's node_modules and test fixtures become suggestions.
func TestFindPackagesIgnoresUnconventionalDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"root","private":true}`)

	buried := filepath.Join(root, "node_modules", "some-dep")
	if err := os.MkdirAll(buried, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite(t, filepath.Join(buried, "package.json"),
		`{"name":"some-dep","bin":{"x":"index.js"}}`)
	mustWrite(t, filepath.Join(buried, "index.js"), "// dep\n")

	if got := findPackages(root); len(got) != 0 {
		t.Errorf("suggested non-package directories: %v", got)
	}
}
