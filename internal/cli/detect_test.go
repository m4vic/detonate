package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The shape of most published MCP servers: TypeScript source, compiled output
// gitignored, package.json pointing at the artifact. Nothing runnable exists
// on disk, so detection has to trust what the package declares.
func TestDetectTypeScriptServer(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"main":"dist/index.js","scripts":{"build":"tsc"}}`,
		"src/index.ts": `console.log(1)`,
	})

	d, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if d.Kind != KindMCP {
		t.Fatalf("Kind = %q, want mcp (%s)", d.Kind, d.Why)
	}
	if d.Command != "node /target/dist/index.js" {
		t.Errorf("Command = %q, want the declared entry point", d.Command)
	}
	if !d.NeedsInstall {
		t.Error("NeedsInstall = false; the project cannot run without a build")
	}
}

// A leftover index.js in the root must not beat the entry point the package
// actually declares. Guessing here would launch the wrong file and report
// findings about code the server never runs.
func TestDeclaredEntryBeatsAGuessWhenABuildIsNeeded(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"main":"dist/server.js","scripts":{"build":"tsc"}}`,
		"index.js":     `// stale helper, not the server`,
		"src/index.ts": `console.log(1)`,
	})

	d, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if d.Command != "node /target/dist/server.js" {
		t.Errorf("Command = %q, want the declared entry point, not the guess", d.Command)
	}
}

// A project that ships its compiled output needs no build, and the guess and
// the declaration agree. This is the path that already worked and must keep
// working.
func TestDetectPrebuiltNodeServer(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json":  `{"main":"dist/index.js"}`,
		"dist/index.js": `console.log(1)`,
	})

	d, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if d.Kind != KindMCP {
		t.Fatalf("Kind = %q, want mcp (%s)", d.Kind, d.Why)
	}
	if d.Command != "node /target/dist/index.js" {
		t.Errorf("Command = %q", d.Command)
	}
}
