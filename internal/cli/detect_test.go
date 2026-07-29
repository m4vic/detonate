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

// A start command does not identify a target. Every TypeScript server in the
// MCP reference monorepo builds to dist/index.js, so memory,
// sequentialthinking and everything shared one baseline — and scanning the
// second reported "9 tool(s) removed since the last scan", a rug-pull finding
// invented entirely by the collision.
func TestBaselineIdentityDistinguishesPackagesInOneRepo(t *testing.T) {
	const repo = "github.com/modelcontextprotocol/servers"

	memory := baselineIdentity(repo, "src/memory")
	sequential := baselineIdentity(repo, "src/sequentialthinking")
	if memory == sequential {
		t.Fatalf("two packages share the identity %q; each would report the "+
			"other's tools as removed", memory)
	}

	// Stable across runs, which a clone's temp directory is not.
	if again := baselineIdentity(repo, "src/memory"); again != memory {
		t.Errorf("identity changed between runs: %q then %q", memory, again)
	}

	// A repository scanned whole is not the same target as a package in it.
	if whole := baselineIdentity(repo, ""); whole == memory {
		t.Error("scanning the whole repo collides with scanning one package")
	}
}

// A local path must resolve to the same identity however it is spelled, or
// each scan records a fresh baseline and rug-pull detection never fires.
func TestBaselineIdentityIsAbsoluteForLocalPaths(t *testing.T) {
	id := baselineIdentity(".", "")
	if !filepath.IsAbs(id) {
		t.Errorf("baselineIdentity(%q) = %q, want an absolute path", ".", id)
	}
	// "." and "./" name one directory and must not produce two baselines.
	if other := baselineIdentity("./", ""); other != id {
		t.Errorf("same folder, different identities: %q vs %q", id, other)
	}

	// A URL is kept verbatim: its clone lands somewhere different every run,
	// so resolving it would defeat the comparison entirely.
	const repo = "github.com/owner/repo"
	if got := baselineIdentity(repo, ""); got != repo {
		t.Errorf("baselineIdentity(%q) = %q, want it unchanged", repo, got)
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
