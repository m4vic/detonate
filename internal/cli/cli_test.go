package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/environment"
	"github.com/m4vic/detonate/internal/mcptest"
)

func TestMain(m *testing.M) {
	mcptest.RunServerIfRequested()
	os.Exit(m.Run())
}

// newTestApp builds an App with buffered output and a stubbed Docker check.
//
// The Docker gate is the only thing stubbed here. Everything under it is real:
// a real skill on disk, a real MCP server subprocess. Without the stub, the
// gate would make every interesting path untestable on a machine without a
// Docker daemon, which is most developer machines and most CI runners.
func newTestApp(dockerReady bool) (*App, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	status := environment.DockerStatus{Installed: false, Running: false,
		Detail: "docker binary not found on PATH"}
	if dockerReady {
		status = environment.DockerStatus{Installed: true, Running: true, Detail: "stubbed"}
	}
	app := &App{
		Stdout:      &stdout,
		Stderr:      &stderr,
		CheckDocker: func(context.Context) environment.DockerStatus { return status },
	}
	return app, &stdout, &stderr
}

func writeSampleSkill(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	skill := "---\nname: pdf-extractor\n" +
		"description: Extracts text and tables from PDF files for the agent to read.\n" +
		"allowed-tools:\n  - Read\n  - Bash\n---\n\n# PDF Extractor\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skill), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extract.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUsageAndVersion(t *testing.T) {
	t.Run("no args prints usage", func(t *testing.T) {
		app, stdout, _ := newTestApp(true)
		if code := app.Run(context.Background(), nil); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("expected usage, got %q", stdout.String())
		}
	})

	t.Run("version", func(t *testing.T) {
		app, stdout, _ := newTestApp(true)
		app.Run(context.Background(), []string{"--version"})
		if !strings.Contains(stdout.String(), Version) {
			t.Errorf("expected version, got %q", stdout.String())
		}
	})

	t.Run("unknown command is a usage error", func(t *testing.T) {
		app, _, stderr := newTestApp(true)
		if code := app.Run(context.Background(), []string{"detonat"}); code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "unknown command") {
			t.Errorf("stderr = %q", stderr.String())
		}
	})
}

func TestScanRequiresExactlyOneTarget(t *testing.T) {
	t.Run("no target", func(t *testing.T) {
		app, _, stderr := newTestApp(true)
		if code := app.Run(context.Background(), []string{"scan"}); code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "a target is required") {
			t.Errorf("stderr = %q", stderr.String())
		}
	})

	t.Run("both targets", func(t *testing.T) {
		app, _, stderr := newTestApp(true)
		code := app.Run(context.Background(), []string{"scan", "--mcp", "x", "--skill", "y"})
		if code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "mutually exclusive") {
			t.Errorf("stderr = %q", stderr.String())
		}
	})
}

// The Docker gate is detonate's core safety promise: no sandbox, no scan.
func TestScanBlockedWithoutDocker(t *testing.T) {
	app, _, stderr := newTestApp(false)
	dir := writeSampleSkill(t)

	code := app.Run(context.Background(), []string{"scan", "--skill", dir})
	if code != exitUsage {
		t.Errorf("exit = %d, want %d (environment problem, not scan failure)", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "requires Docker") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestScanSkill(t *testing.T) {
	app, stdout, stderr := newTestApp(true)
	dir := writeSampleSkill(t)

	if code := app.Run(context.Background(), []string{"scan", "--skill", dir}); code != exitOK {
		t.Fatalf("exit = %d, want 0. stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "discovered 2 tool(s)") {
		t.Errorf("expected 2 tools, got %q", out)
	}
	if !strings.Contains(out, "pdf-extractor") {
		t.Errorf("expected the skill name, got %q", out)
	}
}

func TestScanMCPAgainstRealServer(t *testing.T) {
	app, stdout, stderr := newTestApp(true)

	code := app.Run(context.Background(), []string{"scan", "--mcp", mcptest.Command()})
	if code != exitOK {
		t.Fatalf("exit = %d, want 0. stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"read_file", "echo"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got %q", want, out)
		}
	}
}

// M1 runs the MCP target on the host. That warning must not quietly disappear
// when M2 lands: if someone wires up the sandbox and forgets to remove this,
// the test fails and tells them to. If they remove it without a sandbox, it
// also fails.
func TestScanMCPWarnsItIsUnsandboxed(t *testing.T) {
	app, stdout, _ := newTestApp(true)
	app.Run(context.Background(), []string{"scan", "--mcp", mcptest.Command()})
	if !strings.Contains(stdout.String(), "sandbox not yet implemented") {
		t.Error("the unsandboxed warning is missing from MCP scan output")
	}
}

func TestScanEnumerationFailureExitsOne(t *testing.T) {
	// A directory with no SKILL.md must fail the scan, not report a clean
	// zero-tool result.
	app, _, stderr := newTestApp(true)
	if code := app.Run(context.Background(), []string{"scan", "--skill", t.TempDir()}); code != exitFailure {
		t.Errorf("exit = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "enumeration failed") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// Windows consoles default to cp1252 and mangle non-ASCII. detonate is a CLI
// people run on Windows, so its own output stays ASCII. (M0 shipped an em-dash
// in the CLI description and it rendered as a replacement character.)
func TestOutputIsASCII(t *testing.T) {
	app, stdout, _ := newTestApp(true)
	app.Run(context.Background(), []string{"scan", "--skill", writeSampleSkill(t)})
	app.Run(context.Background(), nil)

	for i, r := range stdout.String() {
		if r > 127 {
			t.Fatalf("non-ASCII rune %q at byte %d in CLI output", r, i)
		}
	}
}
