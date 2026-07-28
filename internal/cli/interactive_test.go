package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/environment"
)

// withStdin feeds scripted answers to the wizard.
//
// The wizard reads os.Stdin directly rather than an injected reader, because
// that is what a real terminal session is. Swapping the global for the length
// of a test keeps production simple at the cost of this helper.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() { os.Stdin = old; r.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.WriteString(input)
		w.Close()
	}()

	fn()
	<-done
}

func wizardApp(dockerReady bool) (*App, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	status := environment.DockerStatus{Detail: "docker binary not found on PATH"}
	if dockerReady {
		status = environment.DockerStatus{Installed: true, Running: true, Detail: "stubbed"}
	}
	return &App{
		Stdout: &out, Stderr: &errb,
		CheckDocker: func(context.Context) environment.DockerStatus { return status },
	}, &out, &errb
}

// The wizard's whole reason to exist: a user should never have to learn that
// the server command must reference /target rather than their own path.
func TestWizardDetectsEntryPoint(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	app, out, _ := wizardApp(true)
	withStdin(t, "1\n"+dir+"\ny\n", func() {
		app.runInteractive(context.Background())
	})

	s := out.String()
	for _, want := range []string{
		"What do you want to scan?",
		"Detected entry point",
		"python /target/server.py",
		// The equivalent flag form matters: someone who runs this once by hand
		// and then wants it in CI should copy a line, not reread the docs.
		"Equivalent command",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("wizard output missing %q\n---\n%s", want, s)
		}
	}
}

func TestWizardChecksDockerBeforeAsking(t *testing.T) {
	// Being told "Docker is not running" after answering four questions is
	// worse than being told before the first.
	app, out, errb := wizardApp(false)
	withStdin(t, "", func() {
		if code := app.runInteractive(context.Background()); code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
	})

	if !strings.Contains(errb.String(), "Docker is not ready") {
		t.Errorf("stderr = %q", errb.String())
	}
	if strings.Contains(out.String(), "What do you want to scan?") {
		t.Error("wizard asked questions despite Docker being unavailable")
	}
}

func TestWizardRejectsMissingPath(t *testing.T) {
	app, _, errb := wizardApp(true)
	withStdin(t, "1\nZ:\\definitely\\not\\here\n", func() {
		if code := app.runInteractive(context.Background()); code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
	})
	if !strings.Contains(errb.String(), "does not exist") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestWizardRejectsSkillFolderWithoutSkillMD(t *testing.T) {
	app, _, errb := wizardApp(true)
	withStdin(t, "2\n"+t.TempDir()+"\n", func() {
		app.runInteractive(context.Background())
	})
	if !strings.Contains(errb.String(), "No SKILL.md") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestGuessCommand(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"server.py", "python /target/server.py"},
		{"main.py", "python /target/main.py"},
		{"index.js", "node /target/index.js"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, c.file), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := guessCommand(dir); got != c.want {
			t.Errorf("guessCommand(%s) = %q, want %q", c.file, got, c.want)
		}
	}

	if got := guessCommand(t.TempDir()); got != "" {
		t.Errorf("guessCommand(empty dir) = %q, want empty so the user is asked", got)
	}
}

// Paths pasted from a terminal or dragged into one arrive quoted. Failing on
// a path the user actually got right is a bad first experience.
func TestWizardStripsQuotesFromPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	app, out, _ := wizardApp(true)
	withStdin(t, "1\n\""+dir+"\"\ny\n", func() {
		app.runInteractive(context.Background())
	})
	if !strings.Contains(out.String(), "Detected entry point") {
		t.Errorf("quoted path was not accepted\n---\n%s", out.String())
	}
}
