package fetch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsURLDistinguishesGitURLsFromLocalPaths(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/example/server", true},
		{"github.com/example/server", true},
		{"git@github.com:example/server.git", true},
		{"./archive/python-m1-tests/fixtures/sample_skill", false},
		{"../skills/sample", false},
		{`C:\work\server`, false},
		{`\\server\share\target`, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsURL(tt.input); got != tt.want {
				t.Errorf("IsURL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRevisionAtReturnsCheckedOutCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	runGit("init", "--quiet")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "README.md")
	runGit("-c", "user.name=Detonate Test", "-c", "user.email=test@example.invalid",
		"commit", "--quiet", "-m", "fixture")

	want := runGit("rev-parse", "HEAD")
	got, err := revisionAt(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got+"\n" != want {
		t.Fatalf("revision = %q, want %q", got, want)
	}
}
