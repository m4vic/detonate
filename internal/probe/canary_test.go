package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateCanary(t *testing.T) {
	c, err := GenerateCanary()
	if err != nil {
		t.Fatalf("GenerateCanary: %v", err)
	}
	defer func() { _ = c.Cleanup() }()

	if c.Token == "" {
		t.Fatal("token is empty")
	}
	if len(c.Token) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("token length = %d, want 32", len(c.Token))
	}
	if !strings.HasPrefix(c.Filename, "detonate-canary-") {
		t.Errorf("filename = %q, want prefix detonate-canary-", c.Filename)
	}
	if c.HostDir == "" || filepath.Dir(c.HostPath) != c.HostDir {
		t.Fatalf("canary is not contained by its staging directory: %+v", c)
	}

	// File must exist on disk with the token inside
	data, err := os.ReadFile(c.HostPath)
	if err != nil {
		t.Fatalf("reading canary file: %v", err)
	}
	if !strings.Contains(string(data), c.Token) {
		t.Errorf("canary file does not contain the token")
	}
}

func TestCanaryCleanup(t *testing.T) {
	c, err := GenerateCanary()
	if err != nil {
		t.Fatalf("GenerateCanary: %v", err)
	}

	dir := c.HostDir
	if err := c.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("canary staging directory still exists after Cleanup")
	}
	if err := c.Cleanup(); err != nil {
		t.Errorf("second Cleanup should be a no-op: %v", err)
	}
}

func TestGenerateCanaryDoesNotMutateTargetDirectory(t *testing.T) {
	target := t.TempDir()
	marker := filepath.Join(target, "source.txt")
	if err := os.WriteFile(marker, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}

	c, err := GenerateCanary()
	if err != nil {
		t.Fatalf("GenerateCanary: %v", err)
	}
	defer func() { _ = c.Cleanup() }()
	if rel, err := filepath.Rel(target, c.HostPath); err == nil &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("canary path %q is inside target %q", c.HostPath, target)
	}

	after, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("target directory changed: before=%v after=%v", before, after)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "original" {
		t.Fatalf("target content changed: data=%q err=%v", data, err)
	}
}
