package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateCanary(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateCanary(dir)
	if err != nil {
		t.Fatalf("GenerateCanary: %v", err)
	}
	defer c.Cleanup()

	if c.Token == "" {
		t.Fatal("token is empty")
	}
	if len(c.Token) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("token length = %d, want 32", len(c.Token))
	}
	if !strings.HasPrefix(c.Filename, "detonate-canary-") {
		t.Errorf("filename = %q, want prefix detonate-canary-", c.Filename)
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
	dir := t.TempDir()
	c, err := GenerateCanary(dir)
	if err != nil {
		t.Fatalf("GenerateCanary: %v", err)
	}

	path := c.HostPath
	c.Cleanup()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("canary file still exists after Cleanup")
	}
}

func TestGenerateCanaryEmptyDir(t *testing.T) {
	_, err := GenerateCanary("")
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestGenerateCanaryBadDir(t *testing.T) {
	_, err := GenerateCanary(filepath.Join(t.TempDir(), "nonexistent", "subdir"))
	if err == nil {
		t.Fatal("expected error for nonexistent dir")
	}
}
