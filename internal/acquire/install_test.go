package acquire

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/sandbox"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
}

// A target with no manifest must skip the install entirely rather than
// failing. A stdlib-only server is a perfectly good target.
func TestInstallSkipsWhenNothingToInstall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Install(context.Background(), dir, sandbox.DefaultPolicy())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Volume != "" {
		t.Errorf("created a volume for a target with no dependencies: %q", res.Volume)
	}
	if len(res.Mounts()) != 0 {
		t.Errorf("Mounts() = %v, want none", res.Mounts())
	}
	if err := res.Cleanup(context.Background()); err != nil {
		t.Errorf("Cleanup on an empty result should be a no-op: %v", err)
	}
}

// The end-to-end claim: a package installed in phase 1 is importable in phase
// 2, which has no network. Without this the sandbox can only run stdlib-only
// servers, and almost every real MCP server imports something.
func TestInstallMakesPackagesImportableWithoutNetwork(t *testing.T) {
	requireDocker(t)

	dir := t.TempDir()
	// A tiny, dependency-free package so the test does not depend on a large
	// tree resolving correctly.
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("six==1.17.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := sandbox.DefaultPolicy()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	if err := sandbox.EnsureImage(ctx, policy.Image); err != nil {
		t.Skipf("cannot pull sandbox image: %v", err)
	}

	res, err := Install(ctx, dir, policy)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer res.Cleanup(context.Background())

	if res.Volume == "" {
		t.Fatal("no dependency volume created")
	}
	if res.Env["PYTHONPATH"] != DepsDir {
		t.Errorf("PYTHONPATH = %q, want %q", res.Env["PYTHONPATH"], DepsDir)
	}

	// Now the actual proof: import it in a container with the network OFF.
	p := sandbox.DefaultPolicy()
	p.Env = res.Env
	p.Timeout = 60 * time.Second

	name, err := sandbox.NewName()
	if err != nil {
		t.Fatal(err)
	}
	c, err := sandbox.Start(ctx, name, p, res.Mounts(),
		[]string{"python", "-c", "import six; print('IMPORT_OK', six.__version__)"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	out := readAll(t, c)
	if !strings.Contains(out, "IMPORT_OK") {
		t.Fatalf("package not importable in the offline sandbox.\nstdout: %q\nstderr: %q",
			out, c.Stderr())
	}
}

// The dependency mount must be read-only in phase 2: a target that can rewrite
// its own dependencies while being observed means the code we report on is not
// the code that ran.
func TestDependencyMountIsReadOnly(t *testing.T) {
	res := &Result{Volume: "some-volume"}
	mounts := res.Mounts()
	if len(mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mounts))
	}
	if !mounts[0].ReadOnly {
		t.Error("dependencies must be mounted read-only during detonation")
	}
	if mounts[0].ContainerPath != DepsDir {
		t.Errorf("ContainerPath = %q, want %q", mounts[0].ContainerPath, DepsDir)
	}
}

func TestCleanupIsIdempotent(t *testing.T) {
	requireDocker(t)

	res := &Result{}
	if err := res.Cleanup(context.Background()); err != nil {
		t.Errorf("first cleanup: %v", err)
	}
	if err := res.Cleanup(context.Background()); err != nil {
		t.Errorf("second cleanup should be a no-op: %v", err)
	}
}

func readAll(t *testing.T, c *sandbox.Container) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		b := make([]byte, 0, 4096)
		buf := make([]byte, 1024)
		for {
			n, err := c.Stdout().Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		ch <- string(b)
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(90 * time.Second):
		t.Fatal("timed out reading container output")
		return ""
	}
}
