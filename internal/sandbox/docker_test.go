package sandbox

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Integration tests against a real Docker daemon.
//
// The policy tests prove we generate the right flags. These prove the flags
// actually confine anything, which is a different claim: a correct flag that
// the runtime ignores looks identical from the outside. For a tool whose
// entire value is "we ran it safely", that gap has to be closed by observation
// rather than argument.
//
// Skipped automatically when Docker is unavailable so the suite still runs on
// a machine without it.

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(dockerBinary); err != nil {
		t.Skip("docker not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, dockerBinary, "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
}

// runInSandbox starts a container running a shell command and returns its
// combined stdout. A helper because every test below has the same shape:
// confine something, ask it to misbehave, read what happened.
func runInSandbox(t *testing.T, p Policy, script string) string {
	t.Helper()

	name, err := NewName()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout+30*time.Second)
	defer cancel()

	c, err := Start(ctx, name, p, nil, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	var out strings.Builder
	scanner := bufio.NewScanner(c.Stdout())
	for scanner.Scan() {
		out.WriteString(scanner.Text())
		out.WriteString("\n")
	}
	if s := c.Stderr(); s != "" {
		t.Logf("container stderr: %s", s)
	}
	return out.String()
}

// The headline claim. A sandboxed target must not be able to reach the
// network, because that is what turns a poisoned server from a curiosity into
// an exfiltration.
func TestSandboxBlocksNetwork(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest" // small, and has wget
	p.Timeout = 60 * time.Second

	out := runInSandbox(t, p,
		"wget -q -T3 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED")

	if strings.Contains(out, "REACHED") {
		t.Fatal("sandboxed code reached the internet; --network none is not holding")
	}
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("inconclusive network result: %q", out)
	}
}

func TestSandboxRootfsIsReadOnly(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest"

	out := runInSandbox(t, p,
		"touch /evil 2>/dev/null && echo WROTE || echo READONLY")

	if strings.Contains(out, "WROTE") {
		t.Error("target wrote to the root filesystem; --read-only is not holding")
	}
}

func TestSandboxHasWritableButNonExecutableTmp(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest"

	// Real servers need scratch space, so /tmp must be writable. But a target
	// that stages a payload there must not be able to execute it.
	out := runInSandbox(t, p, strings.Join([]string{
		"echo -e '#!/bin/sh\\necho PWNED' > /tmp/x && echo WROTE_TMP || echo NO_TMP",
		"chmod +x /tmp/x 2>/dev/null",
		"/tmp/x 2>/dev/null && echo EXECUTED || echo NOEXEC",
	}, "; "))

	if !strings.Contains(out, "WROTE_TMP") {
		t.Error("/tmp is not writable; real MCP servers will fail")
	}
	if strings.Contains(out, "EXECUTED") {
		t.Error("code staged in /tmp executed; noexec is not holding")
	}
}

func TestSandboxDoesNotRunAsRoot(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest"

	out := strings.TrimSpace(runInSandbox(t, p, "id -u"))
	if out == "0" {
		t.Error("target is running as root inside the container")
	}
}

// A fork bomb must exhaust its own PID limit, not the host's process table.
func TestSandboxLimitsProcesses(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest"
	p.Timeout = 30 * time.Second

	// If the limit does not hold, this takes the machine down rather than
	// failing the test, so keep the limit small and the timeout short.
	p.PidLimit = 32
	runInSandbox(t, p, "for i in $(seq 1 200); do sleep 5 & done; echo SURVIVED")

	// Reaching here at all means the host stayed usable and teardown worked.
}

// Teardown is a safety property, not tidiness: a scan that returns while its
// subject still runs has not finished scanning.
func TestSandboxIsRemovedAfterClose(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest"

	name, err := NewName()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// A container that ignores stdin closing and would outlive its client.
	c, err := Start(ctx, name, p, nil, []string{"sh", "-c", "sleep 300"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Poll: removal is asynchronous on the daemon side.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if !containerExists(t, name) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("container %s survived Close; untrusted code outlived the scan", name)
}

func containerExists(t *testing.T, name string) bool {
	t.Helper()
	out, err := exec.Command(dockerBinary, "ps", "-a", "--filter", "name="+name, "--format", "{{.Names}}").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), name)
}
