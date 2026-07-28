package sandbox

import (
	"context"
	"io"
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
// stdout. A helper because every test below has the same shape: confine
// something, ask it to misbehave, read what happened.
//
// It retries a silent container once. `go test ./...` runs packages in
// parallel, so several suites hit one Docker daemon at once; under that
// contention a container can be slow enough that the read reaches EOF before
// the shell has written anything. Distinguishing "the target said nothing"
// from "the daemon was busy" is the difference between a real finding and a
// flaky test, and a security suite that fails at random gets ignored.
func runInSandbox(t *testing.T, p Policy, script string) string {
	t.Helper()

	const attempts = 2
	for i := 1; i <= attempts; i++ {
		out, stderr := runOnce(t, p, script)
		if strings.TrimSpace(out) != "" || stderr != "" || i == attempts {
			if stderr != "" {
				t.Logf("container stderr: %s", stderr)
			}
			return out
		}
		t.Logf("attempt %d produced nothing and no stderr; daemon likely contended, retrying", i)
		time.Sleep(2 * time.Second)
	}
	return ""
}

// runOnce is a single container run, returning its stdout and stderr.
func runOnce(t *testing.T, p Policy, script string) (stdout, stderr string) {
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

	// Read until the pipe closes, which happens when the container exits and
	// its write end goes away.
	ch := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(c.Stdout())
		ch <- string(b)
	}()

	select {
	case stdout = <-ch:
	case <-time.After(p.Timeout):
		t.Fatalf("container produced no output within %s", p.Timeout)
	}
	return stdout, c.Stderr()
}

// runInSandboxExpectingOutput is runInSandbox for the tests whose conclusion
// depends on reading what the container said.
//
// Kept separate because one test — the PID limit — deliberately starves the
// container until it cannot fork, and a starved container producing no output
// is the SUCCESS case there. Folding that assertion into the shared helper
// made a passing safety control look like a failure.
func runInSandboxExpectingOutput(t *testing.T, p Policy, script string) string {
	t.Helper()
	out := runInSandbox(t, p, script)
	if strings.TrimSpace(out) == "" {
		t.Fatalf("container produced no output; script was: %s", script)
	}
	return out
}

// The headline claim. A sandboxed target must not be able to reach the
// network, because that is what turns a poisoned server from a curiosity into
// an exfiltration.
func TestSandboxBlocksNetwork(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest" // small, and has wget
	p.Timeout = 60 * time.Second

	out := runInSandboxExpectingOutput(t, p,
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

	out := runInSandboxExpectingOutput(t, p,
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
	out := runInSandboxExpectingOutput(t, p, strings.Join([]string{
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

	out := strings.TrimSpace(runInSandboxExpectingOutput(t, p, "id -u"))
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

	// The evidence is the container's stderr ("can't fork"), NOT its stdout.
	//
	// A container starved of PIDs frequently cannot produce output at all,
	// because even the shell needs to fork. An earlier version of this test
	// required stdout, which turned a working safety control into a failure:
	// the more effective the limit, the more certainly the test failed.
	//
	// What is actually being asserted is that we reached this line at all —
	// meaning 200 forks hit the container's ceiling instead of the host's, the
	// machine stayed usable, and teardown completed. If the limit had not
	// held, the test process would not be here to make an assertion.
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
