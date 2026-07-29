package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dockerBinary is resolved from PATH. Shelling out to the CLI rather than
// importing the Docker SDK keeps detonate a single small binary with no
// transitive dependency on Docker's own (large) Go module tree. The CLI is
// also the stable interface: it changes far less than the API client.
const dockerBinary = "docker"

// Container is a running sandboxed process.
//
// It owns a docker subprocess whose stdin/stdout are the container's, so an
// MCP session can speak JSON-RPC straight through the sandbox boundary. That
// is the whole trick of M2: the protocol does not know it crossed a container.
type Container struct {
	Name   string
	Policy Policy

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *safeBuffer

	cancel context.CancelFunc
	done   chan struct{}

	// waitErr is written once by the reaper goroutine before it closes done,
	// so any read after <-done sees it safely without a lock.
	waitErr error
}

// containerArgs turns a Policy into docker CLI flags.
//
// Separated from Start so the flags can be asserted in tests without a running
// daemon. A silently-dropped security flag is exactly the bug that would make
// detonate unsafe while still appearing to work, so it is worth testing
// directly rather than inferring from behaviour.
func containerArgs(name string, p Policy, mounts []Mount, command []string) []string {
	args := []string{
		"run",
		"--rm",          // delete the container when it exits; scans leave no litter
		"--interactive", // keep stdin open: this is the MCP pipe
		"--name", name,
		"--user", p.User,
		"--memory", strconv.FormatInt(p.MemoryBytes, 10),
		"--pids-limit", strconv.FormatInt(p.PidLimit, 10),
		"--cpu-shares", strconv.FormatInt(p.CPUShares, 10),
	}

	if !p.NetworkEnabled {
		args = append(args, "--network", "none")
	}
	if p.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	for _, c := range dropAllCapabilities {
		args = append(args, "--cap-drop", c)
	}
	for _, o := range securityOptions {
		args = append(args, "--security-opt", o)
	}
	for dest, opts := range tmpfsMounts(p.TmpfsSize) {
		args = append(args, "--tmpfs", dest+":"+opts)
	}
	for _, m := range mounts {
		args = append(args, "--volume", m.arg())
	}

	// HOME must be set explicitly, or the tmpfs home above is invisible: a
	// target resolving ~ with HOME unset gets "/" and writes to the read-only
	// root instead. Overridable, but a caller has to mean it.
	env := map[string]string{"HOME": containerHome}
	for k, v := range p.Env {
		env[k] = v
	}

	// Sorted so the argument list is deterministic. Map iteration order is
	// random in Go, and a scanner whose invocation differs run to run is one
	// whose failures cannot be reproduced from a log.
	for _, k := range sortedKeys(env) {
		args = append(args, "--env", k+"="+env[k])
	}

	args = append(args, p.Image)
	return append(args, command...)
}

// sortedKeys returns a map's keys in a stable order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Mount is a host path exposed inside the sandbox.
type Mount struct {
	HostPath      string
	ContainerPath string

	// ReadOnly should be true for anything we are scanning. A target that can
	// rewrite its own source during a scan can make the evidence disagree with
	// the artifact, which defeats the point of having evidence.
	ReadOnly bool
}

func (m Mount) arg() string {
	s := m.HostPath + ":" + m.ContainerPath
	if m.ReadOnly {
		s += ":ro"
	}
	return s
}

// Start launches command inside a sandboxed container and returns it running,
// with stdio wired for the caller to speak a protocol over.
//
// The container is NOT waited on here. Callers talk to it, then must call
// Close, which is what guarantees teardown.
func Start(ctx context.Context, name string, p Policy, mounts []Mount, command []string) (*Container, error) {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)

	cmd := exec.CommandContext(ctx, dockerBinary, containerArgs(name, p, mounts, command)...)
	// WaitDelay turns context cancellation into a real kill rather than a
	// polite request. Without it, a container holding its pipes open keeps the
	// docker client alive past the deadline we promised.
	cmd.WaitDelay = teardownGrace

	// Own the pipes explicitly instead of using cmd.StdoutPipe/StdinPipe.
	//
	// os/exec documents that Wait closes the pipes it hands out, and it is
	// "incorrect to call Wait before all reads from the pipe have completed".
	// We call Wait in a background goroutine (we have to: something must reap
	// the client), so with cmd.StdoutPipe the pipe can close underneath a
	// reader that has not finished draining. For a long-lived MCP session that
	// races harmlessly; for a container that exits quickly it produces an
	// empty read, which for a security tool reads as "the target did nothing"
	// — the most dangerous possible wrong answer.
	//
	// With pipes we create, lifetime is ours: Wait cannot close them, and the
	// reader sees EOF exactly when the child's write end goes away.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("sandbox stdout pipe: %w", err)
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		cancel()
		stdoutR.Close()
		stdoutW.Close()
		return nil, fmt.Errorf("sandbox stdin pipe: %w", err)
	}
	cmd.Stdout = stdoutW
	cmd.Stdin = stdinR

	stdin, stdout := stdinW, stdoutR

	// Capture stderr rather than discarding it: when a sandbox fails to start,
	// docker's own message on stderr is almost always the actual reason, and
	// guessing at it wastes the user's time.
	//
	// safeBuffer, not strings.Builder: os/exec writes this from its own
	// goroutine while callers read it mid-run, and stderr is where a blocked
	// network call leaves its evidence. See safebuf.go.
	stderr := &safeBuffer{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		cancel()
		stdoutR.Close()
		stdoutW.Close()
		stdinR.Close()
		stdinW.Close()
		return nil, fmt.Errorf("starting sandbox: %w", err)
	}

	// The child now holds its own descriptors, so drop the parent's copies of
	// the far ends. Without this the reader never sees EOF: our still-open
	// write end keeps the pipe alive long after the container has exited, and
	// a scan would hang waiting for output that can never come.
	stdoutW.Close()
	stdinR.Close()

	c := &Container{
		Name: name, Policy: p,
		cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr,
		cancel: cancel, done: make(chan struct{}),
	}
	go func() {
		// Keep the exit error. Discarding it threw away the ONLY explanation
		// when `docker run` itself fails — a bad mount, an image that vanished,
		// a daemon that refused. The symptom was a scan reporting "no
		// behaviour observed" for a container that never ran, which is the
		// most dangerous wrong answer this tool can give.
		c.waitErr = cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

// ExitError reports why the container's client exited, blocking until it has.
// nil means a clean exit.
func (c *Container) ExitError() error {
	<-c.done
	return c.waitErr
}

// Failed reports whether the container failed to run at all, and why.
//
// This is the distinction that matters to a caller: "the target ran and did
// nothing suspicious" and "the target never ran" look identical from the
// outside and mean opposite things. Only one of them is a clean bill of
// health.
func (c *Container) Failed() (bool, string) {
	select {
	case <-c.done:
	default:
		return false, "" // still running
	}
	if c.waitErr == nil {
		return false, ""
	}
	detail := c.waitErr.Error()
	if s := strings.TrimSpace(c.stderr.String()); s != "" {
		detail += ": " + s
	}
	return true, detail
}

// Stdin and Stdout are the container's pipes, so a protocol client can be
// pointed straight at the sandboxed process.
func (c *Container) Stdin() io.WriteCloser { return c.stdin }
func (c *Container) Stdout() io.ReadCloser { return c.stdout }

// Stderr returns whatever the container wrote to stderr so far. Useful both
// for diagnosing a failed start and, later, as evidence.
func (c *Container) Stderr() string { return c.stderr.String() }

// teardownGrace bounds how long a container gets to die politely before it is
// killed. Same reasoning as the MCP driver: a scan that returns while its
// subject still runs has not finished scanning.
const teardownGrace = 5 * time.Second

// Close tears the sandbox down and does not return until the CONTAINER is
// gone — not merely until our client process died.
//
// That distinction is the whole subtlety of this function, and getting it
// wrong is invisible in testing that only checks our own process. `docker run`
// is a client. The container is a child of the DAEMON, so killing the client
// orphans a still-running container: our code returns, reports success, and
// untrusted code keeps executing. detonate's own integration test caught
// exactly that.
//
// So teardown is daemon-side. Closing stdin gives a well-behaved server the
// chance to exit on its own; after that we tell the daemon to stop it, and
// `rm -f` is the backstop.
func (c *Container) Close() error {
	_ = c.stdin.Close()
	// We own the read end too now, so it is ours to release. One leaked
	// descriptor per scan matters for a tool meant to run in a CI loop.
	defer c.stdout.Close()

	select {
	case <-c.done:
		// The client exited, but --rm removal is asynchronous on the daemon
		// side, so still confirm the container is actually gone.
		return c.ensureGone()
	case <-time.After(politeGrace):
	}

	// It ignored the closed pipe. Stop it at the daemon, which is the only
	// place that can actually end it.
	if err := c.stop(); err != nil {
		// Fall through to the kill path rather than returning: a stop that
		// failed is the case where forced removal matters most.
		_ = err
	}

	select {
	case <-c.done:
	case <-time.After(teardownGrace):
	}

	c.cancel() // release our client process and its pipes
	return c.ensureGone()
}

// politeGrace is how long a server gets to exit on its own after its stdin
// closes, before we stop being polite. Short: a cooperative server exits
// immediately, and an uncooperative one is not going to change its mind.
const politeGrace = 2 * time.Second

// stop asks the daemon to stop the container, with a short SIGKILL deadline.
//
// A fresh context every time, deliberately: by this point the scan's own
// context is usually cancelled, and inheriting it would make cleanup fail
// precisely when cleanup is most necessary.
func (c *Container) stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), teardownGrace)
	defer cancel()

	// -t 1: one second to handle SIGTERM, then SIGKILL. We are not negotiating
	// with untrusted code.
	return exec.CommandContext(ctx, dockerBinary, "stop", "-t", "1", c.Name).Run()
}

// ensureGone confirms the container no longer exists, forcing removal if it
// does. This is the function that makes Close's promise true.
func (c *Container) ensureGone() error {
	deadline := time.Now().Add(teardownGrace)
	for {
		if !c.exists() {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), teardownGrace)
	defer cancel()
	if err := exec.CommandContext(ctx, dockerBinary, "rm", "-f", c.Name).Run(); err != nil {
		return fmt.Errorf("sandbox %s survived teardown: %w", c.Name, err)
	}
	if c.exists() {
		return fmt.Errorf("sandbox %s still present after forced removal", c.Name)
	}
	return nil
}

// exists reports whether the daemon still knows about this container.
func (c *Container) exists() bool {
	ctx, cancel := context.WithTimeout(context.Background(), teardownGrace)
	defer cancel()

	out, err := exec.CommandContext(ctx, dockerBinary,
		"ps", "-a", "--filter", "name="+c.Name, "--format", "{{.Names}}").Output()
	if err != nil {
		// If we cannot ask the daemon, assume the worst rather than reporting
		// a clean teardown we did not verify.
		return true
	}
	return strings.Contains(string(out), c.Name)
}
