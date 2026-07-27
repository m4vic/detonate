// Package environment holds detonate's pre-flight checks.
//
// detonate executes UNTRUSTED code, so it must never run without a real
// sandbox. That makes Docker a hard requirement: every scan needs a container
// to detonate inside. This package answers one question, "is Docker ready?",
// before any scan is allowed to start.
//
// Design choice: we check by shelling out to the `docker` CLI rather than
// importing a Docker client library. A liveness check needs no SDK, behaves
// identically on every OS, and keeps the dependency list honest. The real
// client arrives with M2, when we actually orchestrate containers instead of
// just asking whether we could.
package environment

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds the daemon probe. `docker info` against a wedged
// daemon can hang indefinitely, and a scanner that hangs on startup is worse
// than one that fails: the user cannot tell it apart from a slow scan.
const DefaultTimeout = 15 * time.Second

// DockerStatus is the result of the pre-flight check.
type DockerStatus struct {
	Installed bool   // is the `docker` binary on PATH?
	Running   bool   // is the daemon actually responding?
	Detail    string // human-readable status, or the reason it failed
}

// Ready reports whether detonate may proceed. Both conditions are required:
// an installed Docker with a dead daemon sandboxes exactly nothing.
func (s DockerStatus) Ready() bool { return s.Installed && s.Running }

// CheckDocker reports whether Docker is installed and its daemon responding.
//
// The two failure modes are reported distinctly so the user knows what to fix:
// a missing binary means Docker isn't installed, while a non-zero `docker info`
// means it is installed but not started (or the user lacks permission).
func CheckDocker(ctx context.Context) DockerStatus {
	if _, err := exec.LookPath("docker"); err != nil {
		return DockerStatus{Detail: "docker binary not found on PATH"}
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	// CommandContext, not Command: this is what makes the timeout above real.
	// Without it the context would expire while we still blocked on Wait.
	cmd := exec.CommandContext(ctx, "docker", "info")
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return DockerStatus{
				Installed: true,
				Detail:    "docker present but not responding within " + DefaultTimeout.String(),
			}
		}
		return DockerStatus{Installed: true, Detail: daemonFailureReason(stderr.String())}
	}

	return DockerStatus{Installed: true, Running: true, Detail: "docker ready"}
}

// daemonFailureReason surfaces docker's own last line of stderr, which is
// usually the clearest explanation ("Cannot connect to the Docker daemon",
// "permission denied"). Anything we wrote ourselves would be vaguer.
func daemonFailureReason(stderr string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return last
	}
	return "docker daemon not running"
}
