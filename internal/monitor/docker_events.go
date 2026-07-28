// Package monitor observes what a sandboxed target actually does.
//
// This is the half of "dynamic analysis" that makes the sandbox worth having.
// Running untrusted code in a container is only interesting if something is
// watching; without a monitor, detonate would confine a target beautifully and
// learn nothing from it.
//
// The design rule here is that we observe at a layer the target does not
// control. A server can lie in a JSON-RPC response. It cannot lie about the
// container's exit code, the memory ceiling it hit, or the fact that the
// daemon killed it — those come from the runtime, not from the target.
package monitor

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

const dockerBinary = "docker"

// DockerEvents streams container lifecycle events from the Docker daemon into
// a Trace.
//
// This is the coarse tier. It cannot see individual syscalls — that needs eBPF
// (deferred, and Linux-only) — but it reliably reports the things that matter
// most for a first verdict: did the container die on its own or get killed,
// did it hit a resource ceiling, how long did it live.
//
// Crucially these facts come from the DAEMON. A target that fakes a clean exit
// message on stdout cannot fake an OOM kill in the event stream.
type DockerEvents struct {
	container string
	cmd       *exec.Cmd
	events    chan trace.Event
	done      chan struct{}
}

// WatchContainer starts streaming events for one container.
//
// Started before the container itself, deliberately: `docker events` only
// reports what happens after it attaches, so subscribing afterwards races the
// container's own startup and can miss the die event of something that fails
// instantly — which is exactly the case worth catching.
func WatchContainer(ctx context.Context, name string) (*DockerEvents, error) {
	cmd := exec.CommandContext(ctx, dockerBinary, "events",
		"--filter", "type=container",
		"--filter", "container="+name,
		"--format", "{{.Action}}|{{.Actor.Attributes.name}}|{{.Actor.Attributes.exitCode}}")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	d := &DockerEvents{
		container: name,
		cmd:       cmd,
		events:    make(chan trace.Event, 64), // buffered: a burst must not block the daemon reader
		done:      make(chan struct{}),
	}

	go func() {
		defer close(d.events)
		defer close(d.done)

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if ev, ok := parseEvent(scanner.Text()); ok {
				select {
				case d.events <- ev:
				default:
					// Never block the daemon stream to preserve an event. A
					// dropped event is a gap in evidence; a stalled reader
					// silently stops collecting evidence entirely, which is
					// worse and harder to notice.
				}
			}
		}
	}()

	return d, nil
}

// Events yields observed events until the container is gone.
func (d *DockerEvents) Events() <-chan trace.Event { return d.events }

// Close stops watching.
func (d *DockerEvents) Close() {
	if d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
	}
	<-d.done
}

// parseEvent turns one line of `docker events` output into an Event.
//
// The line format is set by the --format string above:
//
//	action|name|exitCode
func parseEvent(line string) (trace.Event, bool) {
	parts := strings.Split(strings.TrimSpace(line), "|")
	if len(parts) < 2 || parts[0] == "" {
		return trace.Event{}, false
	}
	action, exitCode := parts[0], ""
	if len(parts) >= 3 {
		exitCode = parts[2]
	}

	ev := trace.Event{
		Kind:     trace.KindLifecycle,
		Severity: trace.SeverityInfo,
		At:       time.Now(),
		Source:   "docker-events",
		Detail:   map[string]any{"action": action},
	}

	switch action {
	case "create":
		ev.Summary = "container created"
	case "start":
		ev.Summary = "container started"
	case "die":
		ev.Summary = "container exited (code " + exitCode + ")"
		ev.Detail["exit_code"] = exitCode
		// A non-zero exit is not itself an attack, but it is the single most
		// common reason a scan produces nothing, so it must reach the report
		// rather than being swallowed.
		if exitCode != "0" && exitCode != "" {
			ev.Severity = trace.SeverityNotable
		}
	case "oom":
		// The memory ceiling was hit. Either the target is broken or it is
		// deliberately trying to exhaust the host, and both are worth saying
		// out loud.
		ev.Kind = trace.KindResource
		ev.Severity = trace.SeverityCritical
		ev.Summary = "container hit its memory limit (OOM killed)"
	case "kill":
		ev.Kind = trace.KindResource
		ev.Severity = trace.SeverityNotable
		ev.Summary = "container was killed"
	case "destroy":
		ev.Summary = "container removed"
	case "attach":
		// Our own stdio attach. Noise, not behaviour.
		return trace.Event{}, false
	default:
		ev.Summary = "container " + action
	}

	return ev, true
}
