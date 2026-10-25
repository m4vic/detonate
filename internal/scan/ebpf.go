package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/m4vic/detonate/internal/ebpf"
	"github.com/m4vic/detonate/internal/trace"
)

// maxRuntimeEvents caps how many syscall observations one scan will hold.
//
// The events are produced by target-controlled behaviour, so their count is
// target-controlled too: a loop calling connect() in a tight cycle would
// otherwise grow this slice until the host ran out of memory, which is a
// denial of service against the scanner rather than a finding about the
// target. Four thousand distinct observations is far past anything a report
// can usefully say; dedup collapses repeats long before this matters.
const maxRuntimeEvents = 4096

// runtimeMonitor collects syscall-level observations for one sandboxed target.
//
// It exists to keep the eBPF layer's best-effort nature in exactly one place.
// Every way this can fail — a non-Linux host, no privilege, a kernel without
// BTF, a cgroup that cannot be resolved or attributed, Docker Desktop putting
// the container in another VM — ends at the same place: a monitor that is not
// available, yields nothing, and leaves the scan byte-identical to one built
// before any of this existed. Callers do not branch on why.
//
// The zero value is not usable; call startRuntimeMonitor, which never returns
// nil and never returns an error.
type runtimeMonitor struct {
	mon ebpf.Monitor

	// reason records why an unavailable monitor is unavailable. Kept for the
	// progress line and for debugging a CI lane that expected to attach; it is
	// never turned into a finding.
	reason string

	mu        sync.Mutex
	pending   []ebpf.Event
	truncated bool

	drained chan struct{}
}

// startRuntimeMonitor resolves the target container's cgroup and attaches the
// monitor to it, returning a monitor that collects in the background.
//
// Attached AFTER the container starts, because the cgroup id does not exist
// until it does. That leaves a short window at startup — between the first
// instruction the target runs and the attach — which this layer cannot see.
// The window is covered by the stderr tier, which is why evil-mcp's
// import-time egress is caught today, and it is why this layer is additive
// rather than a replacement. Closing the window means pre-creating a cgroup
// and passing --cgroup-parent to docker run, which is a change to the sandbox
// policy and not part of this milestone.
func startRuntimeMonitor(ctx context.Context, containerName string) *runtimeMonitor {
	r := &runtimeMonitor{drained: make(chan struct{})}

	cgid, err := ebpf.CgroupID(ctx, containerName)
	if err != nil {
		r.mon = ebpf.Unavailable()
		r.reason = err.Error()
		close(r.drained)
		return r
	}

	mon, err := ebpf.New(cgid)
	if err != nil {
		// ebpf.New documents that it never errors; handled anyway so a future
		// change to that contract degrades instead of panicking.
		r.mon = ebpf.Unavailable()
		r.reason = err.Error()
		close(r.drained)
		return r
	}
	r.mon = mon
	if !mon.Available() {
		r.reason = "the kernel would not load or attach the monitor"
		close(r.drained)
		return r
	}

	go r.collect()
	return r
}

// collect drains the monitor's channel for the life of the scan.
//
// It keeps reading after the cap is reached rather than stopping. The
// monitor's own reader blocks when its buffered channel fills, and a blocked
// reader stops servicing the kernel ring buffer — so abandoning the drain
// would lose later events and could back pressure into the kernel. Reading and
// discarding is the behaviour that fails smallest.
func (r *runtimeMonitor) collect() {
	defer close(r.drained)

	for ev := range r.mon.Events() {
		r.mu.Lock()
		if len(r.pending) < maxRuntimeEvents {
			r.pending = append(r.pending, ev)
		} else {
			r.truncated = true
		}
		r.mu.Unlock()
	}
}

// available reports whether syscall-level observation is actually running.
func (r *runtimeMonitor) available() bool {
	return r.mon != nil && r.mon.Available()
}

// take returns the observations collected since the last call, mapped into
// evidence and attributed to the named phase, and clears the buffer.
//
// Called at each phase boundary rather than once at the end, because the phase
// is what makes a network attempt meaningful. The stderr tier already draws
// this line: a server that reaches out during enumeration did so unprovoked,
// while a tool reaching its own API when called is doing its job. The kernel
// events carry no phase of their own, so the boundary has to be drawn by when
// they are collected.
func (r *runtimeMonitor) take(during string, now time.Time) []trace.Event {
	r.mu.Lock()
	events := r.pending
	r.pending = nil
	truncated := r.truncated
	r.truncated = false
	r.mu.Unlock()

	findings := ebpf.Findings(events, during, now)

	if truncated {
		// Recorded as an observation, never as a finding: hitting the cap says
		// something about the volume of activity, not about whether any of it
		// was malicious.
		findings = append(findings, trace.Event{
			Kind:     trace.KindLifecycle,
			Severity: trace.SeverityInfo,
			At:       now,
			During:   during,
			Source:   ebpf.Source,
			Summary: fmt.Sprintf(
				"syscall observation was truncated at %d events; the target generated more than this scan records",
				maxRuntimeEvents),
		})
	}
	return findings
}

// close stops the monitor and waits for the collector to finish, so a later
// take cannot race with a drain still in flight.
func (r *runtimeMonitor) close() {
	if r.mon != nil {
		_ = r.mon.Close()
	}
	<-r.drained
}

// attachedEvent records that the syscall layer was active, as an observation.
//
// Returns nothing at all when the monitor did not attach, which is what keeps
// a scan without eBPF byte-identical to one from before this existed — on
// every non-Linux host, every unprivileged run, and every container the
// resolver refused to attribute.
//
// Reported because a reader cannot otherwise tell whether `no_findings` was
// checked at the syscall level or only inferred from stderr, and those support
// very different conclusions. Info severity, so it reaches the observations
// section and changes no verdict: an attached monitor is a fact about the
// scan, not evidence about the target.
func (r *runtimeMonitor) attachedEvent(during string, now time.Time) []trace.Event {
	if !r.available() {
		return nil
	}
	return []trace.Event{{
		Kind:     trace.KindLifecycle,
		Severity: trace.SeverityInfo,
		At:       now,
		During:   during,
		Source:   ebpf.Source,
		Summary: "syscall-level observation was active for this scan " +
			"(connect() and writes to persistence paths, scoped to the target container)",
	}}
}
