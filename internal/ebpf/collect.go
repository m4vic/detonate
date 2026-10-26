package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

// maxCollectedEvents caps how many syscall observations one collector holds.
//
// The events are produced by target-controlled behaviour, so their count is
// target-controlled too: a loop calling connect() in a tight cycle would
// otherwise grow this slice until the host ran out of memory, which is a
// denial of service against the scanner rather than a finding about the
// target. Four thousand distinct observations is far past anything a report
// can usefully say, and dedup collapses repeats long before this matters.
const maxCollectedEvents = 4096

// Collector gathers syscall-level observations for one sandboxed container and
// turns them into evidence.
//
// It lives here, rather than beside either caller, because both target kinds
// need it and they sit on opposite sides of an import edge: internal/scan
// imports internal/skill, so a collector in internal/scan could not be used by
// the skill path at all. It is also the natural home — nothing in it knows
// what a scan or a skill is.
//
// Its real job is to keep the layer's best-effort nature in exactly one place.
// Every way this can fail — a non-Linux host, no privilege, a kernel without
// BTF, a cgroup that cannot be resolved or attributed, Docker Desktop putting
// the container in another VM — ends at the same place: a collector that is not
// available, yields nothing, and leaves the scan identical to one built before
// any of this existed. Callers never branch on why.
//
// The zero value is not usable. Collect never returns nil and never errors.
type Collector struct {
	mon Monitor

	// reason records why an unavailable collector is unavailable. Kept for a
	// progress line and for debugging a privileged lane that expected to
	// attach; it is never turned into a finding.
	reason string

	mu        sync.Mutex
	pending   []Event
	truncated bool

	drained chan struct{}
}

// Collect resolves the container's cgroup, attaches the monitor scoped to it,
// and starts gathering in the background.
//
// Attached AFTER the container starts, because the cgroup id does not exist
// until it does. That leaves a short window — between the target's first
// instruction and the attach — which this layer cannot see. The window is
// covered by the stderr tier, which is why evil-mcp's import-time egress is
// caught today, and it is part of why this layer is additive rather than a
// replacement. Closing it means pre-creating a cgroup and passing
// --cgroup-parent to docker run, which is a sandbox policy change.
func Collect(ctx context.Context, containerName string) *Collector {
	c := &Collector{drained: make(chan struct{})}

	cgid, err := CgroupID(ctx, containerName)
	if err != nil {
		c.mon = Unavailable()
		c.reason = err.Error()
		close(c.drained)
		return c
	}

	mon, err := New(cgid)
	if err != nil {
		// New documents that it never errors; handled anyway so a future
		// change to that contract degrades instead of panicking.
		c.mon = Unavailable()
		c.reason = err.Error()
		close(c.drained)
		return c
	}
	c.mon = mon
	if !mon.Available() {
		c.reason = "the kernel would not load or attach the monitor"
		close(c.drained)
		return c
	}

	go c.collect()
	return c
}

// collect drains the monitor's channel for the collector's lifetime.
//
// It keeps reading after the cap is reached rather than stopping. The
// monitor's own reader blocks when its buffered channel fills, and a blocked
// reader stops servicing the kernel ring buffer — so abandoning the drain
// would lose later events and could back-pressure into the kernel. Reading and
// discarding is the behaviour that fails smallest.
func (c *Collector) collect() {
	defer close(c.drained)

	for ev := range c.mon.Events() {
		c.mu.Lock()
		if len(c.pending) < maxCollectedEvents {
			c.pending = append(c.pending, ev)
		} else {
			c.truncated = true
		}
		c.mu.Unlock()
	}
}

// Available reports whether syscall-level observation is actually running.
func (c *Collector) Available() bool {
	return c != nil && c.mon != nil && c.mon.Available()
}

// Reason explains an unavailable collector, for a progress line or a log. It
// is never evidence.
func (c *Collector) Reason() string { return c.reason }

// Take returns the observations gathered since the last call, mapped into
// evidence and attributed to the named phase, and clears the buffer.
//
// Called at each phase boundary rather than once at the end, because the phase
// is what makes a network attempt meaningful. The stderr tier already draws
// this line: a server that reaches out during enumeration did so unprovoked,
// while a tool reaching its own API when called is doing its job. The kernel
// events carry no phase of their own, so the boundary has to be drawn by when
// they are collected.
func (c *Collector) Take(during string, now time.Time) []trace.Event {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	events := c.pending
	c.pending = nil
	truncated := c.truncated
	c.truncated = false
	c.mu.Unlock()

	findings := Findings(events, during, now)

	if truncated {
		// An observation, never a finding: hitting the cap says something
		// about the volume of activity, not about whether any of it was
		// malicious.
		findings = append(findings, trace.Event{
			Kind:     trace.KindLifecycle,
			Severity: trace.SeverityInfo,
			At:       now,
			During:   during,
			Source:   Source,
			Summary: fmt.Sprintf(
				"syscall observation was truncated at %d events; the target generated more than this scan records",
				maxCollectedEvents),
		})
	}
	return findings
}

// AttachedEvent records that the syscall layer was active, as an observation.
//
// Returns nothing at all when the collector did not attach, which is what
// keeps a scan without eBPF identical to one from before this existed — on
// every non-Linux host, every unprivileged run, and every container the
// resolver refused to attribute.
//
// Reported because a reader cannot otherwise tell whether `no_findings` was
// checked at the syscall level or only inferred from stderr, and those support
// very different conclusions. Info severity, so it reaches the observations
// section and moves no verdict: an attached monitor is a fact about the scan,
// not evidence about the target.
func (c *Collector) AttachedEvent(during string, now time.Time) []trace.Event {
	if !c.Available() {
		return nil
	}
	return []trace.Event{{
		Kind:     trace.KindLifecycle,
		Severity: trace.SeverityInfo,
		At:       now,
		During:   during,
		Source:   Source,
		Summary: "syscall-level observation was active for this scan " +
			"(connect() and writes to persistence paths, scoped to the target container)",
	}}
}

// Close stops the monitor and waits for the collector goroutine to finish, so
// a later Take cannot race a drain still in flight and silently lose the last
// observations of a run.
func (c *Collector) Close() {
	if c == nil {
		return
	}
	if c.mon != nil {
		_ = c.mon.Close()
	}
	<-c.drained
}
