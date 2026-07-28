// Package trace is detonate's evidence model.
//
// A static scanner says "this description looks suspicious". A dynamic one
// says "at t=1.2s, after calling read_file, the process opened a TCP
// connection to 34.x.x.x:443 and wrote 4KB". The second is a fact with a
// timestamp. Nobody argues with it, and it survives being handed to someone
// who does not trust the tool that produced it.
//
// So the trace is the product. Verdicts are derived from it and can be
// recomputed; the trace itself is what gets stored, diffed across runs, and
// pasted into a report.
package trace

import (
	"fmt"
	"time"
)

// Kind is what sort of behaviour was observed.
type Kind string

const (
	// KindNetwork is any attempt to reach the network. With the default
	// policy the attempt fails, and the ATTEMPT is the finding: a tool that
	// tries to phone home while enumerating has already told us what it is.
	KindNetwork Kind = "network"

	// KindFile is a filesystem access outside the target's own directory.
	KindFile Kind = "file"

	// KindProcess is a process spawn. An MCP server that shells out during
	// tool enumeration is doing something it did not need to do.
	KindProcess Kind = "process"

	// KindResource is a resource limit being hit: memory ceiling, PID
	// ceiling, CPU saturation.
	KindResource Kind = "resource"

	// KindProtocol is MCP-level behaviour worth recording — an oversized
	// description, a tool appearing that was not there last run.
	KindProtocol Kind = "protocol"

	// KindLifecycle is the container itself starting, exiting, or being
	// killed. Not suspicious on its own, but it is the spine every other
	// event hangs off: without it, "t=1.2s" has no origin.
	KindLifecycle Kind = "lifecycle"
)

// Severity is how much a single event matters on its own.
//
// Deliberately coarse. Fine-grained scoring invites the alert-fatigue failure
// where everything is a 6.5/10 and nobody reads any of it. The verdict layer
// correlates events; this is just the raw weight of one.
type Severity string

const (
	SeverityInfo     Severity = "info"     // context, not a finding
	SeverityNotable  Severity = "notable"  // worth a human glance
	SeverityCritical Severity = "critical" // a finding on its own
)

// Event is one observed behaviour.
//
// Every field answers a question a reader will ask: what happened, when,
// during what, and how do we know. The last one matters most — Source records
// which monitor saw it, so a finding can be traced back to the mechanism that
// produced it rather than being taken on faith.
type Event struct {
	Kind     Kind      `json:"kind"`
	Severity Severity  `json:"severity"`
	At       time.Time `json:"at"`

	// Elapsed since the container started. Wall-clock time is unstable across
	// runs and useless for diffing; elapsed time is comparable.
	Elapsed time.Duration `json:"elapsed_ms"`

	// Summary is one line a human reads. Detail carries the specifics a
	// machine (or a careful human) needs.
	Summary string         `json:"summary"`
	Detail  map[string]any `json:"detail,omitempty"`

	// During names the probe or phase this happened in, so behaviour can be
	// attributed to a stimulus. "It opened a socket" is interesting. "It
	// opened a socket when we called read_file with a traversal path" is a
	// finding.
	During string `json:"during,omitempty"`

	// Source is the monitor that observed this, e.g. "docker-events",
	// "container-stderr". Evidence that cannot name its own origin is not
	// evidence.
	Source string `json:"source"`
}

func (e Event) String() string {
	return fmt.Sprintf("[%s/%s +%dms] %s",
		e.Kind, e.Severity, e.Elapsed.Milliseconds(), e.Summary)
}

// Trace is the ordered record of everything observed during one scan.
type Trace struct {
	Target  string    `json:"target"`
	Started time.Time `json:"started"`
	Events  []Event   `json:"events"`
}

// Add appends an event, filling in Elapsed relative to the trace start so
// callers never have to compute it (and so they cannot get it wrong).
func (t *Trace) Add(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.Elapsed = e.At.Sub(t.Started)
	t.Events = append(t.Events, e)
}

// Filter returns the events of a given kind.
func (t *Trace) Filter(k Kind) []Event {
	var out []Event
	for _, e := range t.Events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// HasSeverity reports whether any event reached at least the given severity.
func (t *Trace) HasSeverity(s Severity) bool {
	for _, e := range t.Events {
		if severityRank(e.Severity) >= severityRank(s) {
			return true
		}
	}
	return false
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityNotable:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}
