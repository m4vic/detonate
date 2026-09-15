// Package ebpf is detonate's host-side runtime monitor: it observes the two
// behaviours the stderr-inference monitor structurally cannot see — a covert
// connect() to an undisclosed host, and a write to a sensitive persistence path
// — scoped by cgroup to the one container under test.
//
// It is deliberately best-effort and additive. eBPF needs a Linux kernel with
// BTF and privilege to load; where any of that is missing (every non-Linux
// host, an unprivileged run, a kernel without BTF), New returns a Monitor whose
// Available() is false and whose Events channel stays empty, and the scan runs
// exactly as it did before. An absent monitor lowers completeness confidence;
// it never invents a finding. eBPF is never a hard dependency of a scan.
//
// The sandbox itself stays capless and non-root — the monitor runs on the host
// and only observes the container from outside. Target code never executes on
// the host.
package ebpf

// EventKind is which observed behaviour an Event records.
type EventKind uint8

const (
	KindConnect   EventKind = 1 // an outbound connect(), possibly covert egress
	KindOpenWrite EventKind = 2 // a write-intent open, possibly persistence
)

// Event is one syscall observed inside the target cgroup.
type Event struct {
	Kind EventKind
	PID  uint32
	Comm string
	Dest string // KindConnect: "ip:port"
	Path string // KindOpenWrite: the opened path
}

// Monitor observes a target cgroup's syscalls until Close.
type Monitor interface {
	// Events streams observed syscalls. Closed when the monitor stops. On an
	// unavailable monitor it is closed immediately, so a range over it is safe
	// and empty.
	Events() <-chan Event
	// Available reports whether eBPF actually attached. False means the scan
	// gets no syscall-level observation — a completeness fact, not a finding.
	Available() bool
	Close() error
}

// noopMonitor is returned wherever eBPF cannot run. Its Events channel is
// closed, so callers range over nothing and need no special case.
type noopMonitor struct{}

func (noopMonitor) Events() <-chan Event {
	ch := make(chan Event)
	close(ch)
	return ch
}
func (noopMonitor) Available() bool { return false }
func (noopMonitor) Close() error    { return nil }
