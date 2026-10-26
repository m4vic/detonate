package ebpf

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

var collectAt = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// fakeMonitor stands in for a kernel. The collector's job — drain, cap, snapshot
// per phase — is all testable without privilege, a BTF kernel or a container,
// which matters because the developer machine has none of those.
type fakeMonitor struct {
	events    chan Event
	available bool
	closed    bool
}

func newFakeMonitor(buffer int) *fakeMonitor {
	return &fakeMonitor{events: make(chan Event, buffer), available: true}
}

func (f *fakeMonitor) Events() <-chan Event { return f.events }
func (f *fakeMonitor) Available() bool      { return f.available }
func (f *fakeMonitor) Close() error {
	if !f.closed {
		f.closed = true
		close(f.events)
	}
	return nil
}

// startFakeCollector builds a collector around a fake monitor and starts draining,
// mirroring what Collect does once an attach succeeds.
func startFakeCollector(f *fakeMonitor) *Collector {
	r := &Collector{mon: f, drained: make(chan struct{})}
	go r.collect()
	return r
}

// E4, the half that can be proven without a kernel: when eBPF is out of reach
// the layer contributes NOTHING. Not a finding, not an observation, not a
// scenario — so a scan on a non-Linux host, an unprivileged run, or a
// container whose cgroup cannot be attributed is identical to one from before
// any of this existed.
//
// This is the property that makes the layer additive. If it ever adds even an
// observation when unavailable, every existing report changes and every
// recorded corpus expectation has to be re-baselined.
func TestUnavailableMonitorContributesNothing(t *testing.T) {
	// A container name that cannot resolve. On Windows and macOS the resolver
	// refuses outright; on Linux docker inspect fails. Both are the path under
	// test.
	r := Collect(context.Background(), "detonate-no-such-container")
	defer r.Close()

	if r.Available() {
		t.Fatal("monitor reports available for a container that does not exist")
	}
	if r.reason == "" {
		t.Error("an unavailable monitor did not record why")
	}

	if got := r.AttachedEvent("enumeration", collectAt); got != nil {
		t.Errorf("attachedEvent returned %d event(s) while unavailable: %+v", len(got), got)
	}
	for _, phase := range []string{"enumeration", "probe"} {
		if got := r.Take(phase, collectAt); got != nil {
			t.Errorf("take(%q) returned %d event(s) while unavailable: %+v",
				phase, len(got), got)
		}
	}
}

// close must be safe on an unavailable monitor, which is the common case on
// every developer machine. It is called from a defer on every MCP scan.
func TestClosingAnUnavailableMonitorIsSafeAndDoesNotHang(t *testing.T) {
	r := Collect(context.Background(), "detonate-no-such-container")

	done := make(chan struct{})
	go func() { r.Close(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close blocked on an unavailable monitor; every scan defers this")
	}
}

// The phase is what makes a network attempt meaningful: unprovoked at
// enumeration, possibly a tool doing its job during probing. The kernel events
// carry no phase, so the boundary is drawn by when they are collected — and
// take must therefore attribute to the phase it is called for and clear, so
// nothing is counted in two phases.
func TestTakeAttributesToThePhaseAndClears(t *testing.T) {
	f := newFakeMonitor(8)
	r := startFakeCollector(f)

	f.events <- Event{Kind: KindConnect, PID: 1, Comm: "node", Dest: "203.0.113.1:443"}
	waitForPending(t, r, 1)

	enum := r.Take("enumeration", collectAt)
	if len(enum) != 1 {
		t.Fatalf("enumeration take returned %d events, want 1", len(enum))
	}
	if enum[0].During != "enumeration" {
		t.Errorf("During = %q, want enumeration", enum[0].During)
	}
	if enum[0].Source != Source {
		t.Errorf("Source = %q, want %q", enum[0].Source, Source)
	}

	// The same event must not reappear in the next phase.
	if again := r.Take("probe", collectAt); len(again) != 0 {
		t.Fatalf("take did not clear; %d event(s) reported twice: %+v", len(again), again)
	}

	// A new event belongs to the phase it arrived in.
	f.events <- Event{Kind: KindConnect, PID: 2, Comm: "node", Dest: "203.0.113.2:443"}
	waitForPending(t, r, 1)

	probePhase := r.Take("probe", collectAt)
	if len(probePhase) != 1 {
		t.Fatalf("probe take returned %d events, want 1", len(probePhase))
	}
	if probePhase[0].During != "probe" {
		t.Errorf("During = %q, want probe", probePhase[0].During)
	}

	r.Close()
}

// The event count is target-controlled, so it is a budget. A loop calling
// connect() must not be able to grow this slice until the host runs out of
// memory: that would be a denial of service against the scanner rather than a
// finding about the target.
func TestHostileEventVolumeIsCappedAndDisclosed(t *testing.T) {
	f := newFakeMonitor(1)
	r := startFakeCollector(f)

	// Each event is a distinct destination, so dedup cannot collapse them and
	// the cap is what has to hold.
	total := maxCollectedEvents + 500
	for i := 0; i < total; i++ {
		f.events <- Event{
			Kind: KindConnect,
			Dest: netAddr(i),
		}
	}
	// Everything accepted has been queued; the cap is already reached.
	waitForPending(t, r, maxCollectedEvents)

	got := r.Take("probe", collectAt)

	var findings, observations int
	var truncation string
	for _, ev := range got {
		if ev.Severity == trace.SeverityInfo {
			observations++
			if strings.Contains(ev.Summary, "truncated") {
				truncation = ev.Summary
			}
			continue
		}
		findings++
	}

	if findings > maxCollectedEvents {
		t.Errorf("held %d findings, over the %d cap", findings, maxCollectedEvents)
	}
	// Truncation must be disclosed, and as an observation: hitting the cap
	// says something about the volume of activity, not about whether any of it
	// was malicious.
	if truncation == "" {
		t.Error("the report does not disclose that observation was truncated")
	}
	if observations == 0 {
		t.Error("truncation was recorded at a severity that would drive the verdict")
	}

	r.Close()
}

// After the cap, the collector must keep reading. The monitor's own reader
// blocks when its channel fills, and a blocked reader stops servicing the
// kernel ring buffer — so abandoning the drain would lose later events and
// push back into the kernel.
func TestCollectorKeepsDrainingAfterTheCap(t *testing.T) {
	f := newFakeMonitor(1)
	r := startFakeCollector(f)

	// Far more than the cap, through a buffer of one. If the collector stopped
	// reading at the cap, these sends would block forever and the test would
	// time out rather than fail.
	done := make(chan struct{})
	go func() {
		for i := 0; i < maxCollectedEvents*2; i++ {
			f.events <- Event{Kind: KindConnect, Dest: netAddr(i)}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the collector stopped draining after the cap; the kernel ring buffer would back up")
	}

	r.Close()
}

// close must wait for the collector, or a take after close could race a drain
// still in flight and silently drop the last observations of a scan.
func TestCloseWaitsForTheCollector(t *testing.T) {
	f := newFakeMonitor(4)
	r := startFakeCollector(f)

	f.events <- Event{Kind: KindOpenWrite, Path: "/home/app/.bashrc"}
	r.Close()

	// After close the drain has finished, so whatever was observed is readable
	// without a race.
	got := r.Take("probe", collectAt)
	if len(got) != 1 {
		t.Fatalf("got %d events after close, want the 1 that was observed", len(got))
	}
	if !strings.Contains(got[0].Summary, ".bashrc") {
		t.Errorf("unexpected event: %s", got[0].Summary)
	}
}

// An attached monitor is a fact about the scan, not evidence about the target,
// so it is recorded at info severity. At notable or critical it would move the
// risk verdict for every scan that merely managed to attach.
func TestAttachedEventIsAnObservationNotAFinding(t *testing.T) {
	f := newFakeMonitor(1)
	r := startFakeCollector(f)
	defer r.Close()

	got := r.AttachedEvent("enumeration", collectAt)
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Severity != trace.SeverityInfo {
		t.Errorf("severity = %q, want info; an attached monitor is not evidence "+
			"about the target", got[0].Severity)
	}
	if got[0].Source != Source {
		t.Errorf("source = %q, want %q", got[0].Source, Source)
	}
}

// waitForPending blocks until the collector has buffered at least n events, so
// tests do not race the drain goroutine.
func waitForPending(t *testing.T, r *Collector, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		got := len(r.pending)
		r.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("collector did not buffer %d event(s) in time", n)
}

// netAddr builds distinct destinations so dedup cannot collapse them.
func netAddr(i int) string {
	return "203.0." + itoa(i/256) + "." + itoa(i%256) + ":443"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// The skill path closes the collector explicitly once the container is gone,
// and also defers a Close for its early returns — so Close runs twice on every
// successful script. It has to be safe, and the second call must not block on
// a drain channel that is already closed.
//
// Pinned rather than assumed, because this is the same shape that crashed the
// monitor itself: Close there closed an already-closed channel and panicked,
// and the privileged CI lane is what found it.
func TestCollectorCloseIsIdempotent(t *testing.T) {
	f := newFakeMonitor(2)
	r := startFakeCollector(f)

	f.events <- Event{Kind: KindOpenWrite, Path: "/home/app/.bashrc"}

	done := make(chan struct{})
	go func() {
		r.Close()
		r.Close()
		r.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a repeated Close blocked; the skill path calls it twice on every script")
	}

	// What was observed survives repeated closes.
	if got := r.Take("probe", collectAt); len(got) != 1 {
		t.Fatalf("got %d events after three closes, want the 1 observed", len(got))
	}
}

// A nil collector must be safe on every method. Nothing constructs one today,
// but the methods are exported and the layer's whole promise is that its
// absence costs nothing.
func TestNilCollectorIsSafe(t *testing.T) {
	var r *Collector

	if r.Available() {
		t.Error("a nil collector reports available")
	}
	if got := r.Take("probe", collectAt); got != nil {
		t.Errorf("Take on a nil collector returned %+v", got)
	}
	if got := r.AttachedEvent("probe", collectAt); got != nil {
		t.Errorf("AttachedEvent on a nil collector returned %+v", got)
	}
	r.Close() // must not panic
}
