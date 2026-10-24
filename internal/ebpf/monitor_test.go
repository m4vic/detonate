package ebpf

import "testing"

// The contract every platform must honour: New never errors just because eBPF
// is out of reach, and an unavailable monitor is safe to use — its Events
// channel is closed, so a range over it ends immediately and no caller needs a
// nil check or a special case. This is what makes the monitor additive.
func TestUnavailableMonitorIsSafeToUse(t *testing.T) {
	var m Monitor = noopMonitor{}

	if m.Available() {
		t.Fatal("noop monitor reports available")
	}
	got := 0
	for range m.Events() {
		got++
	}
	if got != 0 {
		t.Fatalf("noop monitor emitted %d events, want 0", got)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// New must return a usable Monitor and no error on every platform, even where
// eBPF cannot load. On non-Linux this is the stub; on Linux without privilege
// it is the best-effort downgrade to noop. Either way a caller can range over
// Events and Close without checking for an error first.
func TestNewNeverErrorsAndIsRangeable(t *testing.T) {
	m, err := New(0)
	if err != nil {
		t.Fatalf("New returned an error, breaking the additive contract: %v", err)
	}
	if m == nil {
		t.Fatal("New returned a nil monitor")
	}
	defer m.Close()

	// Draining must be safe whether or not it attached. When unavailable the
	// channel is closed and this returns at once; when available we do not
	// assume any event arrives in a test with no target activity, so only drain
	// what is already there without blocking.
	select {
	case _, ok := <-m.Events():
		_ = ok
	default:
	}
}
