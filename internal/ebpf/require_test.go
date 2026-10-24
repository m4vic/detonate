package ebpf

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// requireEBPFEnv forces the eBPF-backed tests to fail rather than skip when the
// kernel or privilege they need is missing. The privileged CI lane sets it;
// developer machines normally do not.
//
// Same reasoning as DETONATE_REQUIRE_DOCKER in internal/dockertest: a run that
// skips the only test proving the embedded object loads prints exactly the same
// green as a run that proved it, and for a security tool that is the most
// expensive kind of false confidence there is. The env parsing is a few lines
// rather than a shared leaf because this is the only consumer; if a third
// DETONATE_REQUIRE_* appears, that is the moment to extract one.
const requireEBPFEnv = "DETONATE_REQUIRE_EBPF"

// ebpfRequired reports whether the environment demands a working eBPF monitor.
// An unset, empty, "0" or "false" value does not count, so a CI system that
// exports the variable as empty does not silently turn every skip into a
// failure.
func ebpfRequired() bool {
	raw, ok := os.LookupEnv(requireEBPFEnv)
	if !ok {
		return false
	}
	if raw = strings.TrimSpace(raw); raw == "" {
		return false
	}
	if parsed, err := strconv.ParseBool(raw); err == nil {
		return parsed
	}
	return true
}

// unavailable skips, or fails under requireEBPFEnv, naming what was missing.
func unavailable(t *testing.T, reason string) {
	t.Helper()
	if ebpfRequired() {
		t.Fatalf("%s is set, but %s", requireEBPFEnv, reason)
	}
	t.Skip(reason)
}

// The require switch is what makes the CI lane meaningful, so it gets its own
// test rather than being trusted. A bug here is invisible: it would turn the
// privileged job back into one that passes by skipping.
func TestRequireEnvParsing(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		set  bool
		want bool
	}{
		{raw: "", set: false, want: false}, // unset
		{raw: "", set: true, want: false},  // exported empty by a CI system
		{raw: "   ", set: true, want: false},
		{raw: "0", set: true, want: false},
		{raw: "false", set: true, want: false},
		{raw: "1", set: true, want: true},
		{raw: "true", set: true, want: true},
		{raw: "yes", set: true, want: true}, // not a bool literal, still a demand
	} {
		name := "unset"
		if tc.set {
			name = "set to " + strconv.Quote(tc.raw)
		}
		t.Run(name, func(t *testing.T) {
			if tc.set {
				t.Setenv(requireEBPFEnv, tc.raw)
			} else {
				os.Unsetenv(requireEBPFEnv)
			}
			if got := ebpfRequired(); got != tc.want {
				t.Errorf("ebpfRequired() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Close must be idempotent, on every implementation.
//
// This is a regression test for a real crash, found by the privileged CI lane
// on its first run: linuxMonitor.Close closed its done channel unconditionally,
// so a second call panicked with "close of closed channel". That is not an
// exotic sequence — `defer m.Close()` alongside an explicit teardown on the
// success path is the idiomatic shape in this codebase, and it is what a scan's
// teardown does. A panic there takes the process down in a tool whose contract
// is that a scan which could not clean up must not report success.
//
// Asserted through the Monitor interface so it covers whichever implementation
// New returns on this platform: the no-op everywhere eBPF is out of reach, and
// the real monitor on a privileged BTF kernel.
func TestCloseIsIdempotent(t *testing.T) {
	m, err := New(0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if err := m.Close(); err != nil {
			t.Fatalf("Close call %d returned %v, want nil", i, err)
		}
	}
}
