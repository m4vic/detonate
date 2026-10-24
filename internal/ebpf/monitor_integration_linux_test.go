//go:build linux

package ebpf

import (
	"os"
	"testing"
)

// Proves the productized loader works on a real kernel: the embedded CO-RE
// object loads, both tracepoints attach, and Close tears down cleanly. This is
// the step that could regress versus the standalone spike — the embed, the
// collection load, and the attach all running from inside the package.
//
// It is also the only test of the CO-RE portability claim. The committed
// monitor.bpf.o was compiled against one developer machine's kernel BTF
// (WSL2, 6.18); the whole reason the header is generated and never committed is
// that the object is supposed to relocate against whatever kernel it meets.
// Until this ran somewhere other than that machine, that was an argument rather
// than a measurement — which is what the privileged CI lane exists to settle.
//
// Needs root (loading a BPF program is privileged) and a BTF kernel. It skips
// otherwise rather than failing, matching the monitor's own best-effort
// contract; CI runs it with DETONATE_REQUIRE_EBPF=1 so the skip cannot hide a
// break there.
func TestMonitorLoadsAndAttachesOnRealKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		unavailable(t, "needs root to load a BPF program; run: "+
			"go test -c -o /tmp/ebpf.test ./internal/ebpf && sudo /tmp/ebpf.test -test.run RealKernel")
		return
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		unavailable(t, "no kernel BTF at /sys/kernel/btf/vmlinux; a CO-RE load cannot be validated here")
		return
	}

	m, err := New(0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	if !m.Available() {
		t.Fatal("monitor is not Available() as root on a BTF kernel — the embedded " +
			"object failed to load or attach, which the spike proved should work")
	}

	// Close must be clean even with no event ever delivered: the scan path
	// calls it on every run, including the overwhelming majority where the
	// target does nothing the probes watch for.
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
