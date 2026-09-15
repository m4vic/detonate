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
// Needs root (loading a BPF program is privileged) and a BTF kernel. It skips
// otherwise rather than failing, matching the monitor's own best-effort
// contract; CI (E5) runs it privileged so the skip cannot hide a break there.
func TestMonitorLoadsAndAttachesOnRealKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load a BPF program; run: sudo -E go test ./internal/ebpf -run RealKernel")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no kernel BTF; CO-RE load cannot be validated here")
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
}
