//go:build !linux

package ebpf

// New on a non-Linux host returns an unavailable monitor. eBPF is a Linux
// kernel facility; there is nothing to load here, and that must not be an error
// — the scan proceeds without syscall-level observation.
func New(cgroupID uint64) (Monitor, error) {
	return noopMonitor{}, nil
}
