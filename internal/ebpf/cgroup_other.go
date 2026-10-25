//go:build !linux

package ebpf

import (
	"context"
	"fmt"
	"runtime"
)

// CgroupID on a non-Linux host cannot resolve anything.
//
// cgroups are a Linux facility, and there is no /proc/<pid>/cgroup to read even
// when Docker is running — under Docker Desktop the containers live inside the
// daemon's own Linux VM. Returning a refusal keeps the shape identical to the
// Linux path, so the caller has one code path: a resolver error means the
// monitor degrades to a no-op and the scan runs exactly as it does today.
func CgroupID(_ context.Context, containerName string) (uint64, error) {
	return 0, fmt.Errorf("%w: %s has no cgroup hierarchy (container %s)",
		ErrNoUnifiedCgroup, runtime.GOOS, containerName)
}
