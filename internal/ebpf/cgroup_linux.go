//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// cgroup2Magic identifies a cgroup v2 ("unified") filesystem.
//
// Checked rather than assumed, because on a hybrid host /sys/fs/cgroup is a
// tmpfs holding v1 controller directories and the unified hierarchy lives at
// /sys/fs/cgroup/unified. An inode taken from the tmpfs would be a perfectly
// valid number that is not a cgroup id, and the filter would then match
// nothing while looking like it was configured correctly.
const cgroup2Magic = 0x63677270

// unifiedMounts are the places a unified hierarchy is found, in the order to
// try them: the whole mount on a v2-only host, the separate mount on a hybrid.
var unifiedMounts = []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"}

// inspectTimeout bounds `docker inspect`. A daemon that cannot answer quickly
// is treated as unavailable rather than delaying a scan.
const inspectTimeout = 10 * time.Second

// ErrCgroupNotAttributable means a cgroup was resolved but could not be proven
// to belong to the target container.
//
// This is the guard against the most dangerous failure this resolver has. The
// host PID comes from `docker inspect`, and it is only a host PID when the
// daemon shares the host's PID namespace. Under Docker Desktop (WSL2, macOS)
// the container runs inside the daemon's own VM, so that number is a PID in
// the VM — and it will frequently also be a live, unrelated PID on this
// machine. Reading its /proc entry then yields a real cgroup id for the wrong
// process, and the monitor would silently watch something that is not the
// target while reporting itself available.
//
// So the resolved cgroup path must name the container. If it does not, this
// refuses, the monitor degrades to a no-op, and the scan runs exactly as it
// does today. Silence is recoverable; attributing another process's syscalls
// to the target is not.
var ErrCgroupNotAttributable = errors.New("resolved cgroup cannot be attributed to the target container")

// CgroupID resolves the cgroup id that the in-kernel filter compares against,
// for the container detonate launched.
//
// docker inspect -> host PID and full container id -> /proc/<pid>/cgroup ->
// the unified path -> the inode of that cgroup directory, which is what
// bpf_get_current_cgroup_id() reports.
//
// Every failure is a refusal that leaves the scan unchanged: an unavailable
// daemon, a stopped container, a v1-only host, a cgroup that cannot be
// attributed. None of them is a scan error, because the eBPF layer is additive
// — its absence lowers completeness confidence and must never invent a finding
// or fail a run.
func CgroupID(ctx context.Context, containerName string) (uint64, error) {
	id, pid, err := inspectContainer(ctx, containerName)
	if err != nil {
		return 0, err
	}

	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		// On Docker Desktop the PID belongs to the daemon's VM, so this is the
		// ordinary outcome there rather than a problem with this machine.
		return 0, fmt.Errorf("reading the cgroup of pid %d: %w", pid, err)
	}

	rel, err := parseCgroupPath(string(raw))
	if err != nil {
		return 0, err
	}

	// The attribution check. See ErrCgroupNotAttributable.
	if !cgroupNamesContainer(rel, id) {
		return 0, fmt.Errorf("%w: pid %d is in cgroup %q, which does not name container %s",
			ErrCgroupNotAttributable, pid, rel, short(id))
	}

	return cgroupIDAt(rel)
}

// inspectContainer returns the container's full id and the PID the daemon
// reports for it.
func inspectContainer(ctx context.Context, name string) (id string, pid int, err error) {
	ctx, cancel := context.WithTimeout(ctx, inspectTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.Id}} {{.State.Pid}}", name).Output()
	if err != nil {
		return "", 0, fmt.Errorf("docker inspect %s: %w", name, err)
	}

	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) != 2 {
		return "", 0, fmt.Errorf("docker inspect %s: unexpected output %q", name, out)
	}
	id = fields[0]
	pid, err = strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, fmt.Errorf("docker inspect %s: pid %q is not a number", name, fields[1])
	}
	// Docker reports 0 for a container that is not running. There is nothing
	// to attach to, and /proc/0 would be nonsense.
	if pid <= 0 {
		return "", 0, fmt.Errorf("container %s reports pid %d; it is not running", name, pid)
	}
	return id, pid, nil
}

// cgroupIDAt returns the inode of a unified cgroup directory, which is the
// value bpf_get_current_cgroup_id() reports for a task in it.
func cgroupIDAt(rel string) (uint64, error) {
	var tried []string

	for _, mount := range unifiedMounts {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(mount, &fs); err != nil {
			continue
		}
		if uint64(fs.Type) != cgroup2Magic {
			tried = append(tried, mount+" (not cgroup2)")
			continue
		}

		dir := filepath.Join(mount, rel)
		info, err := os.Stat(dir)
		if err != nil {
			tried = append(tried, dir+" (missing)")
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			tried = append(tried, dir+" (no inode)")
			continue
		}
		return stat.Ino, nil
	}

	return 0, fmt.Errorf("%w: looked in %s", ErrNoUnifiedCgroup, strings.Join(tried, ", "))
}
