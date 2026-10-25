package ebpf

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoUnifiedCgroup means the target's cgroup could not be identified in the
// unified (v2) hierarchy.
//
// It is a refusal, not a failure. bpf_get_current_cgroup_id() returns the inode
// of a cgroup directory in the unified hierarchy, so without a v2 path there is
// no id to filter on. Guessing one would be worse than having none: a wrong id
// matches a cgroup that is not the target, which turns the monitor from silent
// into misleading. Callers treat this as "eBPF unavailable" and the scan
// proceeds exactly as it does today.
var ErrNoUnifiedCgroup = errors.New("no unified (cgroup v2) path for the target")

// parseCgroupPath extracts the unified-hierarchy cgroup path from the contents
// of /proc/<pid>/cgroup.
//
// The format is one "hierarchy-id:controllers:path" record per line. The
// unified hierarchy is the record with id 0 and an empty controller list, which
// is how a v2 path is told apart from the v1 records a hybrid host also lists:
//
//	0::/system.slice/docker-abc.scope          <- v2, the one we want
//	12:pids:/docker/abc                        <- v1, not addressable by cgroup id
//
// A host with only v1 records yields ErrNoUnifiedCgroup rather than a path
// built from a v1 line, because a v1 path is not what the kernel helper
// reports and filtering on it would silently watch the wrong thing.
//
// Pure and string-in/string-out so the format handling is testable on any
// platform, including the Windows box where none of this can run.
func parseCgroupPath(content string) (string, error) {
	sawAny := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// SplitN with 3, not Split: a cgroup path may itself contain colons,
		// and splitting on every colon would truncate it.
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue // not a record we understand; ignore rather than fail
		}
		sawAny = true

		id, controllers, p := fields[0], fields[1], fields[2]
		if id != "0" || controllers != "" {
			continue // a v1 record
		}
		if !strings.HasPrefix(p, "/") {
			return "", fmt.Errorf("unified cgroup path %q is not absolute", p)
		}
		return p, nil
	}

	if !sawAny {
		return "", fmt.Errorf("%w: no cgroup records found", ErrNoUnifiedCgroup)
	}
	return "", fmt.Errorf("%w: only v1 records present", ErrNoUnifiedCgroup)
}

// cgroupNamesContainer reports whether a unified cgroup path belongs to the
// given container id.
//
// Docker encodes the full id in the path under every driver in common use:
//
//	/docker/<id>                         (cgroupfs driver)
//	/system.slice/docker-<id>.scope      (systemd driver)
//
// A path that does not contain the id is not accepted on the assumption that
// some other driver might be in use, because the cost of being wrong is
// attributing another process's syscalls to the target.
func cgroupNamesContainer(cgroupPath, containerID string) bool {
	if containerID == "" {
		return false
	}
	return strings.Contains(cgroupPath, containerID)
}

// short renders a container id the way docker does in human output.
func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
