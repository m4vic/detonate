package ebpf

import "testing"

// The attribution guard, which is the difference between a monitor that is
// silent and one that is misleading.
//
// The host PID comes from `docker inspect`, and it is only a host PID when the
// daemon shares this machine's PID namespace. Under Docker Desktop the number
// is a PID inside the daemon's VM, and it will frequently also be a live,
// unrelated process here — so /proc/<pid>/cgroup resolves, yields a real
// cgroup id, and the monitor watches something that is not the target while
// reporting itself available. Requiring the cgroup path to name the container
// is what turns that into a refusal.
func TestCgroupPathMustNameTheContainer(t *testing.T) {
	const id = "6d3b1a9f0cb8e7d2c4a5b6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f70819a2b"

	accepted := []struct {
		name string
		path string
	}{
		{"cgroupfs driver", "/docker/" + id},
		{"systemd driver", "/system.slice/docker-" + id + ".scope"},
		{"nested under a slice", "/system.slice/docker.service/docker/" + id},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			if !cgroupNamesContainer(tc.path, id) {
				t.Errorf("rejected %q for container %s", tc.path, short(id))
			}
		})
	}

	refused := []struct {
		name string
		path string
	}{
		// The Docker Desktop shape: a real cgroup belonging to some unrelated
		// host process that happens to share the PID number.
		{"an unrelated host process", "/user.slice/user-1000.slice/session-3.scope"},
		{"the host root cgroup", "/"},
		{"a different container", "/docker/0000000000000000000000000000000000000000000000000000000000000000"},
		{"a truncated id", "/docker/" + id[:12]},
		{"the init scope", "/init.scope"},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			if cgroupNamesContainer(tc.path, id) {
				t.Errorf("accepted %q for container %s; the monitor would watch the "+
					"wrong cgroup while reporting itself available", tc.path, short(id))
			}
		})
	}
}

// An empty container id must never match. A docker inspect that returned
// nothing useful would otherwise make every path attributable, which is the
// guard failing open.
func TestAnEmptyContainerIDMatchesNothing(t *testing.T) {
	for _, path := range []string{"/docker/abc", "/", "", "/system.slice/x.scope"} {
		if cgroupNamesContainer(path, "") {
			t.Errorf("empty container id matched %q; the guard fails open", path)
		}
	}
}
