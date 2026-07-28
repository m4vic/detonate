package sandbox

import (
	"strings"
	"testing"
)

// These tests assert the security posture directly from the generated flags,
// with no daemon involved.
//
// That is deliberate. A dropped security flag is the failure mode that makes
// detonate unsafe while every behavioural test still passes: the scan runs,
// tools get enumerated, output looks right, and the box was never closed.
// Behaviour cannot catch that. Reading the flags can.

func argsFor(p Policy) []string {
	return containerArgs("detonate-test", p, nil, []string{"echo", "hi"})
}

// hasFlag reports whether flag appears with the given value.
func hasFlag(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}

func has(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestDefaultPolicyIsLockedDown(t *testing.T) {
	args := argsFor(DefaultPolicy())

	checks := []struct {
		what  string
		ok    bool
		why   string
	}{
		{"--network none", hasFlag(args, "--network", "none"),
			"network access is the difference between a scan and an incident"},
		{"--read-only", has(args, "--read-only"),
			"the target must not persist anything to its image layer"},
		{"--cap-drop ALL", hasFlag(args, "--cap-drop", "ALL"),
			"no capability is needed to speak JSON-RPC over a pipe"},
		{"--security-opt no-new-privileges", hasFlag(args, "--security-opt", "no-new-privileges"),
			"blocks the setuid path to escalating mid-run"},
		{"--user 1000:1000", hasFlag(args, "--user", "1000:1000"),
			"root in a container is one kernel bug from root outside it"},
		{"--memory", hasFlag(args, "--memory", "536870912"),
			"an unbounded allocation takes down the host running the scan"},
		{"--pids-limit", hasFlag(args, "--pids-limit", "128"),
			"a fork bomb takes down the host running the scan"},
		{"--rm", has(args, "--rm"),
			"scans must not leave containers behind"},
	}

	for _, c := range checks {
		if !c.ok {
			t.Errorf("default policy is missing %s\n  why it matters: %s\n  args: %v",
				c.what, c.why, args)
		}
	}
}

func TestNetworkCanBeEnabledDeliberately(t *testing.T) {
	// Enabling the network is a real need for later milestones (observing what
	// a server tries to reach), but it must take an explicit opt-in.
	p := DefaultPolicy()
	p.NetworkEnabled = true

	if hasFlag(argsFor(p), "--network", "none") {
		t.Error("--network none should be absent when the network is enabled")
	}
}

func TestTmpfsIsNoexec(t *testing.T) {
	// A writable /tmp is necessary for real servers. A writable AND executable
	// /tmp lets a target stage a payload and run it.
	args := argsFor(DefaultPolicy())
	for i, a := range args {
		if a != "--tmpfs" || i+1 >= len(args) {
			continue
		}
		if !strings.Contains(args[i+1], "noexec") {
			t.Errorf("tmpfs mount %q must be noexec", args[i+1])
		}
		return
	}
	t.Error("no --tmpfs mount found; the target has nowhere writable to run")
}

func TestScannedPathsAreMountedReadOnly(t *testing.T) {
	// A target that can rewrite its own source mid-scan makes the evidence
	// disagree with the artifact.
	m := Mount{HostPath: "/host/skill", ContainerPath: "/target", ReadOnly: true}
	if got := m.arg(); got != "/host/skill:/target:ro" {
		t.Errorf("mount arg = %q, want a :ro suffix", got)
	}
}

func TestNewNameIsUniqueAndPrefixed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := NewName()
		if err != nil {
			t.Fatalf("NewName: %v", err)
		}
		if !strings.HasPrefix(n, NamePrefix) {
			t.Fatalf("name %q lacks the %q prefix used for orphan cleanup", n, NamePrefix)
		}
		if seen[n] {
			t.Fatalf("duplicate name %q; concurrent scans would collide", n)
		}
		seen[n] = true
	}
}
