package sandbox

import (
	"strings"
	"testing"
)

// argLine renders a container invocation as one string for substring checks.
// Named apart from policy_test.go's argsFor, which takes no mounts.
func argLine(p Policy, mounts []Mount) string {
	return strings.Join(containerArgs("detonate-test", p, mounts, []string{"true"}), " ")
}

// A decoy home has to replace the tmpfs home, not sit beside it.
//
// Docker will not mount two things at one path, and which of the two won would
// otherwise depend on argument order — so a caller could plant a full decoy,
// see the scan succeed, and never notice the target was reading an empty tmpfs
// the whole time. That failure is silent, which is the worst kind here.
func TestMountAtHomeReplacesTheTmpfsHome(t *testing.T) {
	p := DefaultPolicy()

	plain := argLine(p, nil)
	if !strings.Contains(plain, "--tmpfs "+ContainerHome+":") {
		t.Fatalf("without a decoy the home should still be a tmpfs:\n%s", plain)
	}

	withDecoy := argLine(p, []Mount{{
		HostPath: "/host/decoy", ContainerPath: ContainerHome, ReadOnly: false,
	}})
	if strings.Contains(withDecoy, "--tmpfs "+ContainerHome+":") {
		t.Fatalf("the home tmpfs survived alongside the decoy mount:\n%s", withDecoy)
	}
	if !strings.Contains(withDecoy, "--volume /host/decoy:"+ContainerHome) {
		t.Fatalf("the decoy was not mounted at the home path:\n%s", withDecoy)
	}

	// /tmp is unrelated and must keep its tmpfs, or a decoy would quietly cost
	// the target its scratch space.
	if !strings.Contains(withDecoy, "--tmpfs /tmp:") {
		t.Fatalf("mounting a decoy home removed the /tmp tmpfs:\n%s", withDecoy)
	}
}

// The decoy home must be writable. Most servers store state under ~ on startup,
// and a read-only home would turn every one of them into "attempted a write the
// sandbox denied" — a finding about our environment rather than their
// behaviour.
func TestDecoyHomeIsMountedWritable(t *testing.T) {
	got := argLine(DefaultPolicy(), []Mount{{
		HostPath: "/host/decoy", ContainerPath: ContainerHome, ReadOnly: false,
	}})
	if strings.Contains(got, "/host/decoy:"+ContainerHome+":ro") {
		t.Fatalf("decoy home was mounted read-only:\n%s", got)
	}
}

// The scanned target keeps its read-only mount even when a decoy is present.
func TestTargetStaysReadOnlyAlongsideADecoy(t *testing.T) {
	got := argLine(DefaultPolicy(), []Mount{
		{HostPath: "/host/target", ContainerPath: "/target", ReadOnly: true},
		{HostPath: "/host/decoy", ContainerPath: ContainerHome, ReadOnly: false},
	})
	if !strings.Contains(got, "--volume /host/target:/target:ro") {
		t.Fatalf("target lost its read-only mount:\n%s", got)
	}
}

// Map iteration is random in Go, and this loop used to emit tmpfs arguments
// straight out of a map — so the same scan produced a different `docker run`
// invocation each time, against this package's own stated rule that an
// invocation which differs run to run cannot be reproduced from a log.
func TestContainerArgsAreDeterministic(t *testing.T) {
	p := DefaultPolicy()
	mounts := []Mount{
		{HostPath: "/host/target", ContainerPath: "/target", ReadOnly: true},
		{HostPath: "/host/decoy", ContainerPath: ContainerHome},
	}

	first := argLine(p, mounts)
	for i := 0; i < 50; i++ {
		if got := argLine(p, mounts); got != first {
			t.Fatalf("invocation %d differed:\n first: %s\n got:   %s", i, first, got)
		}
	}
}

// The decoy must not weaken anything else about the sandbox.
func TestDecoyDoesNotLoosenTheSandbox(t *testing.T) {
	got := argLine(DefaultPolicy(), []Mount{{
		HostPath: "/host/decoy", ContainerPath: ContainerHome,
	}})
	for _, want := range []string{
		"--network none",
		"--read-only",
		"--user 1000:1000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q with a decoy mounted:\n%s", want, got)
		}
	}
}
