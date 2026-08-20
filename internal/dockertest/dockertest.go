// Package dockertest gates the tests that need a real Docker daemon.
//
// Every sandbox invariant detonate claims — the network is blocked, the rootfs
// is read-only, the target does not run as root, no container survives the scan
// — is proved by a Docker-backed test and by nothing else. On a laptop without
// Docker those tests have to skip, or the suite is unrunnable. In CI they must
// not: a run that skips all of them prints the same green as a run that proves
// all of them, and for a security tool that is the most expensive kind of false
// confidence there is.
//
// So the behaviour is made explicit instead of implicit. Set
// DETONATE_REQUIRE_DOCKER=1 — the Docker CI lane does — and an unavailable
// daemon fails the run, naming what was missing. Leave it unset and the same
// tests skip politely, as they should on a developer machine.
//
// It is a shared leaf for the same reason internal/termsafe is one: four
// packages had their own copy of this check, and a rule enforced in four places
// is a rule that will eventually be enforced in three.
package dockertest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RequireEnv forces Docker-backed tests to fail rather than skip when the
// daemon is unavailable. CI sets it; developer machines normally do not.
const RequireEnv = "DETONATE_REQUIRE_DOCKER"

// probeTimeout bounds `docker info`. A daemon that cannot answer within this
// is treated as unavailable rather than hanging the suite.
const probeTimeout = 20 * time.Second

// Require skips (or, under RequireEnv, fails) unless a usable Docker daemon is
// present. Call it first in any test that touches a sandbox.
func Require(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		Unavailable(t, "docker not on PATH")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		Unavailable(t, "docker daemon not running")
	}
}

// Unavailable reports a Docker prerequisite that could not be met after the
// daemon itself was found — an image that will not pull, most often. Same
// policy as Require: skip by default, fail when the environment demanded
// Docker, because "the image would not pull" is a real CI failure and not a
// reason to report success.
func Unavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	reason := format
	if len(args) > 0 {
		reason = fmt.Sprintf(format, args...)
	}
	if Required() {
		t.Fatalf("%s is set, but %s", RequireEnv, reason)
	}
	t.Skip(reason)
}

// Required reports whether the environment demands a working Docker daemon.
// Anything that parses as a true-ish value counts; an unset, empty, "0", or
// "false" value does not, so that a CI system exporting the variable as empty
// does not silently turn every skip into a failure.
func Required() bool {
	raw, ok := os.LookupEnv(RequireEnv)
	if !ok {
		return false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if parsed, err := strconv.ParseBool(raw); err == nil {
		return parsed
	}
	return true
}
