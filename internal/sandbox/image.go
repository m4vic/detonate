package sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// imagePullTimeout is generous because it covers a cold download of a few
// hundred megabytes on a slow connection, which is a one-time cost per machine.
const imagePullTimeout = 10 * time.Minute

// EnsureImage makes sure the sandbox base image is present locally.
//
// This exists because pulling lazily inside a scan is a real bug, not a
// nicety. `docker run` will happily pull on demand, but that download then
// happens INSIDE the session timeout, so the first scan on any new machine
// fails with a protocol EOF while several hundred megabytes come down — and
// the error the user sees is "initialize: EOF", which says nothing about the
// actual cause.
//
// Pulling up front, outside the clock, also keeps scan timeouts meaningful:
// the budget then measures the target's behaviour rather than the user's
// bandwidth.
func EnsureImage(ctx context.Context, image string) error {
	if present, err := imagePresent(ctx, image); err == nil && present {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, imagePullTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerBinary, "pull", image)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pulling sandbox image %s: %w (%s)",
			image, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// imagePresent reports whether the image already exists locally.
func imagePresent(ctx context.Context, image string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, dockerBinary,
		"images", "-q", image).Output()
	if err != nil {
		return false, err
	}
	return len(strings.TrimSpace(string(out))) > 0, nil
}
