package acquire

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/trace"
)

// DepsDir is where dependencies land inside both containers.
const DepsDir = "/deps"

// installTimeout is generous: a cold pip or npm install of a real dependency
// tree on a slow connection legitimately takes minutes. Too tight a budget
// would report a network failure for a target that was merely large.
const installTimeout = 10 * time.Minute

// Result is what phase 1 produced.
type Result struct {
	// Volume holds the installed dependencies. The caller mounts it read-only
	// into the detonation container and must Cleanup it afterwards.
	Volume string

	// Env points the interpreter at the installed dependencies.
	Env map[string]string

	// Events is what the target's installation did. Empty for a target with
	// no dependencies.
	Events []trace.Event

	manifest Manifest
}

// Install runs a target's dependency installation in its own container with
// the network ON, and captures what happened.
//
// The security argument for allowing a network here, given that the whole tool
// exists to deny one: this container executes the PACKAGE MANAGER, not the
// target. It mounts the target read-only, has no other host access, and is
// destroyed immediately after. Install scripts still run — deliberately,
// because suppressing them would hide the supply-chain behaviour that is the
// most valuable thing this phase can find. The target's own code is only ever
// executed in phase 2, with the network off.
func Install(ctx context.Context, targetDir string, policy sandbox.Policy) (*Result, error) {
	m := Detect(targetDir)
	if m.Ecosystem == EcosystemNone {
		// Nothing to install. Not an error: a stdlib-only server is a perfectly
		// good target, and it skips straight to detonation.
		return &Result{manifest: m}, nil
	}

	volume, err := createVolume(ctx)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Volume:   volume,
		Env:      m.EnvFor(DepsDir),
		manifest: m,
	}

	started := time.Now()
	stdout, stderr, runErr := runInstall(ctx, targetDir, volume, m, policy)

	res.Events = append(res.Events, trace.Event{
		Kind: trace.KindLifecycle, Severity: trace.SeverityInfo, At: started,
		Summary: fmt.Sprintf("installing %s dependencies from %s", m.Ecosystem, m.File),
		Source:  "acquire", During: "install",
	})

	// Analyse installer output for behaviour worth reporting. The network is
	// ON here, so the blocked-egress signatures do not apply — what matters is
	// what the install itself did, and the raw log is kept as evidence either
	// way.
	res.Events = append(res.Events, analyseInstall(stdout, stderr)...)

	if runErr != nil {
		_ = res.Cleanup(context.Background())
		return nil, fmt.Errorf("installing dependencies for %s: %w (%s)",
			m.File, runErr, truncate(strings.TrimSpace(stderr), 800))
	}
	return res, nil
}

// Mounts returns what the detonation container should mount, read-only.
func (r *Result) Mounts() []sandbox.Mount {
	if r.Volume == "" {
		return nil
	}
	return []sandbox.Mount{{
		HostPath:      r.Volume,
		ContainerPath: DepsDir,
		// Read-only in phase 2 specifically: the target must not be able to
		// rewrite its own dependencies while being observed, or the code we
		// report on is not the code that ran.
		ReadOnly: true,
	}}
}

// Cleanup destroys the dependency volume. Safe to call more than once.
func (r *Result) Cleanup(ctx context.Context) error {
	if r.Volume == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err := exec.CommandContext(ctx, "docker", "volume", "rm", "-f", r.Volume).Run()
	r.Volume = ""
	return err
}

func createVolume(ctx context.Context) (string, error) {
	name, err := sandbox.NewName()
	if err != nil {
		return "", err
	}
	name += "-deps"

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "docker", "volume", "create", name).Run(); err != nil {
		return "", fmt.Errorf("creating dependency volume: %w", err)
	}
	return name, nil
}

// runInstall executes the package manager in a container with network access.
func runInstall(ctx context.Context, targetDir, volume string, m Manifest, base sandbox.Policy) (stdout, stderr string, err error) {
	p := base
	p.Timeout = installTimeout

	// The two deliberate relaxations, and only these two.
	p.NetworkEnabled = true  // a package manager cannot work without one
	p.ReadOnlyRootfs = false // pip and npm write caches and temp files

	// Root, because pip and npm need to write into the volume, and a
	// non-root uid cannot create files in a fresh Docker volume (which is
	// owned by root). Acceptable here and nowhere else: this container runs
	// the package manager rather than the target, holds no host mounts beyond
	// a read-only copy of the target, and is destroyed immediately after.
	p.User = "0:0"

	// Installs pull large trees and npm is memory-hungry, so the ceiling has
	// to be higher than the detonation phase's. Still bounded: an unbounded
	// install is still a way to take down the host.
	if p.MemoryBytes < 2*1024*1024*1024 {
		p.MemoryBytes = 2 * 1024 * 1024 * 1024
	}
	p.PidLimit = 512

	// pip and npm unpack and build in /tmp. At the detonation phase's 64 MiB
	// a real server dies with "No space left on device" before it is ever
	// scanned — which is a scan that failed for a reason having nothing to do
	// with the target. noexec still applies, so this stays writable but not
	// runnable.
	p.TmpfsSize = "2g"

	name, err := sandbox.NewName()
	if err != nil {
		return "", "", err
	}

	mounts := []sandbox.Mount{
		{HostPath: targetDir, ContainerPath: "/target", ReadOnly: true},
		{HostPath: volume, ContainerPath: DepsDir, ReadOnly: false},
	}

	c, startErr := sandbox.Start(ctx, name, p, mounts, m.installCommand(DepsDir))
	if startErr != nil {
		return "", "", startErr
	}
	defer c.Close()

	out, _ := io.ReadAll(c.Stdout())

	if exitErr := c.ExitError(); exitErr != nil {
		return string(out), c.Stderr(), exitErr
	}
	return string(out), c.Stderr(), nil
}

// analyseInstall looks for behaviour worth reporting during installation.
func analyseInstall(stdout, stderr string) []trace.Event {
	var events []trace.Event
	combined := stdout + "\n" + stderr

	// Lifecycle scripts are where supply-chain payloads execute. Their mere
	// presence is not an attack — plenty of honest packages build native
	// extensions — but it is the thing a reviewer should be told ran, because
	// it is arbitrary code that executed before anyone inspected the package.
	if strings.Contains(strings.ToLower(combined), "postinstall") ||
		strings.Contains(strings.ToLower(combined), "preinstall") {
		events = append(events, trace.Event{
			Kind: trace.KindProcess, Severity: trace.SeverityNotable,
			At: time.Now(), Source: "acquire", During: "install",
			Summary: "package lifecycle script executed during installation",
			Detail:  map[string]any{"evidence": extractLine(combined, "install")},
		})
	}

	// Reuse the runtime signatures for things they still catch here: a
	// permission error or a fork ceiling means the same thing during an
	// install as during a run.
	for _, e := range monitor.Analyze(stderr, "install") {
		if e.Kind != trace.KindNetwork { // the network is legitimately on
			events = append(events, e)
		}
	}
	return events
}

func extractLine(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(strings.ToLower(line), needle) {
			return truncate(strings.TrimSpace(line), 200)
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
