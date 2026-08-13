package acquire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
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

// UnsupportedError means satisfying a target's acquisition request would
// require weakening the root/network execution boundary.
type UnsupportedError struct {
	Reason string
	Events []trace.Event
}

func (e *UnsupportedError) Error() string { return e.Reason }

// Result is what the fetch and offline-install phases produced.
type Result struct {
	// Volume holds the installed dependencies. The caller mounts it read-only
	// into the detonation container and must Cleanup it afterwards.
	Volume string

	// Env points the interpreter at the installed dependencies.
	Env map[string]string

	// Image is the runtime the detonation phase must use.
	//
	// A Node package installed into a volume is useless inside a Python image:
	// the deps are there but `node` is not. The two phases therefore share an
	// ecosystem, not just a volume.
	Image string

	// Root is where the runnable target code lives in the detonation container.
	// Node dependencies are installed beside a copy of the source, so Node must
	// also start from that copy even when no compilation step was needed.
	// Empty means the original read-only /target mount remains the code root.
	Root string

	// Events is what the target's installation did. Empty for a target with
	// no dependencies.
	Events []trace.Event

	manifest Manifest
}

// Install fetches inert artifacts with network access, then performs every
// step that may execute target-controlled code offline and as non-root.
func Install(ctx context.Context, targetDir string, policy sandbox.Policy) (*Result, error) {
	m := Detect(targetDir)
	if m.Ecosystem == EcosystemNone {
		// Nothing to install. Not an error: a stdlib-only server is a perfectly
		// good target, and it skips straight to detonation.
		return &Result{manifest: m}, nil
	}
	if m.Ecosystem == EcosystemPython && m.File != "requirements.txt" {
		return nil, &UnsupportedError{Reason: fmt.Sprintf(
			"safe acquisition of %s is not supported yet: resolving a local Python project may execute its build backend while the network is enabled; provide a wheel-only requirements.txt or skip dynamic acquisition",
			m.File)}
	}
	if err := validateInertFetch(targetDir, m); err != nil {
		return nil, &UnsupportedError{Reason: fmt.Sprintf(
			"safe acquisition is unsupported for this manifest: %v", err)}
	}

	// A package inside a monorepo cannot be built alone: its tsconfig extends
	// one at the repository root. When that is the case the copy starts higher
	// up and the build runs in the package's own subdirectory.
	bc := buildContext{Root: targetDir}
	if m.NeedsBuild {
		bc = buildContextFor(targetDir)
	}
	if reason := unsupportedWorkspaceLifecycle(targetDir, m, bc); reason != "" {
		return nil, &UnsupportedError{Reason: reason}
	}

	volume, err := createVolume(ctx)
	if err != nil {
		return nil, err
	}

	// A built project's dependencies land beside its source in /deps/app, not
	// at the volume root, so the interpreter has to be pointed there instead.
	codeRoot := DepsDir + "/site"
	if m.Ecosystem == EcosystemNode {
		codeRoot = appDir(DepsDir)
		if bc.Sub != "" {
			codeRoot += "/" + bc.Sub
		}
	}

	res := &Result{
		Volume:   volume,
		Env:      m.EnvFor(codeRoot),
		Image:    imageFor(m.Ecosystem, policy.Image),
		manifest: m,
	}
	if m.Ecosystem == EcosystemNode {
		res.Root = codeRoot
	}

	started := time.Now()
	fetchOut, fetchErrOut, runErr := runAcquisitionPhase(ctx, bc, volume,
		fetchPolicy(policy, m), m.fetchCommand(DepsDir, bc.Sub))
	action := fmt.Sprintf("fetching %s dependencies from %s without executing lifecycle scripts",
		m.Ecosystem, m.File)
	res.Events = append(res.Events, trace.Event{
		Kind: trace.KindLifecycle, Severity: trace.SeverityInfo, At: started,
		Summary: action, Source: "acquire", During: "acquire-fetch",
	})
	res.Events = append(res.Events, analyseAcquisition(fetchOut, fetchErrOut,
		"acquire-fetch", true)...)
	if runErr != nil {
		cleanupErr := res.Cleanup(context.Background())
		return nil, errors.Join(
			fmt.Errorf("%s: %w%s", action, runErr, failureOutput(fetchOut, fetchErrOut)),
			cleanupErr,
		)
	}

	started = time.Now()
	buildOut, buildErrOut, runErr := runAcquisitionPhase(ctx, bc, volume,
		offlinePolicy(policy, m), m.offlineCommand(DepsDir, bc.Sub))
	action = fmt.Sprintf("installing %s dependencies offline as non-root", m.Ecosystem)
	if m.NeedsBuild {
		action += fmt.Sprintf(" and building %s", m.Entry)
	}
	res.Events = append(res.Events, trace.Event{
		Kind: trace.KindLifecycle, Severity: trace.SeverityInfo, At: started,
		Summary: action, Source: "acquire", During: "acquire-offline",
	})

	// Network signatures in this phase are blocked egress attempts because
	// target-controlled installation deliberately runs offline.
	offlineEvents := analyseAcquisition(buildOut, buildErrOut,
		"acquire-offline", false)
	res.Events = append(res.Events, offlineEvents...)

	if runErr != nil {
		cleanupErr := res.Cleanup(context.Background())
		if cleanupErr == nil && hasNetworkAttempt(offlineEvents) {
			return nil, &UnsupportedError{
				Reason: fmt.Sprintf(
					"safe acquisition is unsupported: %s requires network access during target-controlled offline installation%s",
					m.File, failureOutput(buildOut, buildErrOut)),
				Events: offlineEvents,
			}
		}
		// Naming the phase matters: a failed `npm run build` and a failed
		// `npm install` need different fixes, and the output alone rarely says
		// which one it was.
		return nil, errors.Join(
			fmt.Errorf("%s: %w%s", action, runErr, failureOutput(buildOut, buildErrOut)),
			cleanupErr,
		)
	}
	return res, nil
}

func unsupportedWorkspaceLifecycle(targetDir string, m Manifest, bc buildContext) string {
	if m.Ecosystem != EcosystemNode || !m.NeedsBuild || bc.Sub == "" {
		return ""
	}
	pkg := readPackageJSON(targetDir)
	if strings.TrimSpace(pkg.Scripts["prepare"]) == "" ||
		fileExists(filepath.Join(targetDir, "package-lock.json")) ||
		!fileExists(filepath.Join(bc.Root, "package-lock.json")) {
		return ""
	}
	return "safe acquisition is unsupported for this monorepo workspace lifecycle: " +
		"the package relies on a repository-root lockfile and a prepare script; " +
		"Detonate cannot yet replay that workspace prepare step offline without changing its build semantics"
}

func hasNetworkAttempt(events []trace.Event) bool {
	for _, event := range events {
		if event.Kind == trace.KindNetwork && event.During == "acquire-offline" {
			return true
		}
	}
	return false
}

// Command rewrites a start command to point at the acquired runtime tree.
//
// Node source and node_modules must share /deps/app for normal module
// resolution. This is true both for compiled servers and for plain JavaScript
// entry points; launching the latter from /target made installed packages
// invisible and failed with ERR_MODULE_NOT_FOUND.
func (r *Result) Command(detected string) string {
	if r.Root == "" {
		return detected
	}
	return strings.ReplaceAll(detected, "/target/", r.Root+"/")
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

// acquisitionPolicy applies bounded resources shared by both phases.
func acquisitionPolicy(base sandbox.Policy, m Manifest) sandbox.Policy {
	p := base
	p.Timeout = installTimeout
	p.Image = imageFor(m.Ecosystem, base.Image)
	if p.MemoryBytes < 2*1024*1024*1024 {
		p.MemoryBytes = 2 * 1024 * 1024 * 1024
	}
	p.PidLimit = 512
	p.TmpfsSize = "2g"
	return p
}

// fetchPolicy may use root and network because its command forbids all target
// lifecycle/build execution.
func fetchPolicy(base sandbox.Policy, m Manifest) sandbox.Policy {
	p := acquisitionPolicy(base, m)
	p.NetworkEnabled = true
	p.ReadOnlyRootfs = false
	p.User = "0:0"
	return p
}

// offlinePolicy is the only policy paired with commands that may execute
// target-controlled code.
func offlinePolicy(base sandbox.Policy, m Manifest) sandbox.Policy {
	p := acquisitionPolicy(base, m)
	p.NetworkEnabled = false
	p.ReadOnlyRootfs = true
	p.User = acquisitionUser
	return p
}

func runAcquisitionPhase(
	ctx context.Context,
	bc buildContext,
	volume string,
	p sandbox.Policy,
	command []string,
) (stdout, stderr string, err error) {
	name, err := sandbox.NewName()
	if err != nil {
		return "", "", err
	}

	// /target is the build root, which for a monorepo package is an ancestor
	// of the directory being scanned. Still read-only: a wider mount must not
	// become a writable one.
	mounts := []sandbox.Mount{
		{HostPath: bc.Root, ContainerPath: "/target", ReadOnly: true},
		{HostPath: volume, ContainerPath: DepsDir, ReadOnly: false},
	}

	c, startErr := sandbox.Start(ctx, name, p, mounts, command)
	if startErr != nil {
		return "", "", startErr
	}
	out, _ := io.ReadAll(c.Stdout())
	exitErr := c.ExitError()
	stderr = c.Stderr()
	closeErr := c.Close()
	if exitErr != nil || closeErr != nil {
		return string(out), stderr, errors.Join(exitErr, closeErr)
	}
	return string(out), stderr, nil
}

// analyseAcquisition extracts evidence from one acquisition phase. Network
// signatures are ignored only during inert fetch, where egress is expected;
// during offline execution they are evidence that a lifecycle/build hook
// attempted to escape its boundary.
func analyseAcquisition(stdout, stderr, during string, networkExpected bool) []trace.Event {
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
			At: time.Now(), Source: "acquire", During: during,
			Summary: "package lifecycle script executed during installation",
			Detail:  map[string]any{"evidence": extractLine(combined, "install")},
		})
	}

	// Reuse the runtime signatures for things they still catch here: a
	// permission error or a fork ceiling means the same thing during an
	// install as during a run.
	for _, e := range monitor.Analyze(stderr, during) {
		if !networkExpected || e.Kind != trace.KindNetwork {
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

// truncateTail keeps the END of a string, which is where a failing build or
// install puts its reason.
func truncateTail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max:]
}

// failureOutput renders what a failed install or build actually said.
//
// Both streams are reported, because the reason is split across them: tsc and
// most build tools write diagnostics to STDOUT, while npm writes only
// "command failed" to stderr. Showing stderr alone — which is what this did
// first — reported that something failed without ever saying what.
//
// Each is cut from the TAIL. A package manager opens with pages of
// deprecation warnings and states the failure last, so trimming from the
// front showed nothing but npm's opinion of glob@7.
func failureOutput(stdout, stderr string) string {
	var b strings.Builder
	for _, s := range []struct{ label, text string }{
		{"output", strings.TrimSpace(stdout)},
		{"stderr", strings.TrimSpace(stderr)},
	} {
		if s.text == "" {
			continue
		}
		b.WriteString("\n  " + s.label + ": " + truncateTail(s.text, 1500))
	}
	return b.String()
}
