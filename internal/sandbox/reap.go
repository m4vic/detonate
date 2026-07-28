package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// maxScanLifetime is how long a container may run before it is assumed
// abandoned rather than busy.
//
// Generously above any real scan (the default policy times out in 60s), because
// the cost of the two mistakes is wildly asymmetric: reaping too eagerly kills
// a live scan and makes it report a false clean, while reaping too late just
// leaves a dead container around a little longer.
const maxScanLifetime = time.Hour

// ReapOrphans removes containers left behind by earlier detonate runs and
// returns how many it destroyed.
//
// Close() guarantees teardown for a scan that ends normally, but nothing can
// guarantee it for one that does not: SIGKILL, a power loss, or a panic in our
// own code all leave a container running with no client attached. For a tool
// whose whole promise is that untrusted code does not outlive the scan, there
// has to be something that cleans up after the case where the guarantee failed.
//
// The subtlety — and this was a real bug, caught by our own test suite — is
// that "has the detonate- prefix" does NOT mean "is an orphan". An earlier
// version force-removed every matching container at startup, so a second scan
// on the same machine killed the first one's container mid-run. The victim saw
// its target die with no output and reported "no suspicious behaviour
// observed": a false clean caused entirely by our own cleanup. Two scans in one
// CI job, or a user in two terminals, would hit it.
//
// So a container is only an orphan if it is not running, or has been running
// longer than any real scan could.
//
// Errors are deliberately not returned. Reaping is opportunistic housekeeping;
// a docker hiccup here must not fail a scan that would otherwise have worked.
func ReapOrphans(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, dockerBinary,
		"ps", "-a",
		"--filter", "name="+NamePrefix,
		"--format", "{{.ID}}|{{.State}}|{{.RunningFor}}").Output()
	if err != nil {
		return 0
	}

	var orphans []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		id, state := parts[0], parts[1]
		age := ""
		if len(parts) >= 3 {
			age = parts[2]
		}
		if isOrphan(state, age) {
			orphans = append(orphans, id)
		}
	}
	if len(orphans) == 0 {
		return 0
	}

	// One rm for all of them: N docker invocations would make startup latency
	// scale with how badly the last run crashed.
	args := append([]string{"rm", "-f"}, orphans...)
	if err := exec.CommandContext(ctx, dockerBinary, args...).Run(); err != nil {
		return 0
	}
	return len(orphans)
}

// isOrphan decides whether a container belongs to a dead run.
//
// Three states, three rules:
//
//   - "created" means the daemon has accepted it but it has not started yet.
//     That is a container mid-launch, so it is treated as LIVE unless it has
//     been stuck there implausibly long. Reaping these was the second half of
//     the concurrent-scan bug: a scan starting up would be destroyed in the
//     window between `docker run` and the process actually running.
//   - "running" is live unless it has outlived any plausible scan.
//   - anything else (exited, dead, paused, removing) is finished by
//     definition and safe to remove.
func isOrphan(state, age string) bool {
	switch state {
	case "running":
		return olderThan(age, maxScanLifetime)
	case "created":
		// A container stuck in "created" for this long is not launching, it is
		// wedged. Short enough to still clean up real debris, long enough to
		// never race a normal start.
		return olderThan(age, 5*time.Minute)
	default:
		return true
	}
}

// olderThan reports whether docker's human-readable age exceeds d.
//
// Docker's ps --format offers no machine-readable age, so this parses strings
// like "5 seconds ago", "About a minute ago", "2 hours ago", "3 days ago".
//
// It deliberately errs toward "not old": anything unparseable returns false,
// so an unfamiliar phrasing leaves a live container alone rather than killing
// a scan in progress. Getting this backwards is what produces a false clean.
func olderThan(age string, d time.Duration) bool {
	parsed, ok := parseAge(age)
	if !ok {
		return false
	}
	return parsed > d
}

// parseAge turns docker's age string into a duration.
func parseAge(age string) (time.Duration, bool) {
	s := strings.ToLower(strings.TrimSpace(age))
	if s == "" {
		return 0, false
	}

	// "About a minute ago" / "About an hour ago" carry no digits, so normalise
	// the article to a literal 1 before parsing. Note "an" must be handled
	// before "a", or the article is only half removed.
	s = strings.ReplaceAll(s, "about ", "")
	for _, article := range []string{"an ", "a "} {
		if strings.HasPrefix(s, article) {
			s = "1 " + strings.TrimPrefix(s, article)
			break
		}
	}

	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0, false
	}

	n := 0
	for _, r := range fields[0] {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}

	unit := fields[1]
	switch {
	case strings.HasPrefix(unit, "second"):
		return time.Duration(n) * time.Second, true
	case strings.HasPrefix(unit, "minute"):
		return time.Duration(n) * time.Minute, true
	case strings.HasPrefix(unit, "hour"):
		return time.Duration(n) * time.Hour, true
	case strings.HasPrefix(unit, "day"):
		return time.Duration(n) * 24 * time.Hour, true
	case strings.HasPrefix(unit, "week"):
		return time.Duration(n) * 7 * 24 * time.Hour, true
	case strings.HasPrefix(unit, "month"):
		return time.Duration(n) * 30 * 24 * time.Hour, true
	case strings.HasPrefix(unit, "year"):
		return time.Duration(n) * 365 * 24 * time.Hour, true
	}
	return 0, false
}
