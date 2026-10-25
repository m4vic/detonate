package ebpf

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

// Source names this monitor in the evidence record.
//
// Effectively frozen: corpus ground truth keys findings by `source`
// (testdata/corpus/*/ground-truth.yaml), so renaming this silently
// un-detects fixtures rather than failing a build.
const Source = "ebpf"

// evidenceLimit bounds how much target-controlled text reaches a report. A
// path arrives straight from the target's own openat argument, so it is a
// budget like any other.
const evidenceLimit = 200

// Findings maps observed syscalls onto detonate's evidence model.
//
// Pure, and deliberately separate from the wiring that collects the events:
// the policy below is the part worth arguing about, and it should be arguable
// without a kernel, a container, or privilege. Everything here is decided from
// the event alone — no I/O, no clock beyond the one passed in, no model
// (invariant 1).
//
// Two rules, and they are only this clean because of what the sandbox already
// guarantees:
//
//   - **Any connect() is a finding.** The sandbox runs with the network
//     disabled, so nothing can have asked the target to talk to anything. An
//     attempt is unprovoked egress and nothing else — the same reasoning the
//     stderr monitor applies to a DNS failure, except observed at the syscall
//     instead of inferred from a line the target chose to print. That
//     difference is the whole point: a covert exfiltrator does not log its own
//     failed delivery.
//   - **A write-intent open is a finding only on a persistence path.** The
//     kernel already dropped reads and other cgroups; what arrives is every
//     write-open the target made, which for a real server is thousands of temp
//     files, caches and lockfiles. Those evidence nothing, and recording them
//     as observations would bury the report rather than inform it — so they are
//     dropped. The allowlist IS this probe's scope; widening it is a deliberate
//     change with a fixture behind it, not a tuning knob.
//
// Deduplicated by behaviour rather than occurrence: one finding per distinct
// destination or path, so a retry loop does not become fifty findings. That
// mirrors internal/monitor's "one event per signature" rule. Order follows
// first observation, so the same event sequence always produces the same
// report.
func Findings(events []Event, during string, now time.Time) []trace.Event {
	var out []trace.Event
	seen := map[string]bool{}

	for _, e := range events {
		var ev trace.Event

		switch e.Kind {
		case KindConnect:
			key := "connect|" + e.Dest
			if e.Dest == "" || seen[key] {
				continue
			}
			seen[key] = true
			ev = trace.Event{
				Kind:     trace.KindNetwork,
				Severity: trace.SeverityCritical,
				Summary: fmt.Sprintf(
					"target called connect() to %s; the sandbox denies the network, so nothing asked it to",
					e.Dest),
				Detail: map[string]any{
					"evidence": fmt.Sprintf("connect() to %s by pid %d (%s)",
						e.Dest, e.PID, e.Comm),
					"destination": e.Dest,
					"rule":        "unprovoked-network",
					"why": "Observed at the syscall, not inferred from stderr. A covert " +
						"exfiltrator does not log its own failed delivery, so this is the " +
						"only tier that sees egress entangled with normal operation.",
				},
			}

		case KindOpenWrite:
			clean := normalizePath(e.Path)
			reason, sensitive := persistenceTarget(clean)
			key := "open|" + clean
			if !sensitive || seen[key] {
				continue
			}
			seen[key] = true
			shown := clip(clean, evidenceLimit)
			ev = trace.Event{
				Kind:     trace.KindFile,
				Severity: trace.SeverityCritical,
				Summary: fmt.Sprintf("target opened %s for writing, which is %s",
					shown, reason),
				Detail: map[string]any{
					"evidence": fmt.Sprintf("write-intent open of %s by pid %d (%s)",
						shown, e.PID, e.Comm),
					"path": shown,
					"rule": "persistence-write",
					"why": "A persistence write leaves no planted token to match, so the " +
						"decoy tier cannot see it at all. The file is executed later, by " +
						"something other than the target.",
				},
			}

		default:
			continue
		}

		ev.At = now
		ev.During = during
		ev.Source = Source
		out = append(out, ev)
	}

	return out
}

// normalizePath makes a target-supplied path comparable without resolving it.
//
// Deliberately NOT resolved against the filesystem: the path came from the
// target's own openat argument, the file may be gone by the time we look, and
// resolving a target-controlled string on the host is the class of thing this
// tool exists to avoid. path.Clean collapses "." and ".." lexically, which is
// enough to stop ".ssh/../.ssh/authorized_keys" reading as a different path
// than the one it is.
//
// Backslashes are left exactly as they arrive. On Linux a backslash is a legal
// character in a filename, so rewriting it to a separator would both mangle a
// real path and invent a component boundary that the kernel never saw.
func normalizePath(p string) string {
	if p = strings.TrimSpace(p); p == "" {
		return ""
	}
	return path.Clean(p)
}

// shellInitFiles are read and executed by a shell at startup, which is what
// makes writing one persistence rather than configuration.
//
// .bash_history is deliberately absent: a shell writes it as a matter of
// course and nothing ever executes it. Including it would report ordinary
// shell use as an implant, and since this rule is critical severity a wrong
// hit fails somebody's build.
var shellInitFiles = map[string]bool{
	".bashrc":       true,
	".bash_profile": true,
	".bash_login":   true,
	".bash_logout":  true,
	".profile":      true,
	".zshrc":        true,
	".zprofile":     true,
	".zlogin":       true,
	".kshrc":        true,
	"bash.bashrc":   true, // /etc/bash.bashrc
	"profile":       true, // /etc/profile
}

// cronDirs hold files that are run on a schedule. Matched by ancestry.
var cronDirs = []string{
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/var/spool/cron",
}

// persistenceTarget reports whether a path is one that gets executed later,
// and names why in words that can go straight into a finding.
//
// Matched on basename and ancestry, never by substring. A substring test for
// "cron" would flag a project file named "cronjob-parser.py", and at critical
// severity that is somebody's build broken for nothing.
func persistenceTarget(clean string) (reason string, ok bool) {
	if clean == "" {
		return "", false
	}

	base := path.Base(clean)
	dir := path.Dir(clean)

	// Matched on the basename so it is caught however the target referred to
	// it: "~/.bashrc", "/home/app/.bashrc", or just ".bashrc" relative to its
	// working directory.
	if shellInitFiles[base] {
		return "a shell startup file, executed on every new shell", true
	}
	if dir == "/etc/profile.d" || strings.HasSuffix(dir, "/profile.d") {
		return "a shell startup fragment, sourced by /etc/profile", true
	}

	// authorized_keys grants a login rather than running a command, which is
	// persistence of the most direct kind.
	if base == "authorized_keys" || base == "authorized_keys2" {
		return "an SSH authorized-keys file, which grants a login", true
	}

	for _, cronDir := range cronDirs {
		if clean == cronDir || strings.HasPrefix(clean, cronDir+"/") {
			return "a cron directory, so its content is run on a schedule", true
		}
	}
	if base == "crontab" || dir == "/var/spool/cron/crontabs" {
		return "a crontab, so its content is run on a schedule", true
	}

	// A systemd user unit starts with the user's session.
	if strings.Contains(clean, "/.config/systemd/user/") ||
		strings.HasPrefix(clean, ".config/systemd/user/") {
		return "a systemd user unit, started with the user's session", true
	}

	return "", false
}

func clip(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}
