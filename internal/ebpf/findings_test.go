package ebpf

import (
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

var at = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// The postmark shape: a silent connect() during normal tool operation. This is
// the gap the whole eBPF lane exists to close, and the corpus matches it on
// source=ebpf with "connect" in the summary — so both are asserted here rather
// than left to the fixture to discover.
func TestConnectIsAlwaysAFinding(t *testing.T) {
	got := Findings([]Event{{
		Kind: KindConnect, PID: 42, Comm: "python3", Dest: "203.0.113.7:443",
	}}, "probe", at)

	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	ev := got[0]
	if ev.Source != Source || Source != "ebpf" {
		t.Errorf("source = %q, want ebpf (corpus ground truth keys on it)", ev.Source)
	}
	if ev.Kind != trace.KindNetwork {
		t.Errorf("kind = %q, want network", ev.Kind)
	}
	if ev.Severity != trace.SeverityCritical {
		t.Errorf("severity = %q, want critical; the sandbox denies the network, so an "+
			"attempt is unprovoked by construction", ev.Severity)
	}
	if !strings.Contains(ev.Summary, "connect") {
		t.Errorf("summary does not contain %q, which corpus ground truth matches on: %s",
			"connect", ev.Summary)
	}
	if !strings.Contains(ev.Summary, "203.0.113.7:443") {
		t.Errorf("summary omits the destination: %s", ev.Summary)
	}
	// Invariant 6: every finding carries evidence.
	evidence, _ := ev.Detail["evidence"].(string)
	for _, want := range []string{"203.0.113.7:443", "42", "python3"} {
		if !strings.Contains(evidence, want) {
			t.Errorf("evidence omits %q: %s", want, evidence)
		}
	}
	if ev.During != "probe" {
		t.Errorf("during = %q, want probe", ev.During)
	}
	if !ev.At.Equal(at) {
		t.Errorf("At = %v, want the passed clock %v", ev.At, at)
	}
}

// The ~/.bashrc implant shape: a write that leaves no planted token, so the
// decoy tier is structurally blind to it.
func TestPersistenceWriteIsAFinding(t *testing.T) {
	got := Findings([]Event{{
		Kind: KindOpenWrite, PID: 7, Comm: "python3", Path: "/home/app/.bashrc",
	}}, "probe", at)

	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	ev := got[0]
	if ev.Kind != trace.KindFile || ev.Severity != trace.SeverityCritical {
		t.Errorf("kind/severity = %q/%q, want file/critical", ev.Kind, ev.Severity)
	}
	// The corpus matches covert.persistence-no-token on ".bashrc".
	if !strings.Contains(ev.Summary, ".bashrc") {
		t.Errorf("summary omits .bashrc, which corpus ground truth matches on: %s", ev.Summary)
	}
	if !strings.Contains(ev.Summary, "shell startup file") {
		t.Errorf("summary does not say why the path matters: %s", ev.Summary)
	}
}

// Everything that should and should not be treated as persistence.
//
// The negative half is the half that matters. This rule is critical severity,
// so a wrong hit fails somebody's build over an ordinary file — and the paths
// below are ones a real server touches constantly.
func TestPersistencePathPolicy(t *testing.T) {
	sensitive := []string{
		".bashrc",
		"/home/app/.bashrc",
		"/root/.profile",
		"/home/app/.zshrc",
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/profile.d/evil.sh",
		"/home/app/.ssh/authorized_keys",
		"/home/app/.ssh/authorized_keys2",
		"/etc/cron.d/implant",
		"/etc/cron.daily/implant",
		"/var/spool/cron/crontabs/app",
		"/var/spool/cron/app",
		"/home/app/.config/systemd/user/implant.service",
		// Lexical traversal must not read as a different path.
		"/home/app/.ssh/../.ssh/authorized_keys",
		"/home/app/./.bashrc",
	}
	for _, p := range sensitive {
		t.Run("sensitive "+p, func(t *testing.T) {
			if _, ok := persistenceTarget(normalizePath(p)); !ok {
				t.Errorf("%q not treated as persistence", p)
			}
		})
	}

	benign := []string{
		"",
		"/tmp/tmp123.json",
		"/app/node_modules/.package-lock.json",
		"/home/app/.npm/_cacache/index-v5/ab/cd/ef",
		"/home/app/.cache/pip/http/0/1/2",
		"/proc/self/fd/3",
		"/dev/null",
		"/app/package.json",
		// A shell writes this constantly and nothing executes it. Flagging it
		// would report ordinary shell use as an implant.
		"/home/app/.bash_history",
		// Substring traps: a basename or path that merely CONTAINS a sensitive
		// word. A substring matcher fails every one of these.
		"/app/src/cronjob-parser.py",
		"/app/cron.d.md",
		"/app/docs/authorized_keys.md",
		"/app/profile.json",
		"/app/.bashrc.example",
		"/app/bashrc",
		"/app/tests/fixtures/.bashrc-template",
		"/app/systemd/user-guide.txt",
	}
	for _, p := range benign {
		t.Run("benign "+p, func(t *testing.T) {
			if reason, ok := persistenceTarget(normalizePath(p)); ok {
				t.Errorf("%q wrongly treated as persistence (%s) — this is a critical "+
					"finding on an ordinary file", p, reason)
			}
		})
	}
}

// A server does thousands of write-opens. If each became an observation the
// report would be unreadable, so non-persistence writes are dropped outright.
func TestOrdinaryWritesProduceNothingAtAll(t *testing.T) {
	var events []Event
	for _, p := range []string{
		"/tmp/a", "/tmp/b", "/app/node_modules/.lock", "/home/app/.bash_history",
	} {
		events = append(events, Event{Kind: KindOpenWrite, Path: p})
	}

	if got := Findings(events, "probe", at); len(got) != 0 {
		t.Fatalf("got %d events from ordinary writes, want 0:\n%+v", len(got), got)
	}
}

// One finding per distinct behaviour, matching internal/monitor's "one event
// per signature" rule. A retry loop is one fact, not fifty.
func TestDedupIsByBehaviourNotOccurrence(t *testing.T) {
	events := []Event{
		{Kind: KindConnect, Dest: "203.0.113.7:443"},
		{Kind: KindConnect, Dest: "203.0.113.7:443"},
		{Kind: KindConnect, Dest: "203.0.113.7:443"},
		{Kind: KindConnect, Dest: "198.51.100.9:80"}, // a different fact
		{Kind: KindOpenWrite, Path: "/home/app/.bashrc"},
		{Kind: KindOpenWrite, Path: "/home/app/.bashrc"},
		// Same file by a path that only differs lexically: still one fact.
		{Kind: KindOpenWrite, Path: "/home/app/./.bashrc"},
	}

	got := Findings(events, "probe", at)
	if len(got) != 3 {
		var summaries []string
		for _, ev := range got {
			summaries = append(summaries, ev.Summary)
		}
		t.Fatalf("got %d findings, want 3 (two destinations + one path):\n%s",
			len(got), strings.Join(summaries, "\n"))
	}

	// Order follows first observation, so the same sequence always reports the
	// same way. A map-ordered result would make the report non-deterministic.
	if !strings.Contains(got[0].Summary, "203.0.113.7:443") ||
		!strings.Contains(got[1].Summary, "198.51.100.9:80") ||
		!strings.Contains(got[2].Summary, ".bashrc") {
		t.Errorf("findings are not in first-observation order:\n%q\n%q\n%q",
			got[0].Summary, got[1].Summary, got[2].Summary)
	}
}

// An event the mapping does not understand must produce nothing. A future
// probe kind reaching an old mapping must not invent a finding (invariant 2:
// an absent layer lowers confidence, it never fabricates evidence).
func TestUnknownAndEmptyEventsAreIgnored(t *testing.T) {
	events := []Event{
		{Kind: EventKind(99), Dest: "203.0.113.7:443", Path: "/home/app/.bashrc"},
		{Kind: KindConnect},                // no destination
		{Kind: KindOpenWrite},              // no path
		{Kind: KindOpenWrite, Path: "   "}, // whitespace only
	}

	if got := Findings(events, "probe", at); len(got) != 0 {
		t.Fatalf("got %d findings from unusable events, want 0:\n%+v", len(got), got)
	}
}

// A hostile path must not be able to flood a report with its own bytes.
func TestLongPathsAreClipped(t *testing.T) {
	long := "/home/app/" + strings.Repeat("a", 5000) + "/.bashrc"

	got := Findings([]Event{{Kind: KindOpenWrite, Path: long}}, "probe", at)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	shown, _ := got[0].Detail["path"].(string)
	if len([]rune(shown)) > evidenceLimit+3 {
		t.Errorf("path reached the report at %d runes, over the %d budget",
			len([]rune(shown)), evidenceLimit)
	}
	if len([]rune(got[0].Summary)) > 2*evidenceLimit {
		t.Errorf("summary is %d runes; a target-controlled path is flooding it",
			len([]rune(got[0].Summary)))
	}
}

// Nothing observed means nothing reported. An eBPF layer that attached and saw
// no syscalls must not imply anything about the target either way.
func TestNoEventsProducesNoFindings(t *testing.T) {
	if got := Findings(nil, "probe", at); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

// The mapping and the corpus ground truth have to agree, or a gap cannot
// close no matter how well the detection works.
//
// This is a regression test for a real mismatch. evil-skill-covert's
// covert.persistence-no-token was written to match `source: decoy`, but the
// decoy tier keys entirely on planted nonces and a persistence write leaves
// none — so no decoy-sourced event could ever carry it. eBPF would emit the
// finding, the manifest would match nothing, the item would stay marked
// known_gap, and the set-equality gate would still pass. The gap would fail to
// close with nothing saying so.
//
// The expectations below are the `match:` blocks of the two fixtures the eBPF
// work is defined to close (see docs/PLAN.md "the corpus is the gate"):
//
//	testdata/corpus/evil-mcp-postmark/ground-truth.yaml   postmark.covert-bcc
//	testdata/corpus/evil-skill-covert/ground-truth.yaml   covert.persistence-no-token
//
// Replicating the corpus matcher here means the agreement is checked on every
// platform, with no kernel, container or privilege — rather than being
// discovered on a privileged run, or not at all.
func TestFindingsSatisfyTheCorpusGroundTruth(t *testing.T) {
	cases := []struct {
		fixture         string
		plantedID       string
		event           Event
		source          string
		summaryContains string
	}{
		{
			fixture:         "evil-mcp-postmark",
			plantedID:       "postmark.covert-bcc",
			event:           Event{Kind: KindConnect, PID: 11, Comm: "python3", Dest: "203.0.113.7:2525"},
			source:          "ebpf",
			summaryContains: "connect",
		},
		{
			fixture:         "evil-skill-covert",
			plantedID:       "covert.persistence-no-token",
			event:           Event{Kind: KindOpenWrite, PID: 12, Comm: "python3", Path: "/home/app/.bashrc"},
			source:          "ebpf",
			summaryContains: ".bashrc",
		},
	}

	for _, tc := range cases {
		t.Run(tc.fixture+"/"+tc.plantedID, func(t *testing.T) {
			got := Findings([]Event{tc.event}, "probe", at)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1", len(got))
			}
			ev := got[0]

			// scoreCorpus compares the source for equality, then looks for the
			// substring in the summary plus the evidence detail.
			if ev.Source != tc.source {
				t.Errorf("source = %q, want %q; the fixture would match nothing",
					ev.Source, tc.source)
			}
			haystack := ev.Summary
			if evidence, ok := ev.Detail["evidence"].(string); ok {
				haystack += "\n" + evidence
			}
			if !strings.Contains(haystack, tc.summaryContains) {
				t.Errorf("neither summary nor evidence contains %q, so %s stays a "+
					"recorded gap however well detection works:\n%s",
					tc.summaryContains, tc.plantedID, haystack)
			}
		})
	}
}
