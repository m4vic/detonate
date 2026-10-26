package skill

import (
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

var assembleAt = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const noMisbehaviour = "ran with no observable misbehaviour"

func hasNoMisbehaviourNote(events []trace.Event) bool {
	for _, ev := range events {
		if strings.Contains(ev.Summary, noMisbehaviour) {
			return true
		}
	}
	return false
}

func finding(summary string) trace.Event {
	return trace.Event{
		Kind: trace.KindFile, Severity: trace.SeverityCritical,
		Summary: summary, Source: "ebpf",
	}
}

func observation(summary string) trace.Event {
	return trace.Event{
		Kind: trace.KindLifecycle, Severity: trace.SeverityInfo,
		Summary: summary, Source: "ebpf",
	}
}

// Silence is worth a line. A reader deciding whether to trust a skill wants to
// know its code executed at all, so a clean run says so rather than saying
// nothing.
func TestACleanScriptRunIsStillReported(t *testing.T) {
	got := assembleScriptEvents("format.py", "skill-detonation:format.py", assembleAt,
		nil, nil, nil, nil)

	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if !hasNoMisbehaviourNote(got) {
		t.Errorf("a clean run reported nothing a reader can read: %+v", got)
	}
}

// The rule this assembly exists to enforce. A ~/.bashrc write caught at the
// syscall level, reported next to "ran with no observable misbehaviour", is a
// report arguing with itself.
func TestASyscallFindingSuppressesTheNoMisbehaviourNote(t *testing.T) {
	syscalls := []trace.Event{finding("target opened /home/app/.bashrc for writing")}

	got := assembleScriptEvents("setup_env.py", "skill-detonation:setup_env.py", assembleAt,
		nil, nil, syscalls, nil)

	if hasNoMisbehaviourNote(got) {
		t.Errorf("reported %q alongside a critical syscall finding:\n%+v",
			noMisbehaviour, got)
	}
	if len(got) != 1 || !strings.Contains(got[0].Summary, ".bashrc") {
		t.Errorf("the finding did not survive assembly: %+v", got)
	}
}

// Each tier that says something about the script must suppress the note, not
// just the syscall one.
func TestAnyEvidenceTierSuppressesTheNote(t *testing.T) {
	tiers := map[string]func() []trace.Event{
		"stderr": func() []trace.Event {
			return assembleScriptEvents("s.py", "d", assembleAt,
				[]trace.Event{finding("target attempted DNS resolution")}, nil, nil, nil)
		},
		"decoy": func() []trace.Event {
			return assembleScriptEvents("s.py", "d", assembleAt,
				nil, []trace.Event{finding("script returned the contents of ~/.aws")}, nil, nil)
		},
		"syscall": func() []trace.Event {
			return assembleScriptEvents("s.py", "d", assembleAt,
				nil, nil, []trace.Event{finding("target opened ~/.bashrc")}, nil)
		},
	}

	for name, run := range tiers {
		t.Run(name, func(t *testing.T) {
			if hasNoMisbehaviourNote(run()) {
				t.Errorf("the %s tier found something and the report still claims "+
					"no observable misbehaviour", name)
			}
		})
	}
}

// The attached note is a fact about the SCAN, not the script. It must never be
// the reason a reader stops being told the script ran, and it must not stand
// in for that line: "observation was active" tells nobody the script executed.
//
// This is the regression that would arrive the first time someone appends the
// attach note before the emptiness check — invisible on an unprivileged run,
// because there is no attach note there at all.
func TestTheAttachedNoteDoesNotSuppressTheNoMisbehaviourNote(t *testing.T) {
	attached := []trace.Event{observation("syscall-level observation was active for this scan")}

	got := assembleScriptEvents("format.py", "skill-detonation:format.py", assembleAt,
		nil, nil, nil, attached)

	if !hasNoMisbehaviourNote(got) {
		t.Fatalf("an attached monitor suppressed the only line saying the script "+
			"ran:\n%+v", got)
	}
	if len(got) != 2 {
		t.Errorf("got %d events, want the note plus the attach observation: %+v",
			len(got), got)
	}
	// The attach note comes last, after the decision it must not influence.
	if !strings.Contains(got[len(got)-1].Summary, "observation was active") {
		t.Errorf("the attach observation is not last: %+v", got)
	}
}

// Order is part of the report. Tiers appear in the order they are collected so
// two runs over the same behaviour read the same way.
func TestAssemblyOrderIsStable(t *testing.T) {
	got := assembleScriptEvents("s.py", "d", assembleAt,
		[]trace.Event{finding("stderr tier")},
		[]trace.Event{finding("decoy tier")},
		[]trace.Event{finding("syscall tier")},
		[]trace.Event{observation("attached")},
	)

	want := []string{"stderr tier", "decoy tier", "syscall tier", "attached"}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Summary != w {
			t.Errorf("event %d = %q, want %q", i, got[i].Summary, w)
		}
	}
}

// An unavailable monitor contributes nothing, so a skill scan without eBPF
// must read exactly as it did before the layer existed: one note, nothing else.
func TestWithoutEBPFTheReportIsUnchanged(t *testing.T) {
	// Both syscall slices nil is precisely what an unavailable collector
	// returns from Take and AttachedEvent.
	got := assembleScriptEvents("format.py", "skill-detonation:format.py", assembleAt,
		nil, nil, nil, nil)

	if len(got) != 1 {
		t.Fatalf("got %d events, want exactly the 1 from before this layer: %+v",
			len(got), got)
	}
	if got[0].Source != "skill-runner" {
		t.Errorf("source = %q, want skill-runner", got[0].Source)
	}
	if got[0].Severity != trace.SeverityInfo {
		t.Errorf("severity = %q, want info", got[0].Severity)
	}
}
