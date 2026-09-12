package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/m4vic/detonate/internal/dockertest"
	"github.com/m4vic/detonate/internal/target"
	"github.com/m4vic/detonate/internal/trace"
)

// The detection corpus: fixtures with a known planted-vulnerability count,
// scored against what detonate actually finds.
//
// The calibration in the README measures the opposite direction — false
// positives on real, known-good targets. That alone can be satisfied by a
// scanner that detects nothing, so it needs this counterpart: adversarial
// fixtures whose contents are enumerated in advance, so "what fraction of what
// is actually there does detonate catch" is a number rather than a claim.
//
// See testdata/corpus/README.md.

type groundTruth struct {
	Schema  string `yaml:"schema"`
	Fixture string `yaml:"fixture"`
	Kind    string `yaml:"kind"`
	Command string `yaml:"command"`
	Planted []struct {
		ID    string `yaml:"id"`
		Class string `yaml:"class"`
		Where string `yaml:"where"`
		// Expect distinguishes a finding (drives the verdict) from an
		// observation (informational context a reviewer reads).
		Expect string `yaml:"expect"`
		// KnownGap marks something planted that detonate does not yet catch.
		// Recorded rather than omitted: a corpus that quietly drops what the
		// scanner misses measures nothing.
		KnownGap bool `yaml:"known_gap"`
		Match    struct {
			Source          string `yaml:"source"`
			SummaryContains string `yaml:"summary_contains"`
		} `yaml:"match"`
	} `yaml:"planted"`
}

func loadGroundTruth(t *testing.T, fixture string) (groundTruth, string) {
	t.Helper()

	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus", fixture))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "ground-truth.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var gt groundTruth
	if err := yaml.Unmarshal(raw, &gt); err != nil {
		t.Fatalf("parsing ground-truth.yaml: %v", err)
	}
	if len(gt.Planted) == 0 {
		t.Fatal("ground truth declares nothing planted")
	}
	return gt, dir
}

// scoreCorpus runs the real pipeline over a fixture and reports which planted
// vulnerabilities came back.
func scoreCorpus(t *testing.T, gt groundTruth, report *Report) (detected []string, missed []string) {
	t.Helper()

	if report == nil || report.Trace == nil {
		t.Fatal("no trace produced")
	}

	for _, planted := range gt.Planted {
		found := false
		for _, ev := range report.Trace.Events {
			if ev.Source != planted.Match.Source {
				continue
			}
			haystack := ev.Summary
			if evidence, ok := ev.Detail["evidence"].(string); ok {
				haystack += "\n" + evidence
			}
			if strings.Contains(haystack, planted.Match.SummaryContains) {
				found = true
				break
			}
		}
		if found {
			detected = append(detected, planted.ID)
		} else {
			missed = append(missed, planted.ID)
		}
	}
	return detected, missed
}

// assertScore reports the score and holds the corpus to its recorded state.
//
// The gate is set equality, not a threshold: the set of undetected items must
// be exactly the set the manifest marks `known_gap`. A newly missed item is a
// regression, and a known gap that starts passing is also a failure — it means
// somebody closed a hole and the manifest still calls it open, which is how a
// corpus quietly rots into fiction.
func assertScore(t *testing.T, gt groundTruth, detected, missed []string) {
	t.Helper()

	expectedGaps := map[string]bool{}
	for _, planted := range gt.Planted {
		if planted.KnownGap {
			expectedGaps[planted.ID] = true
		}
	}

	sort.Strings(missed)
	t.Logf("%s: detected %d/%d planted (%d known gap(s))",
		gt.Fixture, len(detected), len(gt.Planted), len(expectedGaps))

	var regressions, closed []string
	for _, id := range missed {
		if !expectedGaps[id] {
			regressions = append(regressions, id)
		}
	}
	for id := range expectedGaps {
		stillMissed := false
		for _, m := range missed {
			if m == id {
				stillMissed = true
				break
			}
		}
		if !stillMissed {
			closed = append(closed, id)
		}
	}
	sort.Strings(closed)

	if len(regressions) > 0 {
		t.Errorf("detection regressed — planted but not found: %s",
			strings.Join(regressions, ", "))
	}
	if len(closed) > 0 {
		t.Errorf("known gap(s) now detected: %s — remove known_gap from ground-truth.yaml",
			strings.Join(closed, ", "))
	}
}

// TestCorpus discovers every fixture under testdata/corpus, runs the real
// pipeline over it, and scores detected-against-planted.
//
// Discovery is by directory, not a hardcoded list, so growing the corpus is
// adding a fixture folder with a ground-truth.yaml — no test code changes. That
// is the whole workflow: each new evasion someone can think of becomes a
// fixture, the ones detonate misses land as recorded gaps, and closing a gap is
// a detector change that flips the fixture from red to green.
func TestCorpus(t *testing.T) {
	dockertest.Require(t)

	fixtures := discoverFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("no corpus fixtures discovered")
	}

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gt, dir := loadGroundTruth(t, name)
			report := runFixture(t, gt, dir)
			detected, missed := scoreCorpus(t, gt, report)
			assertScore(t, gt, detected, missed)
		})
	}
}

// discoverFixtures returns the corpus fixture directory names, sorted.
func discoverFixtures(t *testing.T) []string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "ground-truth.yaml")); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// runFixture runs one fixture through the pipeline according to its kind.
func runFixture(t *testing.T, gt groundTruth, dir string) *Report {
	t.Helper()

	var req Request
	switch gt.Kind {
	case "mcp":
		if gt.Command == "" {
			t.Fatalf("%s: mcp fixture declares no command", gt.Fixture)
		}
		req = Request{
			Target:   target.Target{Kind: target.KindMCP, Reference: gt.Command},
			MountDir: dir,
			Stages:   Stages{Probe: true},
		}
	case "skill":
		req = Request{
			Target: target.Target{Kind: target.KindSkill, Reference: dir},
			Stages: Stages{RunScripts: true},
		}
	default:
		t.Fatalf("%s: unknown kind %q", gt.Fixture, gt.Kind)
	}

	report, err := Run(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return report
}

// The corpus is only meaningful in both directions: a scanner that flags
// everything scores perfectly on the fixtures above. The honest twins already
// in the repo are the control, and they must stay quiet.
func TestCorpusHonestTwinsStayQuiet(t *testing.T) {
	dockertest.Require(t)

	for _, tc := range []struct {
		name    string
		kind    target.Kind
		dir     string
		command string
		stages  Stages
	}{
		{
			name: "honest-mcp", kind: target.KindMCP, dir: "honest",
			command: "python /target/server.py", stages: Stages{Probe: true},
		},
		{
			name: "benign-skill", kind: target.KindSkill, dir: "benign-formatter",
			stages: Stages{RunScripts: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", tc.dir))
			if err != nil {
				t.Fatal(err)
			}
			req := Request{Stages: tc.stages}
			if tc.kind == target.KindMCP {
				req.Target = target.Target{Kind: tc.kind, Reference: tc.command}
				req.MountDir = dir
			} else {
				req.Target = target.Target{Kind: tc.kind, Reference: dir}
			}

			report, err := Run(context.Background(), req, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if report == nil || report.Trace == nil {
				t.Fatal("no trace produced")
			}

			var flagged []string
			for _, ev := range report.Trace.Events {
				if ev.Severity == trace.SeverityCritical || ev.Severity == trace.SeverityNotable {
					flagged = append(flagged, fmt.Sprintf("[%s] %s", ev.Severity, ev.Summary))
				}
			}
			if len(flagged) > 0 {
				t.Fatalf("honest target produced %d finding(s):\n  %s",
					len(flagged), strings.Join(flagged, "\n  "))
			}
		})
	}
}
