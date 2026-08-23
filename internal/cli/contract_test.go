package cli

import "testing"

// The frozen contract.
//
// Exit codes are what a CI job actually gates on, and they are the one thing a
// consumer cannot adapt to after the fact: a pipeline that treats 3 as "found
// something" silently changes meaning if 3 ever becomes something else. Nothing
// else detonate exposes has that property — flags can be added, report fields
// can grow, output can be reformatted — so these five numbers are pinned here
// deliberately, and changing one is a breaking release, not a patch.
//
// This test exists to fail loudly during review rather than quietly in someone
// else's pipeline.
func TestExitCodesAreFrozen(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"clean", exitOK, 0},
		{"scan failed", exitFailure, 1},
		{"usage or environment", exitUsage, 2},
		{"findings", exitFindings, 3},
		{"incomplete coverage", exitIncomplete, 4},
	} {
		if tc.got != tc.want {
			t.Errorf("exit code for %s is %d, want %d — this is a breaking change "+
				"to the published contract, not an implementation detail",
				tc.name, tc.got, tc.want)
		}
	}
}

// The distinction the whole contract rests on: "the tool broke" and "the tool
// caught something" must never be the same number, or a pipeline cannot tell a
// detonate bug from a real finding in the target.
func TestFailureAndFindingsAreDistinct(t *testing.T) {
	if exitFailure == exitFindings {
		t.Fatal("a broken scan and a scan with findings share an exit code")
	}
	if exitIncomplete == exitOK {
		t.Fatal("incomplete coverage shares an exit code with a clean result")
	}
}
