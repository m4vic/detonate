package cli

import (
	"strings"
	"testing"
)

// The banner is the first thing anyone sees, and a box whose right edge does
// not line up reads as carelessness before the tool has done anything.
//
// It was genuinely broken: four of the ASCII-art lines were two characters
// wider than the rules above and below them, and the version field was sized
// for a tagged release like "v1.0.0" — so any build from an untagged commit
// carried a Go pseudo-version and pushed the border off the screen. That is the
// build every contributor runs.
func TestBannerLinesAreAllTheSameWidth(t *testing.T) {
	lines := nonEmptyLines(bannerText())
	if len(lines) < 5 {
		t.Fatalf("banner has only %d lines", len(lines))
	}

	want := len([]rune(lines[0]))
	for i, l := range lines {
		if got := len([]rune(l)); got != want {
			t.Errorf("line %d is %d wide, want %d:\n%s", i, got, want, l)
		}
	}
}

// A long version must be truncated into the field rather than widening the box.
func TestBannerSurvivesALongVersion(t *testing.T) {
	original := Version
	defer func() { Version = original }()

	for _, v := range []string{
		"v1.0.0",
		"v0.3.0-alpha.1.0.20260823072109-cdea562a6b57+dirty",
		strings.Repeat("x", 200),
		"",
	} {
		Version = v
		lines := nonEmptyLines(bannerText())
		want := len([]rune(lines[0]))
		for i, l := range lines {
			if got := len([]rune(l)); got != want {
				t.Fatalf("version %q broke line %d: %d wide, want %d\n%s",
					v, i, got, want, l)
			}
		}
	}
}

// The version has to actually appear, or the box lines up while telling the
// reader nothing.
func TestBannerShowsTheVersion(t *testing.T) {
	original := Version
	defer func() { Version = original }()

	Version = "v1.2.3"
	if !strings.Contains(bannerText(), "v1.2.3") {
		t.Fatalf("banner does not contain the version:\n%s", bannerText())
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
