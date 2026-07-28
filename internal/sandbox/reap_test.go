package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestIsOrphan(t *testing.T) {
	cases := []struct {
		state, age string
		want       bool
		why        string
	}{
		{"exited", "5 minutes ago", true, "a finished container is safe to remove"},
		{"dead", "2 hours ago", true, "dead containers are always removable"},

		// "created" means mid-launch. Reaping these was the second half of the
		// concurrent-scan bug: a scan was destroyed in the window between
		// `docker run` and its process actually running.
		{"created", "1 second ago", false, "a container still launching is not an orphan"},
		{"created", "30 seconds ago", false, "still plausibly launching under load"},
		{"created", "20 minutes ago", true, "stuck in created this long is wedged, not launching"},

		// The regression this file exists for. An earlier reaper removed every
		// container with our prefix, so a second scan killed the first one's
		// container mid-run and the victim reported a false clean.
		{"running", "2 seconds ago", false, "a live scan must survive another scan starting"},
		{"running", "About a minute ago", false, "a slow but live scan must survive"},
		{"running", "45 minutes ago", false, "still inside the plausible-scan window"},

		{"running", "3 hours ago", true, "far longer than any real scan; abandoned"},
		{"running", "2 days ago", true, "abandoned"},
	}

	for _, c := range cases {
		if got := isOrphan(c.state, c.age); got != c.want {
			t.Errorf("isOrphan(%q, %q) = %v, want %v\n  %s",
				c.state, c.age, got, c.want, c.why)
		}
	}
}

func TestOlderThanIsConservativeOnUnknownFormats(t *testing.T) {
	// An unrecognised age must never read as "old". Killing a running scan is
	// far worse than leaving a dead container around, so unfamiliar phrasing
	// has to fail safe.
	for _, s := range []string{"", "Up", "who knows", "???", "many moons"} {
		if olderThan(s, time.Hour) {
			t.Errorf("olderThan(%q) = true; unknown ages must not be treated as old", s)
		}
	}
}

func TestParseAge(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"5 seconds ago", 5 * time.Second},
		{"About a minute ago", time.Minute},
		{"2 minutes ago", 2 * time.Minute},
		{"About an hour ago", time.Hour},
		{"3 hours ago", 3 * time.Hour},
		{"2 days ago", 48 * time.Hour},
	}
	for _, c := range cases {
		got, ok := parseAge(c.in)
		if !ok {
			t.Errorf("parseAge(%q) failed to parse", c.in)
			continue
		}
		if got != c.want {
			t.Errorf("parseAge(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The end-to-end version: a container that is running right now must still be
// running after a reap.
func TestReapDoesNotKillRunningContainers(t *testing.T) {
	requireDocker(t)

	p := DefaultPolicy()
	p.Image = "alpine:latest"
	p.Timeout = 90 * time.Second

	name, err := NewName()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c, err := Start(ctx, name, p, nil, []string{"sh", "-c", "sleep 60"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	// Let it actually reach running state before reaping.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !c.exists() {
		time.Sleep(200 * time.Millisecond)
	}
	if !c.exists() {
		t.Skip("container never appeared; docker too slow to run this test meaningfully")
	}

	ReapOrphans(context.Background())

	if !c.exists() {
		t.Fatal("ReapOrphans destroyed a running container; " +
			"concurrent scans would sabotage each other and report false cleans")
	}
	if failed, detail := c.Failed(); failed {
		t.Fatalf("container was killed during reap: %s", detail)
	}
}
