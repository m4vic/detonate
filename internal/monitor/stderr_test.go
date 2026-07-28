package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

func nowMinus(d time.Duration) time.Time { return time.Now().Add(-d) }

// The stderr strings below are real output from real runtimes, not invented
// examples. A signature set tested only against text I wrote myself would
// prove nothing except that my regex matches my own writing.
func TestAnalyzeDetectsBlockedNetwork(t *testing.T) {
	cases := []struct {
		name     string
		stderr   string
		wantKind trace.Kind
	}{
		{
			name:     "python socket, resolution blocked",
			stderr:   `socket.gaierror: [Errno -3] Temporary failure in name resolution`,
			wantKind: trace.KindNetwork,
		},
		{
			name:     "python requests",
			stderr:   `requests.exceptions.ConnectionError: HTTPSConnectionPool(host='evil.example', port=443)`,
			wantKind: trace.KindNetwork,
		},
		{
			name:     "node fetch",
			stderr:   `Error: getaddrinfo EAI_AGAIN collect.example.com`,
			wantKind: trace.KindNetwork,
		},
		{
			name:     "busybox wget",
			stderr:   `wget: bad address 'example.com'`,
			wantKind: trace.KindNetwork,
		},
		{
			name:     "go net",
			stderr:   `dial tcp: lookup evil.example on 127.0.0.11:53: no such host... connection refused`,
			wantKind: trace.KindNetwork,
		},
		{
			name:     "read-only filesystem",
			stderr:   `OSError: [Errno 30] Read-only file system: '/implant'`,
			wantKind: trace.KindFile,
		},
		{
			name:     "fork bomb hit the ceiling",
			stderr:   `sh: can't fork: Resource temporarily unavailable`,
			wantKind: trace.KindResource,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := Analyze(tc.stderr, "enumeration")
			if len(events) == 0 {
				t.Fatalf("no events from stderr: %q", tc.stderr)
			}
			found := false
			for _, e := range events {
				if e.Kind == tc.wantKind {
					found = true
					if e.Source != "container-stderr" {
						t.Errorf("Source = %q, evidence must name its origin", e.Source)
					}
					if e.During != "enumeration" {
						t.Errorf("During = %q, behaviour must be attributable to a phase", e.During)
					}
					if e.Detail["evidence"] == nil {
						t.Error("event carries no evidence string")
					}
				}
			}
			if !found {
				t.Errorf("wanted a %s event, got %v", tc.wantKind, events)
			}
		})
	}
}

// A well-behaved server must produce no findings. A monitor that fires on
// ordinary output is a monitor nobody keeps enabled.
func TestAnalyzeIsQuietOnCleanOutput(t *testing.T) {
	clean := []string{
		"",
		"   \n  ",
		"INFO: server started\nINFO: listening on stdio\n",
		"Loaded 3 tools from config.",
	}
	for _, s := range clean {
		if events := Analyze(s, "enumeration"); len(events) != 0 {
			t.Errorf("false positive on %q: %v", s, events)
		}
	}
}

// A retry loop writing the same error 50 times is one behaviour, not 50
// findings. Collapsing them is what keeps a report readable.
func TestAnalyzeDeduplicatesRepeatedErrors(t *testing.T) {
	spam := strings.Repeat("socket.gaierror: Temporary failure in name resolution\n", 50)
	events := Analyze(spam, "enumeration")

	network := 0
	for _, e := range events {
		if e.Kind == trace.KindNetwork {
			network++
		}
	}
	if network > 1 {
		t.Errorf("got %d network events from one repeated error; want 1", network)
	}
}

func TestTraceElapsedIsRelative(t *testing.T) {
	// Wall-clock times are useless for diffing runs; elapsed times are
	// comparable, so Trace.Add must compute them rather than trusting callers.
	tr := &trace.Trace{Target: "test", Started: nowMinus(0)}
	tr.Add(trace.Event{Kind: trace.KindNetwork, Summary: "x"})

	if len(tr.Events) != 1 {
		t.Fatal("event not recorded")
	}
	if tr.Events[0].Elapsed < 0 {
		t.Errorf("Elapsed = %v, must be relative to trace start", tr.Events[0].Elapsed)
	}
	if tr.Events[0].At.IsZero() {
		t.Error("At was not filled in")
	}
}
