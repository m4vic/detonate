package monitor

import (
	"regexp"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

// Analyze extracts behavioural findings from what a container wrote to stderr.
//
// This is a cheap but genuinely useful monitor, and it works precisely BECAUSE
// the sandbox blocks things. When a target tries to reach the network with
// --network none, it does not fail silently: the runtime, the language, or the
// HTTP library writes a resolution or connection error. That error is proof of
// intent. The tool tried to phone home while we were only listing its tools,
// and it left a receipt.
//
// The limits are worth stating plainly rather than overselling this. A target
// that swallows its own exceptions produces no stderr, so absence of findings
// here is NOT evidence of good behaviour. That is the gap eBPF-level syscall
// tracing closes later; until then this tier finds the careless, not the
// careful.
func Analyze(stderr string, during string) []trace.Event {
	if strings.TrimSpace(stderr) == "" {
		return nil
	}

	var events []trace.Event
	now := time.Now()

	for _, sig := range signatures {
		for _, line := range sig.pattern.FindAllString(stderr, -1) {
			events = append(events, trace.Event{
				Kind:     sig.kind,
				Severity: sig.severity,
				At:       now,
				Summary:  sig.summary,
				During:   during,
				Source:   "container-stderr",
				Detail: map[string]any{
					"evidence": strings.TrimSpace(truncate(line, 200)),
				},
			})
			break // one event per signature; a retry loop should not become 50 findings
		}
	}
	return events
}

type signature struct {
	pattern  *regexp.Regexp
	kind     trace.Kind
	severity trace.Severity
	summary  string
}

// signatures are the traces that blocked behaviour leaves behind.
//
// Each one is a thing a target did that it did not need to do in order to list
// its tools. Enumeration should require no network, no subprocesses, and no
// access outside the target's own directory — so any of these during
// enumeration is behaviour worth reporting, not a bug to tolerate.
var signatures = []signature{
	{
		// DNS resolution failure. The most common shape of a blocked
		// exfiltration attempt, because almost everything resolves a hostname
		// before it connects.
		pattern: regexp.MustCompile(`(?i).*(name or service not known|temporary failure in name resolution|nodename nor servname|getaddrinfo|bad address|could not resolve|dns lookup failed).*`),
		kind:    trace.KindNetwork, severity: trace.SeverityCritical,
		summary: "target attempted DNS resolution (network is disabled in the sandbox)",
	},
	{
		pattern: regexp.MustCompile(`(?i).*(network is unreachable|connection refused|no route to host|connect: network|failed to establish a new connection|connection timed out).*`),
		kind:    trace.KindNetwork, severity: trace.SeverityCritical,
		summary: "target attempted an outbound connection (network is disabled in the sandbox)",
	},
	{
		// Python's requests/urllib and Node's fetch produce these even when
		// the underlying cause is the blocked network.
		pattern: regexp.MustCompile(`(?i).*(urllib|requests\.exceptions|ConnectionError|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|httpx\.).*`),
		kind:    trace.KindNetwork, severity: trace.SeverityCritical,
		summary: "target used an HTTP client during enumeration",
	},
	{
		pattern: regexp.MustCompile(`(?i).*(permission denied|read-only file system|operation not permitted).*`),
		kind:    trace.KindFile, severity: trace.SeverityNotable,
		summary: "target attempted a write the sandbox denied",
	},
	{
		pattern: regexp.MustCompile(`(?i).*(can't fork|cannot fork|resource temporarily unavailable|fork failed).*`),
		kind:    trace.KindResource, severity: trace.SeverityCritical,
		summary: "target exhausted its process limit (possible fork bomb)",
	},
	{
		pattern: regexp.MustCompile(`(?i).*(no such file or directory: '?/(etc/passwd|etc/shadow|root/|home/)).*`),
		kind:    trace.KindFile, severity: trace.SeverityCritical,
		summary: "target attempted to read a sensitive system path",
	},
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
