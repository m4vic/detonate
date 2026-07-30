package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Caller is what the engine needs from a live MCP session.
//
// An interface rather than the concrete session type so the engine can be
// tested without Docker, and so the same probes can later drive a skill's
// bundled scripts, which are a different thing wearing the same shape.
type Caller interface {
	// Call invokes a tool and returns its response as text.
	Call(ctx context.Context, tool string, args map[string]any) (string, error)

	// Stderr returns everything the target has written so far. The engine
	// diffs this across calls to attribute behaviour to a specific probe.
	Stderr() string
}

// Run probes every tool and returns what was observed.
//
// Order matters: each tool gets a benign baseline call before any hostile one,
// so behaviour that only appears under attack can be separated from behaviour
// the target exhibits normally. Without the baseline, a server that always
// logs a warning would produce a finding on every probe.
func Run(ctx context.Context, c Caller, tools []toolinfo.ToolInfo, timeout time.Duration) []trace.Event {
	var events []trace.Event

	for _, tool := range tools {
		params := stringParams(tool.InputSchema)
		if len(params) == 0 {
			// Nothing to inject into. A tool with no string inputs is not
			// immune, but it is out of reach of this probe set, and saying so
			// is better than implying it was tested.
			events = append(events, trace.Event{
				Kind: trace.KindProtocol, Severity: trace.SeverityInfo, At: time.Now(),
				Summary: fmt.Sprintf("tool %q has no string parameters; not probed", tool.Name),
				During:  "probe", Source: "probe-engine",
			})
			continue
		}

		baseline := c.Stderr()
		if _, err := c.Call(ctx, tool.Name, argsFor(params, benign)); err != nil {
			// A tool that reaches an external host cannot be probed here,
			// because the sandbox denies the network on purpose. That is the
			// sandbox working, not a defect in the tool — so it is an
			// observation, not a finding, and it must not push the verdict to
			// "dangerous". Reporting 24 API tools as suspicious because Notion
			// could not reach api.notion.com is a confident false accusation,
			// which is worse than saying nothing.
			//
			// The message is still useful to the tool's own author: it names
			// exactly which tools need egress and so cannot be exercised in a
			// sealed sandbox.
			sev, summary := trace.SeverityInfo, fmt.Sprintf(
				"tool %q needs network access the sandbox denies; not probed", tool.Name)
			if !isNetworkBlocked(err) {
				// A benign call that fails for some OTHER reason means the tool
				// is broken on valid input. Still not a security finding — but
				// worth surfacing to its author, and it means the payloads
				// below cannot be trusted.
				summary = fmt.Sprintf("tool %q failed on a benign call; probes may be unreliable", tool.Name)
			}
			events = append(events, trace.Event{
				Kind: trace.KindProtocol, Severity: sev, At: time.Now(),
				Summary: summary,
				During:  "probe:baseline", Source: "probe-engine",
				Detail: map[string]any{"evidence": clip(err.Error(), 200)},
			})
			if isNetworkBlocked(err) {
				// Every payload would hit the same network wall first, so
				// probing this tool learns nothing. Skip it rather than emit a
				// crash finding per payload for an error the sandbox caused.
				continue
			}
		}
		baseline = c.Stderr() // after the benign call: this is "normal"

		for _, p := range payloads {
			select {
			case <-ctx.Done():
				return events
			default:
			}

			before := c.Stderr()
			resp, err := c.Call(ctx, tool.Name, argsFor(params, p.Value))
			after := c.Stderr()

			during := fmt.Sprintf("probe:%s on %s", p.Category, tool.Name)

			// 1. Did the RESPONSE prove the payload worked?
			if ev := checkResponse(tool.Name, p, resp, during); ev != nil {
				events = append(events, *ev)
			}

			// 2. Did the target BEHAVE differently than on the benign call?
			//
			// Diffing against the baseline is what keeps this honest: a
			// server that always writes the same warning produces no finding,
			// while one that reaches for the network only under a traversal
			// path produces a very specific one.
			if delta := strings.TrimPrefix(after, before); delta != "" && !containedIn(delta, baseline) {
				for _, ev := range monitor.Analyze(delta, during) {
					ev.Detail = withPayload(ev.Detail, p, tool.Name)
					events = append(events, ev)
				}
			}

			// 3. A crash under hostile input is itself a result.
			if err != nil && isCrash(err) {
				events = append(events, trace.Event{
					Kind: trace.KindProtocol, Severity: trace.SeverityNotable, At: time.Now(),
					Summary: fmt.Sprintf("tool %q crashed on %s input", tool.Name, p.Category),
					During:  during, Source: "probe-engine",
					Detail: map[string]any{
						"evidence": clip(err.Error(), 200),
						"payload":  clip(p.Value, 80),
						"why":      p.Why,
					},
				})
			}
		}
	}
	return events
}

// checkResponse looks for proof in what the tool returned.
//
// This is the strongest signal the engine produces, because it needs no
// inference: /etc/passwd always contains "root:x:0:0", so a tool returning
// that string has read the file. There is nothing to argue about.
func checkResponse(tool string, p Payload, resp, during string) *trace.Event {
	if resp == "" || len(p.LeakMarkers) == 0 {
		return nil
	}
	for _, marker := range p.LeakMarkers {
		if !strings.Contains(resp, marker) {
			continue
		}

		summary := fmt.Sprintf("tool %q leaked data via %s", tool, p.Category)
		if p.Category == CategoryPromptInjection {
			summary = fmt.Sprintf("tool %q returns caller-supplied text verbatim", tool)
		}

		severity := p.Severity
		if severity == "" {
			severity = trace.SeverityCritical
		}
		return &trace.Event{
			Kind: trace.KindProtocol, Severity: severity, At: time.Now(),
			Summary: summary, During: during, Source: "probe-response",
			Detail: map[string]any{
				"payload":  clip(p.Value, 120),
				"marker":   marker,
				"why":      p.Why,
				"evidence": clip(extractAround(resp, marker), 200),
			},
		}
	}
	return nil
}

// stringParams finds the string-typed inputs a tool accepts.
//
// Driven by the tool's own schema so probes are well-formed: a target can
// legitimately reject malformed input, and a scanner that only ever sends
// malformed input learns nothing about how the tool handles valid-but-hostile
// values.
func stringParams(schema json.RawMessage) []string {
	if len(schema) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil
	}

	var names []string
	for name, prop := range s.Properties {
		if prop.Type == "string" || prop.Type == "" { // untyped defaults to string
			names = append(names, name)
		}
	}
	return names
}

// argsFor fills every string parameter with the same value.
//
// All at once rather than one at a time: a tool that only mishandles its
// third argument still gets caught, and the number of calls stays linear in
// payloads rather than payloads times parameters. The cost is that a hit does
// not say WHICH parameter was vulnerable, which is a follow-up question a
// human can answer quickly once they know there is a hit at all.
func argsFor(params []string, value string) map[string]any {
	args := make(map[string]any, len(params))
	for _, p := range params {
		args[p] = value
	}
	return args
}

// isNetworkBlocked reports whether an error is the sandbox denying egress
// rather than the tool misbehaving.
//
// These are the resolver and connection errors a runtime raises when DNS or
// TCP is unavailable — which, in this sandbox, is always, by design. A tool
// that produces one of these is trying to reach the outside world and being
// stopped, which is the sandbox doing its job, not a finding about the tool.
func isNetworkBlocked(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sig := range []string{
		"eai_again", "getaddrinfo", "enotfound", "econnrefused",
		"network is unreachable", "enetunreach", "name resolution",
		"temporary failure in name resolution", "no address associated",
		"dns", "socket hang up", "eai_fail",
	} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

// isCrash distinguishes a target falling over from it politely refusing.
// A tool returning "invalid path" is working correctly; one returning a
// transport error has died.
func isCrash(err error) bool {
	s := strings.ToLower(err.Error())
	for _, sig := range []string{"eof", "connection", "broken pipe", "closed", "timeout", "panic"} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

func containedIn(delta, baseline string) bool {
	return baseline != "" && strings.Contains(baseline, strings.TrimSpace(delta))
}

func withPayload(detail map[string]any, p Payload, tool string) map[string]any {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["payload"] = clip(p.Value, 120)
	detail["tool"] = tool
	detail["why"] = p.Why
	return detail
}

// extractAround returns the text surrounding a marker, so the report shows the
// leak in context rather than just confirming a string matched.
func extractAround(s, marker string) string {
	i := strings.Index(s, marker)
	if i < 0 {
		return clip(s, 200)
	}
	start := i - 60
	if start < 0 {
		start = 0
	}
	end := i + len(marker) + 60
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func clip(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}
