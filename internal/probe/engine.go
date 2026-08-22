package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/decoy"
	"github.com/m4vic/detonate/internal/monitor"
	scenariodef "github.com/m4vic/detonate/internal/scenario"
	"github.com/m4vic/detonate/internal/toolcall"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Caller is what the engine needs from a live MCP session.
//
// An interface rather than the concrete session type so the engine can be
// tested without Docker, and so the same probes can later drive a skill's
// bundled scripts, which are a different thing wearing the same shape.
type Caller interface {
	// Call invokes a tool. A tool-declared IsError result is a valid response;
	// only transport or protocol failures belong in the Go error.
	Call(ctx context.Context, tool string, args map[string]any) (toolcall.Result, error)

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
	return RunWithResults(ctx, c, tools, timeout).Events
}

// Result includes both evidence and the coverage state for every tool. The
// events answer "what happened"; scenarios answer "what did we actually
// manage to test".
type Result struct {
	Events    []trace.Event
	Scenarios []assessment.ScenarioResult
}

// Probe defines a security scanner check targeting a tool.
type Probe interface {
	Name() string
	Category() Category
	Payloads() []Payload
	Evaluate(ctx context.Context, tool string, p Payload, result toolcall.Result, callErr error, beforeStderr, afterStderr, baselineStderr string) []trace.Event
}

// GenericProbe is a default implementation of the Probe interface.
type GenericProbe struct {
	category Category
	list     []Payload
}

func (g *GenericProbe) Name() string        { return string(g.category) }
func (g *GenericProbe) Category() Category  { return g.category }
func (g *GenericProbe) Payloads() []Payload { return g.list }

func (g *GenericProbe) Evaluate(ctx context.Context, tool string, p Payload, result toolcall.Result, callErr error, beforeStderr, afterStderr, baselineStderr string) []trace.Event {
	var events []trace.Event
	during := fmt.Sprintf("probe:%s on %s", p.Category, tool)

	// 1. Did the RESPONSE prove the payload worked?
	if ev := checkResponse(tool, p, result.SearchableText(), during); ev != nil {
		events = append(events, *ev)
	}

	// 2. Did the target BEHAVE differently than on the benign call?
	if delta := strings.TrimPrefix(afterStderr, beforeStderr); delta != "" && !containedIn(delta, baselineStderr) {
		for _, ev := range monitor.Analyze(delta, during) {
			ev.Detail = withPayload(ev.Detail, p, tool)
			events = append(events, ev)
		}
	}

	// 3. A crash under hostile input is itself a result.
	if callErr != nil && isCrash(callErr) {
		events = append(events, trace.Event{
			Kind: trace.KindProtocol, Severity: trace.SeverityNotable, At: time.Now(),
			Summary: fmt.Sprintf("tool %q crashed on %s input", tool, p.Category),
			During:  during, Source: "probe-engine",
			Detail: map[string]any{
				"evidence": clip(callErr.Error(), 200),
				"payload":  clip(p.Value, 80),
				"why":      p.Why,
			},
		})
	}

	return events
}

// GetDefaultProbes returns the standard set of security probes grouped by category.
func GetDefaultProbes() []Probe {
	grouped := make(map[Category][]Payload)
	for _, p := range payloads {
		grouped[p.Category] = append(grouped[p.Category], p)
	}

	var list []Probe
	for cat, listPayloads := range grouped {
		list = append(list, &GenericProbe{
			category: cat,
			list:     listPayloads,
		})
	}
	return list
}

// RunWithResults probes every tool and records one terminal scenario result
// per tool, including tools that cannot be reached by the current payload set.
// Option configures a probe run. Variadic so the existing four-argument calls
// keep working; a decoy is not required to probe.
type Option func(*config)

type config struct {
	decoy *decoy.Environment
}

// WithDecoy makes the engine check every tool response for planted secrets.
//
// This is the strongest evidence detonate can produce. A payload finding says a
// response looked wrong; a decoy hit says a token that existed only inside this
// sandbox came back out of a tool call, which has no benign explanation.
func WithDecoy(e *decoy.Environment) Option {
	return func(c *config) { c.decoy = e }
}

func RunWithResults(ctx context.Context, c Caller, tools []toolinfo.ToolInfo, timeout time.Duration, opts ...Option) Result {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}

	var events []trace.Event
	var scenarios []assessment.ScenarioResult
	probes := GetDefaultProbes()

	// Reported once per tool+token. A traversal payload set can pull the same
	// key back thirteen times, and thirteen copies of one fact is not thirteen
	// findings.
	leaked := map[string]bool{}

	for i, tool := range tools {
		scenario := assessment.ScenarioResult{
			ID: scenariodef.MCPToolID(tool.Name), Required: true,
		}
		eventStart := len(events)
		params := stringParams(tool.InputSchema)
		if len(params) == 0 {
			// Nothing to inject into. A tool with no string inputs is not
			// immune, but it is out of reach of this probe set, and saying so
			// is better than implying it was tested.
			events = append(events, trace.Event{
				Kind: trace.KindProtocol, Severity: trace.SeverityInfo, At: time.Now(),
				Summary: fmt.Sprintf("tool %q has no adversarial string-input surface; no payloads sent", tool.Name),
				During:  "probe", Source: "probe-engine",
			})
			scenario.Outcome = assessment.OutcomeUnsupported
			scenario.Reason = "current probe set found no adversarial string-input surface"
			scenarios = append(scenarios, scenario)
			continue
		}

		baseline := c.Stderr()
		// A realistic benign value when the sandbox is furnished, so a tool
		// that reads files gets something that actually exists.
		benignValue := benign
		if cfg.decoy != nil {
			benignValue = cfg.decoy.BenignInput()
		}
		baselineResult, err := c.Call(ctx, tool.Name, argsFor(params, benignValue))
		if err != nil {
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
				scenario.Outcome = assessment.OutcomeUnsupported
				scenario.Reason = "tool requires network access denied by the selected sandbox profile"
				scenarios = append(scenarios, scenario)
				continue
			}
			scenario.Outcome = assessment.OutcomeTargetError
			scenario.Reason = "tool failed on a benign schema-valid call"
		} else if baselineResult.IsError {
			events = append(events, trace.Event{
				Kind: trace.KindProtocol, Severity: trace.SeverityInfo, At: time.Now(),
				Summary: fmt.Sprintf("tool %q returned isError on a benign call", tool.Name),
				During:  "probe:baseline", Source: "probe-engine",
				Detail: map[string]any{
					"evidence": clip(baselineResult.SearchableText(), 200),
				},
			})
			scenario.Outcome = assessment.OutcomeTargetError
			scenario.Reason = "tool returned isError on a benign schema-valid call"
		}
		// A benign call that returns a planted secret is worse than a hostile
		// one that does: the tool did not need to be attacked to leak.
		if err == nil {
			events = append(events, leakEvents(&cfg, leaked, tool.Name, "probe:baseline",
				"benign", baselineResult.SearchableText())...)
		}

		baseline = c.Stderr() // after the benign call: this is "normal"

		for _, pr := range probes {
			for _, p := range pr.Payloads() {
				select {
				case <-ctx.Done():
					scenario.Outcome = assessment.OutcomeTimeout
					scenario.Reason = ctx.Err().Error()
					scenarios = append(scenarios, scenario)
					for _, pending := range tools[i+1:] {
						scenarios = append(scenarios, assessment.ScenarioResult{
							ID:       scenariodef.MCPToolID(pending.Name),
							Required: true,
							Outcome:  assessment.OutcomeSkipped,
							Reason:   "scan cancelled before scenario started",
						})
					}
					return Result{Events: events, Scenarios: scenarios}
				default:
				}

				before := c.Stderr()
				result, err := c.Call(ctx, tool.Name, argsFor(params, p.Value))
				after := c.Stderr()

				probeEvents := pr.Evaluate(ctx, tool.Name, p, result, err, before, after, baseline)
				events = append(events, probeEvents...)

				if err == nil {
					events = append(events, leakEvents(&cfg, leaked, tool.Name,
						"probe:"+string(p.Category), clip(p.Value, 80),
						result.SearchableText())...)
				}

				if ctx.Err() != nil {
					scenario.Outcome = assessment.OutcomeTimeout
					scenario.Reason = ctx.Err().Error()
					break
				}
			}
			if scenario.Outcome == assessment.OutcomeTimeout {
				break
			}
		}

		if hasFinding(events[eventStart:]) {
			scenario.Outcome = assessment.OutcomeFinding
			scenario.Reason = "one or more probe findings were observed"
		} else if scenario.Outcome == "" {
			scenario.Outcome = assessment.OutcomePass
		}
		scenarios = append(scenarios, scenario)
	}

	if ev, sc, ok := decoySummary(&cfg, leaked); ok {
		events = append(events, ev)
		scenarios = append(scenarios, sc)
	}

	return Result{Events: events, Scenarios: scenarios}
}

// decoySummary states what the credential check actually proved.
//
// Without it a clean scan says only "no findings", which is the weakest
// possible claim and indistinguishable from a check that never ran. With it the
// scan asserts something bounded and checkable: this many real credentials were
// planted where a thief would look, the target was exercised, and none of them
// came back. That is the strongest honest thing a scanner can say, and it is
// only honest because the same report also states what was not covered.
func decoySummary(cfg *config, leaked map[string]bool) (trace.Event, assessment.ScenarioResult, bool) {
	if cfg.decoy == nil || len(cfg.decoy.Tokens) == 0 {
		return trace.Event{}, assessment.ScenarioResult{}, false
	}

	seen := map[string]bool{}
	for key := range leaked {
		if i := strings.LastIndex(key, "|"); i >= 0 {
			seen[key[i+1:]] = true
		}
	}

	planted := len(cfg.decoy.Tokens)
	untouched := cfg.decoy.Untouched(seen)
	returned := planted - len(untouched)

	kinds := make([]string, 0, planted)
	for _, t := range cfg.decoy.Tokens {
		kinds = append(kinds, string(t.Kind))
	}
	sort.Strings(kinds)

	summary := fmt.Sprintf(
		"planted %d credential decoys in the sandbox; none were returned by any tool", planted)
	outcome := assessment.OutcomePass
	if returned > 0 {
		verb := "were"
		if returned == 1 {
			verb = "was"
		}
		summary = fmt.Sprintf(
			"planted %d credential decoys in the sandbox; %d %s returned by a tool",
			planted, returned, verb)
		outcome = assessment.OutcomeFinding
	}

	return trace.Event{
			Kind: trace.KindFile, Severity: trace.SeverityInfo, At: time.Now(),
			Summary: summary, During: "probe", Source: "decoy",
			Detail: map[string]any{
				"planted":  planted,
				"returned": returned,
				"secrets":  strings.Join(kinds, ", "),
			},
		}, assessment.ScenarioResult{
			ID:       "decoy.credential-exfiltration",
			Required: true,
			Outcome:  outcome,
		}, true
}

// encodingPhrase renders how a secret came back, for the evidence line. A
// secret returned base64-encoded was transformed on the way out, which is
// harder to explain away than one returned verbatim.
func encodingPhrase(encoding string) string {
	switch encoding {
	case "plain":
		return "verbatim"
	case "hex":
		return "hex-encoded"
	default:
		return encoding + "-encoded"
	}
}

// StringInputToolCount reports how many tools the current adversarial payload
// set can actually reach. Progress output uses this before claiming probes ran.
func StringInputToolCount(tools []toolinfo.ToolInfo) int {
	count := 0
	for _, tool := range tools {
		if len(stringParams(tool.InputSchema)) > 0 {
			count++
		}
	}
	return count
}

func hasFinding(events []trace.Event) bool {
	for _, event := range events {
		if event.Severity == trace.SeverityCritical ||
			event.Severity == trace.SeverityNotable {
			return true
		}
	}
	return false
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

// leakEvents reports planted secrets found in a tool's response.
//
// The nonce goes in the evidence because that is what makes the finding
// checkable by someone who does not trust the scanner: they can confirm the
// value never existed outside this scan. It is deliberately NOT part of any
// fingerprint — the token changes every run, so including it would make two
// scans of an unchanged target look like two different findings.
func leakEvents(cfg *config, seen map[string]bool, tool, during, stimulus, response string) []trace.Event {
	if cfg.decoy == nil || response == "" {
		return nil
	}

	var events []trace.Event
	for _, hit := range cfg.decoy.Match(response) {
		key := tool + "|" + hit.Token.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		events = append(events, trace.Event{
			Kind: trace.KindFile, Severity: trace.SeverityCritical, At: time.Now(),
			Summary: fmt.Sprintf("tool %q returned the contents of %s", tool, hit.Token.Path),
			During:  during, Source: "decoy",
			Detail: map[string]any{
				"tool":   tool,
				"secret": string(hit.Token.Kind),
				"path":   hit.Token.Path,
				// The renderers print "evidence", so the nonce has to live
				// there to be seen. A finding whose proof is buried in a field
				// nobody displays is a finding the reader has to take on trust,
				// which is the opposite of the point.
				"evidence": fmt.Sprintf("planted secret %s returned %s (nonce %s)",
					hit.Token.Path, encodingPhrase(hit.Encoding), hit.Token.Value),
				"encoding": hit.Encoding,
				"stimulus": stimulus,
				"nonce":    hit.Token.Value,
			},
		})
	}
	return events
}
