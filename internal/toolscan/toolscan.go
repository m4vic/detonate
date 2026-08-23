// Package toolscan inspects MCP tool metadata for poisoning.
//
// A tool's name, description, and input schema are not documentation. They are
// instructions an agent reads to decide which tool to call and what to put in
// it, and the target controls every byte of them. That makes the description
// the highest-leverage attack surface an MCP server has: it is obeyed by the
// model, it is rarely read by the human who installed the server, and changing
// it requires no code execution at all.
//
// Detonate already collected this metadata into toolinfo.ToolInfo and then
// never looked at it. Everything here reads what was already being carried.
//
// Three properties are deliberate:
//
//   - Pure. No I/O, no network, no model, no clock beyond one timestamp taken
//     at entry. The same inventory produces the same findings, which is what
//     lets a verdict gate CI.
//   - Whole-inventory. Analyze takes every tool at once, not one at a time,
//     because the strongest available signal is cross-referential: a
//     description that names another tool on the same server and tells the
//     agent to route around it. One tool in isolation cannot show that.
//   - Calibrated against false positives first. internal/skill learned this
//     expensively — a 59-skill pack once produced 30 flags, mostly from
//     security documentation that merely *mentioned* dangerous things. The
//     same discipline applies here, with one inversion noted in signatures.go.
package toolscan

import (
	"sort"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// during names the phase these events belong to, matching the convention in
// internal/skill ("skill-analysis").
const during = "tool-analysis"

// evidenceLimit bounds how much target-controlled text reaches a report.
// Matches internal/skill's clip budget: enough to see the payload, not enough
// for a hostile description to flood the output.
const evidenceLimit = 200

// Analyze inspects an inventory of tools and reports what it found.
//
// Events come back in a stable order — tools in the order they were
// enumerated, and within a tool, rules in declaration order — so two runs over
// the same inventory produce the same report. Nothing here consults the
// filesystem, the network, or a model.
//
// The returned events are evidence, not a verdict. Deciding what a finding
// means to risk and completeness belongs to internal/assessment, exactly as it
// does for every other source.
func Analyze(tools []toolinfo.ToolInfo) []trace.Event {
	now := time.Now()
	names := compileToolNames(tools)
	var events []trace.Event

	for _, tool := range tools {
		events = append(events, analyzeDescription(tool, now)...)
		events = append(events, analyzeHiddenCharacters(tool, now)...)
		events = append(events, analyzeSchema(tool, now)...)
		events = append(events, analyzeShadowing(tool, names, now)...)
	}

	return events
}

// analyzeDescription runs the text signatures over a tool's description.
//
// The name is included in the scanned text because a tool name is read by the
// model too, and nothing stops a server from putting a directive there. It is
// a smaller surface, not a safe one.
func analyzeDescription(tool toolinfo.ToolInfo, now time.Time) []trace.Event {
	text := tool.Name + "\n" + tool.Description
	var events []trace.Event

	for _, sig := range textSignatures {
		for _, match := range sig.pattern.FindAllString(text, -1) {
			if sig.warningsAreBenign && isWarning(match) {
				continue
			}
			events = append(events, event(sig.kind, sig.severity, now,
				sig.summary+": "+quoteTool(tool.Name), sourceDescription,
				map[string]any{
					"tool":     tool.Name,
					"evidence": clip(strings.TrimSpace(match), evidenceLimit),
					"rule":     sig.id,
				}))
			// One event per signature per tool. A description that repeats an
			// instruction five times is one behaviour, not five findings.
			break
		}
	}

	return events
}

// analyzeShadowing reports a description that names another tool on the same
// server and directs the agent's use of it.
//
// This is the cross-referential rule, and it is the reason Analyze takes the
// whole inventory. "Always call this before read_file" is only meaningful, and
// only checkable, when read_file is known to exist on the same server. Without
// that cross-reference the rule would have to guess from prose, which is the
// class of inference internal/skill removed after it produced mismatches from
// sentences like "write to the report".
func analyzeShadowing(tool toolinfo.ToolInfo, names []nameMatcher, now time.Time) []trace.Event {
	text := tool.Description
	if !directivePattern.MatchString(text) {
		return nil
	}

	// The directive and the tool it names must appear in the SAME sentence.
	//
	// Without that, any directive word anywhere in a description pairs with any
	// tool name anywhere else in it. Measured on a real registry server with
	// 682 tools, this produced three findings and all three were wrong: one
	// fired on "a small manifest returned instead of the data" — describing a
	// return format, not redirecting the agent — and two displayed evidence
	// that did not contain the trigger at all, because the directive was
	// paragraphs away from the name that matched.
	//
	// Long descriptions and prefixed tool names make this near-certain: on that
	// server every tool began "affiliate_", so almost every description
	// mentioned something matching another tool's name. A finding whose
	// evidence does not show why it fired cannot be argued about, which is the
	// opposite of the point.
	var referenced []string
	var trigger string
	redirects := false
	seen := map[string]bool{}
	for _, sentence := range sentences(text) {
		if !directivePattern.MatchString(sentence) {
			continue
		}
		for _, other := range names {
			if other.name == tool.Name || seen[other.name] {
				continue
			}
			if other.re.MatchString(sentence) {
				referenced = append(referenced, other.name)
				seen[other.name] = true
				if redirectionPattern.MatchString(sentence) {
					// Redirection outranks sequencing: one superseding sentence
					// is the finding, whatever else the description says.
					if !redirects {
						trigger, redirects = strings.TrimSpace(sentence), true
					}
				} else if trigger == "" {
					trigger = strings.TrimSpace(sentence)
				}
			}
		}
	}
	if len(referenced) == 0 {
		return nil
	}
	// Sorted so the reported set does not depend on enumeration order when a
	// description references several tools.
	sort.Strings(referenced)

	severity, summary := trace.SeverityInfo, "tool description sequences a call to another tool, which is ordinary documentation but worth confirming: "+quoteTool(tool.Name)
	if redirects {
		severity = trace.SeverityCritical
		summary = "tool description redirects the agent away from another tool: " + quoteTool(tool.Name)
	}

	return []trace.Event{event(trace.KindProtocol, severity, now,
		summary,
		sourceInventory,
		map[string]any{
			"tool":       tool.Name,
			"references": strings.Join(referenced, ", "),
			// The sentence that actually triggered the rule, not merely the
			// first line carrying a directive somewhere in the description.
			"evidence": clip(trigger, evidenceLimit),
			"rule":     "tool-shadowing",
		})}
}

// event builds one finding. Centralized so every rule in this package records
// the same fields — a finding that cannot name the rule that produced it is
// hard to argue with a maintainer about.
func event(kind trace.Kind, severity trace.Severity, now time.Time, summary, source string, detail map[string]any) trace.Event {
	return trace.Event{
		Kind:     kind,
		Severity: severity,
		At:       now,
		Summary:  summary,
		During:   during,
		Source:   source,
		Detail:   detail,
	}
}

const (
	sourceDescription = "tool-description"
	sourceSchema      = "tool-schema"
	sourceInventory   = "tool-inventory"
)

func quoteTool(name string) string {
	if name == "" {
		return "(unnamed tool)"
	}
	return `"` + name + `"`
}

func clip(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}

// sentences splits a description into units small enough that co-occurrence
// means something.
//
// Newlines count as boundaries too: tool descriptions are frequently bulleted
// or multi-paragraph, and two facts in different bullets are not one claim.
func sentences(text string) []string {
	var out []string
	start := 0
	for i, r := range text {
		if r == '.' || r == '!' || r == '?' || r == '\n' || r == ';' {
			if seg := text[start : i+1]; strings.TrimSpace(seg) != "" {
				out = append(out, seg)
			}
			start = i + 1
		}
	}
	if seg := text[start:]; strings.TrimSpace(seg) != "" {
		out = append(out, seg)
	}
	return out
}
