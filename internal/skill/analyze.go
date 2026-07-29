package skill

import (
	"regexp"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/trace"
)

// Skill analysis: reading the instructions, not just the frontmatter.
//
// A skill is mostly a large prompt. Its SKILL.md body is text an agent reads
// and obeys, so the body IS the attack surface — which makes skills a
// different problem from MCP servers, where the danger is code that executes.
//
// This is not the "static manifest scanning" that other tools already do. That
// reads a declared tool list and pattern-matches descriptions. This reads the
// instructions an agent will follow and asks two questions no scanner
// currently asks:
//
//  1. Do these instructions try to manipulate the agent (injection), or reach
//     for things a skill has no business reaching for (credentials, keys)?
//  2. Do the declared permissions match what the skill actually does? A skill
//     that declares allowed-tools: [Read] and then tells the agent to run
//     shell commands has a permission boundary that means nothing.
//
// The second is the valuable one, and it is the same "declared versus actual"
// idea that makes the MCP side work.

// AnalyzePrompt runs the instruction analysis over arbitrary text.
//
// A skill's body IS a prompt, so the same signatures apply to a raw prompt
// file, a system prompt, an agent config, or a README that an agent is going
// to read. The only thing that changes is that there are no declared
// permissions to compare against, so the permission check is skipped.
//
// This is the cheapest useful surface detonate has: injected instructions look
// the same wherever they are hiding.
func AnalyzePrompt(text string) []trace.Event {
	return Analyze(Skill{Name: "prompt", Body: text, skipPermissions: true})
}

// Analyze inspects a skill's instructions and permissions.
func Analyze(sk Skill) []trace.Event {
	var events []trace.Event
	now := time.Now()

	body := sk.Body
	for _, sig := range textSignatures {
		for _, m := range sig.pattern.FindAllString(body, -1) {
			// Skip lines that warn against the thing rather than instruct it.
			//
			// This was the largest source of false positives, and it was
			// measured: scanning a real 59-skill pack flagged 30 of them, and
			// the top hits were a skill that "warns before rm -rf" and one
			// telling the user not to commit private keys. Security
			// documentation talks about dangerous things constantly. Matching
			// the mention rather than the instruction makes the careful skills
			// look the worst, which is exactly backwards.
			if sig.warningsAreBenign && isWarning(m) {
				continue
			}
			events = append(events, trace.Event{
				Kind: sig.kind, Severity: sig.severity, At: now,
				Summary: sig.summary, During: "skill-analysis", Source: "skill-instructions",
				Detail: map[string]any{"evidence": clip(strings.TrimSpace(m), 200)},
			})
			break // one event per signature; a repeated pattern is one behaviour
		}
	}

	if !sk.skipPermissions {
		events = append(events, checkPermissions(sk, now)...)
	}
	return events
}

// Skill is a parsed skill: its declared permissions plus the instructions an
// agent will actually read.
type Skill struct {
	Name         string
	Description  string
	AllowedTools []string
	Body         string
	Scripts      []string

	// skipPermissions suppresses the declared-versus-actual check for inputs
	// that make no declaration, such as a raw prompt file. Reporting "declares
	// no allowed-tools" for something that was never a skill would be noise.
	skipPermissions bool
}

// warningContext marks a line as cautionary rather than instructional.
//
// Deliberately generous: a missed detection on a skill that also words itself
// like a warning is a much cheaper mistake than a scanner that flags every
// piece of careful security documentation. The rest of the analysis still
// applies to the same skill.
var warningContext = regexp.MustCompile(`(?i)\b(never|do not|don't|avoid|warns?|warning|caution|beware|prevent|block(s|ed)?|reject|refuse|must not|should not|instead of|rather than|protects? against|guard(s)? against|check(s)? for|detect(s)?)\b`)

// isWarning reports whether a matched line is telling the reader NOT to do the
// thing, rather than telling the agent to do it.
func isWarning(line string) bool {
	return warningContext.MatchString(line)
}

type textSignature struct {
	pattern  *regexp.Regexp
	kind     trace.Kind
	severity trace.Severity
	summary  string

	// warningsAreBenign enables the cautionary-language filter for this
	// signature.
	//
	// It must stay OFF for injection patterns. "Do not tell the user" is
	// itself the attack, so a filter that skips anything containing "do not"
	// would suppress the single most conclusive finding available — our own
	// test caught exactly that. Warning language only exonerates a CAPABILITY
	// mention: "never commit private keys" is advice, "read ~/.ssh/id_rsa" is
	// not.
	warningsAreBenign bool
}

// textSignatures are patterns in a skill's instructions worth reporting.
//
// Two categories, and the distinction matters for how a reader should treat
// them. Injection patterns are close to conclusive: honest documentation has
// no reason to tell an agent to conceal its actions. Capability patterns
// (shell, credentials) are informational — plenty of legitimate skills need
// them — but a reviewer must be told, because a malicious skill and an honest
// one look identical until you read what they reach for.
var textSignatures = []textSignature{
	// --- Injection: instructions aimed at subverting the agent ---
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|rules?|context)[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "instructions attempt to override the agent's prior context",
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|disclose|show|notify)\s+(this\s+)?(to\s+)?the\s+user[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "instructions tell the agent to hide its actions from the user",
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(without|avoid)\s+(telling|informing|asking|notifying|alerting)\s+(the\s+)?user[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "instructions tell the agent to act without informing the user",
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(role|instructions?|system\s+prompt))[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityNotable,
		summary: "instructions attempt to redefine the agent's role",
	},

	// --- Capability: what the skill reaches for ---
	//
	// These are INFORMATIONAL, and the calibration matters more than the
	// patterns. Running the analyser over 12 real Google skills flagged 11 of
	// them "suspicious" — they legitimately use API keys and run scripts,
	// because that is what a database-query skill does. A scanner where
	// almost everything is suspicious has told you nothing and will be turned
	// off, so capability alone must never drive a verdict. It is context a
	// reviewer reads alongside the findings, not a finding itself.
	{
		// Requires an ACTION verb next to the sensitive path. Merely naming
		// one is what security documentation does; reading or sending one is
		// the attack. Without this the pack's own "do not commit private keys"
		// advice scored as a critical finding.
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(read|cat|open|load|send|upload|exfiltrat\w*|include|copy|print|dump|fetch)\b[^\n]*(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.kube/config)[^\n]*`),
		kind:    trace.KindFile, severity: trace.SeverityCritical,
		summary:           "instructions tell the agent to read private keys or cloud credentials",
		warningsAreBenign: true,
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*(~/\.env|\.env\b|API[_ ]KEY|SECRET[_ ]KEY|ACCESS[_ ]TOKEN|password)[^\n]*`),
		kind:    trace.KindFile, severity: trace.SeverityInfo,
		summary:           "instructions reference credentials or secrets",
		warningsAreBenign: true,
	},
	{
		pattern: regexp.MustCompile("(?i)[^\\n]*```(bash|sh|shell|zsh)[^\\n]*"),
		kind:    trace.KindProcess, severity: trace.SeverityInfo,
		summary:           "instructions tell the agent to run shell commands",
		warningsAreBenign: true,
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(curl|wget)\s+[^\n]*https?://[^\n]*`),
		kind:    trace.KindNetwork, severity: trace.SeverityInfo,
		summary:           "instructions fetch something from the network",
		warningsAreBenign: true,
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(curl|wget)[^\n]*\|\s*(bash|sh)[^\n]*`),
		kind:    trace.KindProcess, severity: trace.SeverityCritical,
		summary:           "instructions pipe downloaded content straight into a shell",
		warningsAreBenign: true,
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(rm\s+-rf|mkfs|dd\s+if=|:\(\)\{)[^\n]*`),
		kind:    trace.KindProcess, severity: trace.SeverityCritical,
		summary:           "instructions contain a destructive command",
		warningsAreBenign: true,
	},
	{
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(base64\s+-d|atob\(|fromCharCode|eval\()[^\n]*`),
		kind:    trace.KindProcess, severity: trace.SeverityNotable,
		summary:           "instructions decode or evaluate content at runtime",
		warningsAreBenign: true,
	},
}

// capabilityNeeds maps an observed capability to the tool that grants it.
//
// This is what makes the permission check possible: to say "this skill does X
// but did not declare it", we need to know which declaration would have
// covered X.
// Only Bash, and only from a fenced shell block.
//
// Earlier versions also inferred WebFetch from any mention of curl and Write
// from prose like "save a file". Both were guesses about intent made from
// ordinary English, and both were wrong constantly: a 59-skill pack produced
// 30 flags, most of them permission "mismatches" inferred from sentences like
// "write to the report".
//
// A fenced ```bash block is different in kind. It is not prose that might mean
// something — it is a command the skill is telling the agent to run. That is
// the only capability inference reliable enough to raise a critical finding
// on, so it is the only one left.
var capabilityNeeds = []struct {
	pattern *regexp.Regexp
	tool    string
	doing   string
}{
	{regexp.MustCompile("(?i)```(bash|sh|shell|zsh)"), "Bash", "run shell commands"},
}

// checkPermissions compares what a skill declares against what it does.
//
// This is the check nobody else performs, and it is the strongest signal
// available for a skill. A declared allowed-tools list is a security boundary
// only if it is complete; a skill that declares [Read] and then instructs the
// agent to run shell commands has a boundary that means nothing, and whoever
// approved it on the strength of that declaration was misled.
func checkPermissions(sk Skill, now time.Time) []trace.Event {
	var events []trace.Event

	declared := map[string]bool{}
	for _, t := range sk.AllowedTools {
		declared[strings.ToLower(strings.TrimSpace(t))] = true
	}

	// No declaration at all is its own finding. It is not a violation — the
	// field is optional — but it means the skill runs with whatever the agent
	// already has, so nothing here is constrained.
	if len(sk.AllowedTools) == 0 {
		// Informational, not a finding. allowed-tools is optional, most real
		// skills omit it, and treating a missing optional field as suspicious
		// is what produced an 11-out-of-12 false-positive rate against real
		// published skills.
		//
		// The contrast with a genuine mismatch is the whole point: omitting
		// the field makes no claim, while declaring [Read] and then running
		// shell commands makes a claim that is false. Only the second is a
		// finding.
		summary := "skill declares no allowed-tools; it is unconstrained by its own manifest"
		for _, c := range capabilityNeeds {
			if c.pattern.MatchString(sk.Body) {
				summary = "skill declares no allowed-tools and instructs the agent to " + c.doing
				break
			}
		}
		events = append(events, trace.Event{
			Kind: trace.KindProtocol, Severity: trace.SeverityInfo, At: now,
			Summary: summary, During: "skill-analysis", Source: "skill-permissions",
		})
		return events
	}

	for _, c := range capabilityNeeds {
		if !c.pattern.MatchString(sk.Body) || declared[strings.ToLower(c.tool)] {
			continue
		}
		events = append(events, trace.Event{
			Kind: trace.KindProtocol, Severity: trace.SeverityCritical, At: now,
			Summary: "permission mismatch: skill instructs the agent to " + c.doing +
				" but does not declare " + c.tool,
			During: "skill-analysis", Source: "skill-permissions",
			Detail: map[string]any{
				"declared": strings.Join(sk.AllowedTools, ", "),
				"missing":  c.tool,
			},
		})
	}

	// A bundled script is executable code, and no allowed-tools value covers
	// "runs an arbitrary program" except Bash.
	if len(sk.Scripts) > 0 && !declared["bash"] {
		events = append(events, trace.Event{
			Kind: trace.KindProcess, Severity: trace.SeverityCritical, At: now,
			Summary: "skill ships executable scripts but does not declare Bash",
			During:  "skill-analysis", Source: "skill-permissions",
			Detail: map[string]any{
				"scripts":  strings.Join(sk.Scripts, ", "),
				"declared": strings.Join(sk.AllowedTools, ", "),
			},
		})
	}

	return events
}

func clip(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}
