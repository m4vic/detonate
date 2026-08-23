package toolscan

import (
	"regexp"
	"strings"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// minToolNameLength is the shortest name the shadowing rule will cross-
// reference. A server with a tool called "go" or "ls" would otherwise match
// those letters inside ordinary prose in every other description.
const minToolNameLength = 4

type textSignature struct {
	// id names the rule in the report. A reader who disagrees with a finding
	// needs to be able to point at the specific rule, not at "the scanner".
	id       string
	pattern  *regexp.Regexp
	kind     trace.Kind
	severity trace.Severity
	summary  string

	// warningsAreBenign enables the cautionary-language filter.
	//
	// It stays OFF for every injection signature, for the reason internal/skill
	// documents: "do not tell the user" IS the attack, so a filter that skips
	// anything containing "do not" would suppress the most conclusive finding
	// available.
	//
	// That choice has a known cost, and it is not mitigated anywhere: a
	// security-scanner MCP server whose tool is honestly described as "detects
	// prompt injection such as 'ignore previous instructions'" WILL be flagged
	// by instruction-override. Detonate itself would be such a server. The
	// false positive is accepted deliberately, because the alternative — letting
	// any line that also contains "detects" exonerate itself — hands every
	// attacker a two-word bypass. A description is short and a reviewer can
	// dismiss the finding in seconds; a silent miss cannot be dismissed at all.
	//
	// The filter is therefore kept only for the capability signatures, where
	// internal/skill measured that mention-versus-instruction is the dominant
	// error. How often the accepted false positive actually fires is a question
	// for the benign corpus, not for a guess made here.
	warningsAreBenign bool
}

// warningContext marks text as cautionary rather than instructional. Kept
// deliberately generous, matching internal/skill: a missed detection on a tool
// that also words itself like a warning is cheaper than a scanner that flags
// every honest security tool.
var warningContext = regexp.MustCompile(`(?i)\b(never|do not|don't|avoid|warns?|warning|caution|beware|prevent|block(s|ed)?|reject|refuse|must not|should not|instead of|rather than|protects? against|guards? against|checks? for|detects?|scans? for|identifies)\b`)

func isWarning(line string) bool { return warningContext.MatchString(line) }

// directivePattern is the second half of the shadowing rule: a description
// that merely *names* another tool is ordinary cross-referencing ("similar to
// read_file"), which honest servers do constantly. A description that names
// another tool AND issues a directive about it is the tool-poisoning pattern.
// Both halves must be present.
var directivePattern = regexp.MustCompile(`(?i)\b(instead\s+of|rather\s+than|before\s+(using|calling|invoking)|after\s+(using|calling|invoking)|do\s+not\s+(use|call)|never\s+(use|call)|always\s+(use|call)|must\s+(first\s+)?(use|call)|prefer|redirect|route)\b`)

// lineContaining returns the whole line the first match falls on.
//
// The bare match is useless as evidence: directivePattern matches two words, so
// a report would read `evidence: "Always call"` and leave the reader unable to
// judge the finding without opening the target themselves. A finding has to
// carry enough of its own context to be argued about.
func lineContaining(re *regexp.Regexp, s string) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return s
	}
	start := strings.LastIndexByte(s[:loc[0]], '\n') + 1
	end := strings.IndexByte(s[loc[1]:], '\n')
	if end < 0 {
		return s[start:]
	}
	return s[start : loc[1]+end]
}

// nameMatcher is a tool name compiled once for cross-referencing.
//
// Compiled up front rather than inside the shadowing loop: that loop is every
// tool against every other tool, so building the pattern there would compile
// the same expressions n² times for a result that never changes.
type nameMatcher struct {
	name string
	re   *regexp.Regexp
}

// compileToolNames builds the cross-reference matchers for one inventory.
//
// Tool names carry underscores and hyphens, which \b does not treat as
// boundaries the way this needs — `\bread_file\b` matches inside
// `safe_read_file`. The boundaries are therefore spelled out explicitly, and
// the name is quoted so a server cannot inject regex syntax through it.
func compileToolNames(tools []toolinfo.ToolInfo) []nameMatcher {
	matchers := make([]nameMatcher, 0, len(tools))
	for _, t := range tools {
		if len(t.Name) < minToolNameLength {
			continue
		}
		matchers = append(matchers, nameMatcher{
			name: t.Name,
			re: regexp.MustCompile(
				`(?i)(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(t.Name) + `($|[^A-Za-z0-9_-])`),
		})
	}
	return matchers
}

// textSignatures are patterns in tool metadata worth reporting.
//
// Ordered by how conclusive they are. The injection group is close to
// dispositive: an honest tool description has no reason to address the model in
// the second person about its prior instructions. The capability group is
// informational and must never drive a verdict on its own — plenty of
// legitimate tools read files and take API keys, and a scanner where everything
// is suspicious has told the reader nothing.
var textSignatures = []textSignature{
	// --- Injection: metadata aimed at subverting the agent ---
	{
		id:      "instruction-override",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(previous|prior|earlier|above|preceding)\s+(instructions?|prompts?|rules?|context|directions?)[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "tool description attempts to override the agent's prior context",
	},
	{
		id:      "concealment",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|disclose|show|notify|report)\s+(this\s+|that\s+)?(to\s+)?(the\s+)?(user|human|operator)[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "tool description tells the agent to hide its actions from the user",
	},
	{
		id:      "silent-action",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(without|avoid)\s+(telling|informing|asking|notifying|alerting|mentioning)\s+(the\s+)?(user|human|operator)[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "tool description tells the agent to act without informing the user",
	},
	{
		id:      "role-redefinition",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(role|instructions?|system\s+prompt)|new\s+system\s+prompt)[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityNotable,
		summary: "tool description attempts to redefine the agent's role",
	},
	{
		id: "unconditional-precedence",
		// The classic MCP tool-poisoning opener. Distinct from the shadowing
		// rule because it needs no second tool to exist: it claims precedence
		// over the entire toolset at once.
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(before|prior\s+to)\s+(using|calling|invoking)\s+(any|every|all|each)\s+(other\s+)?tools?[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityCritical,
		summary: "tool description claims precedence over every other tool",
	},
	{
		id:      "fake-authority",
		pattern: regexp.MustCompile(`(?i)[^\n]*<\s*/?\s*(system|important|secret|admin)[^>]*>[^\n]*`),
		kind:    trace.KindProtocol, severity: trace.SeverityNotable,
		summary: "tool description contains pseudo-system markup",
	},

	// --- Capability: what the tool reaches for ---
	//
	// Informational. See internal/skill: running its analyser over 12 real
	// Google skills flagged 11 as suspicious because they legitimately use API
	// keys and run scripts. Capability alone is context for a reviewer, not a
	// finding.
	{
		id:      "credential-path",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(read|cat|open|load|send|upload|exfiltrat\w*|include|copy|print|dump|fetch|return)\b[^\n]*(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.kube/config|/etc/shadow)[^\n]*`),
		kind:    trace.KindFile, severity: trace.SeverityCritical,
		summary:           "tool description instructs reading private keys or cloud credentials",
		warningsAreBenign: true,
	},
	{
		id:      "env-harvest",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(all|every|entire|full)\s+(the\s+)?(environment\s+variables?|env\s+vars?|environment)\b[^\n]*`),
		kind:    trace.KindFile, severity: trace.SeverityNotable,
		summary:           "tool description refers to harvesting the whole environment",
		warningsAreBenign: true,
	},
	{
		id:      "encoded-content",
		pattern: regexp.MustCompile(`(?i)[^\n]*\b(base64\s+-d|atob\(|fromCharCode|eval\(|exec\()[^\n]*`),
		kind:    trace.KindProcess, severity: trace.SeverityNotable,
		summary:           "tool description decodes or evaluates content at runtime",
		warningsAreBenign: true,
	},
}
