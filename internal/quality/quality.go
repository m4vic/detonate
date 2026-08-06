// Package quality reports what a target costs and how well it is designed.
//
// This is the half of the answer security analysis does not give. A tool can
// be perfectly safe and still be badly built: descriptions an agent cannot
// choose between, schemas nobody can fill in correctly, or a tool list so
// verbose it burns thousands of tokens of the user's context on every single
// request, forever, in every conversation.
//
// Nothing here is a security finding, and nothing here may change a scan's
// exit code. Mixing "this description is vague" into the same verdict as
// "this tool returned /etc/passwd" would destroy the signal that makes the
// security result worth reading, and a style suggestion that fails a CI
// pipeline is a style suggestion nobody keeps enabled.
//
// It is also entirely static. No container, no execution, no network — which
// is what lets it run in under a second on a machine with no Docker at all.
package quality

import (
	"strings"
	"unicode"
)

// Level is how much a design note matters.
//
// Two levels, not five. A note the reader cannot act on differently is a note
// that did not need its own severity, and a scale with more rungs than the
// reader has responses is how a report becomes wallpaper.
type Level string

const (
	// LevelSuggestion is worth doing. Nothing breaks if it is ignored.
	LevelSuggestion Level = "suggestion"

	// LevelWarning is a design fault an agent will actually trip over —
	// a tool it cannot choose correctly, or arguments it cannot supply.
	LevelWarning Level = "warning"
)

// Note is one observation about how a target is built.
type Note struct {
	Level Level `json:"level"`

	// Subject names what the note is about: a tool name, a file. Empty when
	// the note is about the target as a whole.
	Subject string `json:"subject,omitempty"`

	// Summary is the finding. Detail is the fix, when there is an obvious
	// one — a note that only says what is wrong makes the reader do the
	// second half of the work.
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

// CostItem is the context price of one component.
type CostItem struct {
	Name   string `json:"name"`
	Tokens int    `json:"tokens"`
}

// Cost is what having this target installed costs in context.
//
// The number that matters is Total: for an MCP server every tool description
// is injected into the model's context on every request, whether or not any
// tool is used. A server nobody calls is still charged for.
type Cost struct {
	// Total is the whole surface, in estimated tokens.
	Total int `json:"total_tokens"`

	// Unit names what Total is charged per, so the number can be read
	// without knowing how the target is loaded.
	Unit string `json:"unit"`

	// Items is the breakdown, heaviest first, so the one thing worth
	// rewriting is the first thing read.
	Items []CostItem `json:"items,omitempty"`
}

// Report is the non-security view of one target.
type Report struct {
	Design []Note `json:"design,omitempty"`
	Cost   Cost   `json:"cost"`
}

// Warnings counts the notes that describe a fault rather than a preference,
// so a caller can offer to gate on them without inspecting every note.
func (r Report) Warnings() int {
	n := 0
	for _, note := range r.Design {
		if note.Level == LevelWarning {
			n++
		}
	}
	return n
}

// EstimateTokens approximates how many tokens a string occupies.
//
// Deliberately an estimate, and labelled as one everywhere it is shown. Exact
// counts need a model-specific BPE table that drifts between model versions,
// and the extra precision would not change a single decision: the reader is
// deciding whether a description is too long, not reconciling a bill.
//
// The heuristic is the usual one — roughly four characters per token for
// English prose — with a floor of one token per whitespace-separated word,
// because short words tokenize closer to one-to-one than the character ratio
// suggests and the ratio alone under-counts terse text.
func EstimateTokens(s string) int {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0
	}

	words := len(strings.FieldsFunc(trimmed, unicode.IsSpace))
	byChars := (len(trimmed) + 3) / 4

	if words > byChars {
		return words
	}
	return byChars
}
