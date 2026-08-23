package toolscan

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Hidden characters in tool metadata.
//
// This is the rule that most justifies reading descriptions at all, because the
// payload is invisible to the person reviewing the server. Three families
// matter, in descending order of how conclusive they are:
//
//   - Unicode tag characters (U+E0000–U+E007F). The block carries a complete
//     shadow ASCII alphabet: U+E0041 renders as nothing and means "A". A
//     description can therefore contain instructions that a model reads and a
//     human literally cannot see. There is no legitimate use of this block in a
//     tool description, so the finding is critical and the hidden text is
//     decoded into the evidence — the whole point is to make it visible.
//   - Bidirectional overrides (U+202A–U+202E, U+2066–U+2069). The Trojan Source
//     technique: reorder how text displays without changing what is parsed, so
//     the rendered description says something other than the bytes do.
//   - Zero-width characters. Weaker, because U+200D legitimately joins emoji
//     sequences, so it is reported as notable rather than critical and ZWJ is
//     only counted when it sits next to ASCII rather than inside an emoji.

const (
	tagBlockStart = 0xE0000
	tagBlockEnd   = 0xE007F

	// tagASCIIOffset converts a tag character back to the ASCII it shadows:
	// U+E0020 is space, U+E007E is '~'.
	tagASCIIOffset = 0xE0000
)

// zeroWidth are the invisible characters that carry no formatting meaning in a
// plain tool description.
var zeroWidth = map[rune]string{
	0x200B: "ZERO WIDTH SPACE",
	0x200C: "ZERO WIDTH NON-JOINER",
	0x200D: "ZERO WIDTH JOINER",
	0x2060: "WORD JOINER",
	0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
}

// bidiControls reorder rendered text without changing the underlying bytes.
var bidiControls = map[rune]string{
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
}

// analyzeHiddenCharacters inspects every target-controlled string on a tool.
func analyzeHiddenCharacters(tool toolinfo.ToolInfo, now time.Time) []trace.Event {
	var events []trace.Event
	for _, field := range []struct{ label, text string }{
		{"name", tool.Name},
		{"description", tool.Description},
	} {
		events = append(events, hiddenCharacterEvents(tool.Name, field.label, field.text, now)...)
	}
	return events
}

// hiddenCharacterEvents reports the invisible content of one field.
func hiddenCharacterEvents(toolName, field, text string, now time.Time) []trace.Event {
	if text == "" {
		return nil
	}

	var (
		events  []trace.Event
		tags    []rune
		bidi    = map[rune]int{}
		invisib = map[rune]int{}
	)

	runes := []rune(text)
	for i, r := range runes {
		switch {
		case r >= tagBlockStart && r <= tagBlockEnd:
			tags = append(tags, r)
		case bidiControls[r] != "":
			bidi[r]++
		case zeroWidth[r] != "":
			// A zero-width joiner between two non-ASCII runes is almost
			// certainly building an emoji sequence, not hiding anything.
			if r == 0x200D && !adjacentToASCII(runes, i) {
				continue
			}
			invisib[r]++
		}
	}

	if len(tags) > 0 {
		detail := map[string]any{
			"tool":  toolName,
			"field": field,
			"count": len(tags),
			"rule":  "unicode-tag-smuggling",
		}
		// Decoding is the point: an invisible instruction that stays invisible
		// in the report has only moved the problem.
		if decoded := decodeTags(tags); decoded != "" {
			detail["decoded"] = clip(decoded, evidenceLimit)
		}
		events = append(events, event(trace.KindProtocol, trace.SeverityCritical, now,
			"tool "+field+" contains invisible Unicode tag characters: "+quoteTool(toolName),
			sourceDescription, detail))
	}

	if len(bidi) > 0 {
		events = append(events, event(trace.KindProtocol, trace.SeverityCritical, now,
			"tool "+field+" contains bidirectional override characters: "+quoteTool(toolName),
			sourceDescription, map[string]any{
				"tool":       toolName,
				"field":      field,
				"characters": describeRunes(bidi, bidiControls),
				"rule":       "unicode-bidi-override",
			}))
	}

	if len(invisib) > 0 {
		events = append(events, event(trace.KindProtocol, trace.SeverityNotable, now,
			"tool "+field+" contains zero-width characters: "+quoteTool(toolName),
			sourceDescription, map[string]any{
				"tool":       toolName,
				"field":      field,
				"characters": describeRunes(invisib, zeroWidth),
				"rule":       "unicode-zero-width",
			}))
	}

	return events
}

// adjacentToASCII reports whether either neighbour of runes[i] is ASCII, which
// separates a joiner hiding inside prose from one building an emoji.
func adjacentToASCII(runes []rune, i int) bool {
	if i > 0 && runes[i-1] < unicode.MaxASCII {
		return true
	}
	if i+1 < len(runes) && runes[i+1] < unicode.MaxASCII {
		return true
	}
	return false
}

// decodeTags turns tag characters back into the ASCII they shadow.
func decodeTags(tags []rune) string {
	var out strings.Builder
	for _, r := range tags {
		decoded := r - tagASCIIOffset
		if decoded >= 0x20 && decoded <= 0x7E {
			out.WriteRune(decoded)
		}
	}
	return out.String()
}

// describeRunes renders a rune tally deterministically: sorted by code point,
// named, with counts. Map iteration order is random in Go, so an unsorted
// version would produce a different report on every run of the same scan.
func describeRunes(counts map[rune]int, names map[rune]string) string {
	points := make([]rune, 0, len(counts))
	for r := range counts {
		points = append(points, r)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })

	parts := make([]string, 0, len(points))
	for _, r := range points {
		parts = append(parts, fmt.Sprintf("U+%04X %s (x%d)", r, names[r], counts[r]))
	}
	return strings.Join(parts, ", ")
}
