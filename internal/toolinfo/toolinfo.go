// Package toolinfo defines the shape both drivers (MCP, skill) normalize into.
//
// Everything downstream (probes, monitor, verdict) works against ToolInfo, not
// against the MCP SDK's types or a SKILL.md's raw frontmatter. That keeps the
// pipeline input-agnostic: a probe doesn't need to know whether a tool came
// from an MCP server or a skill's bundled script, only that it has a name, a
// description (the thing an attacker poisons), and enough detail to invoke it.
package toolinfo

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Source says which kind of target a tool was discovered on.
type Source string

const (
	SourceMCP   Source = "mcp"
	SourceSkill Source = "skill"
)

// ToolInfo is one invokable capability discovered on a Target.
type ToolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Source      Source `json:"source"`

	// InputSchema is kept as raw JSON rather than the MCP SDK's schema type.
	// Storing the SDK type here would leak the SDK into every downstream
	// package and defeat the point of normalizing. Raw JSON serializes
	// straight into reports, and a probe can unmarshal only what it needs.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`

	// Metadata is free-form detail a later stage MAY use (a skill's script
	// path, the command that launched a server). Never required for basic
	// enumeration, so it stays untyped rather than growing a field per kind.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// maxDescLen is how much description we show in one-line CLI output before
// truncating. Long descriptions are exactly where injection payloads hide, so
// the full text always survives in the struct; only this display is clipped.
const maxDescLen = 80

func (t ToolInfo) String() string {
	desc := strings.Join(strings.Fields(t.Description), " ")

	// Count in runes, not bytes: slicing a UTF-8 string by byte offset can cut
	// a multi-byte character in half and emit a broken rune.
	if r := []rune(desc); len(r) > maxDescLen {
		desc = string(r[:maxDescLen-3]) + "..."
	}
	return fmt.Sprintf("[%s] %s: %s", t.Source, t.Name, desc)
}
