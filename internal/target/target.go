// Package target models what detonate scans.
//
// v1 supports two input kinds, and both execute, so both flow through the same
// sandbox detonation pipeline:
//
//   - mcp   : an MCP server launched over stdio (a command to run)
//   - skill : an agent skill directory (a SKILL.md plus bundled scripts)
//
// Modelling the input as one small type with a Kind keeps the rest of the
// pipeline (sandbox, driver, probe, verdict) input-agnostic: it detonates a
// Target and doesn't care which flavour beyond the few points where they
// genuinely differ. New executable kinds (plugins, etc.) slot in here later
// without touching the pipeline.
//
// Text-only inputs (raw prompts) are deliberately NOT modelled here. They need
// no sandbox, so they belong to a separate static path, deferred to phase 2.
package target

import (
	"fmt"
	"path/filepath"
)

type Kind string

const (
	KindMCP   Kind = "mcp"
	KindSkill Kind = "skill"
)

// Target is a single thing to detonate.
type Target struct {
	Kind Kind

	// Reference is the command that launches the server (KindMCP) or the path
	// to the skill directory (KindSkill).
	Reference string
}

// Label is a short human description for logs and reports.
func (t Target) Label() string {
	return fmt.Sprintf("%s:%s", t.Kind, t.Reference)
}

// MCP builds a target from the command that launches a server over stdio.
func MCP(command string) Target {
	return Target{Kind: KindMCP, Reference: command}
}

// Skill builds a target from a skill directory path.
//
// The path is made absolute up front so every later stage gets an unambiguous
// reference: a report that says "./skill" is useless once you no longer know
// which working directory the scan ran in.
func Skill(path string) (Target, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Target{}, fmt.Errorf("resolving skill path %q: %w", path, err)
	}
	return Target{Kind: KindSkill, Reference: abs}, nil
}
