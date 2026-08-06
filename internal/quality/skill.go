package quality

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Thresholds for a skill's instruction body.
//
// A skill is loaded whole when it triggers, so its body is a single charge
// rather than a per-request one. The bound is therefore looser than a tool
// description's, and the concern is different: not what it costs on every
// turn, but whether it is short enough to be followed reliably.
const (
	shortSkillDescriptionTokens = 8
	largeSkillBodyTokens        = 2000
)

// SkillInput is what the skill lens needs, kept as plain fields so this
// package does not depend on the skill package and cannot pull its analysis
// into a quality report by accident.
type SkillInput struct {
	Name         string
	Description  string
	AllowedTools []string
	Body         string
	Scripts      []string
}

// AnalyzeSkill reports how a skill is built and what loading it costs.
func AnalyzeSkill(sk SkillInput) Report {
	report := Report{
		Cost: Cost{Unit: "per invocation (SKILL.md is loaded when the skill triggers)"},
	}

	bodyTokens := EstimateTokens(sk.Body)
	report.Cost.Total = bodyTokens + EstimateTokens(sk.Description)
	report.Cost.Items = []CostItem{{Name: "SKILL.md", Tokens: bodyTokens}}

	// The description is the whole selection surface. Everything else about a
	// skill is irrelevant if the agent never decides to load it.
	descTokens := EstimateTokens(sk.Description)
	switch {
	case descTokens == 0:
		report.Design = append(report.Design, Note{
			Level:   LevelWarning,
			Summary: "no description in frontmatter",
			Detail: "The description is what decides whether this skill is ever " +
				"invoked. Without one it is dead weight in the directory.",
		})
	case descTokens < shortSkillDescriptionTokens:
		report.Design = append(report.Design, Note{
			Level:   LevelWarning,
			Summary: "description is too short to trigger reliably",
			Detail: fmt.Sprintf("~%d tokens. Say what the skill does and when it "+
				"applies, so the agent can tell it apart from everything else "+
				"installed.", descTokens),
		})
	}

	if sk.Name == "" {
		report.Design = append(report.Design, Note{
			Level:   LevelWarning,
			Summary: "no name in frontmatter",
		})
	}

	// An undeclared tool list is not a security finding here — the security
	// analyzer already reports the declared-versus-actual mismatch. This is
	// the design half: a reader cannot tell what the skill will reach for.
	if len(sk.AllowedTools) == 0 {
		report.Design = append(report.Design, Note{
			Level:   LevelSuggestion,
			Summary: "no allowed-tools declared",
			Detail: "Declaring the tools a skill needs lets a host scope its " +
				"permissions instead of granting everything.",
		})
	}

	if bodyTokens > largeSkillBodyTokens {
		report.Design = append(report.Design, Note{
			Level:   LevelSuggestion,
			Summary: fmt.Sprintf("SKILL.md is large (~%d tokens)", bodyTokens),
			Detail: "Long instructions get followed less reliably. Move reference " +
				"material into separate files the agent can read on demand.",
		})
	}

	if langs := scriptLanguages(sk.Scripts); len(sk.Scripts) > 0 {
		report.Design = append(report.Design, Note{
			Level:   LevelSuggestion,
			Subject: "scripts",
			Summary: fmt.Sprintf("%d bundled script(s): %s", len(sk.Scripts), langs),
			Detail: "Bundled scripts are executed rather than read. They are the " +
				"part of a skill worth reviewing by hand.",
		})
	}

	return report
}

// scriptLanguages summarizes what a skill's bundled scripts are written in,
// so a reviewer knows which runtimes a skill drags in before reading them.
func scriptLanguages(scripts []string) string {
	if len(scripts) == 0 {
		return ""
	}

	byExt := map[string]int{}
	for _, s := range scripts {
		ext := filepath.Ext(s)
		if ext == "" {
			ext = "(no extension)"
		}
		byExt[ext]++
	}

	exts := make([]string, 0, len(byExt))
	for ext := range byExt {
		exts = append(exts, ext)
	}
	sort.Strings(exts) // map order is random; a report must be reproducible

	out := ""
	for i, ext := range exts {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d%s", byExt[ext], ext)
	}
	return out
}
