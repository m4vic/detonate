package quality

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/m4vic/detonate/internal/toolinfo"
)

// Thresholds for the description checks.
//
// Chosen from what an agent has to do with the text rather than from style
// preference. Below the short bound there is not enough information to choose
// between two tools; above the long bound the description is being charged for
// on every request in every conversation.
const (
	shortDescriptionTokens = 5
	longDescriptionTokens  = 150

	// manyRequiredParams is where a tool stops being callable in one shot.
	// Every required argument is another value the model has to invent or go
	// looking for, and the failure mode is a confidently wrong call.
	manyRequiredParams = 6
)

// schema is the part of a JSON Schema these checks read. Deliberately partial:
// the goal is to judge whether a model can fill the arguments in, not to
// validate the schema.
type schema struct {
	Properties map[string]struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	} `json:"properties"`
	Required []string `json:"required"`
}

// AnalyzeMCP reports how an MCP server's tool surface is built and what it
// costs to have installed.
func AnalyzeMCP(tools []toolinfo.ToolInfo) Report {
	report := Report{
		Cost: Cost{Unit: "per request (tool list is injected into context)"},
	}

	if len(tools) == 0 {
		return report
	}

	var undocumented []string
	annotated := false

	for _, tool := range tools {
		// Cost is the whole wire surface, not just the prose: the name and the
		// schema are injected alongside the description and are charged for
		// the same way.
		tokens := EstimateTokens(tool.Name) + EstimateTokens(tool.Description) +
			EstimateTokens(string(tool.InputSchema))
		report.Cost.Total += tokens
		report.Cost.Items = append(report.Cost.Items,
			CostItem{Name: tool.Name, Tokens: tokens})

		descTokens := EstimateTokens(tool.Description)
		switch {
		case descTokens == 0:
			undocumented = append(undocumented, tool.Name)
		case descTokens < shortDescriptionTokens:
			report.Design = append(report.Design, Note{
				Level:   LevelWarning,
				Subject: tool.Name,
				Summary: "description is too short for an agent to choose this tool",
				Detail: fmt.Sprintf("~%d tokens. Say what it does and when to use it, "+
					"not just its name restated.", descTokens),
			})
		case descTokens > longDescriptionTokens:
			report.Design = append(report.Design, Note{
				Level:   LevelSuggestion,
				Subject: tool.Name,
				Summary: "description is long enough to be worth shortening",
				Detail: fmt.Sprintf("~%d tokens, charged on every request. "+
					"Move examples and edge cases into the schema's field descriptions.", descTokens),
			})
		}

		if hasAnnotations(tool) {
			annotated = true
		}
		report.Design = append(report.Design, schemaNotes(tool)...)
	}

	if len(undocumented) > 0 {
		report.Design = append(report.Design, Note{
			Level:   LevelWarning,
			Summary: fmt.Sprintf("%d tool(s) have no description", len(undocumented)),
			Detail: "An agent selects tools by description. One with none is " +
				"effectively invisible: " + joinNames(undocumented),
		})
	}

	// Annotations are how a host decides what needs confirming before it runs.
	// Without them every call looks equally consequential, so a client either
	// prompts for everything or for nothing.
	if !annotated {
		report.Design = append(report.Design, Note{
			Level:   LevelSuggestion,
			Summary: "no tool annotations declared",
			Detail: "readOnlyHint and destructiveHint let a client decide what to " +
				"confirm before running. Without them a read is treated like a delete.",
		})
	}

	// Heaviest first: the point of the breakdown is to show the one worth
	// rewriting, not to list everything alphabetically.
	sort.SliceStable(report.Cost.Items, func(i, j int) bool {
		return report.Cost.Items[i].Tokens > report.Cost.Items[j].Tokens
	})

	return report
}

// schemaNotes judges whether a model can actually fill in a tool's arguments.
func schemaNotes(tool toolinfo.ToolInfo) []Note {
	if len(tool.InputSchema) == 0 {
		return nil
	}

	var s schema
	if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
		// An unreadable schema is not reported as a design fault. It may be a
		// shape this partial struct does not model, and guessing would produce
		// a note the author cannot act on.
		return nil
	}

	var notes []Note

	if len(s.Required) > manyRequiredParams {
		notes = append(notes, Note{
			Level:   LevelSuggestion,
			Subject: tool.Name,
			Summary: fmt.Sprintf("%d required parameters", len(s.Required)),
			Detail: "Every required argument is one more value the model has to " +
				"invent. Consider defaults, or splitting the tool.",
		})
	}

	var undescribed []string
	for name, prop := range s.Properties {
		if prop.Description == "" {
			undescribed = append(undescribed, name)
		}
	}
	if len(undescribed) > 0 && len(s.Properties) > 0 {
		sort.Strings(undescribed) // map order is random; a report must not be
		notes = append(notes, Note{
			Level:   LevelSuggestion,
			Subject: tool.Name,
			Summary: fmt.Sprintf("%d of %d parameters have no description",
				len(undescribed), len(s.Properties)),
			Detail: "Undescribed parameters are guessed at: " + joinNames(undescribed),
		})
	}

	return notes
}

// hasAnnotations reports whether the tool carries any MCP behaviour hints.
func hasAnnotations(tool toolinfo.ToolInfo) bool {
	for _, key := range []string{
		"annotations", "readOnlyHint", "destructiveHint",
		"idempotentHint", "openWorldHint",
	} {
		if _, ok := tool.Metadata[key]; ok {
			return true
		}
	}
	return false
}

// joinNames renders a name list, capped so one bad target cannot fill the
// terminal with a single note.
func joinNames(names []string) string {
	const max = 6
	if len(names) <= max {
		return join(names)
	}
	return fmt.Sprintf("%s and %d more", join(names[:max]), len(names)-max)
}

func join(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
