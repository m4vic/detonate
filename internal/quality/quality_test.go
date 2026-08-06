package quality

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/toolinfo"
)

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want func(int) bool
		desc string
	}{
		{"empty", "", func(n int) bool { return n == 0 }, "zero"},
		{"whitespace only", "   \n\t ", func(n int) bool { return n == 0 }, "zero"},
		{"single word", "hello", func(n int) bool { return n >= 1 && n <= 2 }, "1-2"},
		{
			"terse text is not under-counted",
			"a b c d e f g h",
			func(n int) bool { return n >= 8 },
			"at least one per word",
		},
		{
			"prose scales with length",
			strings.Repeat("the quick brown fox ", 20),
			func(n int) bool { return n > 60 && n < 160 },
			"60-160",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := EstimateTokens(tc.in); !tc.want(got) {
				t.Errorf("EstimateTokens(%q) = %d, want %s", tc.in, got, tc.desc)
			}
		})
	}
}

// A tool with no description is invisible to an agent choosing between tools,
// which is a fault rather than a preference.
func TestUndocumentedToolsAreWarnings(t *testing.T) {
	report := AnalyzeMCP([]toolinfo.ToolInfo{
		{Name: "alpha", Description: ""},
		{Name: "beta", Description: ""},
	})

	var found bool
	for _, note := range report.Design {
		if strings.Contains(note.Summary, "no description") {
			found = true
			if note.Level != LevelWarning {
				t.Errorf("level = %q, want %q", note.Level, LevelWarning)
			}
			if !strings.Contains(note.Detail, "alpha") {
				t.Errorf("detail does not name the tools: %q", note.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("undocumented tools produced no note: %+v", report.Design)
	}
}

// Cost is the headline number for an MCP server, because the tool list is
// injected on every request whether or not anything is called.
func TestCostCountsEveryToolAndSortsHeaviestFirst(t *testing.T) {
	report := AnalyzeMCP([]toolinfo.ToolInfo{
		{Name: "small", Description: "Short."},
		{Name: "large", Description: strings.Repeat("a very long description ", 40)},
	})

	if report.Cost.Total == 0 {
		t.Fatal("no cost computed")
	}
	if len(report.Cost.Items) != 2 {
		t.Fatalf("got %d cost items, want 2", len(report.Cost.Items))
	}
	if report.Cost.Items[0].Name != "large" {
		t.Errorf("heaviest tool is %q, want \"large\"", report.Cost.Items[0].Name)
	}
	if report.Cost.Unit == "" {
		t.Error("cost has no unit; the number is unreadable without one")
	}
}

// A report that changes between runs cannot be diffed, and map iteration order
// is the classic way that happens.
func TestReportIsDeterministic(t *testing.T) {
	tools := []toolinfo.ToolInfo{{
		Name:        "search",
		Description: "Search documents by query.",
		InputSchema: json.RawMessage(`{"properties":{
			"query":{"type":"string"},"limit":{"type":"number"},
			"offset":{"type":"number"},"fuzzy":{"type":"boolean"}}}`),
	}}

	first, err := json.Marshal(AnalyzeMCP(tools))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 8; i++ {
		next, err := json.Marshal(AnalyzeMCP(tools))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(first) != string(next) {
			t.Fatalf("report differs between runs:\n%s\n%s", first, next)
		}
	}
}

// An unreadable schema must not become a design note. The author cannot act on
// "detonate could not parse this", and guessing invents work for them.
func TestUnparseableSchemaIsSilent(t *testing.T) {
	report := AnalyzeMCP([]toolinfo.ToolInfo{{
		Name:        "odd",
		Description: "A tool with a schema this analyzer does not model.",
		InputSchema: json.RawMessage(`{"oneOf":[{"type":"string"}]}`),
	}})

	for _, note := range report.Design {
		if note.Subject == "odd" && strings.Contains(note.Summary, "parameter") {
			t.Errorf("invented a parameter note from an unmodelled schema: %+v", note)
		}
	}
}

// The description decides whether a skill is ever invoked, so a missing one is
// a fault and not a style preference.
func TestSkillWithoutDescriptionWarns(t *testing.T) {
	report := AnalyzeSkill(SkillInput{Name: "thing", Body: "Do the thing."})

	if report.Warnings() == 0 {
		t.Fatalf("no warning for a skill with no description: %+v", report.Design)
	}
}

func TestSkillCostCountsTheBody(t *testing.T) {
	report := AnalyzeSkill(SkillInput{
		Name:        "big",
		Description: "A skill that does a specific, well-described thing.",
		Body:        strings.Repeat("instruction line here ", 500),
	})

	if report.Cost.Total < 500 {
		t.Errorf("body cost = %d, want a large count", report.Cost.Total)
	}
	var large bool
	for _, note := range report.Design {
		if strings.Contains(note.Summary, "large") {
			large = true
		}
	}
	if !large {
		t.Errorf("a very large SKILL.md produced no size note: %+v", report.Design)
	}
}

// A well-built target must produce a quiet report. If good input still yields
// warnings, the lens is measuring style rather than fault and will be ignored.
func TestWellBuiltTargetsProduceNoWarnings(t *testing.T) {
	mcp := AnalyzeMCP([]toolinfo.ToolInfo{{
		Name:        "search_documents",
		Description: "Search the indexed document set and return matching passages ranked by relevance.",
		InputSchema: json.RawMessage(`{"properties":{
			"query":{"type":"string","description":"The search text."}},
			"required":["query"]}`),
		Metadata: map[string]any{"readOnlyHint": true},
	}})
	if n := mcp.Warnings(); n != 0 {
		t.Errorf("well-built MCP server produced %d warning(s): %+v", n, mcp.Design)
	}

	sk := AnalyzeSkill(SkillInput{
		Name:         "pdf-extractor",
		Description:  "Extract text and tables from PDF files, preserving reading order.",
		AllowedTools: []string{"Read"},
		Body:         "Use the bundled script to extract content.",
	})
	if n := sk.Warnings(); n != 0 {
		t.Errorf("well-built skill produced %d warning(s): %+v", n, sk.Design)
	}
}
