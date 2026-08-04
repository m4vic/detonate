package scenario

import (
	"testing"
	"time"
)

func TestContractValidateAcceptsBoundedMCPScenario(t *testing.T) {
	t.Parallel()
	c := Contract{
		ID:             "mcp.filesystem/read-fixture",
		TargetKind:     TargetMCP,
		Trigger:        "Read fixtures/hello.txt and return the first line.",
		Required:       true,
		Mode:           ModeDeterministic,
		Runtime:        RuntimeNode,
		Fixtures:       []string{"fixtures/hello.txt"},
		AllowedTools:   []string{"read_file"},
		ForbiddenTools: []string{"write_file"},
		Expectation:    Expectation{MustCall: []string{"read_file"}},
		MaxTurns:       1,
		Timeout:        Duration(10 * time.Second),
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestContractValidateRejectsAmbiguousOrUnsafeDefinitions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Contract)
	}{
		{"missing trigger", func(c *Contract) { c.Trigger = "" }},
		{"invalid ID", func(c *Contract) { c.ID = "MCP Test" }},
		{"outside fixture", func(c *Contract) { c.Fixtures = []string{"../secret"} }},
		{"outside fixture with Windows separators", func(c *Contract) { c.Fixtures = []string{"..\\secret"} }},
		{"conflicting tool policy", func(c *Contract) { c.ForbiddenTools = []string{"read_file"} }},
		{"oracle outside allowlist", func(c *Contract) { c.Expectation.MustCall = []string{"write_file"} }},
		{"negative timeout", func(c *Contract) { c.Timeout = Duration(-time.Second) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Contract{
				ID: "mcp.test/read", TargetKind: TargetMCP, Trigger: "read", Required: true,
				Mode: ModeDeterministic, Runtime: RuntimeNode, AllowedTools: []string{"read_file"},
				Expectation: Expectation{MustCall: []string{"read_file"}},
			}
			tt.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want validation failure")
			}
		})
	}
}

func TestStableExistingScenarioIDs(t *testing.T) {
	t.Parallel()
	if got, want := MCPToolID("read_file"), "mcp.tool/read_file"; got != want {
		t.Errorf("MCPToolID() = %q, want %q", got, want)
	}
	if got, want := SkillScriptID("scripts\\extract.py"), "skill.script/scripts/extract.py"; got != want {
		t.Errorf("SkillScriptID() = %q, want %q", got, want)
	}
}
