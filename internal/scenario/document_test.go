package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileAcceptsYAMLWithPortableDuration(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "scenario.yaml")
	data := `schema: detonate.scenario/v1
scenarios:
  - id: mcp.filesystem/read-fixture
    target_kind: mcp
    trigger: Read fixtures/hello.txt and return its first line.
    required: true
    mode: deterministic
    runtime: python
    fixtures: [fixtures/hello.txt]
    allowed_tools: [read_file]
    forbidden_tools: [write_file]
    expectation:
      must_call: [read_file]
    max_turns: 1
    timeout: 10s
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got, want := document.Scenarios[0].Timeout.Value().Seconds(), 10.0; got != want {
		t.Errorf("timeout = %v seconds, want %v", got, want)
	}
}

func TestDocumentValidateRejectsDuplicateScenarioID(t *testing.T) {
	t.Parallel()
	document := Document{
		Schema: SchemaV1,
		Scenarios: []Contract{
			validContract("mcp.test/read"),
			validContract("mcp.test/read"),
		},
	}
	if err := document.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want duplicate ID failure")
	}
}

func validContract(id string) Contract {
	return Contract{
		ID: id, TargetKind: TargetMCP, Trigger: "read", Required: true,
		Mode: ModeDeterministic, Runtime: RuntimeNode, MaxTurns: 1,
		Timeout: Duration(1),
	}
}
