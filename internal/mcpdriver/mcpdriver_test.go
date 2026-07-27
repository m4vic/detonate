package mcpdriver

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/mcptest"
)

func TestMain(m *testing.M) {
	mcptest.RunServerIfRequested()
	mcptest.RunHostileIfRequested()
	os.Exit(m.Run())
}

func TestEnumerateToolsAgainstRealServer(t *testing.T) {
	tools, err := EnumerateTools(context.Background(), mcptest.Command(), 30*time.Second)
	if err != nil {
		t.Fatalf("EnumerateTools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("got %d tools, want 2: %v", len(tools), tools)
	}

	byName := map[string]int{}
	for i, tool := range tools {
		byName[tool.Name] = i
	}
	idx, ok := byName["read_file"]
	if !ok {
		t.Fatalf("read_file not discovered; got %v", byName)
	}
	if _, ok := byName["echo"]; !ok {
		t.Errorf("echo not discovered; got %v", byName)
	}

	readFile := tools[idx]
	if readFile.Source != "mcp" {
		t.Errorf("Source = %q, want mcp", readFile.Source)
	}
	if !strings.Contains(readFile.Description, "Read the contents") {
		t.Errorf("Description = %q", readFile.Description)
	}
	if readFile.Metadata["command"] != mcptest.Command() {
		t.Errorf("metadata command = %v", readFile.Metadata["command"])
	}

	// The schema is how a probe later knows what arguments to send, so an
	// empty one would silently disarm every probe against this tool.
	var schema struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(readFile.InputSchema, &schema); err != nil {
		t.Fatalf("input schema is not valid JSON: %v", err)
	}
	if _, ok := schema.Properties["path"]; !ok {
		t.Errorf("input schema missing 'path' property: %s", readFile.InputSchema)
	}
}

func TestEnumerateToolsBadCommand(t *testing.T) {
	// A server that cannot start must fail the scan. Reporting zero tools
	// would read as a clean bill of health for something never examined.
	_, err := EnumerateTools(context.Background(), "definitely-not-a-real-binary-xyz", 10*time.Second)
	if err == nil {
		t.Fatal("expected an error for a non-existent server binary")
	}
}

func TestEnumerateToolsEmptyCommand(t *testing.T) {
	if _, err := EnumerateTools(context.Background(), "  ", time.Second); err == nil {
		t.Fatal("expected an error for an empty command")
	}
}
