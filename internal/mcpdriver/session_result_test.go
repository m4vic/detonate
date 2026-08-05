package mcpdriver

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNormalizeToolResultPreservesContentAndIsError(t *testing.T) {
	res, err := normalizeToolResult(&mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "plain"},
			&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI:      "file:///evidence.txt",
				MIMEType: "text/plain",
				Text:     "root:x:0:0",
			}},
		},
		StructuredContent: map[string]any{"nested": "structured evidence"},
		IsError:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("IsError was discarded")
	}
	if len(res.Content) != 2 || res.Content[1].Type != "resource" {
		t.Fatalf("content blocks not preserved: %+v", res.Content)
	}
	searchable := res.SearchableText()
	for _, want := range []string{"plain", "root:x:0:0", "structured evidence"} {
		if !strings.Contains(searchable, want) {
			t.Errorf("searchable content missing %q: %s", want, searchable)
		}
	}
}
