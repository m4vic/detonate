package toolcall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSearchableTextIncludesEveryContentSurface(t *testing.T) {
	result := Result{
		Content: []ContentBlock{
			{Type: "text", Raw: json.RawMessage(`{"type":"text","text":"plain"}`)},
			{Type: "resource", Raw: json.RawMessage(`{"type":"resource","resource":{"text":"embedded"}}`)},
		},
		StructuredContent: json.RawMessage(`{"secret":"structured"}`),
	}
	got := result.SearchableText()
	for _, want := range []string{"plain", "embedded", "structured"} {
		if !strings.Contains(got, want) {
			t.Errorf("searchable result missing %q: %s", want, got)
		}
	}
}
