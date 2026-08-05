package mcpdriver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeToolLister struct {
	pages map[string]*mcp.ListToolsResult
	calls []string
}

func (f *fakeToolLister) ListTools(
	_ context.Context,
	params *mcp.ListToolsParams,
) (*mcp.ListToolsResult, error) {
	f.calls = append(f.calls, params.Cursor)
	page, ok := f.pages[params.Cursor]
	if !ok {
		return nil, fmt.Errorf("unexpected cursor %q", params.Cursor)
	}
	return page, nil
}

func TestListAllToolsFollowsEveryPage(t *testing.T) {
	lister := &fakeToolLister{pages: map[string]*mcp.ListToolsResult{
		"": {
			Tools:      []*mcp.Tool{{Name: "first"}},
			NextCursor: "page-2",
		},
		"page-2": {
			Tools: []*mcp.Tool{{Name: "second"}},
		},
	}}
	tools, err := listAllTools(context.Background(), lister, defaultToolPagination)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 || tools[1].Name != "second" {
		t.Fatalf("later page was hidden: %+v", tools)
	}
	if got := strings.Join(lister.calls, ","); got != ",page-2" {
		t.Fatalf("cursors = %q, want initial then page-2", got)
	}
}

func TestListAllToolsRejectsRepeatedCursor(t *testing.T) {
	lister := &fakeToolLister{pages: map[string]*mcp.ListToolsResult{
		"":     {NextCursor: "same"},
		"same": {NextCursor: "same"},
	}}
	_, err := listAllTools(context.Background(), lister, defaultToolPagination)
	if err == nil || !strings.Contains(err.Error(), "repeated cursor") {
		t.Fatalf("error = %v, want repeated cursor", err)
	}
}

func TestListAllToolsEnforcesItemAndPageLimits(t *testing.T) {
	t.Run("items", func(t *testing.T) {
		lister := &fakeToolLister{pages: map[string]*mcp.ListToolsResult{
			"": {Tools: []*mcp.Tool{{Name: "a"}, {Name: "b"}}},
		}}
		_, err := listAllTools(context.Background(), lister, paginationLimits{
			MaxPages: 2, MaxItems: 1,
		})
		if err == nil || !strings.Contains(err.Error(), "item limit") {
			t.Fatalf("error = %v, want item limit", err)
		}
	})

	t.Run("pages", func(t *testing.T) {
		lister := &fakeToolLister{pages: map[string]*mcp.ListToolsResult{
			"":   {NextCursor: "p2"},
			"p2": {NextCursor: "p3"},
		}}
		_, err := listAllTools(context.Background(), lister, paginationLimits{
			MaxPages: 2, MaxItems: 10,
		})
		if err == nil || !strings.Contains(err.Error(), "page limit") {
			t.Fatalf("error = %v, want page limit", err)
		}
	})
}
