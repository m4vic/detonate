package mcpdriver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Pagination limits are security limits, not tuning knobs. A hostile server
// can otherwise return an endless cursor chain or an unbounded tool inventory
// and make enumeration consume host time and memory indefinitely.
type paginationLimits struct {
	MaxPages int
	MaxItems int
}

var defaultToolPagination = paginationLimits{
	MaxPages: 64,
	MaxItems: 4096,
}

type toolLister interface {
	ListTools(context.Context, *mcp.ListToolsParams) (*mcp.ListToolsResult, error)
}

func listAllTools(
	ctx context.Context,
	lister toolLister,
	limits paginationLimits,
) ([]*mcp.Tool, error) {
	if limits.MaxPages <= 0 || limits.MaxItems <= 0 {
		return nil, fmt.Errorf("invalid tools/list pagination limits")
	}

	var tools []*mcp.Tool
	cursor := ""
	seen := make(map[string]struct{})

	for page := 1; page <= limits.MaxPages; page++ {
		result, err := lister.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		if result == nil {
			return nil, fmt.Errorf("tools/list page %d returned nil", page)
		}
		if len(result.Tools) > limits.MaxItems-len(tools) {
			return nil, fmt.Errorf(
				"tools/list exceeded item limit %d on page %d",
				limits.MaxItems, page,
			)
		}
		tools = append(tools, result.Tools...)

		next := result.NextCursor
		if next == "" {
			return tools, nil
		}
		if next == cursor {
			return nil, fmt.Errorf("tools/list repeated cursor %q", next)
		}
		if _, ok := seen[next]; ok {
			return nil, fmt.Errorf("tools/list cursor loop at %q", next)
		}
		seen[next] = struct{}{}
		cursor = next
	}

	return nil, fmt.Errorf("tools/list exceeded page limit %d", limits.MaxPages)
}
