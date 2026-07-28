package mcpdriver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/toolinfo"
)

// Session is a live sandboxed MCP server that can be enumerated AND called.
//
// EnumerateSandboxed opens a session, lists tools, and closes it, which is all
// enumeration needs. Probing needs the session to stay open: a tool only
// reveals what it does when it is invoked, so the container has to outlive the
// tools/list call.
//
// The caller owns the lifetime and MUST Close, which is what guarantees the
// untrusted process does not outlive the scan.
type Session struct {
	container *sandbox.Container
	session   *mcp.ClientSession
	cancel    context.CancelFunc
	command   string
}

// OpenSession launches a target in the sandbox and keeps the session open.
func OpenSession(
	ctx context.Context,
	command string,
	policy sandbox.Policy,
	mounts []sandbox.Mount,
) (*Session, error) {
	if err := sandbox.EnsureImage(ctx, policy.Image); err != nil {
		return nil, err
	}

	name, err := sandbox.NewName()
	if err != nil {
		return nil, err
	}
	argv, err := splitForContainer(command)
	if err != nil {
		return nil, err
	}

	// A probe run makes many calls, so the session needs a budget well beyond
	// a single enumeration's. Still bounded: nothing untrusted runs forever.
	runCtx, cancel := context.WithCancel(ctx)

	c, err := sandbox.Start(runCtx, name, policy, mounts, argv)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("starting sandbox for %q: %w", command, err)
	}

	sess, err := connectOverPipes(runCtx, c, policy.Timeout)
	if err != nil {
		stderr := c.Stderr()
		_ = c.Close()
		cancel()
		if failed, detail := c.Failed(); failed {
			return nil, fmt.Errorf("sandbox did not run %q: %s", command, truncate(detail, 500))
		}
		if stderr != "" {
			return nil, fmt.Errorf("%w (container stderr: %s)", err, truncate(stderr, 500))
		}
		return nil, err
	}

	return &Session{container: c, session: sess, cancel: cancel, command: command}, nil
}

// Tools lists what the target offers.
func (s *Session) Tools(ctx context.Context) ([]toolinfo.ToolInfo, error) {
	result, err := s.session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return nil, fmt.Errorf("listing tools from sandboxed %q: %w", s.command, err)
	}

	tools := make([]toolinfo.ToolInfo, 0, len(result.Tools))
	for _, t := range result.Tools {
		schema, err := json.Marshal(t.InputSchema)
		if err != nil {
			schema = nil
		}
		tools = append(tools, toolinfo.ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			Source:      toolinfo.SourceMCP,
			InputSchema: schema,
			Metadata: map[string]any{
				"command":   s.command,
				"sandboxed": true,
				"container": s.container.Name,
			},
		})
	}
	return tools, nil
}

// callTimeout bounds a single tool invocation. A tool that hangs on hostile
// input must not stall the whole probe run — and a hang IS a result, so the
// timeout has to be short enough to record it and keep going.
const callTimeout = 15 * time.Second

// Call invokes a tool and returns its response as text.
//
// Implements probe.Caller.
func (s *Session) Call(ctx context.Context, tool string, args map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	res, err := s.session.CallTool(ctx, &mcp.CallToolParams{
		Name:      tool,
		Arguments: args,
	})
	if err != nil {
		return "", err
	}

	// Flatten the response to text. An error result is NOT an error here: a
	// tool reporting "invalid path" is behaving correctly, and its message is
	// exactly the content that must still be searched for leaked data.
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

// Stderr returns what the target has written so far. Implements probe.Caller.
func (s *Session) Stderr() string { return s.container.Stderr() }

// Close tears down the session and the container.
func (s *Session) Close() error {
	_ = s.session.Close()
	err := s.container.Close()
	s.cancel()
	return err
}
