package mcpdriver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/toolcall"
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
	mounts    []sandbox.Mount
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

	return &Session{container: c, session: sess, cancel: cancel, command: command, mounts: mounts}, nil
}

// TargetDir returns the host target directory path mounted to /target.
func (s *Session) TargetDir() string {
	for _, m := range s.mounts {
		if m.ContainerPath == "/target" {
			return m.HostPath
		}
	}
	return ""
}

// Tools lists what the target offers.
func (s *Session) Tools(ctx context.Context) ([]toolinfo.ToolInfo, error) {
	listed, err := listAllTools(ctx, s.session, defaultToolPagination)
	if err != nil {
		return nil, s.enumerationError("listing tools", err)
	}

	tools := make([]toolinfo.ToolInfo, 0, len(listed))
	for _, t := range listed {
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

// enumerationError explains a protocol failure with what the container said.
//
// A bare "EOF" means the server died between the handshake and this call, and
// on its own tells a developer nothing. The reason is almost always in the
// container's stderr — a missing env var, a database it could not reach, an
// unhandled exception on startup. mcp-server-mysql, for one, exits when it
// cannot connect to a database, and "EOF" hid that entirely.
func (s *Session) enumerationError(action string, err error) error {
	// Wait briefly: an EOF here and the container's exit race, and the exit
	// usually wins a moment later. This is what turns mysql-server's silent
	// death — no stderr at all — into "the server exited" rather than a bare
	// "EOF" that reads like the scanner's fault.
	if failed, detail := s.container.FailedWithin(2 * time.Second); failed {
		return fmt.Errorf("%s from sandboxed %q: the server exited: %s",
			action, s.command, truncate(detail, 600))
	}
	if stderr := strings.TrimSpace(s.container.Stderr()); stderr != "" {
		return fmt.Errorf("%s from sandboxed %q: %w (container stderr: %s)",
			action, s.command, err, truncate(stderr, 600))
	}
	return fmt.Errorf("%s from sandboxed %q: %w", action, s.command, err)
}

// callTimeout bounds a single tool invocation. A tool that hangs on hostile
// input must not stall the whole probe run — and a hang IS a result, so the
// timeout has to be short enough to record it and keep going.
const callTimeout = 15 * time.Second

// Call invokes a tool and preserves every MCP content surface.
//
// Implements probe.Caller.
func (s *Session) Call(ctx context.Context, tool string, args map[string]any) (toolcall.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	res, err := s.session.CallTool(ctx, &mcp.CallToolParams{
		Name:      tool,
		Arguments: args,
	})
	if err != nil {
		return toolcall.Result{}, err
	}
	return normalizeToolResult(res)
}

func normalizeToolResult(res *mcp.CallToolResult) (toolcall.Result, error) {
	if res == nil {
		return toolcall.Result{}, fmt.Errorf("tool returned a nil result")
	}
	out := toolcall.Result{IsError: res.IsError}
	for i, content := range res.Content {
		raw, err := json.Marshal(content)
		if err != nil {
			return toolcall.Result{}, fmt.Errorf("encoding tool content block %d: %w", i, err)
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return toolcall.Result{}, fmt.Errorf("reading tool content block %d type: %w", i, err)
		}
		out.Content = append(out.Content, toolcall.ContentBlock{
			Type: header.Type, Raw: raw,
		})
	}
	if res.StructuredContent != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return toolcall.Result{}, fmt.Errorf("encoding structured tool content: %w", err)
		}
		out.StructuredContent = raw
	}
	return out, nil
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
