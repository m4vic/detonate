// Package mcpdriver connects to a real MCP server over stdio and enumerates
// its tools.
//
// No sandbox yet (that is M2). This package proves detonate can speak the real
// MCP protocol against a real server: launch it, initialize a session, list
// what it offers. That is the prerequisite for everything after it, because
// you cannot detonate a tool you cannot yet discover.
//
// Uses the official MCP Go SDK rather than a hand-rolled JSON-RPC client. The
// SDK is the source of truth for the protocol; reimplementing it would mean
// our bugs get mistaken for the server's behaviour, which is fatal in a tool
// whose entire output is claims about how a server behaves.
package mcpdriver

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/m4vic/detonate/internal/toolinfo"
)

// DefaultTimeout bounds the whole launch-handshake-list sequence. A hostile or
// broken server that accepts stdio and then never answers would otherwise hang
// the scan forever, which for a security tool reads as a pass.
const DefaultTimeout = 30 * time.Second

// teardownGrace bounds how long we wait for a server process to die after we
// close its session.
//
// EnumerateTools must not return while the server it launched is still alive.
// That is not tidiness: this process is untrusted by definition, and a scan
// that reports a verdict while its subject keeps running has not finished
// scanning. Our own test suite caught this first, on Windows, where an
// unreaped child holds its executable open and the next build cannot delete
// it. On Unix the same bug is quieter, which is worse.
const teardownGrace = 5 * time.Second

// clientInfo is what we announce to the server during initialize. Servers can
// see this, and honest identification is the right default for a scanner:
// pretending to be a normal client is a decision to make deliberately (and to
// document) if evasion-resistance ever becomes a goal, not a silent default.
var clientInfo = &mcp.Implementation{Name: "detonate", Version: "0.0.1"}

// EnumerateTools launches the MCP server, initializes a session, and lists its
// tools. The server process is torn down before this returns: M1 only
// discovers what a server offers, it does not yet run anything against it.
func EnumerateTools(ctx context.Context, command string, timeout time.Duration) ([]toolinfo.ToolInfo, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name, args, err := ParseCommand(command)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, name, args...)
	// WaitDelay is what turns CommandContext's cancellation into an actual
	// kill. Without it, a server that ignores the closed stdin keeps running
	// (and keeps its pipes open) until it feels like stopping. With it, the
	// runtime gives the process this long to exit on its own and then kills
	// it. A scanner does not negotiate with the thing it is scanning.
	cmd.WaitDelay = teardownGrace

	client := mcp.NewClient(clientInfo, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to MCP server %q: %w", command, err)
	}
	defer shutdown(session, cancel)

	listed, err := listAllTools(ctx, session, defaultToolPagination)
	if err != nil {
		return nil, fmt.Errorf("listing tools from %q: %w", command, err)
	}

	tools := make([]toolinfo.ToolInfo, 0, len(listed))
	for _, t := range listed {
		schema, err := json.Marshal(t.InputSchema)
		if err != nil {
			// A schema we cannot re-encode is worth reporting later, but it is
			// not a reason to discard an otherwise-discovered tool: a tool we
			// failed to list is a tool we failed to scan.
			schema = nil
		}
		tools = append(tools, toolinfo.ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			Source:      toolinfo.SourceMCP,
			InputSchema: schema,
			Metadata:    map[string]any{"command": command},
		})
	}
	return tools, nil
}

// shutdown tears the server down and does not return until it is actually
// gone, or until teardownGrace expires.
//
// The order matters. Close() shuts the session's streams, which asks a
// well-behaved server to exit. cancel() then fires CommandContext's kill for
// one that refuses. Relying on the deferred cancel() in EnumerateTools would
// invert this: defers run last-in-first-out, so the kill would arrive after
// this function had already given up waiting.
func shutdown(session *mcp.ClientSession, cancel context.CancelFunc) {
	_ = session.Close()

	done := make(chan struct{})
	go func() {
		_ = session.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(teardownGrace):
		// Escalate: the server ignored a closed stdin.
	}

	cancel()
	select {
	case <-done:
	case <-time.After(teardownGrace):
		// Even the kill did not reap it. Nothing further we can do from here
		// without leaking a goroutine forever; M2's container teardown is the
		// real backstop, since killing a container kills whatever it holds.
	}
}
