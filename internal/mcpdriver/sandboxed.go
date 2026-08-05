package mcpdriver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// EnumerateSandboxed launches an MCP server INSIDE a disposable container and
// enumerates its tools from outside.
//
// This is the function detonate exists for. EnumerateTools (the unsandboxed
// sibling) runs the server on the host, which is what every other executing
// scanner does. Here the server gets a container with no network, a read-only
// root, no capabilities and a non-root uid, while the JSON-RPC session speaks
// straight through the boundary over the container's stdio.
//
// The protocol does not know it crossed a sandbox. That is the whole trick:
// `docker run -i` gives us a process whose stdin and stdout are pipes, which is
// exactly what an MCP stdio transport wants, so no protocol changes are needed
// to gain full confinement.
// Result is what a sandboxed enumeration produced: the tools a target
// declares, and what it was observed doing while declaring them.
//
// Both halves matter and neither is sufficient. The tools are what a static
// scanner would report. The trace is what only running it can reveal, and it
// is the part that catches a clean-looking manifest whose server phones home
// on startup.
type Result struct {
	Tools []toolinfo.ToolInfo
	Trace *trace.Trace
}

func EnumerateSandboxed(
	ctx context.Context,
	command string,
	policy sandbox.Policy,
	mounts []sandbox.Mount,
) ([]toolinfo.ToolInfo, error) {
	res, err := EnumerateSandboxedWithTrace(ctx, command, policy, mounts)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// EnumerateSandboxedWithTrace is EnumerateSandboxed plus the behavioural
// record. Separate function rather than a changed signature so the simple
// call site stays simple.
func EnumerateSandboxedWithTrace(
	ctx context.Context,
	command string,
	policy sandbox.Policy,
	mounts []sandbox.Mount,
) (*Result, error) {
	// Pull before the session clock starts. `docker run` would pull lazily,
	// but that download happens inside the timeout and makes the first scan on
	// any machine fail with an opaque protocol EOF.
	if err := sandbox.EnsureImage(ctx, policy.Image); err != nil {
		return nil, err
	}

	name, err := sandbox.NewName()
	if err != nil {
		return nil, err
	}

	// The container command is the target's own command line. Parsing happens
	// here rather than inside sandbox so that package stays generic: it runs
	// containers, it does not know what MCP is.
	argv, err := splitForContainer(command)
	if err != nil {
		return nil, err
	}

	tr := &trace.Trace{Target: command, Started: time.Now()}

	c, err := sandbox.Start(ctx, name, policy, mounts, argv)
	if err != nil {
		return nil, fmt.Errorf("starting sandbox for %q: %w", command, err)
	}
	defer func() {
		// Teardown failure is a safety event, not a cleanup detail: it means
		// untrusted code may still be running. It cannot be returned from a
		// defer without masking the real error, so it is surfaced through the
		// container's own error channel for the caller to report.
		_ = c.Close()
	}()

	tr.Add(trace.Event{
		Kind: trace.KindLifecycle, Severity: trace.SeverityInfo,
		Summary: "sandbox started", Source: "sandbox",
		Detail: map[string]any{"container": name, "image": policy.Image},
	})

	session, err := connectOverPipes(ctx, c, policy.Timeout)
	if err != nil {
		// Distinguish "the container never ran" from "the server misbehaved".
		// Both surface as a protocol EOF, and conflating them is how a failed
		// scan gets mistaken for a clean one.
		if failed, detail := c.Failed(); failed {
			return nil, fmt.Errorf("sandbox did not run %q: %s", command, truncate(detail, 500))
		}
		// Otherwise include container stderr: when a sandboxed server fails to
		// start, the reason is almost always there (missing interpreter, bad
		// path), and without it the user just sees an opaque EOF.
		if stderr := c.Stderr(); stderr != "" {
			return nil, fmt.Errorf("%w (container stderr: %s)", err, truncate(stderr, 500))
		}
		return nil, err
	}
	defer session.Close()

	listCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()

	listed, err := listAllTools(listCtx, session, defaultToolPagination)
	if err != nil {
		// A crash between the handshake and this call surfaces as a bare EOF.
		// The reason is in the container's output — a missing env var, a
		// database it could not reach — so include it rather than report EOF
		// alone.
		if failed, detail := c.Failed(); failed {
			return nil, fmt.Errorf("the sandboxed server %q exited during enumeration: %s",
				command, truncate(detail, 600))
		}
		if stderr := c.Stderr(); stderr != "" {
			return nil, fmt.Errorf("listing tools from sandboxed %q: %w (container stderr: %s)",
				command, err, truncate(stderr, 600))
		}
		return nil, fmt.Errorf("listing tools from sandboxed %q: %w", command, err)
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
				"command":   command,
				"sandboxed": true,
				"container": name,
			},
		})
	}

	tr.Add(trace.Event{
		Kind: trace.KindProtocol, Severity: trace.SeverityInfo,
		Summary: fmt.Sprintf("enumerated %d tool(s)", len(tools)),
		Source:  "mcp-driver", During: "enumeration",
	})

	// Read the container's stderr LAST, after the protocol exchange, so it
	// includes whatever the target did during startup and enumeration.
	//
	// This is where an innocent-looking server gives itself away: a blocked
	// network call leaves an error here even though the manifest is clean and
	// the protocol exchange succeeded.
	for _, ev := range monitor.Analyze(c.Stderr(), "enumeration") {
		tr.Add(ev)
	}

	return &Result{Tools: tools, Trace: tr}, nil
}

// connectOverPipes builds an MCP client session on top of a running
// container's stdio.
//
// mcp.IOTransport takes an arbitrary reader/writer pair, which is what lets the
// same protocol client talk to a sandboxed process and a host process without
// caring which it got.
func connectOverPipes(ctx context.Context, c *sandbox.Container, timeout time.Duration) (*mcp.ClientSession, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := mcp.NewClient(clientInfo, nil)

	// Tap stdout on the way to the protocol client. When a handshake fails
	// the SDK reports the parse error ("invalid character 'C'") and discards
	// the bytes that caused it, which leaves a user knowing only that
	// something was wrong with output they never get to see.
	//
	// Anything a target writes here that is not JSON-RPC is itself worth
	// reading: a server logging to stdout has corrupted its own protocol
	// channel, and the text it emitted usually says why.
	tap := &firstBytes{max: 400}
	transport := &mcp.IOTransport{
		Reader: readCloser{io.TeeReader(c.Stdout(), tap)},
		Writer: c.Stdin(),
	}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		if wrote := tap.String(); wrote != "" {
			return nil, fmt.Errorf("connecting to sandboxed MCP server: %w "+
				"(target wrote this to stdout instead of protocol: %q)", err, wrote)
		}
		return nil, fmt.Errorf("connecting to sandboxed MCP server: %w", err)
	}
	return session, nil
}

// firstBytes records the opening bytes of a stream and then stops, so a
// chatty target cannot grow it without bound.
//
// Writes come from the SDK's read loop while the error path reads it, so the
// mutex is guarding a real cross-goroutine race rather than a theoretical one.
type firstBytes struct {
	mu   sync.Mutex
	buf  []byte
	max  int
	full bool
}

func (f *firstBytes) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if room := f.max - len(f.buf); room > 0 {
		if len(p) <= room {
			f.buf = append(f.buf, p...)
		} else {
			f.buf = append(f.buf, p[:room]...)
			f.full = true
		}
	}
	// Always report the whole write as consumed: a TeeReader treats a short
	// write as an error and would break the protocol stream it is teeing.
	return len(p), nil
}

func (f *firstBytes) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := strings.TrimSpace(string(f.buf))
	if s != "" && f.full {
		s += "..."
	}
	return s
}

// readCloser gives a plain reader the Close the transport interface demands.
// Closing is a no-op for the same reason it is on the container's own pipes:
// lifetime belongs to the container.
type readCloser struct{ io.Reader }

func (readCloser) Close() error { return nil }

// splitForContainer turns the target's command string into argv for the
// container. Reuses the same tokenizer as the unsandboxed path so quoting
// behaves identically whether or not a sandbox is involved.
func splitForContainer(command string) ([]string, error) {
	name, args, err := ParseCommand(command)
	if err != nil {
		return nil, err
	}
	return append([]string{name}, args...), nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
