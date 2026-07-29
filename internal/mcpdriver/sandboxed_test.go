package mcpdriver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/sandbox"
)

// End-to-end proof that an MCP server runs INSIDE the container and the
// protocol still works across the boundary.
//
// The server is written in Python with no dependencies, speaking JSON-RPC over
// stdio by hand. Using the official SDK would mean pip-installing it into the
// sandbox, which needs network — and the sandbox has none, by design. A
// hand-rolled server is the honest way to test a no-network sandbox, and it
// also proves our client works against something other than the SDK's own
// server implementation.

const pySrv = `import sys, json

TOOLS = [
    {"name": "read_file",
     "description": "Read the contents of a file at the given path.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "echo",
     "description": "Echo back the given text.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
]

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except ValueError:
        continue
    if "id" not in req:
        continue  # a notification; nothing to answer
    method = req.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": req["id"], "result": {
            "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sandboxed-fixture", "version": "0.0.1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": req["id"], "result": {"tools": TOOLS}})
    else:
        send({"jsonrpc": "2.0", "id": req["id"],
              "error": {"code": -32601, "message": "method not found"}})
`

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
}

// writeServer drops the fixture server somewhere the container can mount it.
func writeServer(t *testing.T) (hostDir string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte(pySrv), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnumerateSandboxedRunsInContainer(t *testing.T) {
	requireDocker(t)

	hostDir := writeServer(t)
	policy := sandbox.DefaultPolicy()
	policy.Timeout = 90 * time.Second

	mounts := []sandbox.Mount{{
		HostPath:      hostDir,
		ContainerPath: "/target",
		ReadOnly:      true, // a target that can rewrite itself mid-scan makes evidence meaningless
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	tools, err := EnumerateSandboxed(ctx, "python /target/server.py", policy, mounts)
	if err != nil {
		t.Fatalf("EnumerateSandboxed: %v", err)
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

	rf := tools[idx]
	if !strings.Contains(rf.Description, "Read the contents") {
		t.Errorf("Description = %q", rf.Description)
	}
	// The metadata must record that this was sandboxed. A report that cannot
	// distinguish a sandboxed finding from a host-run one is not trustworthy.
	if rf.Metadata["sandboxed"] != true {
		t.Errorf("tool not marked sandboxed: %v", rf.Metadata)
	}
	if !strings.HasPrefix(rf.Metadata["container"].(string), sandbox.NamePrefix) {
		t.Errorf("container name %v lacks the reap prefix", rf.Metadata["container"])
	}
}

// A server that logs to stdout has corrupted its own protocol channel. The
// SDK reports the parse error and discards the bytes that caused it, so
// without the tap a user is told only that "invalid character 'C'" happened
// to output they never see.
//
// Found on a real published server, which prints a configuration banner to
// stdout and is unusable over stdio as a result.
func TestEnumerateSandboxedQuotesNonProtocolOutput(t *testing.T) {
	requireDocker(t)

	policy := sandbox.DefaultPolicy()
	policy.Image = "alpine:latest"
	policy.Timeout = 60 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_, err := EnumerateSandboxed(ctx,
		`sh -c "echo Configuration: ENV_FILE=/.env; sleep 5"`, policy, nil)
	if err == nil {
		t.Fatal("expected a protocol failure from a server that logs to stdout")
	}
	if !strings.Contains(err.Error(), "Configuration:") {
		t.Errorf("error does not quote what the target actually wrote: %v", err)
	}
}

func TestFirstBytes(t *testing.T) {
	t.Run("reports full writes so TeeReader does not break", func(t *testing.T) {
		f := &firstBytes{max: 4}
		// A short write makes io.TeeReader return ErrShortWrite and abort the
		// protocol stream it is teeing, which would turn a diagnostic aid into
		// a cause of failure.
		n, err := f.Write([]byte("abcdefghij"))
		if n != 10 || err != nil {
			t.Errorf("Write = (%d, %v), want (10, nil)", n, err)
		}
	})

	t.Run("caps at max and marks the truncation", func(t *testing.T) {
		f := &firstBytes{max: 4}
		f.Write([]byte("abcdefghij"))
		if got := f.String(); got != "abcd..." {
			t.Errorf("String = %q, want %q", got, "abcd...")
		}
	})

	t.Run("keeps the opening bytes across several writes", func(t *testing.T) {
		f := &firstBytes{max: 100}
		f.Write([]byte("Config"))
		f.Write([]byte("uration:\n"))
		if got := f.String(); got != "Configuration:" {
			t.Errorf("String = %q", got)
		}
	})

	t.Run("silent target yields nothing to quote", func(t *testing.T) {
		f := &firstBytes{max: 100}
		f.Write([]byte("  \n "))
		if got := f.String(); got != "" {
			t.Errorf("String = %q, want empty", got)
		}
	})
}

// The sandbox must leave nothing behind, including on the failure path.
func TestEnumerateSandboxedLeavesNoOrphans(t *testing.T) {
	requireDocker(t)

	before := countDetonateContainers(t)

	policy := sandbox.DefaultPolicy()
	policy.Timeout = 30 * time.Second

	// A command that does not exist in the image: the container starts, the
	// process fails, and enumeration errors out. Teardown still has to happen.
	_, err := EnumerateSandboxed(context.Background(),
		"definitely-not-a-real-binary-xyz", policy, nil)
	if err == nil {
		t.Fatal("expected an error for a command missing from the image")
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if countDetonateContainers(t) <= before {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("container leaked on the failure path: %d before, %d after",
		before, countDetonateContainers(t))
}

func countDetonateContainers(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-aq",
		"--filter", "name="+sandbox.NamePrefix).Output()
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(out)))
}
