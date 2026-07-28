package probe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// fakeCaller stands in for a live MCP session so the engine can be tested
// without Docker. The responses are what a real target would return; only the
// transport is faked.
type fakeCaller struct {
	respond func(tool string, args map[string]any) string
	stderr  string
	calls   []string
}

func (f *fakeCaller) Call(_ context.Context, tool string, args map[string]any) (string, error) {
	f.calls = append(f.calls, tool)
	if f.respond == nil {
		return "", nil
	}
	return f.respond(tool, args), nil
}

func (f *fakeCaller) Stderr() string { return f.stderr }

func schema(props ...string) json.RawMessage {
	m := map[string]any{"type": "object", "properties": map[string]any{}}
	p := m["properties"].(map[string]any)
	for _, name := range props {
		p[name] = map[string]any{"type": "string"}
	}
	b, _ := json.Marshal(m)
	return b
}

func findingsOnly(events []trace.Event) []trace.Event {
	var out []trace.Event
	for _, e := range events {
		if e.Severity == trace.SeverityCritical || e.Severity == trace.SeverityNotable {
			out = append(out, e)
		}
	}
	return out
}

// The headline capability: a tool that resolves a traversal path and returns
// the file is caught by the CONTENT it returned, not by a heuristic.
func TestRunDetectsPathTraversalLeak(t *testing.T) {
	c := &fakeCaller{respond: func(_ string, args map[string]any) string {
		if p, _ := args["path"].(string); strings.Contains(p, "etc/passwd") {
			return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
		}
		return "ok"
	}}

	tools := []toolinfo.ToolInfo{{Name: "read_file", InputSchema: schema("path")}}
	found := findingsOnly(Run(context.Background(), c, tools, 0))

	var hit *trace.Event
	for i := range found {
		if strings.Contains(found[i].Summary, "leaked data via path-traversal") {
			hit = &found[i]
		}
	}
	if hit == nil {
		t.Fatalf("traversal leak not detected; got %d findings", len(found))
	}
	if hit.Severity != trace.SeverityCritical {
		t.Errorf("severity = %s, want critical", hit.Severity)
	}
	// Attribution is what turns an observation into evidence.
	if !strings.Contains(hit.During, "read_file") {
		t.Errorf("finding not attributed to the tool: During = %q", hit.During)
	}
	if hit.Detail["evidence"] == nil || hit.Detail["payload"] == nil {
		t.Errorf("finding carries no evidence or payload: %v", hit.Detail)
	}
}

// The control, and the reason the probe set was recalibrated. A server that
// rejects every hostile path must produce no findings, even though its error
// messages quote the input back.
func TestRunIsQuietOnAHardenedTool(t *testing.T) {
	c := &fakeCaller{respond: func(_ string, args map[string]any) string {
		p, _ := args["path"].(string)
		if strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
			return "rejected: invalid path " + p // quotes the input, as real tools do
		}
		return "ok: would read data/" + p
	}}

	tools := []toolinfo.ToolInfo{{Name: "read_file", InputSchema: schema("path")}}
	if found := findingsOnly(Run(context.Background(), c, tools, 0)); len(found) != 0 {
		t.Errorf("hardened tool produced %d findings; a scanner that flags correct "+
			"validation gets turned off:\n%v", len(found), found)
	}
}

// Echoing the caller's own argument is normal behaviour, not injection: the
// agent already had that text. An earlier version called this critical and
// flagged both a hardened server and a tool named "echo".
func TestRunTreatsEchoAsContextNotFinding(t *testing.T) {
	c := &fakeCaller{respond: func(_ string, args map[string]any) string {
		return args["text"].(string) // a pure echo tool
	}}

	tools := []toolinfo.ToolInfo{{Name: "echo", InputSchema: schema("text")}}
	events := Run(context.Background(), c, tools, 0)

	if found := findingsOnly(events); len(found) != 0 {
		t.Errorf("an echo tool must not produce findings for echoing:\n%v", found)
	}

	var sawInfo bool
	for _, e := range events {
		if e.Severity == trace.SeverityInfo && strings.Contains(e.Summary, "verbatim") {
			sawInfo = true
		}
	}
	if !sawInfo {
		t.Error("echo behaviour should still be reported as context")
	}
}

func TestRunDetectsCommandInjection(t *testing.T) {
	// A tool that shells out returns the output of the injected command.
	c := &fakeCaller{respond: func(_ string, args map[string]any) string {
		if v, _ := args["q"].(string); strings.Contains(v, "id") {
			return "uid=0(root) gid=0(root) groups=0(root)"
		}
		return "no results"
	}}

	tools := []toolinfo.ToolInfo{{Name: "search", InputSchema: schema("q")}}
	found := findingsOnly(Run(context.Background(), c, tools, 0))

	var ok bool
	for _, e := range found {
		if strings.Contains(e.Summary, "command-injection") {
			ok = true
		}
	}
	if !ok {
		t.Errorf("command injection not detected; got %v", found)
	}
}

func TestRunSendsABenignBaselineFirst(t *testing.T) {
	// Diffing against normal behaviour is what stops a server that always
	// logs a warning from producing a finding on every payload.
	c := &fakeCaller{}
	tools := []toolinfo.ToolInfo{{Name: "t", InputSchema: schema("x")}}
	Run(context.Background(), c, tools, 0)

	if len(c.calls) != len(payloads)+1 {
		t.Errorf("made %d calls, want %d (one baseline + one per payload)",
			len(c.calls), len(payloads)+1)
	}
}

func TestRunReportsToolsItCannotProbe(t *testing.T) {
	// A tool with no string inputs is out of reach of this probe set. Saying
	// so is honest; staying silent would imply it was tested and found clean.
	c := &fakeCaller{}
	tools := []toolinfo.ToolInfo{{Name: "ping", InputSchema: json.RawMessage(`{"type":"object"}`)}}

	events := Run(context.Background(), c, tools, 0)
	if len(c.calls) != 0 {
		t.Errorf("called a tool with no string parameters: %v", c.calls)
	}
	if len(events) != 1 || !strings.Contains(events[0].Summary, "not probed") {
		t.Errorf("expected an explicit not-probed note, got %v", events)
	}
}

func TestStringParams(t *testing.T) {
	got := stringParams(schema("path", "mode"))
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 string params", got)
	}

	if p := stringParams(json.RawMessage(`{"type":"object","properties":{"n":{"type":"number"}}}`)); len(p) != 0 {
		t.Errorf("numeric params should not be probed with string payloads, got %v", p)
	}
	if p := stringParams(nil); len(p) != 0 {
		t.Errorf("nil schema = %v, want none", p)
	}
	if p := stringParams(json.RawMessage(`not json`)); len(p) != 0 {
		t.Errorf("malformed schema must not panic or invent params, got %v", p)
	}
}
