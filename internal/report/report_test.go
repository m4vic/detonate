package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

func sampleTrace() *trace.Trace {
	tr := &trace.Trace{Target: "test", Started: time.Now()}
	tr.Add(trace.Event{
		Kind: trace.KindProtocol, Severity: trace.SeverityCritical,
		Summary: `tool "read_file" leaked data via path-traversal`,
		During:  "probe:path-traversal on read_file", Source: "probe-response",
		Detail: map[string]any{
			"evidence": "root:x:0:0:root:/root:/bin/bash",
			"payload":  "../../../../etc/passwd",
			"why":      "a tool that resolves this reads files outside its directory",
		},
	})
	tr.Add(trace.Event{
		Kind: trace.KindNetwork, Severity: trace.SeverityNotable,
		Summary: "target attempted DNS resolution", Source: "container-stderr",
		Detail: map[string]any{"evidence": "Temporary failure in name resolution"},
	})
	tr.Add(trace.Event{
		Kind: trace.KindProcess, Severity: trace.SeverityInfo,
		Summary: "instructions tell the agent to run shell commands",
		Source:  "skill-instructions",
	})
	return tr
}

func TestBuildSeparatesFindingsFromObservations(t *testing.T) {
	s := Build(sampleTrace(), nil, "./target", "v1")

	if len(s.Findings) != 2 {
		t.Errorf("got %d findings, want 2 (critical + notable)", len(s.Findings))
	}
	// Info-level events must never count toward the verdict. Letting them
	// would reproduce the false-positive rate that made an earlier revision
	// call 11 of 12 real skills suspicious.
	if len(s.Observations) != 1 {
		t.Errorf("got %d observations, want 1 (the info event)", len(s.Observations))
	}
	if s.Verdict != "dangerous" {
		t.Errorf("verdict = %q, want dangerous (a critical is present)", s.Verdict)
	}
	if s.Counts.Critical != 1 || s.Counts.Notable != 1 || s.Counts.Info != 1 {
		t.Errorf("counts = %+v", s.Counts)
	}
}

func TestBuildVerdictLadder(t *testing.T) {
	cases := []struct {
		name string
		sev  trace.Severity
		want string
	}{
		{"critical", trace.SeverityCritical, "dangerous"},
		{"notable", trace.SeverityNotable, "suspicious"},
		{"info only", trace.SeverityInfo, "clean"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &trace.Trace{Started: time.Now()}
			tr.Add(trace.Event{Kind: trace.KindProtocol, Severity: c.sev, Summary: "x"})
			if got := Build(tr, nil, "t", "v1").Verdict; got != c.want {
				t.Errorf("verdict = %q, want %q", got, c.want)
			}
		})
	}

	if got := Build(nil, nil, "t", "v1").Verdict; got != "clean" {
		t.Errorf("nil trace verdict = %q, want clean", got)
	}
}

func TestJSONIsValidAndFlattensDetail(t *testing.T) {
	var buf bytes.Buffer
	s := Build(sampleTrace(), []toolinfo.ToolInfo{{Name: "read_file"}}, "./target", "v1")
	if err := JSON(&buf, s); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var back Scan
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if back.Verdict != "dangerous" {
		t.Errorf("verdict round-trip = %q", back.Verdict)
	}
	// The Detail map is convenient internally and awkward for a consumer, so
	// the fields that matter are lifted into named ones.
	f := back.Findings[0]
	if f.Evidence == "" || f.Payload == "" || f.Why == "" {
		t.Errorf("detail not flattened into named fields: %+v", f)
	}
}

func TestSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleTrace(), "server.py", "v1"); err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log["version"] != sarifVersion {
		t.Errorf("version = %v, want %s", log["version"], sarifVersion)
	}
	if log["$schema"] == nil {
		t.Error("missing $schema; GitHub rejects a log without it")
	}

	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (info becomes a note, not dropped)", len(results))
	}

	first := results[0].(map[string]any)
	if first["level"] != "error" {
		t.Errorf("critical mapped to %v, want error", first["level"])
	}
	// The annotation is often all a reviewer reads, so a finding they cannot
	// verify from the message alone will be dismissed.
	msg := first["message"].(map[string]any)["text"].(string)
	for _, want := range []string{"Evidence:", "root:x:0:0", "Payload:", "Why it matters:"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	// Fingerprints stop a known finding being re-reported as new every run.
	if first["partialFingerprints"] == nil {
		t.Error("no partialFingerprints; findings would appear new on every scan")
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[trace.Severity]string{
		trace.SeverityCritical: "error",
		trace.SeverityNotable:  "warning",
		trace.SeverityInfo:     "note",
	}
	for sev, want := range cases {
		if got := levelFor(sev); got != want {
			t.Errorf("levelFor(%s) = %q, want %q", sev, got, want)
		}
	}
}

func TestRuleIDIsStableAcrossTargets(t *testing.T) {
	// Derived from kind and source, never the summary: summaries contain tool
	// names, so a summary-derived ID would change per target and make every
	// finding look like a new rule.
	a := trace.Event{Kind: trace.KindProtocol, Source: "probe-response",
		Summary: `tool "read_file" leaked data`}
	b := trace.Event{Kind: trace.KindProtocol, Source: "probe-response",
		Summary: `tool "search" leaked data`}

	if ruleID(a) != ruleID(b) {
		t.Errorf("rule IDs differ for the same rule: %q vs %q", ruleID(a), ruleID(b))
	}
	if strings.Contains(ruleID(a), " ") {
		t.Errorf("rule ID %q contains a space", ruleID(a))
	}
}

func TestSARIFHandlesEmptyTrace(t *testing.T) {
	// A clean scan still has to produce a valid document, or CI fails on the
	// upload step precisely when there was nothing wrong.
	var buf bytes.Buffer
	if err := SARIF(&buf, nil, "x", "v1"); err != nil {
		t.Fatalf("SARIF(nil): %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("empty trace produced invalid JSON: %v", err)
	}
}
