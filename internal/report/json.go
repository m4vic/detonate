package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Scan is the complete machine-readable result of one scan.
//
// Separate from SARIF because the two answer different questions. SARIF is for
// GitHub's code-scanning UI and is shaped by that spec. This is for anything
// else that wants the data — a dashboard, a diff between two scans, a script
// deciding whether to proceed with an install.
type Scan struct {
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Target  string    `json:"target"`
	Started time.Time `json:"started"`

	// Verdict is the same word the terminal prints, so the two never disagree.
	Verdict string `json:"verdict"`

	// Counts save every consumer from recomputing the thing they all want.
	Counts Counts `json:"counts"`

	Tools    []toolinfo.ToolInfo `json:"tools"`
	Findings []Finding           `json:"findings"`

	// Observations are context that deliberately did not affect the verdict.
	// Included rather than dropped so a consumer can show what a target
	// reaches for without that changing whether it passed.
	Observations []Finding `json:"observations,omitempty"`
}

type Counts struct {
	Critical int `json:"critical"`
	Notable  int `json:"notable"`
	Info     int `json:"info"`
}

// Finding is one observed behaviour, flattened for consumption.
//
// trace.Event carries a free-form Detail map, which is right internally and
// awkward for a consumer. The fields that matter are lifted out and named.
type Finding struct {
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Summary   string `json:"summary"`
	Evidence  string `json:"evidence,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Why       string `json:"why,omitempty"`
	During    string `json:"during,omitempty"`
	Source    string `json:"source"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// Build assembles a Scan from a trace.
func Build(tr *trace.Trace, tools []toolinfo.ToolInfo, target, version string) Scan {
	s := Scan{
		Tool: "detonate", Version: version,
		Target: target, Tools: tools, Verdict: "clean",
	}
	if tr == nil {
		return s
	}
	s.Started = tr.Started

	for _, e := range tr.Events {
		f := toFinding(e)
		switch e.Severity {
		case trace.SeverityCritical:
			s.Counts.Critical++
			s.Findings = append(s.Findings, f)
		case trace.SeverityNotable:
			s.Counts.Notable++
			s.Findings = append(s.Findings, f)
		default:
			s.Counts.Info++
			s.Observations = append(s.Observations, f)
		}
	}

	switch {
	case s.Counts.Critical > 0:
		s.Verdict = "dangerous"
	case s.Counts.Notable > 0:
		s.Verdict = "suspicious"
	}
	return s
}

func toFinding(e trace.Event) Finding {
	f := Finding{
		Severity: string(e.Severity), Kind: string(e.Kind),
		Summary: e.Summary, During: e.During, Source: e.Source,
		ElapsedMS: e.Elapsed.Milliseconds(),
	}
	if v, ok := e.Detail["evidence"].(string); ok {
		f.Evidence = v
	}
	if v, ok := e.Detail["payload"].(string); ok {
		f.Payload = v
	}
	if v, ok := e.Detail["why"].(string); ok {
		f.Why = v
	}
	return f
}

// JSON writes the scan as indented JSON.
func JSON(w io.Writer, s Scan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
