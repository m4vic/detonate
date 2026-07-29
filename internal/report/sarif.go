// Package report renders a scan's findings in machine-readable formats.
//
// The exit code already gates CI, but a pipeline that wants to say WHERE the
// problem is needs structured output. SARIF is what GitHub code scanning
// consumes: upload it and findings appear as annotations on the pull request
// diff, next to the file that caused them. That is the difference between a
// tool someone remembers to run and one that reviews every change.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/m4vic/detonate/internal/trace"
)

// SARIF 2.1.0. The schema is fixed by the spec; the fields below are the
// subset GitHub actually reads.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	DefaultConfiguration sarifConfig       `json:"defaultConfiguration"`
	Properties           map[string]any    `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints let a code-scanning UI recognise the same finding
	// across runs, so a known issue is not re-reported as new every scan.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// levelFor maps our severities onto SARIF's.
//
// Info becomes "note" rather than being dropped: GitHub renders notes
// quietly, and context a reviewer can expand is more useful than context
// thrown away.
func levelFor(s trace.Severity) string {
	switch s {
	case trace.SeverityCritical:
		return "error"
	case trace.SeverityNotable:
		return "warning"
	default:
		return "note"
	}
}

// ruleID turns a finding into a stable identifier.
//
// Derived from kind and source rather than the summary text, because summaries
// contain tool names and change between targets. A rule ID that shifts when
// the message does would make every finding look new.
func ruleID(e trace.Event) string {
	return "detonate/" + string(e.Kind) + "/" + strings.ReplaceAll(e.Source, "-", "_")
}

// SARIF writes a scan's findings as a SARIF 2.1.0 log.
//
// artifactURI is what the finding is attached to. For a scanned folder that is
// a path GitHub can resolve inside the repository; when detonate scanned
// something outside the checkout there is nothing to point at, so the target
// string is used and the annotation lands on the run rather than a line.
func SARIF(w io.Writer, tr *trace.Trace, artifactURI, version string) error {
	if tr == nil {
		tr = &trace.Trace{}
	}

	rules := map[string]sarifRule{}
	var results []sarifResult

	for _, e := range tr.Events {
		id := ruleID(e)
		if _, seen := rules[id]; !seen {
			rules[id] = sarifRule{
				ID:               id,
				Name:             string(e.Kind),
				ShortDescription: sarifText{Text: shortDescriptionFor(e)},
				FullDescription:  sarifText{Text: fullDescriptionFor(e)},
				DefaultConfiguration: sarifConfig{Level: levelFor(e.Severity)},
				Properties: map[string]any{
					"tags": []string{"security", "ai-supply-chain", string(e.Kind)},
				},
			}
		}

		results = append(results, sarifResult{
			RuleID:  id,
			Level:   levelFor(e.Severity),
			Message: sarifText{Text: messageFor(e)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: artifactURI},
				},
			}},
			PartialFingerprints: map[string]string{
				// Kind + summary is stable across runs of the same target, so
				// a finding that has not changed is not re-raised as new.
				"detonateFinding/v1": fingerprint(e),
			},
		})
	}

	ordered := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ordered = append(ordered, r)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "detonate",
				Version:        version,
				InformationURI: "https://github.com/m4vic/detonate",
				Rules:          ordered,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func messageFor(e trace.Event) string {
	var b strings.Builder
	b.WriteString(e.Summary)

	// Evidence belongs in the message, not a separate field: the annotation is
	// often all a reviewer reads, and a finding they cannot verify from the
	// text alone gets dismissed.
	if ev, ok := e.Detail["evidence"].(string); ok && ev != "" {
		b.WriteString("\n\nEvidence: ")
		b.WriteString(ev)
	}
	if p, ok := e.Detail["payload"].(string); ok && p != "" {
		b.WriteString("\nPayload: ")
		b.WriteString(p)
	}
	if why, ok := e.Detail["why"].(string); ok && why != "" {
		b.WriteString("\nWhy it matters: ")
		b.WriteString(why)
	}
	if e.During != "" {
		b.WriteString(fmt.Sprintf("\nObserved at +%dms during %s (source: %s)",
			e.Elapsed.Milliseconds(), e.During, e.Source))
	}
	return b.String()
}

func shortDescriptionFor(e trace.Event) string {
	switch e.Kind {
	case trace.KindNetwork:
		return "Target attempted network access"
	case trace.KindFile:
		return "Target accessed sensitive files"
	case trace.KindProcess:
		return "Target spawned or executed code"
	case trace.KindResource:
		return "Target exhausted a resource limit"
	case trace.KindProtocol:
		return "Suspicious tool or instruction behaviour"
	default:
		return "Observed behaviour"
	}
}

func fullDescriptionFor(e trace.Event) string {
	switch e.Kind {
	case trace.KindNetwork:
		return "detonate runs targets with the network disabled. An attempt to " +
			"resolve or connect is therefore an attempt to reach the outside " +
			"world during a scan, which is behaviour worth reviewing."
	case trace.KindFile:
		return "The target read or attempted to read files outside its own " +
			"directory, or referenced credentials and private keys."
	case trace.KindProcess:
		return "The target executed code, spawned a process, or instructed an " +
			"agent to do so."
	case trace.KindResource:
		return "The target hit a memory, CPU or process ceiling, which can " +
			"indicate a denial-of-service pattern."
	case trace.KindProtocol:
		return "The target's declared behaviour and its actual behaviour " +
			"disagree, or its instructions attempt to manipulate the agent."
	default:
		return "Behaviour observed while the target ran in the sandbox."
	}
}

func fingerprint(e trace.Event) string {
	return fmt.Sprintf("%s|%s|%s", e.Kind, e.Source, e.Summary)
}
