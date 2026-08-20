package toolscan

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Input schemas are target-controlled too.
//
// A parameter's description is read by the model when it decides what to put in
// that parameter, which makes it the same attack surface as the tool
// description with a smaller audience and far less scrutiny. The text
// signatures therefore run over parameter descriptions as well — one rule
// table, two places, so a payload cannot escape by moving one level down.
//
// The second thing a schema reveals is what the tool asks the agent to hand
// over. A parameter called api_key is ordinary; one called ssh_private_key is
// not, and the difference is worth reporting even though neither is proof of
// anything. Calibration follows internal/skill: capability is context for a
// reviewer, never a verdict on its own.

// maxSchemaDepth bounds the walk. A schema is target-controlled data, so it can
// nest arbitrarily or cyclically via repeated wrappers; the walk is bounded for
// the same reason every other budget in detonate exists.
const maxSchemaDepth = 8

// secretParameters name things a tool is asking the agent to supply.
//
// Split by how alarming the ask is. The first group is routine — most API
// wrappers need a token, and flagging them all would reproduce the 11-of-12
// false-positive rate internal/skill measured against real Google skills. The
// second group asks for material that is not a service credential at all.
var (
	routineSecretParam = regexp.MustCompile(`(?i)(^|[_-])(api[_-]?key|apikey|token|access[_-]?token|auth|authorization|password|passwd|secret|credential)s?($|[_-])`)

	sensitiveSecretParam = regexp.MustCompile(`(?i)(^|[_-])(ssh[_-]?key|private[_-]?key|id[_-]?rsa|id[_-]?ed25519|secret[_-]?access[_-]?key|aws[_-]?secret|session[_-]?cookie|master[_-]?key|seed[_-]?phrase|mnemonic)s?($|[_-])`)
)

// parameter is one leaf of a walked schema.
type parameter struct {
	path        string
	description string
}

// analyzeSchema inspects a tool's declared inputs.
func analyzeSchema(tool toolinfo.ToolInfo, now time.Time) []trace.Event {
	if len(tool.InputSchema) == 0 {
		return nil
	}

	var root map[string]any
	if err := json.Unmarshal(tool.InputSchema, &root); err != nil {
		// A schema that will not parse is a compatibility fact, not a security
		// finding. Report it so the reader knows this tool's inputs were never
		// examined rather than examined and found clean — the same
		// risk/completeness separation the rest of detonate keeps.
		return []trace.Event{event(trace.KindProtocol, trace.SeverityInfo, now,
			"tool input schema could not be parsed; its parameters were not analyzed: "+quoteTool(tool.Name),
			sourceSchema, map[string]any{
				"tool":  tool.Name,
				"error": clip(err.Error(), evidenceLimit),
				"rule":  "schema-unparsable",
			})}
	}

	// Not re-sorted here: walkSchema already emits parameters in a fixed order
	// (each level's keys sorted, parent before its children). Flattening and
	// re-sorting by path would be a second mechanism for the same guarantee,
	// and would also break the natural nesting order a reader expects in a
	// report. One guarantee, in one place.
	params := walkSchema(root, "", 0)

	var events []trace.Event
	for _, p := range params {
		events = append(events, secretParameterEvents(tool, p, now)...)
		events = append(events, poisonedParameterEvents(tool, p, now)...)
	}
	return events
}

// secretParameterEvents reports parameters that ask for credentials.
func secretParameterEvents(tool toolinfo.ToolInfo, p parameter, now time.Time) []trace.Event {
	leaf := p.path
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}

	switch {
	case sensitiveSecretParam.MatchString(leaf):
		return []trace.Event{event(trace.KindFile, trace.SeverityNotable, now,
			"tool asks the agent to supply private key material: "+quoteTool(tool.Name),
			sourceSchema, map[string]any{
				"tool":      tool.Name,
				"parameter": p.path,
				"rule":      "schema-sensitive-secret",
			})}
	case routineSecretParam.MatchString(leaf):
		return []trace.Event{event(trace.KindProtocol, trace.SeverityInfo, now,
			"tool accepts a credential parameter: "+quoteTool(tool.Name),
			sourceSchema, map[string]any{
				"tool":      tool.Name,
				"parameter": p.path,
				"rule":      "schema-credential-parameter",
			})}
	}
	return nil
}

// poisonedParameterEvents runs the description rules over a parameter's own
// description, plus the hidden-character check.
func poisonedParameterEvents(tool toolinfo.ToolInfo, p parameter, now time.Time) []trace.Event {
	if p.description == "" {
		return nil
	}

	var events []trace.Event
	for _, sig := range textSignatures {
		for _, match := range sig.pattern.FindAllString(p.description, -1) {
			if sig.warningsAreBenign && isWarning(match) {
				continue
			}
			events = append(events, event(sig.kind, sig.severity, now,
				sig.summary+", in parameter "+quoteTool(p.path)+" of "+quoteTool(tool.Name),
				sourceSchema, map[string]any{
					"tool":      tool.Name,
					"parameter": p.path,
					"evidence":  clip(strings.TrimSpace(match), evidenceLimit),
					"rule":      sig.id,
				}))
			break
		}
	}

	events = append(events,
		hiddenCharacterEvents(tool.Name, "parameter "+p.path, p.description, now)...)
	return events
}

// walkSchema collects every named parameter and its description.
//
// Keys are sorted at each level because Go randomizes map iteration, and an
// unsorted walk would emit the same findings in a different order on every run
// — which would break both the determinism guarantee and SARIF diffing.
func walkSchema(node map[string]any, prefix string, depth int) []parameter {
	if depth >= maxSchemaDepth {
		return nil
	}

	var out []parameter

	props, ok := node["properties"].(map[string]any)
	if !ok {
		return nil
	}

	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		child, ok := props[name].(map[string]any)
		if !ok {
			continue
		}

		path := name
		if prefix != "" {
			path = prefix + "." + name
		}

		desc, _ := child["description"].(string)
		out = append(out, parameter{path: path, description: desc})

		// Nested objects.
		out = append(out, walkSchema(child, path, depth+1)...)

		// Array element schemas carry descriptions too, and a poisoned one is
		// just as readable to the model as a top-level parameter.
		if items, ok := child["items"].(map[string]any); ok {
			if desc, _ := items["description"].(string); desc != "" {
				out = append(out, parameter{path: path + "[]", description: desc})
			}
			out = append(out, walkSchema(items, path+"[]", depth+1)...)
		}
	}

	return out
}
