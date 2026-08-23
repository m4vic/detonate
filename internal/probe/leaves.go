package probe

import (
	"encoding/json"
	"sort"
)

// A tool's attack surface is not the same thing as its top-level string
// parameters, and treating the two as equal cost most of the coverage on a real
// server.
//
// Measured on the official `modelcontextprotocol/servers` memory server: it
// declares eleven tools, and eight of them take arrays of objects.
// `create_entities` wants entities carrying `name`, `entityType`, and
// `observations`; `create_relations` wants `from`, `to`, `relationType`. Every
// one of those is a string the caller controls. Reading only the top level of
// `properties` found no strings at all, so all eight reported "no adversarial
// string-input surface" and 8 of 11 tools were declared out of reach — when the
// reach was one level down.
//
// The completeness model was honest about it, which is why the failure was
// visible rather than silent: those tools came back `unsupported`, not `pass`.
// But "we could not reach it" is only the right answer when it is true.

// maxStringLeaves bounds how many injection points one tool contributes.
//
// The schema comes from the target, so its size is chosen by whoever wrote it.
// A schema declaring thousands of nested properties would otherwise turn one
// tool into thousands of arguments per payload, which is a denial of service
// against the scanner written in JSON.
const maxStringLeaves = 32

// step is one hop into a tool's arguments: the property named key, and — when
// inArray is set — the first element of the array found there.
//
// Element zero only. Probing further into an array tests the target's loop, not
// its input handling, and multiplies calls for no new information.
type step struct {
	key     string
	inArray bool
}

// leaf addresses one string inside a tool's input schema.
type leaf struct {
	path []step
	// name is the leaf's own property name, which is what benign-value
	// selection keys on: a nested "path" deserves the same directory-or-file
	// treatment as a top-level one.
	name string
	enum []string
}

// stringLeaves finds every string a caller can set, at any depth.
func stringLeaves(schema json.RawMessage) []leaf {
	var out []leaf
	collectLeaves(schema, nil, 0, &out)
	return out
}

func collectLeaves(raw json.RawMessage, prefix []step, depth int, out *[]leaf) {
	if len(raw) == 0 || depth >= maxSchemaDepth || len(*out) >= maxStringLeaves {
		return
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return
	}

	// Sorted: map iteration order is random, and a probe set that varies
	// between runs makes two scans of an unchanged target disagree.
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if len(*out) >= maxStringLeaves {
			return
		}
		var p struct {
			Type       string                     `json:"type"`
			Items      json.RawMessage            `json:"items"`
			Enum       []json.RawMessage          `json:"enum"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(s.Properties[name], &p); err != nil {
			continue
		}

		switch {
		case p.Type == "object" || (p.Type == "" && len(p.Properties) > 0):
			collectLeaves(s.Properties[name], append(prefix, step{key: name}), depth+1, out)

		case p.Type == "array":
			var item struct {
				Type       string                     `json:"type"`
				Enum       []json.RawMessage          `json:"enum"`
				Properties map[string]json.RawMessage `json:"properties"`
			}
			if err := json.Unmarshal(p.Items, &item); err != nil {
				continue
			}
			inArray := append(prefix, step{key: name, inArray: true})
			if item.Type == "object" || len(item.Properties) > 0 {
				collectLeaves(p.Items, inArray, depth+1, out)
				continue
			}
			// An array of strings: the element itself is the injection point.
			if item.Type == "string" || item.Type == "" {
				*out = append(*out, leaf{
					path: inArray, name: name, enum: enumStrings(item.Enum),
				})
			}

		case p.Type == "string" || p.Type == "":
			// Untyped defaults to string, matching the top-level rule this
			// replaced: a schema that declares a property without a type still
			// accepts one, and refusing to probe it would hand any target a
			// one-word way to opt out.
			*out = append(*out, leaf{
				path: append(prefix, step{key: name}), name: name, enum: enumStrings(p.Enum),
			})
		}
	}
}

func enumStrings(raw []json.RawMessage) []string {
	var out []string
	for _, r := range raw {
		var v string
		if err := json.Unmarshal(r, &v); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// leafNames lists the distinct property names the leaves address, for callers
// that reason about parameters rather than positions.
func leafNames(leaves []leaf) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range leaves {
		if !seen[l.name] {
			seen[l.name] = true
			out = append(out, l.name)
		}
	}
	return out
}

// setLeaf writes value at a leaf's address, building whatever containers the
// path needs on the way down.
func setLeaf(args map[string]any, path []step, value any) {
	if len(path) == 0 {
		return
	}
	cur := args
	for i, st := range path {
		last := i == len(path)-1

		if !st.inArray {
			if last {
				cur[st.key] = value
				return
			}
			next, ok := cur[st.key].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[st.key] = next
			}
			cur = next
			continue
		}

		arr, ok := cur[st.key].([]any)
		if !ok || len(arr) == 0 {
			arr = []any{nil}
			cur[st.key] = arr
		}
		if last {
			arr[0] = value
			return
		}
		elem, ok := arr[0].(map[string]any)
		if !ok {
			elem = map[string]any{}
			arr[0] = elem
		}
		cur = elem
	}
}

// argsForLeaves fills every reachable string with the same value.
//
// All at once rather than one at a time, for the reason the top-level version
// gave: a tool that only mishandles its third argument still gets caught, and
// the call count stays linear in payloads rather than payloads times
// parameters. The cost is that a hit does not name which parameter was
// vulnerable — a follow-up question a human answers quickly once they know
// there is a hit at all.
func argsForLeaves(leaves []leaf, value string) map[string]any {
	args := map[string]any{}
	for _, l := range leaves {
		setLeaf(args, l.path, value)
	}
	return args
}
