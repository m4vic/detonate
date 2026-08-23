package probe

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The exact schema that exposed the hole: the official memory server's
// create_entities. Every string in it is caller-controlled, and not one of them
// is a top-level property, so the tool reported "no adversarial string-input
// surface" and was never probed.
const memoryCreateEntities = `{
	"type": "object",
	"required": ["entities"],
	"properties": {
		"entities": {
			"type": "array",
			"items": {
				"type": "object",
				"required": ["name", "entityType", "observations"],
				"properties": {
					"name":         {"type": "string"},
					"entityType":   {"type": "string"},
					"observations": {"type": "array", "items": {"type": "string"}}
				}
			}
		}
	}
}`

func TestNestedStringsAreReachable(t *testing.T) {
	leaves := stringLeaves(json.RawMessage(memoryCreateEntities))
	if len(leaves) == 0 {
		t.Fatal("no injection points found in create_entities; this is the original defect")
	}

	got := leafNames(leaves)
	want := []string{"entityType", "name", "observations"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reachable strings = %v, want %v", got, want)
	}
}

// Finding the leaves is only half of it — the payload has to actually arrive at
// the right place in the JSON the target receives.
func TestPayloadLandsInsideTheNestedObject(t *testing.T) {
	args := argsForLeaves(stringLeaves(json.RawMessage(memoryCreateEntities)), "PAYLOAD")

	entities, ok := args["entities"].([]any)
	if !ok || len(entities) != 1 {
		t.Fatalf("entities = %#v, want a one-element array", args["entities"])
	}
	el, ok := entities[0].(map[string]any)
	if !ok {
		t.Fatalf("element = %#v, want an object", entities[0])
	}
	for _, field := range []string{"name", "entityType"} {
		if el[field] != "PAYLOAD" {
			t.Errorf("entities[0].%s = %#v, want the payload", field, el[field])
		}
	}
	// An array of strings: the element itself is the injection point, not some
	// property of it.
	obs, ok := el["observations"].([]any)
	if !ok || len(obs) != 1 || obs[0] != "PAYLOAD" {
		t.Errorf("observations = %#v, want [\"PAYLOAD\"]", el["observations"])
	}
}

// Whatever is built has to survive the target's own schema validation, or the
// tool errors before it runs and takes the blame as target_error — the failure
// mode that required non-string parameters were added to prevent.
func TestNestedArgumentsAreSchemaValid(t *testing.T) {
	args := argsForLeaves(stringLeaves(json.RawMessage(memoryCreateEntities)), "x")
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("arguments do not marshal: %v", err)
	}
	// No nils anywhere: a null where a string is required fails validation just
	// as hard as an absent field.
	if strings.Contains(string(encoded), "null") {
		t.Errorf("arguments contain a null: %s", encoded)
	}
}

func TestLeafWalkShapes(t *testing.T) {
	for _, tc := range []struct {
		name, schema string
		want         []string
	}{
		{
			// The behaviour that must not regress: top-level strings, and
			// untyped properties treated as strings.
			name:   "top level",
			schema: `{"properties":{"path":{"type":"string"},"loose":{},"n":{"type":"number"}}}`,
			want:   []string{"loose", "path"},
		},
		{
			name:   "nested object",
			schema: `{"properties":{"cfg":{"type":"object","properties":{"host":{"type":"string"}}}}}`,
			want:   []string{"host"},
		},
		{
			// An object that declares properties but omits "type" is still an
			// object; reading it as an untyped string would inject into the
			// container instead of its contents.
			name:   "object without a declared type",
			schema: `{"properties":{"cfg":{"properties":{"host":{"type":"string"}}}}}`,
			want:   []string{"host"},
		},
		{
			name:   "array of strings",
			schema: `{"properties":{"tags":{"type":"array","items":{"type":"string"}}}}`,
			want:   []string{"tags"},
		},
		{
			name:   "no strings anywhere",
			schema: `{"properties":{"n":{"type":"number"},"ok":{"type":"boolean"}}}`,
			want:   nil,
		},
		{
			name:   "malformed",
			schema: `not json`,
			want:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := leafNames(stringLeaves(json.RawMessage(tc.schema)))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("= %v, want %v", got, tc.want)
			}
		})
	}
}

// The schema is written by the target, so its size is the target's choice. A
// schema that nests forever, or declares thousands of properties, would turn
// one tool into an unbounded number of arguments per payload — a denial of
// service against the scanner, written in JSON.
func TestHostileSchemasAreBounded(t *testing.T) {
	deep := `{"type":"string"}`
	for i := 0; i < 200; i++ {
		deep = `{"type":"object","properties":{"a":` + deep + `}}`
	}
	if n := len(stringLeaves(json.RawMessage(`{"properties":{"a":` + deep + `}}`))); n > maxStringLeaves {
		t.Errorf("deep schema produced %d leaves", n)
	}

	var wide strings.Builder
	wide.WriteString(`{"properties":{`)
	for i := 0; i < 500; i++ {
		if i > 0 {
			wide.WriteString(",")
		}
		wide.WriteString(`"p`)
		wide.WriteString(string(rune('a' + i%26)))
		wide.WriteString(string(rune('a' + (i/26)%26)))
		wide.WriteString(`":{"type":"string"}`)
	}
	wide.WriteString(`}}`)
	if n := len(stringLeaves(json.RawMessage(wide.String()))); n > maxStringLeaves {
		t.Errorf("wide schema produced %d leaves, want at most %d", n, maxStringLeaves)
	}
}

// Two scans of an unchanged target must send the same arguments, or a
// difference between runs cannot be attributed to the target. Go randomises map
// iteration, so this is not free.
func TestLeafOrderIsStable(t *testing.T) {
	schema := json.RawMessage(`{"properties":{
		"c":{"type":"string"},"a":{"type":"string"},"b":{"type":"string"},
		"nested":{"type":"object","properties":{"z":{"type":"string"},"y":{"type":"string"}}}
	}}`)

	first := leafNames(stringLeaves(schema))
	for i := 0; i < 50; i++ {
		if got := leafNames(stringLeaves(schema)); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d gave %v, first run gave %v", i, got, first)
		}
	}
}

// An enum one level down constrains its parameter exactly as much as one at the
// top, and a path is not a valid answer to either.
func TestNestedEnumsAreRespected(t *testing.T) {
	leaves := stringLeaves(json.RawMessage(`{"properties":{
		"opts":{"type":"object","properties":{
			"sortBy":{"type":"string","enum":["name","size"]}
		}}
	}}`))
	if len(leaves) != 1 {
		t.Fatalf("leaves = %d, want 1", len(leaves))
	}
	if got := leaves[0].enum; !reflect.DeepEqual(got, []string{"name", "size"}) {
		t.Errorf("enum = %v, want [name size]", got)
	}
}

// The read-only rootfs is deliberate, so a target that trips over it is not
// broken. The official memory server persists its knowledge graph next to its
// entry point; six of its eleven tools answered EROFS on a valid call and were
// recorded as target_error — detonate blaming a working server for detonate's
// own mount.
func TestSandboxDenialIsNotTheTargetsFault(t *testing.T) {
	denied := []string{
		`{"type":"text","text":"EROFS: read-only file system, open '/target/dist/memory.jsonl'"}`,
		"Error: read-only file system",
		"EACCES: permission denied, mkdir '/target/out'",
		"permission denied, open '/target/db.sqlite'",
	}
	for _, s := range denied {
		if !isSandboxDenied(s) {
			t.Errorf("isSandboxDenied(%q) = false; the sandbox caused this", s)
		}
	}

	// A tool refusing to read a secret is working correctly, and calling that a
	// sandbox problem would hide the one behaviour worth seeing.
	notDenied := []string{
		"permission denied: /etc/shadow",
		"EACCES: cannot read /home/detonate/.ssh/id_rsa",
		"invalid path",
		"ENOENT: no such file or directory",
		"access denied by policy",
		"",
	}
	for _, s := range notDenied {
		if isSandboxDenied(s) {
			t.Errorf("isSandboxDenied(%q) = true, want false", s)
		}
	}
}
