package staticinv

import (
	"bytes"
	"encoding/json"
)

// declarationLines finds the line in the manifest that each declared tool
// should be reported against.
//
// This exists so a finding can say "manifest.json:14" rather than just naming
// the directory that was scanned. That is the difference between a SARIF result
// GitHub renders inline on the diff, next to the poisoned text, and one it
// attaches to nothing because the path it was given is a folder.
//
// The offsets come from the JSON token stream, not from searching the text for
// the tool's name. A manifest is target-controlled: a tool named
// `"description"`, or a description containing `"name": "read_file"`, would
// send a text search to the wrong line, and a wrong line points a reviewer at
// innocent text. Walking the tokens cannot be fooled this way, because the
// decoder tells us where it actually is.
//
// Best effort by contract. Any malformed or surprising shape returns zeroes,
// which the caller reports as "this file, line unknown" — a missing line
// degrades the annotation, while a wrong one is a false piece of evidence.
func declarationLines(raw []byte, count int) []int {
	lines := make([]int, count)
	if count == 0 {
		return lines
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return lines
	}

	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return lines
		}
		if name, _ := key.(string); name != "tools" {
			if err := skipValue(dec); err != nil {
				return lines
			}
			continue
		}

		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			return lines
		}
		for i := 0; dec.More(); i++ {
			// The offset before the element is the end of the previous token,
			// so it can sit on the previous line. Only offsets taken just
			// after a token are trusted below.
			at, err := describedAt(dec)
			if err != nil {
				return lines
			}
			if i < count && at > 0 {
				lines[i] = lineAt(raw, at)
			}
		}
		// The array we came for has been consumed; nothing after it matters.
		return lines
	}
	return lines
}

// describedAt consumes one element of the tools array and returns the byte
// offset of the end of its "description" key, which is always on the same line
// as that key. The description is what an attacker poisons, so it is the line
// worth pointing at; a tool that declares none falls back to its "name" key,
// and an element that is not an object at all returns 0.
func describedAt(dec *json.Decoder) (int64, error) {
	t, err := dec.Token()
	if err != nil {
		return 0, err
	}
	if t != json.Delim('{') {
		return 0, skipRest(dec, t)
	}

	var description, name int64
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return 0, err
		}
		// Taken immediately after the key token, so this offset is inside the
		// key's own line whatever the manifest's formatting.
		end := dec.InputOffset()
		switch s, _ := k.(string); {
		case s == "description" && description == 0:
			description = end
		case s == "name" && name == 0:
			name = end
		}
		if err := skipValue(dec); err != nil {
			return 0, err
		}
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return 0, err
	}

	if description > 0 {
		return description, nil
	}
	return name, nil
}

// skipValue consumes exactly one JSON value, however deeply nested.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	return skipRest(dec, t)
}

// skipRest consumes the remainder of a value whose first token has already
// been read. A scalar is already complete; a container is read to its match.
func skipRest(dec *json.Decoder, first json.Token) error {
	d, ok := first.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	for depth := 1; depth > 0; {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// lineAt converts a byte offset into a 1-based line number.
func lineAt(raw []byte, offset int64) int {
	if offset <= 0 || offset > int64(len(raw)) {
		return 0
	}
	return 1 + bytes.Count(raw[:offset], []byte{'\n'})
}
