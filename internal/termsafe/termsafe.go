// Package termsafe strips terminal-control sequences from target-controlled
// strings, so a scanned tool cannot inject ANSI styling or cursor movement into
// scanner output — whether rendered live or replayed from a saved bundle.
//
// It exists as its own leaf package for one reason: the live renderer
// (internal/cli) and the saved-bundle renderer (internal/bundle) must sanitize
// identically. When each had its own copy, the saved path silently shipped
// without any, and the two drifted. One definition, imported by both, cannot.
package termsafe

import (
	"strings"
	"unicode"
)

// Clean removes control runes (including newlines and tabs) and repairs invalid
// UTF-8. Apply it per field, never to a whole multi-line render: it strips the
// newlines that give a render its structure, so the caller keeps the structural
// literals unsanitized and cleans only the target-controlled values between them.
func Clean(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(value, "?"))
}
