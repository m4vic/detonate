package termsafe

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Clean defangs by removing the control runes that make an escape sequence
// *executable*, not by matching sequence grammars. The printable remainder of a
// sequence survives as inert text — `\x1b[31m` becomes `[31m`. These cases pin
// that contract exactly, because the alternative reading ("the whole sequence
// disappears") would look equally correct on a casual test and is not what the
// renderers rely on.
//
// Control characters appear here only as escapes, never as literal bytes: a raw
// C1 byte in source is invisible in review and easy for an editor to mangle.
func TestCleanRemovesTerminalControl(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "SGR colour sequence",
			input: "\x1b[31mred\x1b[0m",
			want:  "[31mred[0m",
		},
		{
			name:  "CSI cursor movement and screen clear",
			input: "\x1b[2J\x1b[H",
			want:  "[2J[H",
		},
		{
			name:  "OSC 8 hyperlink, BEL-terminated",
			input: "\x1b]8;;https://evil.example\x07label\x1b]8;;\x07",
			want:  "]8;;https://evil.examplelabel]8;;",
		},
		{
			name:  "bare C0 controls and DEL",
			input: "\x00\x08\x7f",
			want:  "",
		},
		{
			name:  "C1 eight-bit CSI introducer",
			input: string(rune(0x9b)) + "31m",
			want:  "31m",
		},
		{
			name:  "carriage return cannot rewrite the line",
			input: "real finding\rFAKE CLEAN RESULT",
			want:  "real findingFAKE CLEAN RESULT",
		},
		{
			name:  "printable text is untouched",
			input: "tool \"get_current_time\" has no adversarial string-input surface",
			want:  "tool \"get_current_time\" has no adversarial string-input surface",
		},
		{
			name:  "non-ASCII text and emoji survive",
			input: "日本語 · café · 🎯",
			want:  "日本語 · café · 🎯",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Clean(tc.input); got != tc.want {
				t.Fatalf("Clean(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// The newline-stripping behaviour is not incidental — it is the reason
// bundle.Text sanitizes each target-controlled field separately instead of
// wrapping the finished render. If Clean ever starts preserving newlines, that
// caller's structure comment becomes wrong and this test should fail loudly.
func TestCleanStripsNewlinesAndTabs(t *testing.T) {
	got := Clean("line one\nline two\r\n\tindented")
	want := "line oneline twoindented"
	if got != want {
		t.Fatalf("Clean = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("Clean kept structural whitespace: %q", got)
	}
}

func TestCleanRepairsInvalidUTF8(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "lone continuation byte", input: "a\xffb", want: "a?b"},
		{name: "run collapses to one marker", input: "a\xff\xfe\xfdb", want: "a?b"},
		{name: "truncated multi-byte rune", input: "caf\xc3", want: "caf?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Clean(tc.input)
			if got != tc.want {
				t.Fatalf("Clean(%q) = %q, want %q", tc.input, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("Clean returned invalid UTF-8: %q", got)
			}
		})
	}
}

// Both renderers may clean a value that has already been cleaned upstream.
// A second pass must be a no-op, or output would depend on how many layers a
// value happened to pass through.
func TestCleanIsIdempotent(t *testing.T) {
	for _, input := range []string{
		"\x1b[31mred\x1b[0m",
		"a\xffb",
		"plain text",
		"\x00\x1b]8;;x\x07",
	} {
		once := Clean(input)
		if twice := Clean(once); twice != once {
			t.Fatalf("Clean not idempotent for %q: %q then %q", input, once, twice)
		}
	}
}

// The invariant, stated independently of any specific input: whatever a target
// sends, the result carries no control runes and is valid UTF-8. Table cases
// cover the sequences known to matter; this covers the ones nobody thought of.
func FuzzCleanNeverEmitsControlRunes(f *testing.F) {
	for _, seed := range []string{
		"", "plain", "\x1b[31mred\x1b[0m", "\x1b]8;;https://evil.example\x07x",
		"a\xffb", string(rune(0x9b)) + "31m", "line\nbreak", "日本語 🎯", "\x00\x08\x7f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := Clean(input)
		if !utf8.ValidString(got) {
			t.Fatalf("Clean(%q) returned invalid UTF-8: %q", input, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) {
				t.Fatalf("Clean(%q) kept control rune %U in %q", input, r, got)
			}
		}
		if strings.ContainsRune(got, 0x1b) {
			t.Fatalf("Clean(%q) kept an ESC introducer: %q", input, got)
		}
	})
}
