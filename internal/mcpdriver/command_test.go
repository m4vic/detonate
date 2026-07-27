package mcpdriver

import (
	"reflect"
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantArgs []string
		wantErr  bool
	}{
		{
			name:     "command and args",
			input:    "uvx some-mcp-server --flag",
			wantName: "uvx",
			wantArgs: []string{"some-mcp-server", "--flag"},
		},
		{
			name:     "quoted path with spaces",
			input:    `"C:/Program Files/py.exe" server.py`,
			wantName: "C:/Program Files/py.exe",
			wantArgs: []string{"server.py"},
		},
		{
			// The reason this package doesn't use POSIX escaping. A shlex-style
			// splitter eats these backslashes and hands exec a path that does
			// not exist, so detonate would report a broken server rather than
			// scanning a working one.
			name:     "windows path keeps its backslashes",
			input:    `C:\Users\me\server.exe --port 8080`,
			wantName: `C:\Users\me\server.exe`,
			wantArgs: []string{"--port", "8080"},
		},
		{
			name:     "single quotes",
			input:    "python -c 'print(1)'",
			wantName: "python",
			wantArgs: []string{"-c", "print(1)"},
		},
		{
			name:     "collapses repeated whitespace",
			input:    "  uvx    server  ",
			wantName: "uvx",
			wantArgs: []string{"server"},
		},
		{
			name:     "empty quoted arg is preserved",
			input:    `srv --name ""`,
			wantName: "srv",
			wantArgs: []string{"--name", ""},
		},
		{name: "empty command", input: "   ", wantErr: true},
		{name: "unterminated quote", input: `srv "unclosed`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, args, err := ParseCommand(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseCommand(%q) = %q %v, want error", tc.input, name, args)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCommand(%q) unexpected error: %v", tc.input, err)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if len(args) != 0 || len(tc.wantArgs) != 0 {
				if !reflect.DeepEqual(args, tc.wantArgs) {
					t.Errorf("args = %#v, want %#v", args, tc.wantArgs)
				}
			}
		})
	}
}
