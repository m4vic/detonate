package fetch

import "testing"

func TestIsURLDistinguishesGitURLsFromLocalPaths(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/example/server", true},
		{"github.com/example/server", true},
		{"git@github.com:example/server.git", true},
		{"./archive/python-m1-tests/fixtures/sample_skill", false},
		{"../skills/sample", false},
		{`C:\work\server`, false},
		{`\\server\share\target`, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsURL(tt.input); got != tt.want {
				t.Errorf("IsURL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
