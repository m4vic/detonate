package mcpdriver

import (
	"fmt"
	"strings"
)

// ParseCommand splits a shell-style command string ("uvx some-server --flag")
// into the executable name and its arguments.
//
// Go has no shlex in the standard library, so this is hand-written. It is a
// deliberately small tokenizer: it honours single and double quotes, and
// nothing else.
//
// In particular it does NOT treat backslash as an escape character, which is
// where a naive port of Python's shlex.split() would go wrong. On Windows the
// backslash is the path separator, so a POSIX-style shlex quietly eats it:
//
//	shlex.split(`C:\Users\me\server.exe`)  ->  ["C:Usersmeserver.exe"]
//
// A scanner that mangles the path to the thing it is scanning is worse than
// one that refuses, so on the platform where that input is most likely we
// treat backslash as an ordinary character. Users who need a literal quote or
// a space in a path can still quote the argument.
func ParseCommand(command string) (name string, args []string, err error) {
	fields, err := splitFields(command)
	if err != nil {
		return "", nil, err
	}
	if len(fields) == 0 {
		return "", nil, fmt.Errorf("empty MCP command: %q", command)
	}
	return fields[0], fields[1:], nil
}

func splitFields(s string) ([]string, error) {
	var (
		fields  []string
		current strings.Builder
		quote   rune // 0 when not inside quotes, else the opening quote char
		started bool // distinguishes "" (an intentional empty arg) from no arg
	)

	flush := func() {
		if started {
			fields = append(fields, current.String())
			current.Reset()
			started = false
		}
	}

	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0 // closing quote; the field itself continues
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			started = true // so `--flag=""` keeps its empty value
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			current.WriteRune(r)
			started = true
		}
	}

	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote in command: %q", quote, s)
	}
	flush()
	return fields, nil
}
