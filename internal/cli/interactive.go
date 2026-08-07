package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/m4vic/detonate/internal/acquire"
)

// Interactive mode: what `detonate` does when run with no arguments.
//
// The flags exist for CI, where a scan is scripted and nobody is watching. A
// person at a terminal is a different user with a different problem: they have
// a folder they were about to trust and no idea what to type. Making them
// learn that the server's command must reference /target rather than their own
// path — because /target is where we mount it inside the container — is a
// needless obstacle in front of the one thing the tool does.
//
// So the wizard asks where the thing is, works the rest out, and shows the
// equivalent flag form afterwards. The second part matters: someone who runs
// this once by hand and then wants it in CI should be able to copy the line
// rather than reread the docs.

const banner = `
 +----------------------------------------------------------------------------+
 |                                                                            |
 |   ___  ____ _____ ___  _   _    _  _____ _____                             |
 |  |  _ \| ____|_   _/ _ \| \ | |  / \|_   _| ____|                            |
 |  | | | |  _|   | || | | |  \| | / _ \ | | |  _|                              |
 |  | |_| | |___  | || |_| | |\  |/ ___ \| | | |___                             |
 |  |____/|_____| |_| \___/|_| \_/_/   \_\_| |_____|                            |
 |                                                                            |
 |  Dynamic Sandbox for Untrusted AI Tools & MCP Servers | v0.2.0-alpha       |
 +----------------------------------------------------------------------------+
`

// entryPoints are the filenames an MCP server's entry point usually has,
// in the order we guess. Ordering matters: a project with both server.py and
// main.py almost always means server.py.
var entryPoints = []struct {
	file string
	cmd  string
}{
	{"server.py", "python /target/server.py"},
	{"main.py", "python /target/main.py"},
	{"__main__.py", "python /target"},
	{"app.py", "python /target/app.py"},
	{"index.js", "node /target/index.js"},
	{"server.js", "node /target/server.js"},
	{"dist/index.js", "node /target/dist/index.js"},
	{"build/index.js", "node /target/build/index.js"},
}

// runInteractive drives the REPL wizard and returns a process exit code.
func (a *App) runInteractive(ctx context.Context) int {
	input := a.Stdin
	if input == nil {
		input = os.Stdin
	}
	output := a.Stdout
	if output == nil {
		output = os.Stdout
	}

	fmt.Fprint(output, banner)
	fmt.Fprintln(output, "  alpha: /static is safe by default; /dynamic is experimental.")
	fmt.Fprintln(output, "  Commands: /static <target>, /dynamic <target>, /combined <target>, /help, /exit")
	fmt.Fprintln(output, "  Paste a target without a slash to use /static.")

	// Only use readline (with its internal goroutines and terminal raw-mode) when
	// stdin really is a terminal. In CI, during tests, or when input is piped the
	// reader will be a *strings.Reader or *os.File (non-TTY); in those cases
	// readline's goroutines can touch fd state that the race detector flags.
	// The bufio fallback is functionally identical for non-interactive callers.
	isRealTerminal := false
	if f, ok := input.(*os.File); ok {
		info, err := f.Stat()
		if err == nil {
			isRealTerminal = info.Mode()&os.ModeCharDevice != 0
		}
	}

	if isRealTerminal {
		var stdinCloser io.ReadCloser
		if rc, ok := input.(io.ReadCloser); ok {
			stdinCloser = rc
		} else {
			stdinCloser = io.NopCloser(input)
		}

		rl, err := readline.NewEx(&readline.Config{
			Prompt:          "  detonate> ",
			Stdin:           stdinCloser,
			Stdout:          output,
			Stderr:          a.Stderr,
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",
		})
		if err == nil {
			defer rl.Close()
			var lastCode int = exitOK
			fmt.Fprintln(output)
			for {
				line, err := rl.Readline()
				if err != nil {
					break
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if line == "/exit" || line == "/quit" {
					return exitOK
				}
				if line == "/help" {
					fmt.Fprint(output, modeUsage)
					fmt.Fprintln(output)
					continue
				}
				lastCode = a.dispatchInteractiveLine(ctx, line)
				fmt.Fprintln(output)
			}
			return lastCode
		}
	}

	return a.runInteractiveFallback(ctx, input, output)
}

func (a *App) runInteractiveFallback(ctx context.Context, input io.Reader, output io.Writer) int {
	in := bufio.NewReader(input)
	var lastCode int = exitOK
	fmt.Fprintln(output)
	for {
		line := a.ask(in, "  detonate> ", "")
		line = strings.TrimSpace(line)
		if line == "" || line == "/exit" || line == "/quit" {
			break
		}
		if line == "/help" {
			fmt.Fprint(output, modeUsage)
			fmt.Fprintln(output)
			continue
		}
		lastCode = a.dispatchInteractiveLine(ctx, line)
		fmt.Fprintln(output)
	}
	return lastCode
}

func (a *App) dispatchInteractiveLine(ctx context.Context, line string) int {
	// Strip optional "detonate" or "detonate.exe" prefix if typed in REPL
	line = strings.TrimPrefix(line, "detonate.exe ")
	line = strings.TrimPrefix(line, "detonate ")
	line = strings.TrimSpace(line)

	if line == "" {
		return exitOK
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return exitOK
	}

	cmd := fields[0]

	// Handle slash or word subcommands (/static, static, /dynamic, dynamic, /combined, combined)
	switch cmd {
	case "/static", "static":
		if len(fields) < 2 {
			fmt.Fprintln(a.Stderr, "usage: /static <target> [options]")
			return exitUsage
		}
		return a.runStatic(ctx, fields[1:])
	case "/dynamic", "dynamic":
		if len(fields) < 2 {
			fmt.Fprintln(a.Stderr, "usage: /dynamic <target> [options]")
			return exitUsage
		}
		return a.runDynamic(ctx, fields[1:])
	case "/combined", "combined":
		if len(fields) < 2 {
			fmt.Fprintln(a.Stderr, "usage: /combined <target> [options]")
			return exitUsage
		}
		return a.runCombined(fields[1:])
	case "doctor":
		return a.doctor(ctx)
	}

	// If no subcommand was specified, default to static mode with all args passed
	return a.runStatic(ctx, fields)
}

func (a *App) interactiveSkill(in *bufio.Reader, ctx context.Context) int {
	dir := a.askPath(in, "\n  Path to the skill folder (the one containing SKILL.md): ")
	if dir == "" {
		return exitUsage
	}
	if !fileExists(filepath.Join(dir, "SKILL.md")) {
		fmt.Fprintf(a.Stderr, "\n  No SKILL.md in %s\n", dir)
		fmt.Fprintln(a.Stderr, "  A skill folder must contain a SKILL.md file.")
		return exitUsage
	}

	fmt.Fprintf(a.Stdout, "\n  Equivalent command:\n    detonate scan --skill \"%s\"\n\n", dir)
	return a.scan(ctx, []string{"--skill", dir})
}

func (a *App) interactiveMCP(in *bufio.Reader, ctx context.Context) int {
	dir := a.askPath(in, "\n  Path to the server folder: ")
	if dir == "" {
		return exitUsage
	}

	// Guess the command so nobody has to learn about /target.
	cmd := guessCommand(dir)
	if cmd == "" {
		fmt.Fprintln(a.Stdout, "\n  Could not find an obvious entry point in that folder.")
		fmt.Fprintln(a.Stdout, "  Enter the command that starts the server. Inside the sandbox")
		fmt.Fprintln(a.Stdout, "  your folder is mounted at /target, so use paths like")
		fmt.Fprintln(a.Stdout, "  'python /target/server.py'.")
		cmd = strings.TrimSpace(a.ask(in, "\n  Command: ", ""))
		if cmd == "" {
			fmt.Fprintln(a.Stderr, "  No command given.")
			return exitUsage
		}
	} else {
		fmt.Fprintf(a.Stdout, "\n  Detected entry point. Command: %s\n", cmd)
		if ans := a.ask(in, "  Use this? [Y/n]: ", "y"); strings.HasPrefix(strings.ToLower(ans), "n") {
			cmd = strings.TrimSpace(a.ask(in, "  Command: ", ""))
			if cmd == "" {
				return exitUsage
			}
		}
	}

	// Offer the install phase only when there is something to install, and
	// default to yes: a server with a manifest will simply fail without it.
	args := []string{"--mcp", cmd, "--dir", dir}
	if m := acquire.Detect(dir); m.Ecosystem != acquire.EcosystemNone {
		fmt.Fprintf(a.Stdout, "\n  Found %s (%s dependencies).\n", m.File, m.Ecosystem)
		fmt.Fprintln(a.Stdout, "  These install in a separate container that has network access")
		fmt.Fprintln(a.Stdout, "  and may execute dependency/build hooks as root. Without this the scan will fail.")
		if ans := a.ask(in, "\n  Install dependencies? [Y/n]: ", "y"); !strings.HasPrefix(strings.ToLower(ans), "n") {
			args = append(args, "--install")
		}
	}

	fmt.Fprint(a.Stdout, "\n  Equivalent command:\n    detonate scan")
	for _, arg := range args {
		if strings.ContainsAny(arg, " \\/") {
			fmt.Fprintf(a.Stdout, " \"%s\"", arg)
		} else {
			fmt.Fprintf(a.Stdout, " %s", arg)
		}
	}
	fmt.Fprint(a.Stdout, "\n\n")

	return a.scan(ctx, args)
}

// guessCommand finds a likely entry point so the user never has to think
// about the /target mount path.
func guessCommand(dir string) string {
	for _, e := range entryPoints {
		if fileExists(filepath.Join(dir, filepath.FromSlash(e.file))) {
			return e.cmd
		}
	}
	return ""
}

// ask prints a prompt and reads one line, returning def if the answer is empty.
func (a *App) ask(in *bufio.Reader, prompt, def string) string {
	fmt.Fprint(a.Stdout, prompt)
	line, err := in.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return def
	}
	if s := strings.TrimSpace(line); s != "" {
		return s
	}
	return def
}

// askPath reads a path and validates it, because a typo caught here is much
// cheaper than one that surfaces as a container failing to start.
func (a *App) askPath(in *bufio.Reader, prompt string) string {
	raw := strings.TrimSpace(a.ask(in, prompt, ""))
	// Terminals and drag-and-drop both add quotes; strip them rather than
	// failing on a path the user pasted correctly.
	raw = strings.Trim(raw, `"'`)
	if raw == "" {
		fmt.Fprintln(a.Stderr, "  No path given.")
		return ""
	}

	abs, err := filepath.Abs(raw)
	if err != nil {
		fmt.Fprintf(a.Stderr, "  Bad path: %v\n", err)
		return ""
	}
	info, err := os.Stat(abs)
	if err != nil {
		fmt.Fprintf(a.Stderr, "\n  That path does not exist:\n    %s\n", abs)
		return ""
	}
	if !info.IsDir() {
		fmt.Fprintf(a.Stderr, "\n  That is a file, not a folder:\n    %s\n", abs)
		fmt.Fprintln(a.Stderr, "  Give the folder that contains it.")
		return ""
	}
	return abs
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// stdinIsTerminal reports whether we can prompt.
//
// Without this check, `detonate` in a CI job with no terminal would block
// forever on a question nobody can answer — a hung pipeline is a much worse
// failure than a usage message.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
