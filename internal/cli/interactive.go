package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
  ____      _                   _
 |  _ \  ___| |_ ___  _ __   __ _| |_ ___
 | | | |/ _ \ __/ _ \| '_ \ / _' | __/ _ \
 | |_| |  __/ || (_) | | | | (_| | ||  __/
 |____/ \___|\__\___/|_| |_|\__,_|\__\___|

 Run untrusted AI tools in a sandbox. Report what they actually do.
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

// runInteractive drives the wizard and returns a process exit code.
func (a *App) runInteractive(ctx context.Context) int {
	input := a.Stdin
	if input == nil {
		input = os.Stdin
	}
	in := bufio.NewReader(input)
	fmt.Fprint(a.Stdout, banner)
	fmt.Fprintln(a.Stdout, "  alpha: /static is safe by default; /dynamic is experimental.")
	fmt.Fprintln(a.Stdout, "  Commands: /static <target>, /dynamic <target>, /combined <target>, /help, /exit")
	fmt.Fprintln(a.Stdout, "  Paste a target without a slash to use /static.")

	line := strings.TrimSpace(a.ask(in, "\n  detonate> ", ""))
	if line == "" || line == "/exit" || line == "/quit" {
		return exitOK
	}
	if line == "/help" {
		fmt.Fprint(a.Stdout, modeUsage)
		return exitOK
	}
	// A Unix absolute path also begins with '/'. Treat only a non-path slash
	// prefix as a command so `/tmp/server` remains a usable target in Linux
	// containers and CI, while Windows users still get the familiar commands.
	if !strings.HasPrefix(line, "/") || filepath.IsAbs(line) {
		// No --path here: the wizard takes a bare target. A monorepo is
		// reported with the exact commands that reach its packages, which is
		// the answer the user needs anyway.
		return a.scanStatic(ctx, strings.Trim(line, `"'`), "")
	}

	command := strings.Fields(line)[0]
	target := interactiveTarget(line, command)
	switch command {
	case "/static":
		return a.runStatic(ctx, []string{target})
	case "/dynamic":
		return a.runDynamic(ctx, []string{target})
	case "/combined":
		return a.runCombined([]string{target})
	default:
		fmt.Fprintf(a.Stderr, "unknown command %q; use /help\n", command)
		return exitUsage
	}
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
