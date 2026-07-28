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
	in := bufio.NewReader(os.Stdin)
	fmt.Fprint(a.Stdout, banner)

	// Check the environment first. Being told "Docker is not running" after
	// answering four questions is worse than being told before the first.
	status := a.CheckDocker(ctx)
	if !status.Ready() {
		fmt.Fprintf(a.Stderr, "\n  Docker is not ready: %s\n", status.Detail)
		fmt.Fprintln(a.Stderr, "  detonate needs Docker to sandbox untrusted code.")
		fmt.Fprintln(a.Stderr, "  Install Docker Desktop, start it, and run detonate again.")
		return exitUsage
	}
	fmt.Fprintf(a.Stdout, "\n  docker: %s\n", status.Detail)

	kind := a.ask(in, "\n  What do you want to scan?\n"+
		"    1) MCP server   (a plugin for Claude Desktop, Cursor, etc.)\n"+
		"    2) Agent skill  (a folder with a SKILL.md)\n"+
		"\n  Choose [1/2]: ", "1")

	switch strings.TrimSpace(kind) {
	case "2":
		return a.interactiveSkill(in, ctx)
	default:
		return a.interactiveMCP(in, ctx)
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
		fmt.Fprintln(a.Stdout, "  but never runs the server. Without this the scan will fail.")
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
