package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/fetch"
)

// Target auto-detection: work out what the user pointed at.
//
// The old CLI made the user declare the kind up front (--mcp, --skill,
// --prompt) and then separately turn on the checks that make a scan worth
// running (--install, --probe, --run-scripts). Both are things detonate can
// determine for itself, and every one it cannot determine is a chance to get
// it wrong.
//
// A folder with a SKILL.md is a skill. A folder with a server.py and a
// pyproject.toml is an MCP server that needs its dependencies installed. A
// .txt file is a prompt. Making a person state each of those is asking them to
// do the tool's job before the tool will do theirs.

// Kind is what a target turned out to be.
type Kind string

const (
	KindMCP     Kind = "mcp"
	KindSkill   Kind = "skill"
	KindPrompt  Kind = "prompt"
	KindUnknown Kind = "unknown"
)

// Detected is the result of examining a target.
type Detected struct {
	Kind Kind

	// Dir is the folder to scan (mcp, skill) or File the text to read (prompt).
	Dir  string
	File string

	// Command starts an MCP server, using the /target mount path.
	Command string

	// NeedsInstall is true when a dependency manifest was found.
	NeedsInstall bool
	Manifest     string

	// Scripts counts a skill's bundled scripts, so the caller can say whether
	// running them is worth offering.
	Scripts int

	// Why explains the decision, printed so a user can correct a wrong guess
	// rather than wondering what the tool decided about their folder.
	Why string
}

// promptExtensions are files we treat as instruction text.
//
// Deliberately narrow. A scan that silently treats a source file as a prompt
// would produce confusing findings about code, so anything not obviously prose
// is rejected rather than guessed at.
var promptExtensions = map[string]bool{
	".txt": true, ".md": true, ".prompt": true, ".xml": true,
}

// Detect examines a path or URL and decides what it is.
//
// Errors are for genuinely unusable input. An ambiguous folder returns
// KindUnknown with an explanation, so the caller can ask rather than guess:
// scanning the wrong thing produces confident findings about something the
// user never asked about, which is worse than a question.
func Detect(target string) (Detected, error) {
	target = strings.Trim(strings.TrimSpace(target), `"'`)
	if target == "" {
		return Detected{}, fmt.Errorf("no target given")
	}

	// URLs are resolved by the caller (it owns the clone's lifetime), so this
	// only reports that a fetch is needed.
	if fetch.IsURL(target) {
		return Detected{Kind: KindUnknown, Why: "remote repository"}, nil
	}

	abs, err := filepath.Abs(target)
	if err != nil {
		return Detected{}, fmt.Errorf("bad path %q: %w", target, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Detected{}, fmt.Errorf("%s does not exist", abs)
	}

	if !info.IsDir() {
		if !promptExtensions[strings.ToLower(filepath.Ext(abs))] {
			return Detected{}, fmt.Errorf(
				"%s is a file. For a prompt use .txt or .md; for a server or skill, "+
					"give the folder that contains it", filepath.Base(abs))
		}
		return Detected{
			Kind: KindPrompt, File: abs,
			Why: "a text file, analysed as instructions an agent would read",
		}, nil
	}

	return detectDir(abs)
}

func detectDir(dir string) (Detected, error) {
	// A SKILL.md is unambiguous and takes priority: a skill folder can also
	// contain Python, and that Python is a bundled script rather than a server.
	if fileExists(filepath.Join(dir, "SKILL.md")) {
		scripts := countScripts(dir)
		return Detected{
			Kind: KindSkill, Dir: dir, Scripts: scripts,
			Why: fmt.Sprintf("contains SKILL.md (%d bundled script(s))", scripts),
		}, nil
	}

	m := acquire.Detect(dir)

	cmd := guessCommand(dir)
	// A package.json with no obvious entry file still names its start command
	// in "bin" or "main". Reading it beats guessing, and beats reporting "no
	// recognisable entry point" for a project that plainly states one.
	if cmd == "" && m.Ecosystem == acquire.EcosystemNode {
		cmd = nodeEntryFromPackageJSON(dir)
	}

	if cmd == "" {
		if m.Ecosystem == acquire.EcosystemNone {
			return Detected{
				Kind: KindUnknown, Dir: dir,
				Why: "no SKILL.md, no recognisable entry point, no dependency manifest",
			}, nil
		}
		// A manifest with no obvious entry point is a real project whose start
		// command we simply cannot guess, which is a question, not a failure.
		return Detected{
			Kind: KindUnknown, Dir: dir,
			NeedsInstall: true, Manifest: m.File,
			Why: fmt.Sprintf("found %s but no recognisable entry point", m.File),
		}, nil
	}

	d := Detected{Kind: KindMCP, Dir: dir, Command: cmd}
	if m.Ecosystem != acquire.EcosystemNone {
		d.NeedsInstall = true
		d.Manifest = m.File
		d.Why = fmt.Sprintf("entry point detected, plus %s to install", m.File)
	} else {
		d.Why = "entry point detected, no dependencies to install"
	}
	return d, nil
}

// nodeEntryFromPackageJSON reads the start command a Node project declares.
//
// "bin" first, then "main". A published MCP server declares a bin entry
// because that is how it gets launched by an agent host, so it is the closest
// thing to a statement of intent the package offers.
func nodeEntryFromPackageJSON(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ""
	}

	var pkg struct {
		Bin  json.RawMessage `json:"bin"`
		Main string          `json:"main"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ""
	}

	// "bin" is either a string or an object of name -> path.
	if len(pkg.Bin) > 0 {
		var s string
		if json.Unmarshal(pkg.Bin, &s) == nil && s != "" {
			return "node /target/" + strings.TrimPrefix(filepath.ToSlash(s), "./")
		}
		var m map[string]string
		if json.Unmarshal(pkg.Bin, &m) == nil {
			// Sorted so the same package always yields the same command;
			// map order in Go is random, and a scan that picks a different
			// entry point per run is not reproducible.
			names := make([]string, 0, len(m))
			for k := range m {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, n := range names {
				if p := m[n]; p != "" {
					return "node /target/" + strings.TrimPrefix(filepath.ToSlash(p), "./")
				}
			}
		}
	}

	if pkg.Main != "" {
		return "node /target/" + strings.TrimPrefix(filepath.ToSlash(pkg.Main), "./")
	}
	return ""
}

func countScripts(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".py", ".sh", ".js", ".ts":
			n++
		}
	}
	return n
}
