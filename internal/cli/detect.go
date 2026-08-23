package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/fetch"
	"github.com/m4vic/detonate/internal/skill"
	"github.com/m4vic/detonate/internal/staticinv"
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

	// Packages names scannable sub-directories found when the folder itself
	// could not be classified. A monorepo is the common case and the most
	// likely thing a person pastes: github.com/modelcontextprotocol/servers
	// holds every reference server and is not itself one.
	Packages []string
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

	// An MCPB manifest is a definitive statement that this directory IS an MCP
	// server — stronger evidence than any entry-point guess, because the target
	// declared it rather than us inferring it.
	//
	// Checked before the guessing path for a concrete reason: a bundle keeps its
	// code under server/, which matches none of the guessed filenames, so an
	// MCPB bundle with a perfectly good manifest was reported as "no
	// recognisable entry point" and refused. That made the declared tool list
	// unreachable for exactly the targets that publish one.
	bundle := staticinv.Extract(dir)
	if bundle.Source == staticinv.SourceMCPBManifest {
		d := Detected{
			Kind: KindMCP, Dir: dir,
			// A declared command is preferred, but its absence does not
			// downgrade the detection: static analysis needs no command, and
			// dynamic mode already asks for --cmd when one is missing.
			Command: bundle.StartCommand("/target"),
			Why:     "MCPB manifest.json declares an MCP server",
		}
		if d.Command == "" {
			if declared := m.StartCommand(); declared != "" {
				d.Command = declared
			} else {
				d.Command = guessCommand(dir)
			}
		}
		if m.Ecosystem != acquire.EcosystemNone {
			d.NeedsInstall = true
			d.Manifest = m.File
			d.Why += fmt.Sprintf(", plus %s to install", m.File)
		}
		return d, nil
	}

	cmd := guessCommand(dir)
	// A package.json with no obvious entry file still names its start command
	// in "bin" or "main". Reading it beats guessing, and beats reporting "no
	// recognisable entry point" for a project that plainly states one.
	//
	// Fall back to what the manifest declares, and prefer it outright when the
	// project must be built: a TypeScript server usually has an index.ts in
	// the root that a guess would happily latch onto, but `node index.ts` is
	// not how it starts — the compiled dist/ is.
	//
	// This is also the only way Python servers are found at all. They keep
	// their code in src/<package>/ and are started through the installed
	// module, so there is no top-level file to guess and every one of the
	// official reference servers reported "no recognisable entry point".
	if declared := m.StartCommand(); declared != "" && (cmd == "" || m.NeedsBuild) {
		cmd = declared
	}

	if cmd == "" {
		// Before giving up, look one level down. A repository that holds many
		// servers rather than being one is the likeliest thing a person pastes,
		// and "no recognisable entry point" is a dead end for a folder whose
		// contents are perfectly scannable one directory deeper.
		packages := findPackages(dir)

		if m.Ecosystem == acquire.EcosystemNone {
			return Detected{
				Kind: KindUnknown, Dir: dir, Packages: packages,
				Why: "no SKILL.md, no recognisable entry point, no dependency manifest",
			}, nil
		}
		// A manifest with no obvious entry point is a real project whose start
		// command we simply cannot guess, which is a question, not a failure.
		return Detected{
			Kind: KindUnknown, Dir: dir, Packages: packages,
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

// packageParents are the directories a monorepo keeps its packages in.
//
// Deliberately a fixed list rather than a full tree walk. Recursing an
// arbitrary repository is slow and finds node_modules, test fixtures and
// vendored copies — suggestions that waste the reader's attention. These four
// cover the conventions in practice, including `src/`, which is where the MCP
// reference servers live.
var packageParents = []string{"src", "packages", "servers", "skills"}

// maxSuggestedPackages bounds the list. A repository with sixty packages
// should print a usable sample and say there are more, not a wall of paths
// nobody reads.
const maxSuggestedPackages = 8

// findPackages looks one level down for directories that are themselves
// scannable, so an unclassifiable folder can name what IS scannable inside it.
//
// One level only, and only under known parents. The point is to answer "what
// did you mean?" cheaply, not to enumerate a repository.
func findPackages(dir string) []string {
	var found []string

	for _, parent := range packageParents {
		entries, err := os.ReadDir(filepath.Join(dir, parent))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			child := filepath.Join(dir, parent, entry.Name())
			// Reuse real detection rather than guessing from filenames. A
			// suggestion that turns out not to be scannable is worse than no
			// suggestion: the user follows it and gets the same dead end.
			d, err := detectDir(child)
			if err != nil || d.Kind == KindUnknown {
				continue
			}
			found = append(found, filepath.ToSlash(filepath.Join(parent, entry.Name())))
			if len(found) >= maxSuggestedPackages {
				return found
			}
		}
	}
	return found
}

// countScripts reports how many bundled scripts a skill would detonate.
//
// Delegates to the skill package rather than counting here. A second copy of
// this logic is a second chance to disagree with the code that actually runs
// the scripts, and that is exactly what happened: this counted only the top
// level while the convention puts executable code in scripts/, so the plan
// line promised "analyse instructions only" for skills full of Python.
func countScripts(dir string) int {
	scripts, err := skill.FindBundledScripts(dir)
	if err != nil {
		return 0
	}
	return len(scripts)
}
