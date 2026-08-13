// Package acquire installs a target's dependencies before it is detonated.
//
// This exists because of a hard constraint the sandbox creates: the detonation
// container has no network, and almost every real MCP server needs one to
// install (`from mcp.server.fastmcp import FastMCP` requires a pip install).
// Without this package detonate can only scan stdlib-only servers, which is a
// demo rather than a tool.
//
// The answer is separate trust phases:
//
//	FETCH      network ON, root allowed, target scripts disabled
//	BUILD      network OFF, non-root, lifecycle/build scripts observed
//	DETONATE   network OFF, non-root, dependencies mounted read-only
//
// Install scripts remain evidence: they run in BUILD, where they can be
// observed without being allowed to combine network access and root.
package acquire

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ecosystem is the package manager a target needs.
type Ecosystem string

const (
	EcosystemNone   Ecosystem = "none" // stdlib only; nothing to install
	EcosystemPython Ecosystem = "python"
	EcosystemNode   Ecosystem = "node"
)

// Manifest is what a target declares it depends on.
type Manifest struct {
	Ecosystem Ecosystem

	// File is the manifest's name relative to the target directory, empty when
	// Ecosystem is None.
	File string

	// Entry is the start file a Node package declares, relative to the target
	// directory and slash-separated. Empty for other ecosystems, and for a
	// package.json that declares neither bin nor main.
	Entry string

	// NeedsBuild is true when Entry does not exist on disk but a build script
	// does — the signature of a TypeScript project whose compiled output is
	// generated at publish time and gitignored in source.
	//
	// This is most of the published MCP ecosystem. Without a build phase every
	// one of those targets fails phase 2 with MODULE_NOT_FOUND, which is a
	// scan that says nothing about the target's safety.
	NeedsBuild bool

	// PyEntry is the console script a Python project declares, as the raw
	// "module:function" spec, e.g. "mcp_server_fetch:main" from the pyproject
	// entry  mcp-server-fetch = "mcp_server_fetch:main".
	//
	// Python servers rarely keep a runnable file at the top level — the code
	// lives in src/<package>/ and is reached through the installed package —
	// so filename guessing finds nothing and the declaration is the only
	// statement of how to start them. Both halves are kept because a console
	// script calls the function directly; `python -m module` is not equivalent
	// and fails on any package without a __main__.py.
	PyEntry string
}

// StartCommand is the command that launches this project inside the sandbox,
// or "" when the manifest declares none.
//
// Both ecosystems are answered here so that "how is this started" lives with
// the code that already parses the manifest, rather than being re-derived by
// whoever needs it.
func (m Manifest) StartCommand() string {
	switch m.Ecosystem {
	case EcosystemNode:
		if m.Entry != "" {
			return "node /target/" + m.Entry
		}
	case EcosystemPython:
		if mod, fn, ok := strings.Cut(m.PyEntry, ":"); ok && mod != "" && fn != "" {
			// python -c, not -m: the console-script form "module:function"
			// means "call function", and -m only works for a package that
			// ships a __main__.py. mcp-atlassian and most FastMCP servers do
			// not, so -m failed with "cannot be directly executed" for the
			// bulk of the Python ecosystem.
			//
			// After pip install --target, the package is on PYTHONPATH, so the
			// import resolves without the source tree being importable itself.
			return fmt.Sprintf("python -c \"from %s import %s; %s()\"", mod, fn, fn)
		}
	}
	return ""
}

// manifestFiles maps a filename to the ecosystem that owns it, in priority
// order. requirements.txt comes before pyproject.toml because it is the more
// specific instruction: a project with both is telling us exactly what to
// install rather than how it is packaged.
var manifestFiles = []struct {
	name string
	eco  Ecosystem
}{
	{"requirements.txt", EcosystemPython},
	{"pyproject.toml", EcosystemPython},
	{"setup.py", EcosystemPython},
	{"package.json", EcosystemNode},
}

// Detect reports what a target directory needs installed.
//
// Only the top level is examined. A manifest buried in a subdirectory belongs
// to a vendored component or an example, and guessing which of several
// manifests is authoritative is worse than reporting none: a scan that
// installs the wrong dependency set produces findings about software the user
// did not ask about.
func Detect(dir string) Manifest {
	for _, m := range manifestFiles {
		if !fileExists(filepath.Join(dir, m.name)) {
			continue
		}
		found := Manifest{Ecosystem: m.eco, File: m.name}
		if m.eco == EcosystemPython && m.name == "pyproject.toml" {
			found.PyEntry = pythonEntryModule(filepath.Join(dir, m.name))
		}
		if m.eco == EcosystemNode {
			found.Entry = NodeEntry(dir)
			// Only a declared-but-absent entry justifies a build. A project
			// that ships its compiled output already runs, and building it
			// anyway would pull a devDependency tree for nothing.
			found.NeedsBuild = found.Entry != "" &&
				!fileExists(filepath.Join(dir, filepath.FromSlash(found.Entry))) &&
				hasBuildScript(dir)
		}
		return found
	}
	return Manifest{Ecosystem: EcosystemNone}
}

// packageJSON is the subset of a Node manifest that decides how to start and
// build the project.
type packageJSON struct {
	Bin     json.RawMessage   `json:"bin"`
	Main    string            `json:"main"`
	Scripts map[string]string `json:"scripts"`
}

// readPackageJSON parses dir/package.json. A malformed or missing file yields
// the zero value rather than an error: it means "we learned nothing here", and
// every caller already has a sensible answer for that.
func readPackageJSON(dir string) packageJSON {
	var pkg packageJSON
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return pkg
	}
	// A BOM makes encoding/json fail on an otherwise valid file. Real
	// package.json files written by Windows editors carry one.
	data = []byte(strings.TrimPrefix(string(data), "\uFEFF"))
	if err := json.Unmarshal(data, &pkg); err != nil {
		return packageJSON{}
	}
	return pkg
}

// NodeEntry is the start file a Node package declares, relative to dir and
// slash-separated. Empty when package.json declares neither bin nor main.
//
// "bin" wins over "main": a published MCP server declares a bin entry because
// that is how an agent host launches it, so it is the closest thing to a
// statement of intent the package offers. "main" is the library entry point,
// which is only a fallback.
//
// This lives in acquire rather than the CLI because the same parse decides
// whether the project needs building, and two copies of that logic would be
// two chances to disagree about what the entry point is.
func NodeEntry(dir string) string {
	pkg := readPackageJSON(dir)

	// "bin" is either a string or an object of name -> path.
	if len(pkg.Bin) > 0 {
		var s string
		if json.Unmarshal(pkg.Bin, &s) == nil && s != "" {
			return cleanEntry(s)
		}
		var m map[string]string
		if json.Unmarshal(pkg.Bin, &m) == nil {
			// Sorted so the same package always yields the same entry point.
			// Go map order is random, and a scan that picks a different entry
			// point per run is not reproducible.
			names := make([]string, 0, len(m))
			for k := range m {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, n := range names {
				if p := m[n]; p != "" {
					return cleanEntry(p)
				}
			}
		}
	}

	if pkg.Main != "" {
		return cleanEntry(pkg.Main)
	}
	return ""
}

func cleanEntry(p string) string {
	return strings.TrimPrefix(filepath.ToSlash(p), "./")
}

// pythonEntryModule reads the module named by a pyproject's [project.scripts]
// table, e.g. "mcp_server_fetch" from:
//
//	[project.scripts]
//	mcp-server-fetch = "mcp_server_fetch:main"
//
// A deliberately narrow reader rather than a TOML dependency. Only one table
// of simple `name = "module:function"` lines is needed, which is a dozen lines
// of scanning; a parser for the whole format would be a dependency earning its
// place on one field. Anything it cannot understand yields "", which lands on
// the same "no recognisable entry point" message as before — no worse than
// not looking.
func pythonEntryModule(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	inScripts := false
	entries := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			// Any new table ends the one we care about.
			inScripts = strings.HasPrefix(line, "[project.scripts]")
			continue
		}
		if !inScripts {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		// "module:function". Both halves are kept: the function is what a
		// console script actually calls, and `python -m module` only works
		// when the module ships a __main__.py — which most do not.
		if mod, fn, found := strings.Cut(value, ":"); found && mod != "" && fn != "" {
			entries[strings.TrimSpace(name)] = strings.TrimSpace(mod) + ":" + strings.TrimSpace(fn)
		}
	}
	if len(entries) == 0 {
		return ""
	}

	// Sorted, so a project declaring several scripts always yields the same
	// one. Go map order is random, and a scan that starts a different process
	// per run is not reproducible.
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return entries[names[0]]
}

// maxBuildRootDepth bounds how far above a target we will look for the config
// it inherits from. Two levels covers the monorepo layout in practice
// (repo/src/<server>) and stops a malformed extends chain from dragging an
// entire drive into the container.
const maxBuildRootDepth = 4

// buildContext says where a build has to run.
//
// Root is the host directory to copy into the container; Sub is the target's
// slash-separated position inside it, empty when they are the same directory.
type buildContext struct {
	Root string
	Sub  string
}

// buildContextFor works out whether a project can be built alone.
//
// A package inside a monorepo usually cannot. The official memory server's
// tsconfig.json is four lines and an `extends: "../../tsconfig.json"`, and the
// root config it inherits supplies esModuleInterop and skipLibCheck. Copying
// only the package leaves tsc with neither, so it type-checks node_modules and
// drowns in errors from zod — a failure with no connection to the code being
// scanned.
//
// Only relative extends are followed. A bare specifier like
// "@tsconfig/node20/tsconfig.json" resolves from node_modules, which the
// install step provides anyway.
func buildContextFor(targetDir string) buildContext {
	self := buildContext{Root: targetDir}

	data, err := os.ReadFile(filepath.Join(targetDir, "tsconfig.json"))
	if err != nil {
		return self
	}
	var cfg struct {
		Extends string `json:"extends"`
	}
	// tsconfig.json permits comments and trailing commas, which encoding/json
	// rejects. A file we cannot parse simply means we learned nothing, and the
	// package is built on its own exactly as before.
	if json.Unmarshal([]byte(strings.TrimPrefix(string(data), "\uFEFF")), &cfg) != nil {
		return self
	}
	if !strings.HasPrefix(cfg.Extends, "../") {
		return self
	}

	root := filepath.Clean(filepath.Join(targetDir, filepath.FromSlash(filepath.Dir(cfg.Extends))))
	rel, err := filepath.Rel(root, targetDir)
	if err != nil {
		return self
	}
	rel = filepath.ToSlash(rel)
	// Rel must describe a descent. Anything containing ".." means the resolved
	// root is not an ancestor, and copying it would not contain the target.
	if rel == "." || strings.HasPrefix(rel, "..") {
		return self
	}
	if strings.Count(rel, "/")+1 > maxBuildRootDepth {
		return self
	}
	if !fileExists(filepath.Join(root, "tsconfig.json")) {
		return self
	}
	// The root must look like a project root, not merely a directory that
	// happens to hold a tsconfig.
	//
	// This is a security bound, not tidiness. Widening the copy widens what
	// phase 1 can read, and phase 1 is the phase WITH a network — a malicious
	// postinstall in a package that ships a doctored `extends` could otherwise
	// nominate an arbitrary parent directory and exfiltrate it. Requiring a
	// package.json or a .git alongside the config keeps the climb inside
	// something that is recognisably one project.
	if !fileExists(filepath.Join(root, "package.json")) && !exists(filepath.Join(root, ".git")) {
		return self
	}
	return buildContext{Root: root, Sub: rel}
}

func hasBuildScript(dir string) bool {
	return strings.TrimSpace(readPackageJSON(dir).Scripts["build"]) != ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// exists reports whether anything is at path, directory included. Used for
// .git, which is a directory in a clone and a file in a worktree.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

const acquisitionUser = "1000:1000"

// fetchCommand downloads dependencies while target-controlled lifecycle and
// build scripts are disabled. It is the only acquisition command allowed to
// run with network access or as root.
func (m Manifest) fetchCommand(depsDir, sub string) []string {
	switch m.Ecosystem {
	case EcosystemPython:
		if m.File != "requirements.txt" {
			return nil
		}
		return []string{"sh", "-c", strings.Join([]string{
			"set -e",
			"mkdir -p " + depsDir + "/cache " + depsDir + "/site",
			// Source distributions can execute setup.py or a PEP-517 backend
			// merely to resolve metadata. Wheel-only fetch makes that impossible.
			"pip download --disable-pip-version-check --only-binary=:all: " +
				"--dest " + depsDir + "/cache -r /target/requirements.txt",
			"chmod -R a+rwX " + depsDir,
		}, "\n")}

	case EcosystemNode:
		app := appDir(depsDir)
		workDir := app
		if sub != "" {
			workDir += "/" + sub
		}
		installArgs := "--ignore-scripts"
		if !m.NeedsBuild {
			installArgs += " --omit=dev"
		}
		install := "if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then " +
			"npm ci " + installArgs + "; else npm install " + installArgs + "; fi"
		script := strings.Join([]string{
			"set -e",
			"mkdir -p " + app,
			"mkdir -p " + depsDir + "/cache/npm",
			"export npm_config_cache=" + depsDir + "/cache/npm",
			// The fetch container runs as non-root. Preserve modes and timestamps,
			// but not ownership from the read-only host mount: GNU cp's archive mode
			// attempts chown(2) and fails on Linux runners.
			"cp -R --preserve=mode,timestamps --no-preserve=ownership /target/. " + app + "/",
			"rm -rf " + app + "/node_modules " + app + "/.git",
			`cd "$1"`,
			install,
			"chmod -R a+rwX " + depsDir,
		}, "\n")
		return []string{"sh", "-c", script, "detonate-acquire", workDir}
	}
	return nil
}

// offlineCommand performs every acquisition step that may execute
// target-controlled code. Its policy is network-off and non-root.
func (m Manifest) offlineCommand(depsDir, sub string) []string {
	switch m.Ecosystem {
	case EcosystemPython:
		if m.File != "requirements.txt" {
			return nil
		}
		return []string{"sh", "-c", strings.Join([]string{
			"set -e",
			"pip install --disable-pip-version-check --no-index --only-binary=:all: " +
				"--find-links " + depsDir + "/cache --target " + depsDir +
				"/site -r /target/requirements.txt",
		}, "\n")}

	case EcosystemNode:
		workDir := appDir(depsDir)
		if sub != "" {
			workDir += "/" + sub
		}
		steps := []string{
			"set -e",
			"export npm_config_cache=" + depsDir + "/cache/npm",
			`cd "$1"`,
			// This runs the lifecycle scripts suppressed during fetch. They stay
			// observable without being allowed network access or root privilege.
			"if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then " +
				"npm ci --offline; else npm install --offline; fi",
		}
		if m.NeedsBuild {
			steps = append(steps, "npm run build")
		}
		return []string{"sh", "-c", strings.Join(steps, "\n"),
			"detonate-acquire", workDir}
	}
	return nil
}

// appDir is where a built project's source lives inside the dependency volume.
func appDir(depsDir string) string { return depsDir + "/app" }

// Images retain a readable tag but are pinned to the multi-platform manifest
// digest. The tag explains the runtime to a human; the digest makes the actual
// bytes stable across machines and across time.
const (
	// PythonImage carries pip and a Python runtime.
	PythonImage = "python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"

	// NodeImage carries npm and a Node runtime. Chosen because most published
	// MCP servers are Node packages, and the Python image has no npm at all.
	NodeImage = "node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436"
)

// imageFor picks the container image an ecosystem needs.
func imageFor(eco Ecosystem, fallback string) string {
	switch eco {
	case EcosystemNode:
		return NodeImage
	case EcosystemPython:
		return PythonImage
	default:
		return fallback
	}
}

// ImageFor is the exported form, so the detonation phase can run a target on
// the runtime its dependencies were built for.
func ImageFor(eco Ecosystem, fallback string) string { return imageFor(eco, fallback) }

// EnvFor returns the environment that points an interpreter at depsDir.
func (m Manifest) EnvFor(depsDir string) map[string]string {
	switch m.Ecosystem {
	case EcosystemPython:
		return map[string]string{"PYTHONPATH": depsDir, "PYTHONDONTWRITEBYTECODE": "1"}
	case EcosystemNode:
		return map[string]string{"NODE_PATH": depsDir + "/node_modules"}
	}
	return nil
}
