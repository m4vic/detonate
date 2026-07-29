// Package acquire installs a target's dependencies before it is detonated.
//
// This exists because of a hard constraint the sandbox creates: the detonation
// container has no network, and almost every real MCP server needs one to
// install (`from mcp.server.fastmcp import FastMCP` requires a pip install).
// Without this package detonate can only scan stdlib-only servers, which is a
// demo rather than a tool.
//
// The answer is two containers, two phases:
//
//	Phase 1 ACQUIRE   network ON, no target execution, deps into a volume
//	Phase 2 DETONATE  network OFF, that volume mounted read-only
//
// Phase 1 is not a necessary evil to be minimised. Install scripts are THE
// npm/PyPI supply-chain surface — a postinstall hook or setup.py runs
// arbitrary code before anyone has looked at the package — and nobody
// currently watches them. So install-time behaviour is captured as evidence
// like any other, and this phase is a finding generator in its own right.
package acquire

import (
	"encoding/json"
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

func hasBuildScript(dir string) bool {
	return strings.TrimSpace(readPackageJSON(dir).Scripts["build"]) != ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// installCommand is the shell command that installs a manifest's dependencies
// into depsDir.
//
// Installing into an explicit directory rather than the image's site-packages
// is what makes the result portable to phase 2: the deps live in a volume we
// mount read-only, so the detonation container gets them without ever having
// had a network.
func (m Manifest) installCommand(depsDir string) []string {
	switch m.Ecosystem {
	case EcosystemPython:
		var pipArgs string
		switch m.File {
		case "requirements.txt":
			pipArgs = "-r /target/requirements.txt"
		default:
			// pyproject.toml / setup.py: install the project itself. No -e:
			// an editable install writes into the target directory, which we
			// mount read-only precisely so a target cannot modify itself
			// mid-scan.
			pipArgs = "/target"
		}
		return []string{"sh", "-c",
			"pip install --no-cache-dir --target " + depsDir + " " + pipArgs}

	case EcosystemNode:
		// --ignore-scripts is NOT used in either branch. Lifecycle scripts are
		// the supply-chain attack surface we are here to observe; suppressing
		// them would hide the exact behaviour worth reporting. Safe to allow
		// because this runs in a throwaway container with no host mounts
		// beyond a read-only copy of the target.
		if m.NeedsBuild {
			app := appDir(depsDir)
			// The whole project has to move into the volume: a build writes
			// its output next to the source, and /target is a read-only host
			// mount precisely so a target cannot rewrite itself mid-scan.
			//
			// set -e so a failed build fails the container. Silently
			// continuing would leave phase 2 launching an entry point that
			// was never produced, and report that as the target's fault.
			return []string{"sh", "-c", strings.Join([]string{
				"set -e",
				"mkdir -p " + app,
				"cp -a /target/. " + app + "/",
				// A host node_modules is built for the host's OS and libc;
				// inside the container its native modules are wrong. .git is
				// dead weight that can dwarf the source.
				"rm -rf " + app + "/node_modules " + app + "/.git",
				"cd " + app,
				// devDependencies are required here, unlike the no-build
				// branch: the compiler doing the build is one of them.
				"npm install",
				"npm run build",
				// Phase 2 runs as a non-root uid that has no relationship to
				// the root uid that just wrote these files.
				"chmod -R a+rX " + app,
			}, "\n")}
		}
		return []string{"sh", "-c",
			"cp /target/package*.json " + depsDir + "/ && cd " + depsDir + " && npm install --omit=dev"}
	}
	return nil
}

// appDir is where a built project's source lives inside the dependency volume.
func appDir(depsDir string) string { return depsDir + "/app" }

// Images are pinned to a major version rather than :latest so a scan run twice
// a month apart behaves the same. A scanner whose environment drifts produces
// findings that cannot be reproduced.
const (
	// PythonImage carries pip and a Python runtime.
	PythonImage = "python:3.12-slim"

	// NodeImage carries npm and a Node runtime. Chosen because most published
	// MCP servers are Node packages, and the Python image has no npm at all.
	NodeImage = "node:22-slim"
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
