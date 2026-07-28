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
	"os"
	"path/filepath"
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
		if fileExists(filepath.Join(dir, m.name)) {
			return Manifest{Ecosystem: m.eco, File: m.name}
		}
	}
	return Manifest{Ecosystem: EcosystemNone}
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
		// --ignore-scripts is NOT used. Lifecycle scripts are the supply-chain
		// attack surface we are here to observe; suppressing them would hide
		// the exact behaviour worth reporting. Safe to allow because this runs
		// in a throwaway container with no host mounts beyond a read-only copy
		// of the target.
		return []string{"sh", "-c",
			"cp /target/package*.json " + depsDir + "/ && cd " + depsDir + " && npm install --omit=dev"}
	}
	return nil
}

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
