// Package staticinv recovers a target's tool inventory without running it.
//
// Static mode's problem was never the analysis — internal/toolscan does that —
// it was that static mode had nothing to analyze. A tool list normally comes
// from `tools/list`, which requires launching the server, which is precisely
// what static mode must not do. So static MCP scanning reported
// "not implemented" and returned no verdict at all, on the one code path a user
// without Docker can reach.
//
// An MCPB bundle already declares its tools in manifest.json, for the host UI's
// benefit. That declaration is target-controlled, informational, and possibly
// incomplete — which makes it a perfectly good input for a scanner whose whole
// design separates "what did we find" from "how much did we actually look at".
//
// The honesty rule this package exists to serve: a declared inventory is
// evidence about what the target SAYS it exposes, never proof of what it
// exposes. Every path here reports its own completeness, and a target whose
// tools cannot be recovered must reduce completeness rather than quietly
// produce a clean-looking result over an empty list.
package staticinv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/m4vic/detonate/internal/toolinfo"
)

// maxManifestBytes bounds the manifest read. The file is target-controlled, so
// it is a budget like any other: a bundle shipping a gigabyte of JSON should be
// reported as unreadable, not loaded into memory.
const maxManifestBytes = 5 << 20 // 5 MiB

// SourceMCPBManifest names the only extraction source implemented today.
const SourceMCPBManifest = "mcpb-manifest"

// Result is what could be learned about a target's tools without executing it.
type Result struct {
	// Tools is the declared inventory. It may be empty even on success.
	Tools []toolinfo.ToolInfo

	// Source names where the inventory came from, for the report's provenance.
	// Empty when nothing was found.
	Source string

	// Complete says whether this is believed to be the target's whole tool
	// list. False is the common case and is not a failure: it is the difference
	// between "we looked and found nothing wrong" and "we could not look".
	Complete bool

	// Reason explains an incomplete or empty result in terms a user can act on.
	Reason string

	// ServerType and EntryPoint are how the bundle says it starts. They are
	// read here because this package already parses the manifest, and they let
	// detection recognize an MCPB bundle whose layout no entry-point guess
	// would find. Neither is used by the analyzer.
	ServerType string
	EntryPoint string
}

// StartCommand renders the declared entry point as a command inside the
// sandbox, where the target directory is mounted at mount.
//
// Returns empty when the manifest declares a runtime detonate does not launch
// this way ("binary", "uv") or omits the entry point — an unknown start command
// is a question for the user, never a guess made here.
func (r Result) StartCommand(mount string) string {
	if r.EntryPoint == "" {
		return ""
	}
	// A declared entry point is target-controlled. Anything that escapes the
	// mount is refused rather than normalized: a manifest is not allowed to
	// point the launcher outside the directory being scanned.
	clean := path.Clean("/" + strings.ReplaceAll(r.EntryPoint, `\`, "/"))
	if clean == "/" || strings.HasPrefix(clean, "/..") {
		return ""
	}

	switch r.ServerType {
	case "node":
		return "node " + mount + clean
	case "python":
		return "python " + mount + clean
	default:
		return ""
	}
}

// Extract reads whatever static inventory a target directory offers.
//
// It never executes anything and never leaves the directory. A target with no
// recognizable declaration returns an empty Result with a Reason, not an error:
// "this kind of target has no static inventory" is an ordinary outcome, and the
// caller turns it into reduced completeness.
func Extract(dir string) Result {
	manifestPath := filepath.Join(dir, "manifest.json")

	raw, err := readBounded(manifestPath, maxManifestBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Result{Reason: "no MCPB manifest.json; this target declares no tools statically, so its inventory is only knowable by running it"}
	case err != nil:
		return Result{Reason: fmt.Sprintf("MCPB manifest.json could not be read: %v", err)}
	}

	var m mcpbManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Result{Reason: fmt.Sprintf("manifest.json is not valid JSON: %v", err)}
	}

	// A manifest.json in the root means nothing on its own — browser
	// extensions, web apps and npm tooling all use that filename. Requiring the
	// two fields the MCPB spec makes mandatory keeps this from misreading an
	// unrelated file as a tool declaration.
	if m.ManifestVersion == "" || m.Server == nil {
		return Result{Reason: "manifest.json is present but is not an MCPB manifest (no manifest_version/server); no static tool inventory available"}
	}

	if len(m.Tools) == 0 {
		// The tools array is optional in the spec, so its absence does not mean
		// the server has no tools. Saying "no tools found" here would be the
		// exact false-clean this package exists to avoid.
		return Result{
			Source:     SourceMCPBManifest,
			ServerType: m.Server.Type,
			EntryPoint: m.Server.EntryPoint,
			Reason:     "MCPB manifest declares no tools array; the field is optional, so the tool list cannot be determined without running the server",
		}
	}

	tools := make([]toolinfo.ToolInfo, 0, len(m.Tools))
	for _, t := range m.Tools {
		tools = append(tools, toolinfo.ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			Source:      toolinfo.SourceMCP,
			Metadata: map[string]any{
				"declared_in":      "manifest.json",
				"manifest_version": m.ManifestVersion,
			},
		})
	}

	result := Result{
		Tools:      tools,
		Source:     SourceMCPBManifest,
		Complete:   true,
		ServerType: m.Server.Type,
		EntryPoint: m.Server.EntryPoint,
	}

	// tools_generated is the spec's own admission that the declaration is a
	// lower bound: the server provides at least these "and possibly more". A
	// scan over a lower bound is partial by definition.
	if m.ToolsGenerated {
		result.Complete = false
		result.Reason = "MCPB manifest sets tools_generated; the server creates further tools at runtime, so the declared list is a lower bound"
	}

	return result
}

// mcpbManifest is the subset of the MCPB manifest schema this package reads.
// Deliberately partial: unknown fields are ignored, so a manifest written
// against a newer spec revision still yields its tool list.
type mcpbManifest struct {
	ManifestVersion string `json:"manifest_version"`

	// Server is required by the spec, and its presence is what distinguishes an
	// MCPB manifest from any other manifest.json. Only the two fields detection
	// needs are read; the rest of the object is ignored.
	Server *struct {
		Type       string `json:"type"`
		EntryPoint string `json:"entry_point"`
	} `json:"server"`

	ToolsGenerated bool `json:"tools_generated"`

	Tools []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tools"`
}

// readBounded reads at most limit bytes, and reports a file that exceeds it as
// an error rather than silently truncating — a truncated manifest would parse
// as invalid JSON and be reported as the wrong problem.
func readBounded(file string, limit int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than the %d-byte limit", limit)
	}
	return data, nil
}
