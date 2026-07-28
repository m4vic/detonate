// Package skill reads a SKILL.md directory into the same ToolInfo shape the
// MCP driver produces, so everything after this point doesn't need to care
// which input kind it is looking at.
//
// A skill is a directory holding a SKILL.md (YAML frontmatter plus a Markdown
// body) and usually one or more bundled scripts the model may invoke. The
// frontmatter's description is exactly what a supply-chain attack poisons
// (Snyk's ToxicSkills research found injection in 36% of skills tested), so
// enumerating it faithfully is the whole point of this package.
package skill

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/m4vic/detonate/internal/toolinfo"
)

// frontmatterDelim is a line of exactly "---", the convention SKILL.md shares
// with most static-site frontmatter formats.
const frontmatterDelim = "---"

// utf8BOM is the byte-order mark Windows editors and PowerShell prepend.
// Written as an escape, not the literal character: Go rejects a raw BOM in
// source, and an escape also survives being copied, re-encoded, or viewed in
// an editor that hides invisible runes.
const utf8BOM = "\ufeff"

// scriptExtensions is what we treat as an invokable bundled script. It is a
// short explicit allowlist rather than "every file in the directory" so a
// stray README or image doesn't get reported as a tool.
var scriptExtensions = map[string]bool{
	".py": true, ".sh": true, ".js": true, ".ts": true,
}

// maxBodyFallback caps how much Markdown body we borrow as a description when
// the frontmatter has none, so a skill with a book-length body doesn't flood
// the report.
const maxBodyFallback = 200

// frontmatter is the subset of SKILL.md's YAML header detonate reads. Fields
// we don't model are ignored rather than rejected: skills carry vendor-specific
// keys, and refusing to scan one over an unknown field would be a scanner that
// skips exactly the unusual inputs most worth looking at.
type frontmatter struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	AllowedTools []string `yaml:"allowed-tools"`
}

// parseFrontmatter splits a SKILL.md's YAML header from its Markdown body.
//
// A file with no frontmatter, malformed YAML, or an unclosed delimiter yields
// an empty header rather than an error. A skill that ships broken frontmatter
// is a finding to report, not a reason to abort the scan, and it is exactly
// the kind of input a scanner must survive.
func parseFrontmatter(text string) (frontmatter, string) {
	// Strip a UTF-8 BOM before anything else.
	//
	// Windows editors and PowerShell's `-Encoding utf8` prepend one, so the
	// first line becomes BOM+"---" and never matches the delimiter. The whole
	// file then parses as body: the skill is reported with its raw YAML as a
	// description and, worse, allowed-tools comes back empty, so a permission
	// check would see a skill that declares no tools and report nothing.
	// Caught on a real file written on Windows.
	text = strings.TrimPrefix(text, utf8BOM)

	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != frontmatterDelim {
		return frontmatter{}, text
	}

	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != frontmatterDelim {
			continue
		}
		var fm frontmatter
		if err := yaml.Unmarshal([]byte(strings.Join(lines[1:i], "\n")), &fm); err != nil {
			return frontmatter{}, strings.Join(lines[i+1:], "\n")
		}
		return fm, strings.Join(lines[i+1:], "\n")
	}

	// Opening delimiter with no closing one: treat the whole file as body.
	return frontmatter{}, text
}

// FindBundledScripts lists the script-like files in a skill directory.
//
// Non-recursive at this milestone. Deeply nested skills are a later
// refinement, not something needed to prove the loader works.
func FindBundledScripts(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading skill directory %q: %w", dir, err)
	}

	var scripts []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if scriptExtensions[strings.ToLower(filepath.Ext(e.Name()))] {
			scripts = append(scripts, e.Name())
		}
	}
	// ReadDir is already sorted, but sort explicitly so report order is
	// guaranteed by us rather than inherited from a filesystem's promise.
	sort.Strings(scripts)
	return scripts, nil
}

// Load reads a skill directory's SKILL.md and returns it as ToolInfo entries.
//
// The SKILL.md itself becomes one ToolInfo (the name and description a
// poisoned frontmatter targets), plus one per bundled script (what actually
// executes when the skill is invoked).
func Load(dir string) ([]toolinfo.ToolInfo, error) {
	skillMD := filepath.Join(dir, "SKILL.md")
	raw, err := os.ReadFile(skillMD)
	if err != nil {
		// A directory with no SKILL.md is not a skill. Fail loudly rather than
		// returning zero tools, which would read like a clean bill of health.
		return nil, fmt.Errorf("no SKILL.md found in %q: %w", dir, err)
	}

	fm, body := parseFrontmatter(string(raw))

	name := fm.Name
	if name == "" {
		name = filepath.Base(dir)
	}

	description := fm.Description
	if description == "" {
		description = truncate(strings.TrimSpace(body), maxBodyFallback)
	}

	tools := []toolinfo.ToolInfo{{
		Name:        name,
		Description: description,
		Source:      toolinfo.SourceSkill,
		Metadata: map[string]any{
			"path":          dir,
			"allowed_tools": fm.AllowedTools,
		},
	}}

	scripts, err := FindBundledScripts(dir)
	if err != nil {
		return nil, err
	}
	for _, s := range scripts {
		tools = append(tools, toolinfo.ToolInfo{
			Name:        name + ":" + s,
			Description: "bundled script: " + s,
			Source:      toolinfo.SourceSkill,
			Metadata: map[string]any{
				"path":         filepath.Join(dir, s),
				"parent_skill": name,
			},
		})
	}
	return tools, nil
}

func truncate(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}
