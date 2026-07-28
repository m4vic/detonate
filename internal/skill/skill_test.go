package skill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSkill builds a throwaway skill directory. Using a real directory rather
// than an in-memory fs keeps these tests honest about the thing that actually
// breaks: filesystem layout and file naming.
func writeSkill(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

const goodSkill = `---
name: pdf-extractor
description: Extracts text and tables from PDF files for the agent to read.
allowed-tools:
  - Read
  - Bash
---

# PDF Extractor

Use this skill when the user asks you to read or summarize a PDF file.
`

func TestLoadReadsFrontmatter(t *testing.T) {
	dir := writeSkill(t, map[string]string{
		"SKILL.md":   goodSkill,
		"extract.py": "print('hi')\n",
	})

	tools, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("got %d tools, want 2 (the skill + one bundled script)", len(tools))
	}

	skill := tools[0]
	if skill.Name != "pdf-extractor" {
		t.Errorf("Name = %q, want pdf-extractor", skill.Name)
	}
	// The description is what a supply-chain attack poisons, so it has to
	// survive the round trip intact.
	if skill.Description != "Extracts text and tables from PDF files for the agent to read." {
		t.Errorf("Description = %q", skill.Description)
	}
	allowed, ok := skill.Metadata["allowed_tools"].([]string)
	if !ok || len(allowed) != 2 || allowed[0] != "Read" || allowed[1] != "Bash" {
		t.Errorf("allowed_tools = %#v, want [Read Bash]", skill.Metadata["allowed_tools"])
	}

	script := tools[1]
	if script.Name != "pdf-extractor:extract.py" {
		t.Errorf("script Name = %q, want pdf-extractor:extract.py", script.Name)
	}
	if script.Metadata["parent_skill"] != "pdf-extractor" {
		t.Errorf("parent_skill = %v", script.Metadata["parent_skill"])
	}
}

// A skill that ships broken frontmatter is a finding to report, not a reason
// to abort the scan. These are the inputs most likely to appear in something
// worth scanning, so none of them may return an error.
func TestLoadSurvivesBadFrontmatter(t *testing.T) {
	cases := map[string]string{
		"no frontmatter":     "Just instructions.",
		"malformed yaml":     "---\nname: [unclosed\n---\nbody\n",
		"unclosed delimiter": "---\nname: x\nno closing delimiter\n",
		"empty file":         "",
		"frontmatter only":   "---\nname: bare\n---\n",
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeSkill(t, map[string]string{"SKILL.md": content})
			tools, err := Load(dir)
			if err != nil {
				t.Fatalf("Load returned error on %s: %v", name, err)
			}
			if len(tools) != 1 {
				t.Fatalf("got %d tools, want 1", len(tools))
			}
		})
	}
}

// A UTF-8 BOM must not defeat frontmatter parsing.
//
// Windows editors and PowerShell's -Encoding utf8 prepend one, so the first
// line becomes "<BOM>---" and never matches the delimiter. The whole file
// then parses as body: the skill gets its raw YAML as a description and,
// worse, allowed-tools comes back empty — so a permission check would see a
// skill that declares no tools and report nothing. Found on a real file.
func TestLoadHandlesUTF8BOM(t *testing.T) {
	dir := writeSkill(t, map[string]string{
		"SKILL.md": "\ufeff" + goodSkill,
	})

	tools, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tools[0].Name != "pdf-extractor" {
		t.Errorf("Name = %q, want pdf-extractor (BOM broke frontmatter parsing)", tools[0].Name)
	}
	if !strings.HasPrefix(tools[0].Description, "Extracts text") {
		t.Errorf("Description = %q; raw YAML leaked into it", tools[0].Description)
	}
	allowed, ok := tools[0].Metadata["allowed_tools"].([]string)
	if !ok || len(allowed) != 2 {
		t.Errorf("allowed_tools = %#v; a permission check would see nothing",
			tools[0].Metadata["allowed_tools"])
	}
}

func TestLoadFallsBackToDirectoryName(t *testing.T) {
	dir := writeSkill(t, map[string]string{"SKILL.md": "Some instructions."})
	tools, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tools[0].Name != filepath.Base(dir) {
		t.Errorf("Name = %q, want %q", tools[0].Name, filepath.Base(dir))
	}
	if tools[0].Description != "Some instructions." {
		t.Errorf("Description = %q, want the body as fallback", tools[0].Description)
	}
}

func TestLoadMissingSkillMD(t *testing.T) {
	// An empty directory is not a skill. This must fail loudly rather than
	// reporting zero tools, which would read like a clean bill of health.
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("Load on a directory with no SKILL.md should error")
	}
}

func TestFindBundledScripts(t *testing.T) {
	dir := writeSkill(t, map[string]string{
		"SKILL.md":   goodSkill,
		"extract.py": "",
		"run.sh":     "",
		"helper.js":  "",
		"README.md":  "", // documentation, not an invokable script
		"logo.png":   "",
	})

	scripts, err := FindBundledScripts(dir)
	if err != nil {
		t.Fatalf("FindBundledScripts: %v", err)
	}
	want := []string{"extract.py", "helper.js", "run.sh"}
	if len(scripts) != len(want) {
		t.Fatalf("got %v, want %v", scripts, want)
	}
	for i := range want {
		if scripts[i] != want[i] {
			t.Errorf("scripts[%d] = %q, want %q", i, scripts[i], want[i])
		}
	}
}
