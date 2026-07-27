"""Tests for the skill loader.

The loader's job is to survive whatever a real skill directory throws at it.
A skill that ships broken frontmatter is a finding to report, not a reason to
crash the scan — so most of these tests are about NOT raising.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detonate.skill_loader import _parse_frontmatter, find_bundled_scripts, load_skill


class TestParseFrontmatter:
    def test_well_formed(self):
        fm, body = _parse_frontmatter("---\nname: x\n---\n# Body\n")
        assert fm == {"name": "x"}
        assert "# Body" in body

    def test_no_frontmatter_returns_empty_dict(self):
        """A SKILL.md that's pure Markdown is still a skill worth reporting."""
        fm, body = _parse_frontmatter("# Just a heading\n")
        assert fm == {}
        assert body == "# Just a heading\n"

    def test_malformed_yaml_does_not_raise(self):
        """Broken YAML is a finding, not a crash."""
        fm, _ = _parse_frontmatter("---\nname: [unclosed\n---\nbody\n")
        assert fm == {}

    def test_unclosed_delimiter_treated_as_body(self):
        fm, body = _parse_frontmatter("---\nname: x\nno closing delimiter\n")
        assert fm == {}
        assert "no closing delimiter" in body

    def test_empty_file(self):
        assert _parse_frontmatter("") == ({}, "")


class TestFindBundledScripts:
    def test_finds_script_by_extension(self, sample_skill_dir: Path):
        names = [p.name for p in find_bundled_scripts(sample_skill_dir)]
        assert "extract.py" in names

    def test_ignores_non_scripts(self, sample_skill_dir: Path):
        """SKILL.md itself is documentation, not an invokable script."""
        names = [p.name for p in find_bundled_scripts(sample_skill_dir)]
        assert "SKILL.md" not in names


class TestLoadSkill:
    def test_returns_skill_plus_each_script(self, sample_skill_dir: Path):
        tools = load_skill(str(sample_skill_dir))
        assert len(tools) == 2

    def test_reads_frontmatter_into_tool_info(self, sample_skill_dir: Path):
        skill = load_skill(str(sample_skill_dir))[0]
        assert skill.name == "pdf-extractor"
        assert skill.source == "skill"
        # The description is the field a supply-chain attack poisons, so it has
        # to survive the round trip intact.
        assert "PDF" in skill.description
        assert skill.metadata["allowed_tools"] == ["Read", "Bash"]

    def test_bundled_script_namespaced_under_parent(self, sample_skill_dir: Path):
        script = load_skill(str(sample_skill_dir))[1]
        assert script.name == "pdf-extractor:extract.py"
        assert script.metadata["parent_skill"] == "pdf-extractor"

    def test_missing_skill_md_raises(self, tmp_path: Path):
        """An empty directory isn't a skill — fail loudly, don't report zero
        tools as if the scan succeeded."""
        with pytest.raises(FileNotFoundError):
            load_skill(str(tmp_path))

    def test_falls_back_to_directory_name(self, tmp_path: Path):
        """No frontmatter -> still enumerable, named after its directory."""
        (tmp_path / "SKILL.md").write_text("Some instructions.", encoding="utf-8")
        skill = load_skill(str(tmp_path))[0]
        assert skill.name == tmp_path.name
        assert skill.description == "Some instructions."
