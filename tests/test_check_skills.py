"""Catalog checks for .claude/skills and SKILLS.md."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_skills  # noqa: E402


VALID_SKILL = """---
name: demo-skill
description: Use when asked to demonstrate the catalog check.
user-invocable: true
---

# Demo
"""

CATALOG_ROW = (
    "| [demo-skill](.claude/skills/demo-skill/SKILL.md) "
    "| Technique | ✓ | Demonstrate the catalog check. |"
)


def write_repo(root: Path, skill: str = VALID_SKILL, row: str = CATALOG_ROW, extras=None):
    skill_dir = root / ".claude" / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(skill, encoding="utf-8")
    catalog = "\n".join(
        [
            "# Skills index",
            "",
            "| Skill | Type | User-invocable | Description |",
            "|-------|------|:--------------:|-------------|",
            row,
            "",
        ]
    )
    (root / "SKILLS.md").write_text(catalog, encoding="utf-8")
    for rel, content in (extras or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class CheckSkillsTest(unittest.TestCase):
    def test_repository_catalog_passes(self):
        self.assertEqual(check_skills.check_repo(ROOT), [])

    def test_valid_fixture_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            self.assertEqual(check_skills.check_repo(root), [])

    def test_folded_description_is_accepted(self):
        skill = """---
name: demo-skill
description: >-
  Use when asked to demonstrate
  a folded description.
---

# Demo
"""
        row = (
            "| [demo-skill](.claude/skills/demo-skill/SKILL.md) "
            "| Pattern |  | Folded description. |"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, skill=skill, row=row)
            self.assertEqual(check_skills.check_repo(root), [])

    def test_description_must_start_with_use_when(self):
        skill = VALID_SKILL.replace(
            "Use when asked to demonstrate the catalog check.",
            "Fetches packages by calling the API.",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, skill=skill)
            errors = check_skills.check_repo(root)
        self.assertTrue(any("description must start with 'Use when'" in error for error in errors))

    def test_name_must_match_directory(self):
        skill = VALID_SKILL.replace("name: demo-skill", "name: other-skill")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, skill=skill)
            errors = check_skills.check_repo(root)
        self.assertTrue(any("directory is 'demo-skill'" in error for error in errors))

    def test_frontmatter_limit(self):
        skill = VALID_SKILL.replace(
            "Use when asked to demonstrate the catalog check.",
            "Use when " + ("x" * 1200),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, skill=skill)
            errors = check_skills.check_repo(root)
        self.assertTrue(any("limit is 1024" in error for error in errors))

    def test_missing_catalog_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            (root / "SKILLS.md").write_text(
                "# Skills index\n\n"
                "| Skill | Type | User-invocable | Description |\n"
                "|-------|------|:--------------:|-------------|\n",
                encoding="utf-8",
            )
            errors = check_skills.check_repo(root)
        self.assertIn("SKILLS.md: missing a row for 'demo-skill'", errors)

    def test_user_invocable_mark_must_match_frontmatter(self):
        row = CATALOG_ROW.replace("✓", "")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, row=row)
            errors = check_skills.check_repo(root)
        self.assertTrue(any("user-invocable cell" in error for error in errors))

    def test_unknown_type_fails(self):
        row = CATALOG_ROW.replace("Technique", "Guide")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, row=row)
            errors = check_skills.check_repo(root)
        self.assertTrue(any("type must be one of" in error for error in errors))

    def test_relative_link_must_exist_inside_the_repo(self):
        skill = VALID_SKILL + "\nSee [notes](notes.md) and [missing](missing.md).\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(
                root,
                skill=skill,
                extras={".claude/skills/demo-skill/notes.md": "notes\n"},
            )
            errors = check_skills.check_repo(root)
        self.assertEqual(errors, [".claude/skills/demo-skill/SKILL.md: broken relative link `missing.md`"])

    def test_link_outside_the_repository_fails(self):
        skill = VALID_SKILL + "\nSee [passwd](../../../../../../../../etc/passwd).\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, skill=skill)
            errors = check_skills.check_repo(root)
        self.assertTrue(any("points outside the repository" in error for error in errors))

    def test_links_inside_code_fences_are_ignored(self):
        skill = VALID_SKILL + "\n```\n[missing](missing.md)\n```\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, skill=skill)
            self.assertEqual(check_skills.check_repo(root), [])


if __name__ == "__main__":
    unittest.main()
