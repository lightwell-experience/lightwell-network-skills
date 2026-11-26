#!/usr/bin/env python3
"""Check skill frontmatter, the SKILLS.md catalog, and relative links.

Stdlib only. The rules match CONTRIBUTING.md: frontmatter shape, a catalog row
per skill, and relative links that stay inside the repository.
"""

from __future__ import annotations

import re
import sys
import urllib.parse
from pathlib import Path

FRONTMATTER_LIMIT = 1024
SKILL_TYPES = ("Reference", "Technique", "Pattern")
NAME_RE = re.compile(r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$")
CATALOG_HREF_RE = re.compile(r"^\.claude/skills/([^/]+)/SKILL\.md$")
USER_INVOCABLE_MARK = "✓"

ROOT = Path(__file__).resolve().parents[1]


class FrontmatterError(ValueError):
    """SKILL.md frontmatter is missing or not the small YAML subset we accept."""


def parse_scalar(raw: str):
    """Parse one plain YAML scalar, including an inline ``#`` comment."""
    value = raw.strip()
    if not value:
        raise FrontmatterError("expected a value")
    if value[0] not in {'"', "'"} and " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    return value


def parse_mapping(body: str) -> dict:
    """Parse the flat YAML mapping used by skill frontmatter.

    Accepts single-line scalars and ``>``, ``>-``, ``|``, and ``|-`` blocks.
    Nested mappings are rejected so a typo cannot silently pass the checks.
    """
    lines = body.splitlines()
    data: dict = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        if line[0] in {" ", "\t"}:
            raise FrontmatterError(f"unexpected indented line: {line.strip()}")
        key, separator, rest = line.partition(":")
        if not separator or not key.strip():
            raise FrontmatterError(f"expected 'key: value', found: {line.strip()}")
        key = key.strip()
        if key in data:
            raise FrontmatterError(f"duplicate frontmatter key {key!r}")
        rest = rest.strip()
        if rest in {">", ">-", "|", "|-"}:
            index += 1
            block: list[str] = []
            while index < len(lines):
                current = lines[index]
                if not current.strip():
                    peek = index + 1
                    while peek < len(lines) and not lines[peek].strip():
                        peek += 1
                    if peek < len(lines) and lines[peek][0] in {" ", "\t"}:
                        block.append("")
                        index += 1
                        continue
                    break
                if current[0] not in {" ", "\t"}:
                    break
                if current.startswith("\t"):
                    raise FrontmatterError("frontmatter indentation must use spaces")
                block.append(current.strip())
                index += 1
            if not block:
                raise FrontmatterError(f"{key} has an empty block")
            if rest.startswith(">"):
                text = " ".join(part for part in block if part).strip()
            else:
                text = "\n".join(block)
            if rest.endswith("-"):
                text = text.rstrip()
            data[key] = text
            continue
        if rest == "":
            raise FrontmatterError(f"{key} needs a value")
        data[key] = parse_scalar(rest)
        index += 1
    return data


def parse_frontmatter(text: str) -> tuple[str, dict]:
    """Return the raw frontmatter block and its mapping.

    The block includes the opening and closing ``---`` lines. CONTRIBUTING.md
    caps that block at 1024 characters.
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        raise FrontmatterError("SKILL.md must start with a --- frontmatter line")
    for index, line in enumerate(lines[1:], start=1):
        if line.rstrip("\r\n") == "---":
            block = "".join(lines[: index + 1])
            body = "".join(lines[1:index])
            return block, parse_mapping(body)
    raise FrontmatterError("frontmatter is missing the closing ---")


def split_table_row(line: str) -> list[str]:
    """Split one markdown table row on unescaped pipes."""
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    cells: list[str] = []
    buf: list[str] = []
    escaped = False
    for char in stripped:
        if escaped:
            buf.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "|":
            cells.append("".join(buf).strip())
            buf = []
            continue
        buf.append(char)
    cells.append("".join(buf).strip())
    return cells


def is_separator_row(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def parse_catalog(text: str) -> list[list[str]]:
    """Return data rows from the SKILLS.md table."""
    rows: list[list[str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("|"):
            continue
        cells = split_table_row(line)
        if not cells or cells[0] == "Skill" or is_separator_row(cells):
            continue
        if len(cells) != 4:
            raise FrontmatterError(
                f"SKILLS.md:{line_number}: expected 4 table cells, found {len(cells)}"
            )
        rows.append(cells)
    return rows


def visible_markdown(text: str) -> str:
    """Drop fenced and inline code so sample links are not checked."""
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"~~~.*?~~~", "", text, flags=re.DOTALL)
    return re.sub(r"`[^`\n]*`", "", text)


def iter_link_destinations(text: str):
    """Yield destinations of inline links, images, and reference definitions."""
    index = 0
    while True:
        found = text.find("](", index)
        if found < 0:
            break
        pos = found + 2
        if pos < len(text) and text[pos] == "<":
            end = text.find(">", pos + 1)
            if end < 0:
                break
            yield text[pos + 1 : end].strip()
            index = end + 1
            continue
        depth = 1
        buf: list[str] = []
        while pos < len(text) and depth:
            char = text[pos]
            if char == "(":
                depth += 1
                buf.append(char)
            elif char == ")":
                depth -= 1
                if depth:
                    buf.append(char)
            elif char.isspace() and depth == 1:
                break
            else:
                buf.append(char)
            pos += 1
        yield "".join(buf).strip()
        index = pos
    for match in re.finditer(r"(?m)^[ ]{0,3}\[[^\]]+\]:[ \t]*(\S+)", text):
        dest = match.group(1)
        if dest.startswith("<") and dest.endswith(">"):
            dest = dest[1:-1]
        yield dest


def check_relative_link(root: Path, md_path: Path, dest: str) -> str | None:
    """Return an error when a relative link escapes the repo or does not exist."""
    dest = dest.strip()
    if not dest or dest.startswith("#"):
        return None
    parsed = urllib.parse.urlparse(dest)
    if parsed.scheme:
        return None
    path = urllib.parse.unquote(parsed.path)
    if not path:
        return None
    if path.startswith("/"):
        candidate = root / path.lstrip("/")
    else:
        candidate = md_path.parent / path
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root.resolve())
    except ValueError:
        rel = md_path.relative_to(root)
        return f"{rel}: link `{dest}` points outside the repository"
    if not resolved.exists():
        rel = md_path.relative_to(root)
        return f"{rel}: broken relative link `{dest}`"
    return None


def check_skill_links(root: Path, skill_dir: Path) -> list[str]:
    errors: list[str] = []
    for md_path in sorted(skill_dir.rglob("*.md")):
        text = visible_markdown(md_path.read_text(encoding="utf-8"))
        for dest in iter_link_destinations(text):
            error = check_relative_link(root, md_path, dest)
            if error:
                errors.append(error)
    return errors


def check_skill_document(root: Path, skill_dir: Path) -> tuple[dict | None, list[str]]:
    """Validate one skill. Returns parsed frontmatter, or None when it did not parse."""
    rel = skill_dir.relative_to(root) / "SKILL.md"
    path = skill_dir / "SKILL.md"
    errors: list[str] = []
    if not path.is_file():
        return None, [f"{rel}: missing SKILL.md"]
    try:
        block, data = parse_frontmatter(path.read_text(encoding="utf-8"))
    except FrontmatterError as exc:
        return None, [f"{rel}: {exc}"]
    if len(block) > FRONTMATTER_LIMIT:
        errors.append(
            f"{rel}: frontmatter is {len(block)} characters; the limit is {FRONTMATTER_LIMIT}"
        )
    name = data.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        errors.append(
            f"{rel}: name must contain only letters, numbers, and hyphens "
            f"(found {name!r})"
        )
    elif name != skill_dir.name:
        errors.append(
            f"{rel}: name is {name!r}; the directory is {skill_dir.name!r}"
        )
    description = data.get("description")
    if not isinstance(description, str) or not description.startswith("Use when"):
        errors.append(
            f"{rel}: description must start with 'Use when' (found {description!r})"
        )
    if "user-invocable" in data and not isinstance(data["user-invocable"], bool):
        errors.append(
            f"{rel}: user-invocable must be true or false "
            f"(found {data['user-invocable']!r})"
        )
    for key in ("name", "description"):
        if key not in data:
            errors.append(f"{rel}: missing frontmatter key {key!r}")
    return data, errors


def check_catalog_row(root: Path, cells: list[str], skills: dict[str, dict | None]) -> list[str]:
    errors: list[str] = []
    link, skill_type, invocable, description = cells
    match = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", link)
    if not match:
        return [f"SKILLS.md: skill cell is not a markdown link (found {link!r})"]
    label, href = match.group(1), match.group(2)
    href_match = CATALOG_HREF_RE.fullmatch(href)
    if not href_match:
        return [f"SKILLS.md: {label!r} must link to .claude/skills/<name>/SKILL.md"]
    directory = href_match.group(1)
    if label != directory:
        errors.append(
            f"SKILLS.md: link text {label!r} does not match directory {directory!r}"
        )
    if directory not in skills:
        errors.append(f"SKILLS.md: lists {directory!r}, which has no skill directory")
        return errors
    if skill_type not in SKILL_TYPES:
        errors.append(
            f"SKILLS.md: {directory} type must be one of {', '.join(SKILL_TYPES)} "
            f"(found {skill_type!r})"
        )
    data = skills[directory]
    expects_mark = bool(data and data.get("user-invocable") is True)
    expected = USER_INVOCABLE_MARK if expects_mark else ""
    if invocable != expected:
        shown = invocable or "blank"
        wanted = expected or "blank"
        errors.append(
            f"SKILLS.md: {directory} user-invocable cell is {shown!r}; expected {wanted!r}"
        )
    if not description:
        errors.append(f"SKILLS.md: {directory} is missing a description")
    skill_md = root / href
    if not skill_md.is_file():
        errors.append(f"SKILLS.md: {href} does not exist")
    return errors


def check_repo(root: Path) -> list[str]:
    """Return every catalog and link error in ``root``. An empty list means it passed."""
    errors: list[str] = []
    skills_root = root / ".claude" / "skills"
    if not skills_root.is_dir():
        errors.append(".claude/skills directory is missing")
        return errors

    for path in sorted(skills_root.rglob("SKILL.md")):
        if len(path.relative_to(skills_root).parts) != 2:
            rel = path.relative_to(root)
            errors.append(f"{rel}: skills are a flat namespace (.claude/skills/<name>/SKILL.md)")

    skills: dict[str, dict | None] = {}
    for skill_dir in sorted(path for path in skills_root.iterdir() if path.is_dir()):
        data, skill_errors = check_skill_document(root, skill_dir)
        errors.extend(skill_errors)
        skills[skill_dir.name] = data
        errors.extend(check_skill_links(root, skill_dir))

    catalog_path = root / "SKILLS.md"
    if not catalog_path.is_file():
        errors.append("SKILLS.md is missing")
        return errors
    try:
        rows = parse_catalog(catalog_path.read_text(encoding="utf-8"))
    except FrontmatterError as exc:
        errors.append(str(exc))
        return errors

    seen: set[str] = set()
    for cells in rows:
        link = cells[0]
        match = re.fullmatch(r"\[[^\]]+\]\(([^)]+)\)", link)
        href_match = CATALOG_HREF_RE.fullmatch(match.group(1)) if match else None
        directory = href_match.group(1) if href_match else None
        if directory:
            if directory in seen:
                errors.append(f"SKILLS.md: duplicate row for {directory!r}")
            seen.add(directory)
        errors.extend(check_catalog_row(root, cells, skills))

    for directory in skills:
        if directory not in seen:
            errors.append(f"SKILLS.md: missing a row for {directory!r}")
    return errors


def main() -> None:
    errors = check_repo(ROOT)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: checked skills in {ROOT}")


if __name__ == "__main__":
    main()
