#!/usr/bin/env python3
"""CI copy of the Codex Skill quick validator used by local release checks."""

import re
import sys
from pathlib import Path

def validate_skill(skill_path):
    import yaml

    skill_md = Path(skill_path) / "SKILL.md"
    if not skill_md.exists():
        return False, "SKILL.md not found"
    content = skill_md.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return False, "Invalid frontmatter format"
    try:
        frontmatter = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        return False, "Invalid YAML in frontmatter: " + str(exc)
    if not isinstance(frontmatter, dict):
        return False, "Frontmatter must be a YAML dictionary"
    allowed = {"name", "description", "license", "allowed-tools", "metadata"}
    unknown = set(frontmatter) - allowed
    if unknown:
        return False, "Unexpected frontmatter keys: " + ", ".join(sorted(unknown))
    if set(("name", "description")) - set(frontmatter):
        return False, "Missing name or description"
    name = frontmatter["name"]
    description = frontmatter["description"]
    if (
        not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
        or len(name) > 64
    ):
        return False, "Invalid Skill name"
    if not isinstance(description, str) or len(description) > 1024 or "<" in description or ">" in description:
        return False, "Invalid Skill description"
    body = content[match.end():]
    if re.search(r"(?m)^[ ]{0,3}\[TODO:[^\n]*\][ \t]*$", body):
        return False, "Skill instructions contain an unfinished TODO placeholder"
    return True, "Skill is valid!"


def validate_docker_inventory_script(script_path):
    """Compile the read-only inventory entrypoint without writing bytecode."""
    path = Path(script_path)
    try:
        if not path.is_file() or path.is_symlink():
            return False, "Docker inventory script not found or unsafe"
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return False, "Invalid Docker inventory script: " + str(exc)
    return True, "Docker inventory script is valid!"


def validate_docker_inventory_v2_script(script_path):
    """Compile the separate inventory-v2 entrypoint without writing bytecode."""
    valid, message = validate_docker_inventory_script(script_path)
    if not valid:
        return False, message.replace("Docker inventory", "Docker inventory v2", 1)
    return True, "Docker inventory v2 script is valid!"


if __name__ == "__main__":
    if len(sys.argv) == 2:
        valid, message = validate_skill(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1] == "--docker-inventory-script":
        valid, message = validate_docker_inventory_script(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "--docker-inventory-v2-script":
        valid, message = validate_docker_inventory_v2_script(sys.argv[2])
    else:
        print("Usage: python quick_validate.py <skill_directory> | --docker-inventory-script <script> | --docker-inventory-v2-script <script>")
        raise SystemExit(1)
    print(message)
    raise SystemExit(0 if valid else 1)
