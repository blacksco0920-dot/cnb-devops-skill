"""Check this package's inline local Markdown links, including heading anchors.

This is a test utility for the package's ATX headings and inline links, not a
complete Markdown parser. Fenced examples do not define headings or links.
"""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


def prose(text):
    lines = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines)


def heading_anchors(text):
    anchors = set()
    for heading in re.findall(r"(?m)^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", prose(text)):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        anchor = slug
        suffix = 0
        while anchor in anchors:
            suffix += 1
            anchor = f"{slug}-{suffix}"
        anchors.add(anchor)
    return anchors


def local_link_errors(source: Path):
    errors = []
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", prose(source.read_text(encoding="utf-8"))):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc:
            continue
        resolved = (source.parent / unquote(parsed.path)).resolve() if parsed.path else source
        if not resolved.is_file():
            errors.append(f"{source}: missing target {target}")
        elif parsed.fragment and unquote(parsed.fragment) not in heading_anchors(resolved.read_text(encoding="utf-8")):
            errors.append(f"{source}: missing anchor {target}")
    return errors
