"""Check local Markdown links, including headings and explicit HTML anchors.

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
    body = prose(text)
    anchors = set()
    for heading in re.findall(r"(?m)^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", body):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        anchor = slug
        suffix = 0
        while anchor in anchors:
            suffix += 1
            anchor = f"{slug}-{suffix}"
        anchors.add(anchor)
    for _, anchor in re.findall(r"<a\b[^>]*\b(?:id|name)\s*=\s*(['\"])(.*?)\1", body, re.IGNORECASE):
        anchors.add(anchor)
    return anchors


def local_link_errors(source: Path):
    errors = []
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", prose(source.read_text(encoding="utf-8"))):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc:
            continue
        resolved = (source.parent / unquote(parsed.path)).resolve() if parsed.path else source
        if not (resolved.is_file() or resolved.is_dir()):
            errors.append(f"{source}: missing target {target}")
        elif parsed.fragment and (not resolved.is_file() or unquote(parsed.fragment) not in heading_anchors(resolved.read_text(encoding="utf-8"))):
            errors.append(f"{source}: missing anchor {target}")
    return errors
