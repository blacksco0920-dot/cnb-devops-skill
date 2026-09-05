"""Structural validation for the evaluator catalog; never executes mapped tests."""
import ast
from pathlib import PurePosixPath
import re


def validate_catalog(catalog, mappings, root):
    sections = re.split(r"(?m)^#{2,6} ([A-Z][A-Z0-9_]+)\s*$", catalog)
    ids = sections[1::2]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("missing or duplicate catalog scenario IDs")
    for scenario_id, body in zip(ids, sections[2::2]):
        if not re.search(r"```text\n\S[\s\S]*?\n```", body) or not re.search(r"Expected:\s*\S", body):
            raise ValueError(f"{scenario_id}: missing prompt or expected behavior")
    if not isinstance(mappings, list):
        raise ValueError("mappings must be a list")
    mapped = []
    for entry in mappings:
        if not isinstance(entry, dict) or set(entry) != {"scenario_id", "tests"}:
            raise ValueError("invalid mapping record")
        scenario_id, tests = entry["scenario_id"], entry["tests"]
        mapped.append(scenario_id)
        if not isinstance(tests, list) or not tests or any(not isinstance(t, str) for t in tests):
            raise ValueError(f"{scenario_id}: missing test references")
        if len(tests) != len(set(tests)):
            raise ValueError(f"{scenario_id}: duplicate test reference")
        for reference in tests:
            if not re.fullmatch(r"tests\.test_[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_]*\.test_[a-z0-9_]+", reference):
                raise ValueError(f"invalid test reference: {reference}")
            module, cls, method = reference.rsplit(".", 2)
            source = root / (module.replace(".", "/") + ".py")
            try:
                tree = ast.parse(source.read_text(encoding="utf-8"))
            except (OSError, SyntaxError) as error:
                raise ValueError(f"unresolved test module: {reference}") from error
            if not any(isinstance(node, ast.ClassDef) and node.name == cls and
                       any(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                           child.name == method for child in node.body) for node in tree.body):
                raise ValueError(f"unresolved test class/method: {reference}")
    if len(mapped) != len(set(mapped)) or set(mapped) != set(ids):
        raise ValueError("missing, duplicate or unknown mapped scenario IDs")


def validate_fixture(fixture, scenario_ids):
    if fixture.get("scenario_id") not in scenario_ids or not fixture.get("user_request", "").strip():
        raise ValueError("unknown scenario or empty request")
    files = fixture.get("files")
    if not isinstance(files, dict) or not files or any(not isinstance(v, str) for v in files.values()):
        raise ValueError("fixture requires text files")
    paths = [fixture.get("task_root", ""), *fixture.get("read_only_paths", []), *files]
    for value in paths:
        path = PurePosixPath(value)
        if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError(f"unsafe fixture path: {value}")
    for value in [fixture["task_root"], *fixture.get("read_only_paths", [])]:
        if value != "." and not any(name == value or name.startswith(value + "/") for name in files):
            raise ValueError(f"fixture path does not exist: {value}")
