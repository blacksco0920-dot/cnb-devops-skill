#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
from urllib import error, parse, request


API_BASE = os.environ.get("CNB_API_BASE", "https://api.cnb.cool").rstrip("/")


class CnbError(RuntimeError):
    pass


CNB_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GIT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
FULL_COMMIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def token() -> str:
    value = os.environ.get("CNB_TOKEN", "").strip()
    if not value:
        raise CnbError("Missing CNB_TOKEN. Run: export CNB_TOKEN='your token'")
    return value


def redact(value: str) -> str:
    secret = os.environ.get("CNB_TOKEN", "")
    return value.replace(secret, "[REDACTED]") if secret else value


def validate_component(value: str, label: str) -> str:
    if not CNB_COMPONENT.fullmatch(value):
        raise CnbError(f"{label} must contain only letters, digits, '.', '_' or '-'")
    return value


def validate_namespace(value: str, label: str = "Organization") -> str:
    parts = value.split("/")
    if not parts or any(not CNB_COMPONENT.fullmatch(part) for part in parts):
        raise CnbError(f"{label} must contain valid path components")
    return value


def encode_repo(repo: str) -> str:
    if "/" not in repo:
        raise CnbError("Repository must be in owner/repo format, for example blacksco0920/FinAgent")
    owner, name = repo.rsplit("/", 1)
    validate_namespace(owner, "Repository organization")
    validate_component(name, "Repository name")
    return parse.quote(repo, safe="")


def validate_git_ref(value: str, label: str = "Branch") -> str:
    invalid = (
        not GIT_REF.fullmatch(value)
        or value.startswith(("/", "."))
        or value.endswith(("/", ".", ".lock"))
        or ".." in value
        or "//" in value
        or "@{" in value
    )
    if invalid:
        raise CnbError(f"{label} is not a safe Git reference")
    return value


def validate_event(value: str) -> str:
    if not EVENT_NAME.fullmatch(value):
        raise CnbError("Event must contain only letters, digits, '.', '_' or '-'")
    return value


def validate_commit_sha(value: str, *, full: bool) -> str:
    pattern = FULL_COMMIT_SHA if full else COMMIT_SHA
    if not pattern.fullmatch(value):
        requirement = "a full 40 or 64 character" if full else "a 7 to 64 character"
        raise CnbError(f"Commit SHA must be {requirement} hexadecimal value")
    return value.lower()


def api(method: str, path: str, body=None):
    data = None
    headers = {
        "Authorization": f"Bearer {token()}",
        "Accept": "application/vnd.cnb.api+json",
    }
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(f"{API_BASE}{path}", data=data, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise CnbError(f"CNB API {exc.code} {exc.reason}: {redact(raw)}") from exc
    except error.URLError as exc:
        raise CnbError(f"CNB API network error: {exc.reason}") from exc


def print_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def build_status(repo: str, sn: str):
    return api("GET", f"/{encode_repo(repo)}/-/build/status/{parse.quote(sn, safe='')}")


def active_stage_names(status_payload):
    names = []
    for pipeline in (status_payload.get("pipelinesStatus") or {}).values():
        for stage in pipeline.get("stages") or []:
            if stage.get("status") in ("start", "running"):
                names.append(stage.get("name") or stage.get("id") or "unknown")
    return names


def error_stage_names(status_payload):
    names = []
    for pipeline in (status_payload.get("pipelinesStatus") or {}).values():
        for stage in pipeline.get("stages") or []:
            if stage.get("status") in ("error", "failed"):
                names.append(stage.get("name") or stage.get("id") or "unknown")
    return names


def print_status_line(status_payload):
    status = status_payload.get("status", "unknown")
    active = active_stage_names(status_payload)
    errors = error_stage_names(status_payload)
    parts = [status]
    if active:
        parts.append("active: " + ", ".join(active))
    if errors:
        parts.append("error: " + ", ".join(errors))
    print(" | ".join(parts), flush=True)


def cmd_me(_args):
    print_json(api("GET", "/user"))


def cmd_groups(_args):
    print_json(api("GET", "/user/groups?page=1&page_size=100"))


def cmd_repos(args):
    slug = validate_namespace(args.slug)
    print_json(api("GET", f"/{parse.quote(slug, safe='')}/-/repos"))


def repository_entries(payload):
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    if isinstance(payload, dict):
        for key in ("data", "repositories", "repos", "items"):
            entries = payload.get(key)
            if isinstance(entries, list):
                return [entry for entry in entries if isinstance(entry, dict)]
    return []


def repository_name(entry):
    return entry.get("name") or entry.get("repo_name") or entry.get("repoName") or ""


def create_repository(slug: str, name: str, description: str, public: bool):
    body = {
        "name": validate_component(name, "Repository name"),
        "description": description or "",
        "visibility": "public" if public else "private",
    }
    return api("POST", f"/{parse.quote(slug, safe='')}/-/repos", body)


def cmd_create_repo(args):
    slug = validate_namespace(args.slug)
    print_json(create_repository(slug, args.name, args.description, args.public))


def cmd_ensure_repo(args):
    slug = validate_namespace(args.slug)
    name = validate_component(args.name, "Repository name")
    payload = api("GET", f"/{parse.quote(slug, safe='')}/-/repos")
    existing = next(
        (
            entry
            for entry in repository_entries(payload)
            if repository_name(entry).casefold() == name.casefold()
        ),
        None,
    )
    if existing is not None:
        print_json({"ok": True, "created": False, "repository": existing})
        return
    created = create_repository(slug, name, args.description, args.public)
    print_json({"ok": True, "created": True, "repository": created})


def cmd_settings(args):
    print_json(api("GET", f"/{encode_repo(args.repo)}/-/settings/cloud-native-build"))


def cmd_head(args):
    print_json(api("GET", f"/{encode_repo(args.repo)}/-/git/head"))


def cmd_enable_auto(args):
    current = api("GET", f"/{encode_repo(args.repo)}/-/settings/cloud-native-build") or {}
    current["auto_trigger"] = True
    current["cron_auto_trigger"] = False
    current["forked_repo_auto_trigger"] = False
    result = api("PUT", f"/{encode_repo(args.repo)}/-/settings/cloud-native-build", current)
    print_json({"ok": True, "repo": args.repo, "settings": current, "result": result})


def cmd_trigger(args):
    body = {
        "branch": validate_git_ref(args.branch),
        "event": validate_event(args.event),
        "title": args.title,
        "sync": "false",
    }
    if args.sha:
        body["sha"] = validate_commit_sha(args.sha, full=False)
    if args.tag:
        body["tag"] = validate_git_ref(args.tag, "Tag")
    print_json(api("POST", f"/{encode_repo(args.repo)}/-/build/start", body))


def cmd_promote(args):
    body = {
        "branch": validate_git_ref(args.branch),
        "event": validate_event(args.event),
        "title": args.title,
        "sha": validate_commit_sha(args.sha, full=True),
        "sync": "false",
    }
    print_json(api("POST", f"/{encode_repo(args.repo)}/-/build/start", body))


def cmd_status(args):
    payload = build_status(args.repo, args.sn)
    if args.compact:
        print_status_line(payload)
    else:
        print_json(payload)


def cmd_builds(args):
    query = parse.urlencode({"size": args.size})
    payload = api("GET", f"/{encode_repo(args.repo)}/-/build/logs?{query}") or {}
    builds = payload.get("data") if isinstance(payload, dict) else None
    if not args.compact or builds is None:
        print_json(payload)
        return
    for build in builds[: args.size]:
        sn = build.get("sn", "")
        status = build.get("status", "")
        created = build.get("createTime", "")
        sha = (build.get("sha") or "")[:10]
        title = (build.get("commitTitle") or "").replace("\n", " ")[:100]
        print(f"{sn}\t{status}\t{created}\t{sha}\t{title}")


def cmd_wait(args):
    deadline = time.monotonic() + args.timeout
    last_status = None
    while True:
        payload = build_status(args.repo, args.sn)
        status = payload.get("status", "unknown")
        line_signature = (
            status,
            tuple(active_stage_names(payload)),
            tuple(error_stage_names(payload)),
        )
        if line_signature != last_status or args.verbose:
            print_status_line(payload)
            last_status = line_signature

        if status == "success":
            return
        if status in ("error", "failed"):
            raise CnbError(f"Build {args.sn} ended with {status}")
        if time.monotonic() >= deadline:
            raise CnbError(f"Timed out waiting for build {args.sn} after {args.timeout}s")
        time.sleep(args.interval)


def cmd_runner_log(args):
    print(api("GET", f"/{encode_repo(args.repo)}/-/build/runner/download/log/{parse.quote(args.pipeline_id, safe='')}"))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cnb.py",
        description="Small CNB OpenAPI helper for Codex DevOps workflows.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("me", help="Show current CNB user")
    p.set_defaults(func=cmd_me)

    p = sub.add_parser("groups", help="List organizations available to the current CNB user")
    p.set_defaults(func=cmd_groups)

    p = sub.add_parser("repos", help="List repositories under an owner/group")
    p.add_argument("slug", help="Owner or group slug, for example blacksco0920")
    p.set_defaults(func=cmd_repos)

    p = sub.add_parser("create-repo", help="Create a private repository under an owner/group")
    p.add_argument("slug", help="Owner or group slug")
    p.add_argument("name", help="Repository name")
    p.add_argument("--description", default="", help="Repository description")
    p.add_argument("--public", action="store_true", help="Explicitly create a public repository")
    p.set_defaults(func=cmd_create_repo)

    p = sub.add_parser("ensure-repo", help="Reuse an existing repository or create it privately")
    p.add_argument("slug", help="Owner or group slug")
    p.add_argument("name", help="Repository name")
    p.add_argument("--description", default="", help="Repository description")
    p.add_argument("--public", action="store_true", help="Explicitly create a public repository")
    p.set_defaults(func=cmd_ensure_repo)

    p = sub.add_parser("settings", help="Get cloud-native build settings")
    p.add_argument("repo", help="owner/repo")
    p.set_defaults(func=cmd_settings)

    p = sub.add_parser("head", help="Get the repository default branch")
    p.add_argument("repo", help="owner/repo")
    p.set_defaults(func=cmd_head)

    p = sub.add_parser("enable-auto", help="Enable cloud-native build auto trigger")
    p.add_argument("repo", help="owner/repo")
    p.set_defaults(func=cmd_enable_auto)

    p = sub.add_parser("trigger", help="Trigger a CNB build")
    p.add_argument("repo", help="owner/repo")
    p.add_argument("--branch", default="main", help="Branch to build")
    p.add_argument("--event", default="api_trigger_codex", help="CNB trigger event name")
    p.add_argument("--title", default="Triggered by Codex", help="Build title")
    p.add_argument("--sha", default="", help="Optional commit SHA")
    p.add_argument("--tag", default="", help="Optional tag")
    p.set_defaults(func=cmd_trigger)

    p = sub.add_parser("promote", help="Trigger production for one exact full commit SHA")
    p.add_argument("repo", help="owner/repo")
    p.add_argument("--sha", required=True, help="Full 40 or 64 character commit SHA")
    p.add_argument("--branch", default="main", help="Release branch containing the commit")
    p.add_argument("--event", default="api_trigger_production", help="CNB production event name")
    p.add_argument("--title", default="Promote verified commit", help="Build title")
    p.set_defaults(func=cmd_promote)

    p = sub.add_parser("status", help="Get build status by build sn")
    p.add_argument("repo", help="owner/repo")
    p.add_argument("sn", help="Build serial number")
    p.add_argument("--compact", action="store_true", help="Print one status line instead of JSON")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("builds", help="List recent build records")
    p.add_argument("repo", help="owner/repo")
    p.add_argument("--size", type=int, default=5, help="Number of builds to fetch")
    p.add_argument("--compact", action="store_true", help="Print tab-separated summary lines")
    p.set_defaults(func=cmd_builds)

    p = sub.add_parser("wait", help="Wait for a build to finish")
    p.add_argument("repo", help="owner/repo")
    p.add_argument("sn", help="Build serial number")
    p.add_argument("--interval", type=int, default=20, help="Polling interval in seconds")
    p.add_argument("--timeout", type=int, default=1800, help="Maximum wait time in seconds")
    p.add_argument("--verbose", action="store_true", help="Print every poll, not only changes")
    p.set_defaults(func=cmd_wait)

    p = sub.add_parser("runner-log", help="Download runner log by pipeline id")
    p.add_argument("repo", help="owner/repo")
    p.add_argument("pipeline_id", help="Pipeline id")
    p.set_defaults(func=cmd_runner_log)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
        return 0
    except CnbError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
