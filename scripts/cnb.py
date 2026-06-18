#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
from urllib import error, parse, request


API_BASE = os.environ.get("CNB_API_BASE", "https://api.cnb.cool").rstrip("/")


class CnbError(RuntimeError):
    pass


def token() -> str:
    value = os.environ.get("CNB_TOKEN", "").strip()
    if not value:
        raise CnbError("Missing CNB_TOKEN. Run: export CNB_TOKEN='your token'")
    return value


def encode_repo(repo: str) -> str:
    if "/" not in repo:
        raise CnbError("Repository must be in owner/repo format, for example blacksco0920/FinAgent")
    return parse.quote(repo, safe="")


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
        raise CnbError(f"CNB API {exc.code} {exc.reason}: {raw}") from exc
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


def cmd_repos(args):
    print_json(api("GET", f"/{parse.quote(args.slug, safe='')}/-/repos"))


def cmd_create_repo(args):
    body = {
        "name": args.name,
        "description": args.description or "",
        "visibility": "private" if args.private else "public",
    }
    print_json(api("POST", f"/{parse.quote(args.slug, safe='')}/-/repos", body))


def cmd_settings(args):
    print_json(api("GET", f"/{encode_repo(args.repo)}/-/settings/cloud-native-build"))


def cmd_enable_auto(args):
    current = api("GET", f"/{encode_repo(args.repo)}/-/settings/cloud-native-build") or {}
    current["auto_trigger"] = True
    current.setdefault("cron_auto_trigger", False)
    current.setdefault("forked_repo_auto_trigger", False)
    result = api("PUT", f"/{encode_repo(args.repo)}/-/settings/cloud-native-build", current)
    print_json({"ok": True, "repo": args.repo, "settings": current, "result": result})


def cmd_trigger(args):
    body = {
        "branch": args.branch,
        "event": args.event,
        "title": args.title,
        "sync": "false",
    }
    if args.sha:
        body["sha"] = args.sha
    if args.tag:
        body["tag"] = args.tag
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

    p = sub.add_parser("repos", help="List repositories under an owner/group")
    p.add_argument("slug", help="Owner or group slug, for example blacksco0920")
    p.set_defaults(func=cmd_repos)

    p = sub.add_parser("create-repo", help="Create a repository under an owner/group")
    p.add_argument("slug", help="Owner or group slug")
    p.add_argument("name", help="Repository name")
    p.add_argument("--description", default="", help="Repository description")
    p.add_argument("--private", action="store_true", help="Create as private repository")
    p.set_defaults(func=cmd_create_repo)

    p = sub.add_parser("settings", help="Get cloud-native build settings")
    p.add_argument("repo", help="owner/repo")
    p.set_defaults(func=cmd_settings)

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
