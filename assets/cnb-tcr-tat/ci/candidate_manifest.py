#!/usr/bin/env python3
"""Create and strictly validate immutable CNB candidate manifests.

Adapted from the source-pinned implementation; see dependencies/SOURCES.md."""

import argparse
import datetime as datetime_module
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse


SCHEMA = "cnb-candidate/v1"
TOP_LEVEL_KEYS = {
    "project", "environment", "controller", "policy_sha256", "release_receipt_sha256",
    "application_commit",
    "build_id",
    "build_url",
    "candidate_tag",
    "controller_commit",
    "controller_compose_sha256",
    "controller_program_sha256",
    "created_at",
    "evidence",
    "manifest_sha256",
    "schema",
    "services",
}
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BUILD_ID = re.compile(r"^cnb-[a-z0-9][a-z0-9-]{2,127}$")


class CandidateError(ValueError):
    """Raised when candidate evidence is not a complete canonical manifest."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError(f"duplicate candidate key: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise CandidateError(f"invalid JSON constant: {value}")


def _canonical(model):
    return json.dumps(
        model, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def manifest_sha256(model):
    unsigned = dict(model)
    unsigned.pop("manifest_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _require_object(value, name):
    if type(value) is not dict:
        raise CandidateError(f"{name} must be an object")
    return value


def _require_exact_keys(value, name, keys):
    value = _require_object(value, name)
    actual = set(value)
    expected = set(keys)
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unknown:
        raise CandidateError(f"unknown {name} keys: {', '.join(unknown)}")
    if missing:
        raise CandidateError(f"missing {name} keys: {', '.join(missing)}")
    return value


def _require_string(value, name):
    if type(value) is not str:
        raise CandidateError(f"{name} must be a string")
    if not value:
        raise CandidateError(f"{name} must not be empty")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise CandidateError(f"{name} contains control characters")
    return value


def _require_sha256(value, name):
    value = _require_string(value, name)
    if not SHA256.fullmatch(value):
        raise CandidateError(f"{name} must be a lowercase SHA-256")
    return value


def _require_commit(value, name):
    value = _require_string(value, name)
    if not GIT_COMMIT.fullmatch(value):
        raise CandidateError(f"{name} must be a 40-character lowercase commit")
    return value


def _require_timestamp(value, name):
    value = _require_string(value, name)
    if not UTC_TIMESTAMP.fullmatch(value):
        raise CandidateError(f"{name} must be a UTC timestamp")
    try:
        datetime_module.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise CandidateError(f"{name} must be a UTC timestamp") from exc
    return value


def validate_config(config):
    _require_object(config, "CI config")
    if config.get("schema") != "cnb-devops-ci/v1" or config.get("environment") != "test":
        raise CandidateError("unsupported config or environment; production is not implemented")
    for field, pattern in (("project", r"[a-z][a-z0-9-]{0,62}"), ("controller_id", r"[a-z][a-z0-9-]{0,95}"), ("candidate_prefix", r"[a-z][a-z0-9-]{0,62}-"), ("cnb_repository", r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)+")):
        if not re.fullmatch(pattern, _require_string(config.get(field), field)):
            raise CandidateError(f"invalid config {field}")
    if any(part in (".", "..") for part in config["cnb_repository"].split("/")):
        raise CandidateError("invalid repository path")
    services = _require_object(config.get("services"), "config services")
    if not services:
        raise CandidateError("config services are empty")
    for name, spec in services.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
            raise CandidateError("invalid service name")
        repository = _require_string(spec.get("image_repository"), "image_repository")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9._/-]+", repository):
            raise CandidateError("invalid image repository")
    for key in ('controller_program_sha256', 'controller_compose_sha256', 'policy_sha256'):
        _require_sha256(config.get(key), key)
    expected_probes(config)
    return config


def expected_probes(config):
    probes = config.get("probes")
    if type(probes) is not list or not probes:
        raise CandidateError("expected probes are required")
    result = []
    for probe in probes:
        url = _require_string(probe.get("url"), "probe URL")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
            raise CandidateError("invalid expected probe URL")
        result.append(url)
    return sorted(set(result))


def _validate_build(model, config):
    build_id = _require_string(model["build_id"], "build_id")
    if not BUILD_ID.fullmatch(build_id):
        raise CandidateError("build_id has an invalid format")
    if model["candidate_tag"] != config["candidate_prefix"] + build_id:
        raise CandidateError("candidate_tag must be bound to build_id")
    expected_url = f"https://cnb.cool/{config['cnb_repository']}/-/build/logs/{build_id}"
    if model["build_url"] != expected_url:
        raise CandidateError("build_url must be the exact CNB build URL")


def _validate_services(value, config):
    services = _require_exact_keys(value, "services", config["services"])
    for service, spec in config["services"].items():
        image = _require_string(services[service], f"{service} image")
        expected = spec["image_repository"] + "@sha256:"
        if not image.startswith(expected) or not SHA256.fullmatch(image.removeprefix(expected)):
            raise CandidateError(f"{service} image must be its exact registry digest")


def _validate_reference(value, name):
    reference = _require_string(value, name)
    parsed = urlparse(reference)
    if reference.startswith("tat:"):
        if not re.fullmatch(r"tat:inv-[A-Za-z0-9-]{8,64}", reference):
            raise CandidateError(f"{name} has an invalid TAT reference")
    elif parsed.scheme != "https" or not parsed.netloc:
        raise CandidateError(f"{name} must be a non-secret HTTPS or TAT reference")
    return reference


def _validate_evidence(value, build_url, config):
    evidence = _require_exact_keys(value, "evidence", ("build", "runtime", "public"))
    expected_keys = {
        "build": {"status", "verified_at", "reference"},
        "runtime": {"status", "verified_at", "reference", "container_count"},
        "public": {"status", "verified_at", "reference", "probe_count", "probes"},
    }
    for plane, keys in expected_keys.items():
        item = _require_exact_keys(evidence[plane], f"evidence.{plane}", keys)
        if _require_string(item["status"], f"evidence.{plane}.status") != "passed":
            raise CandidateError(f"evidence.{plane}.status must be passed")
        _require_timestamp(item["verified_at"], f"evidence.{plane}.verified_at")
        reference = _validate_reference(item["reference"], f"evidence.{plane}.reference")
        if plane == "build" and reference != build_url:
            raise CandidateError("evidence.build.reference must equal build_url")
    if type(evidence["runtime"]["container_count"]) is not int or evidence["runtime"]["container_count"] != len(config["services"]):
        raise CandidateError("runtime evidence must cover exact service set")
    if type(evidence["public"]["probe_count"]) is not int or evidence["public"]["probe_count"] != len(expected_probes(config)):
        raise CandidateError("public evidence must cover exact expected probe set")
    if evidence["public"]["probes"] != expected_probes(config):
        raise CandidateError("public evidence probes do not match config")
    runtime_reference = evidence["runtime"]["reference"]
    public_reference = evidence["public"]["reference"]
    if not runtime_reference.startswith("tat:") or public_reference != runtime_reference:
        raise CandidateError("runtime and public evidence must bind the same TAT invocation")


def _validate_model(model, config, require_manifest_sha256):
    validate_config(config)
    required_keys = TOP_LEVEL_KEYS if require_manifest_sha256 else TOP_LEVEL_KEYS - {"manifest_sha256"}
    _require_exact_keys(model, "candidate", required_keys)
    if _require_string(model["schema"], "schema") != SCHEMA:
        raise CandidateError("unsupported candidate schema")
    for key, expected in (("project",config["project"]),("environment",config["environment"]),("controller",config["controller_id"])):
        if model[key] != expected:
            raise CandidateError(f"candidate {key} mismatch")
    _validate_build(model, config)
    application_commit = _require_commit(
        model["application_commit"], "application_commit"
    )
    controller_commit = _require_commit(model["controller_commit"], "controller_commit")
    if controller_commit != application_commit:
        raise CandidateError("controller_commit must equal application_commit")
    _require_timestamp(model["created_at"], "created_at")
    _require_sha256(model["controller_program_sha256"], "controller_program_sha256")
    _require_sha256(model["controller_compose_sha256"], "controller_compose_sha256")
    _require_sha256(model["policy_sha256"], "policy_sha256")
    _require_sha256(model["release_receipt_sha256"], "release_receipt_sha256")
    for key in ("controller_program_sha256", "controller_compose_sha256", "policy_sha256"):
        if model[key] != config[key]:
            raise CandidateError(f"candidate {key} does not match generated configuration")
    _validate_services(model["services"], config)
    _validate_evidence(model["evidence"], model["build_url"], config)
    if require_manifest_sha256:
        actual_hash = _require_sha256(model["manifest_sha256"], "manifest_sha256")
        if actual_hash != manifest_sha256(model):
            raise CandidateError("manifest_sha256 does not match manifest content")
    return model


def create_manifest(values: Mapping[str, object], config: dict) -> bytes:
    if not isinstance(values, Mapping):
        raise CandidateError("candidate values must be a mapping")
    model = dict(values)
    _validate_model(model, config, require_manifest_sha256=False)
    model["manifest_sha256"] = manifest_sha256(model)
    _validate_model(model, config, require_manifest_sha256=True)
    return _canonical(model) + b"\n"


def parse_manifest(raw: bytes, config: dict, expected_tag: str | None = None, expected_commit: str | None = None) -> dict:
    if type(raw) is not bytes:
        raise CandidateError("candidate manifest must be bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateError("candidate manifest must be UTF-8") from exc
    try:
        model = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except CandidateError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CandidateError("candidate manifest is invalid JSON") from exc
    _validate_model(model, config, require_manifest_sha256=True)
    if raw != _canonical(model) + b"\n":
        raise CandidateError("candidate manifest is not canonical")
    if expected_tag is not None and model["candidate_tag"] != expected_tag:
        raise CandidateError("candidate_tag does not match expected tag")
    if expected_commit is not None and model["application_commit"] != expected_commit:
        raise CandidateError("application_commit does not match expected commit")
    return model


def load_json(path):
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 128 * 1024:
            raise CandidateError("JSON input is too large")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError("cannot read valid JSON input") from exc


def assemble_candidate(raw, config, *, receipt_sha256, invocation_id, completed_at, build_id, commit):
    validate_config(config)
    _require_sha256(receipt_sha256, "receipt_sha256")
    if hashlib.sha256(raw).hexdigest() != receipt_sha256:
        raise CandidateError("receipt file differs from verified TAT output")
    try:
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError("invalid release receipt") from exc
    keys = {"schema", "status", "project", "environment", "controller", "git_sha", "controller_commit", "build_id", "images", "controller_program_sha256", "controller_compose_sha256", "policy_sha256", "database_backup_sha256", "container_count", "probe_count", "probes"}
    _require_exact_keys(receipt, "release receipt", keys)
    expected = {"schema":"cnb-deploy-result/v1", "status":"passed", "project":config["project"], "environment":config["environment"], "controller":config["controller_id"], "git_sha":commit, "controller_commit":commit, "build_id":build_id}
    for key, value in expected.items():
        if receipt[key] != value:
            raise CandidateError(f"receipt {key} mismatch")
    _validate_services(receipt["images"], config)
    for key in ("controller_program_sha256", "controller_compose_sha256", "policy_sha256", "database_backup_sha256"):
        _require_sha256(receipt[key], key)
    for key in ("controller_program_sha256", "controller_compose_sha256", "policy_sha256"):
        if receipt[key] != config[key]:
            raise CandidateError(f"receipt {key} does not match generated configuration")
    probes = expected_probes(config)
    if type(receipt["container_count"]) is not int or receipt["container_count"] != len(config["services"]) or type(receipt["probe_count"]) is not int or receipt["probe_count"] != len(probes) or receipt["probes"] != probes:
        raise CandidateError("release receipt coverage mismatch")
    if not re.fullmatch(r"inv-[A-Za-z0-9-]{8,64}", invocation_id):
        raise CandidateError("invalid invocation ID")
    _require_timestamp(completed_at, "completed_at")
    build_url = f"https://cnb.cool/{config['cnb_repository']}/-/build/logs/{build_id}"
    model = {"schema":SCHEMA, "project":config["project"], "environment":config["environment"], "controller":config["controller_id"], "application_commit":commit, "controller_commit":commit, "build_id":build_id, "build_url":build_url, "candidate_tag":config["candidate_prefix"]+build_id, "created_at":completed_at, "controller_program_sha256":receipt["controller_program_sha256"], "controller_compose_sha256":receipt["controller_compose_sha256"], "policy_sha256":receipt["policy_sha256"], "release_receipt_sha256":receipt_sha256, "services":receipt["images"], "evidence":{"build":{"status":"passed", "verified_at":completed_at, "reference":build_url}, "runtime":{"status":"passed", "verified_at":completed_at, "reference":"tat:"+invocation_id, "container_count":receipt["container_count"]}, "public":{"status":"passed", "verified_at":completed_at, "reference":"tat:"+invocation_id, "probe_count":receipt["probe_count"], "probes":probes}}}
    return create_manifest(model, config)


def emit_cnb_outputs(model):
    for key in ("candidate_tag", "manifest_sha256", "application_commit"):
        print(f"##[set-output {key}={model[key]}]")


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    subparsers=parser.add_subparsers(dest="command",required=True)
    for command in ("create", "validate", "assemble"):
        sub=subparsers.add_parser(command)
        sub.add_argument("--config",required=True)
        if command == "validate":
            sub.add_argument("--manifest",required=True)
            sub.add_argument("--expected-tag")
            sub.add_argument("--expected-commit")
            sub.add_argument("--emit-cnb-outputs",action="store_true")
        else:
            sub.add_argument("--output",required=True)
        if command == "create":
            sub.add_argument("--input",required=True)
        if command == "assemble":
            for field in ("receipt", "receipt-sha256", "invocation-id", "completed-at", "build-id", "commit"):
                sub.add_argument("--"+field,required=True)
    args=parser.parse_args(argv)
    try:
        config=validate_config(load_json(args.config))
        if args.command == "validate":
            model=parse_manifest(Path(args.manifest).read_bytes(), config, args.expected_tag, args.expected_commit)
            if args.emit_cnb_outputs:
                emit_cnb_outputs(model)
        else:
            if args.command == "create":
                raw=create_manifest(load_json(args.input),config)
            else:
                raw=assemble_candidate(Path(args.receipt).read_bytes(),config,receipt_sha256=args.receipt_sha256,invocation_id=args.invocation_id,completed_at=args.completed_at,build_id=args.build_id,commit=args.commit)
            with open(args.output,"xb") as destination:
                destination.write(raw)
            emit_cnb_outputs(parse_manifest(raw,config))
    except (CandidateError, OSError, TypeError, KeyError, AttributeError) as exc:
        print(f"candidate manifest error: {exc}",file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
