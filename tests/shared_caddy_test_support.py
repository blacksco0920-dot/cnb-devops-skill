import gzip
import io
import json
from pathlib import Path
import shutil
import tarfile


ARCHIVE_FILES = (
    "caddy/declaration.json",
    "caddy/site.caddy",
    "caddy/helper-requirement.json",
    "caddy/bundle-provenance.json",
    "runtime/compose.json",
)


def install_fixture_bundle(helper, layout, fixture, deployment_id):
    pending = layout.bundle_root / deployment_id / "pending"
    shutil.copytree(fixture / "bundle", pending)
    helper_sha = helper.sha256_file(layout.helper_path)
    requirement_path = pending / "caddy" / "helper-requirement.json"
    requirement = json.loads(requirement_path.read_text())
    requirement["helper_sha256"] = helper_sha
    requirement_path.write_text(json.dumps(requirement, sort_keys=True) + "\n")

    declaration_path = pending / "caddy" / "declaration.json"
    fragment_path = pending / "caddy" / "site.caddy"
    compose_path = pending / "runtime" / "compose.json"
    manifest_path = pending / "caddy" / "server-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    declaration = json.loads(declaration_path.read_text())
    provenance = {
        "schema_version": "shared-caddy-bundle-provenance/v1",
        "contract_version": "shared-caddy-contract/v1",
        "helper_version": "1.0.0",
        "helper_sha256": helper_sha,
        "project_id": declaration["project_id"],
        "environment": declaration["environment"],
        "deployment_id": declaration["deployment_id"],
        "source_repo": declaration["source_repo"],
        "hosts": [route["host"] for route in declaration["routes"]],
        "git_sha": manifest["git_sha"],
        "declaration_sha256": helper.sha256_file(declaration_path),
        "fragment_sha256": helper.sha256_file(fragment_path),
        "compose_sha256": helper.sha256_file(compose_path),
        "helper_requirement_sha256": helper.sha256_file(requirement_path),
        "source": {"kind": "bundle"},
    }
    provenance_path = pending / "caddy" / "bundle-provenance.json"
    provenance_path.write_text(json.dumps(provenance, sort_keys=True) + "\n")

    archive_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=archive_buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for relative in ARCHIVE_FILES:
                data = (pending / relative).read_bytes()
                member = tarfile.TarInfo(relative)
                member.size = len(data)
                member.mode = 0o644
                member.mtime = 0
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(data))
    archive_data = archive_buffer.getvalue()
    bundle_id = helper.sha256_bytes(archive_data)
    (pending / "deploy-bundle.tar.gz").write_bytes(archive_data)

    manifest.update({
        "deploy_bundle_sha256": bundle_id,
        "helper_version": "1.0.0",
        "helper_sha256": helper_sha,
        "declaration_sha256": provenance["declaration_sha256"],
        "fragment_sha256": provenance["fragment_sha256"],
        "compose_sha256": provenance["compose_sha256"],
        "helper_requirement_sha256": provenance["helper_requirement_sha256"],
        "internal_provenance_sha256": helper.sha256_file(provenance_path),
    })
    (pending / "server-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    target = pending.with_name(bundle_id)
    pending.rename(target)
    return bundle_id
