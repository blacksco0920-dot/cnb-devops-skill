import importlib.util
import copy
import base64
import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


from test_bundle_host_policy import load_host, sample_policy

MODULE = load_host()


class PortedHostTransactionTests(unittest.TestCase):
    def setUp(self):
        policy = sample_policy(("api", "web", "worker", "reports"))
        policy["required_env"] += ["REDIS_URL", "REDIS_KEY_PREFIX", "JWT_SECRET", "SAMPLE_MAP_CODE"]
        policy["redis"] = {"url_env": "REDIS_URL", "host": "project-redis", "port": 6379,
                           "database": 0, "prefix_env": "REDIS_KEY_PREFIX", "prefix": "sample-test:",
                           "container": "project-redis"}
        MODULE.configure_policy(policy, policy_sha256="b" * 64)
        self.images = {
            name: (
                f"registry.example.invalid/demo/sample-{name}"
                f"@sha256:{index * 64}"
            )
            for name, index in (
                ("api", "1"),
                ("web", "2"),
                ("worker", "3"),
                ("reports", "4"),
            )
        }
        self.env = """# preserved comment
SAMPLE_API_IMAGE=old-api
SAMPLE_WEB_IMAGE=old-web
SAMPLE_WORKER_IMAGE=old-worker
SAMPLE_REPORTS_IMAGE=old-reports
DATABASE_URL=postgresql://sample_test_user:secret@project-postgres:5432/sample_test
REDIS_URL=redis://:secret@project-redis:6379/0
REDIS_KEY_PREFIX=sample-test:
JWT_SECRET=secret
SAMPLE_MAP_CODE=secret
API_PORT=3300
NODE_ENV=production
"""

    def _create_snapshot(self, release_root, *, created_at="2026-09-02T01:02:03Z"):
        env_bytes = b"ENV=value\n"
        compose_bytes = b"services:\n  api:\n    image: old\n"
        dump_bytes = b"PGDMP" + b"x" * 2048

        def backup_database(directory_fd, name, uid, gid):
            MODULE._write_new_at(directory_fd, name, dump_bytes, 0o600, uid, gid)
            return hashlib.sha256(dump_bytes).hexdigest()

        with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database):
            snapshot_ref = MODULE.create_release_snapshot(
                release_root,
                env_bytes=env_bytes,
                compose_bytes=compose_bytes,
                git_sha="a" * 40,
                build_id="cnb-backup-123",
                created_at=created_at,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        return snapshot_ref, env_bytes, compose_bytes, dump_bytes

    def _load_snapshot(self, snapshot_dir, release_root):
        valid_restore = mock.Mock(returncode=0)
        with mock.patch.object(MODULE.subprocess, "run", return_value=valid_restore):
            return MODULE.load_snapshot_manifest(
                snapshot_dir,
                release_root=release_root,
                uid=os.getuid(),
                gid=os.getgid(),
            )

    @staticmethod
    def _write_manifest(snapshot_dir, model):
        raw = (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        path = snapshot_dir / "snapshot-manifest.json"
        path.write_bytes(raw)
        path.chmod(0o600)

    @staticmethod
    def _canonical_bytes(model):
        return (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")

    def _previous_images(self):
        return {
            service: (
                f"registry.example.invalid/demo/sample-{service}"
                f"@sha256:{digit * 64}"
            )
            for service, digit in (
                ("api", "5"),
                ("web", "6"),
                ("worker", "7"),
                ("reports", "8"),
            )
        }

    def _legacy_release_record(self):
        return {
            "build_id": "cnb-previous-123",
            "controller": "sample-test-controller-v1",
            "controller_compose_sha256": MODULE.CONTROLLER_COMPOSE_SHA256,
            "controller_program_sha256": "9" * 64,
            "database_backup": (
                "/opt/apps/sample-test/backups/releases/"
                "20260901T010203Z-0123456789abcdef/database.dump"
            ),
            "database_backup_sha256": "a" * 64,
            "deployed_at": "2026-09-01T01:02:03Z",
            "git_sha": "b" * 40,
            "images": self._previous_images(),
            "probes": list(MODULE.PUBLIC_PROBES),
            "schema": "cnb-test-release/v1",
            "status": "passed",
        }

    def _v2_release_record(
        self,
        snapshot_ref,
        *,
        git_sha="b" * 40,
        build_id="cnb-previous-123",
    ):
        return {
            "build_id": build_id,
            "controller": "sample-test-controller-v1",
            "controller_compose_sha256": MODULE.CONTROLLER_COMPOSE_SHA256,
            "controller_program_sha256": "9" * 64,
            "deployed_at": "2026-09-01T01:02:03Z",
            "git_sha": git_sha,
            "images": self._previous_images(),
            "probes": list(MODULE.PUBLIC_PROBES),
            "schema": "cnb-test-release/v2",
            "snapshot": snapshot_ref.name,
            "snapshot_manifest_sha256": snapshot_ref.manifest_sha256,
            "status": "passed",
        }

    def _v2_release_transaction(
        self,
        snapshot_ref,
        *,
        git_sha="a" * 40,
        build_id="cnb-candidate-123",
    ):
        return {
            "build_id": build_id,
            "controller": "sample-test-controller-v1",
            "controller_compose_sha256": MODULE.CONTROLLER_COMPOSE_SHA256,
            "controller_program_sha256": "8" * 64,
            "git_sha": git_sha,
            "images": self.images,
            "phase": "prepared",
            "previous_images": self._previous_images(),
            "previous_release_sha256": "7" * 64,
            "schema": "cnb-test-release-transaction/v2",
            "snapshot": snapshot_ref.name,
            "snapshot_manifest_sha256": snapshot_ref.manifest_sha256,
            "status": "active",
            "updated_at": "2026-09-02T01:02:03Z",
        }

    @contextlib.contextmanager
    def _deploy_fixture(self, temporary, *, previous_release_bytes=None):
        base = Path(temporary).resolve()
        apps_root = base / "opt" / "apps"
        app_dir = apps_root / "sample-test"
        app_dir.mkdir(parents=True, mode=0o755)
        env_path = app_dir / ".env"
        compose_path = app_dir / "docker-compose.yml"
        release_path = app_dir / ".release.json"
        transaction_path = app_dir / ".release.transaction.json"
        lock_path = apps_root / ".sample-test.deploy.lock"
        recovery_root = base / "opt" / "sample-recovery"
        recovery_state = recovery_root / "state"
        recovery_marker = recovery_state / "sample-test.transaction.json"
        previous_images = self._previous_images()
        env_text = self.env
        for service, image in previous_images.items():
            key = f"SAMPLE_{service.upper()}_IMAGE"
            env_text = env_text.replace(f"{key}=old-{service}", f"{key}={image}")
        env_path.write_text(env_text, encoding="utf-8")
        env_path.chmod(0o600)
        compose_bytes = b"services: {}\n"
        compose_path.write_bytes(compose_bytes)
        compose_path.chmod(0o644)
        if previous_release_bytes is not None:
            release_path.write_bytes(previous_release_bytes)
            release_path.chmod(0o600)

        dump_bytes = b"PGDMP" + b"x" * 2048

        def backup_database(directory_fd, filename, uid, gid):
            MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
            return hashlib.sha256(dump_bytes).hexdigest()

        compose = mock.Mock(return_value=b"")
        preflight = mock.Mock()
        wait_for_runtime = mock.Mock()
        probe_public_urls = mock.Mock(return_value=MODULE.PUBLIC_PROBES)
        stdout = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in (
                ("APP_DIR", app_dir),
                ("ENV_PATH", env_path),
                ("COMPOSE_PATH", compose_path),
                ("RELEASE_PATH", release_path),
                ("TRANSACTION_PATH", transaction_path),
                ("LOCK_PATH", lock_path),
                ("RECOVERY_ROOT", recovery_root),
                ("RECOVERY_STATE_DIR", recovery_state),
                ("RECOVERY_TRANSACTION_PATH", recovery_marker),
            ):
                stack.enter_context(mock.patch.object(MODULE, name, value, create=True))
            stack.enter_context(
                mock.patch.object(
                    MODULE,
                    "_arguments",
                    return_value=(
                        SimpleNamespace(git_sha="a" * 40, controller_commit="a" * 40, build_id="cnb-candidate-123"),
                        self.images,
                        compose_bytes,
                    ),
                )
            )
            stack.enter_context(mock.patch.object(MODULE, "controller_program_sha256", return_value="c" * 64))
            stack.enter_context(mock.patch.object(MODULE, "_preflight", preflight))
            stack.enter_context(mock.patch.object(MODULE, "_compose", compose))
            stack.enter_context(mock.patch.object(MODULE, "_wait_for_runtime", wait_for_runtime))
            stack.enter_context(mock.patch.object(MODULE, "_probe_public_urls", probe_public_urls))
            stack.enter_context(mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database))
            stack.enter_context(mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)))
            stack.enter_context(mock.patch.object(MODULE.sys, "stdout", stdout))
            yield {
                "app_dir": app_dir,
                "compose": compose,
                "env_path": env_path,
                "preflight": preflight,
                "probe_public_urls": probe_public_urls,
                "recovery_marker": recovery_marker,
                "recovery_root": recovery_root,
                "recovery_state": recovery_state,
                "release_path": release_path,
                "stdout": stdout,
                "transaction_path": transaction_path,
                "wait_for_runtime": wait_for_runtime,
            }

    def _install_v2_deploy_history(self, fixture, *, count=7):
        release_root = fixture["app_dir"] / "backups" / "releases"
        release_root.mkdir(parents=True, mode=0o700)
        (fixture["app_dir"] / "backups").chmod(0o700)
        release_root.chmod(0o700)
        snapshots = [
            self._create_snapshot(
                release_root,
                created_at=f"2026-09-01T01:10:{second:02d}Z",
            )[0]
            for second in range(count)
        ]
        release = self._v2_release_record(
            snapshots[-1],
            git_sha="a" * 40,
            build_id="cnb-backup-123",
        )
        fixture["release_path"].write_bytes(self._canonical_bytes(release))
        fixture["release_path"].chmod(0o600)
        return release_root, snapshots

    def test_release_snapshot_writes_exact_canonical_manifest_and_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshot_ref, env_bytes, compose_bytes, dump_bytes = self._create_snapshot(release_root)
            snapshot_dir = release_root / snapshot_ref.name
            manifest_path = snapshot_dir / "snapshot-manifest.json"
            manifest_raw = manifest_path.read_bytes()
            manifest = self._load_snapshot(snapshot_dir, release_root)

            self.assertIsInstance(snapshot_ref, MODULE.SnapshotRef)
            self.assertEqual(snapshot_ref.manifest_path, manifest_path)
            self.assertEqual(snapshot_ref.manifest_sha256, hashlib.sha256(manifest_raw).hexdigest())
            self.assertEqual(
                manifest,
                {
                    "build_id": "cnb-backup-123",
                    "created_at": "2026-09-02T01:02:03Z",
                    "files": {
                        "docker-compose.before.yml": {
                            "bytes": len(compose_bytes),
                            "sha256": hashlib.sha256(compose_bytes).hexdigest(),
                        },
                        "database.dump": {
                            "bytes": len(dump_bytes),
                            "sha256": hashlib.sha256(dump_bytes).hexdigest(),
                        },
                        "env.before": {
                            "bytes": len(env_bytes),
                            "sha256": hashlib.sha256(env_bytes).hexdigest(),
                        },
                    },
                    "git_sha": "a" * 40,
                    "schema": "cnb-test-backup/v1",
                    "snapshot": snapshot_ref.name,
                },
            )
            self.assertEqual(
                manifest_raw,
                (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            )
            self.assertEqual(stat.S_IMODE(snapshot_dir.lstat().st_mode), 0o700)
            self.assertEqual(
                set(path.name for path in snapshot_dir.iterdir()),
                {
                    "env.before",
                    "docker-compose.before.yml",
                    "database.dump",
                    "snapshot-manifest.json",
                },
            )
            for path in snapshot_dir.iterdir():
                info = path.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode), path.name)
                self.assertEqual(info.st_nlink, 1, path.name)
                self.assertEqual((info.st_uid, info.st_gid), (os.getuid(), os.getgid()), path.name)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600, path.name)

    def test_release_snapshot_publishes_manifest_only_after_all_payload_fsyncs(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            events = []
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_fsync_file = MODULE._fsync_snapshot_file
            real_atomic_write = MODULE._atomic_write_at
            real_fsync_directory = MODULE._fsync_directory_fd

            def backup_database(directory_fd, name, uid, gid):
                MODULE._write_new_at(directory_fd, name, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            def fsync_file(directory_fd, name, uid, gid):
                events.append(("file", name))
                return real_fsync_file(directory_fd, name, uid, gid)

            def atomic_write(directory_fd, name, data, mode, uid, gid):
                events.append(("atomic", name))
                return real_atomic_write(directory_fd, name, data, mode, uid, gid)

            def fsync_directory(descriptor):
                events.append(("directory",))
                return real_fsync_directory(descriptor)

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE, "_fsync_snapshot_file", side_effect=fsync_file
            ), mock.patch.object(MODULE, "_atomic_write_at", side_effect=atomic_write), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=fsync_directory
            ):
                snapshot_ref = MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            manifest_event = events.index(("atomic", "snapshot-manifest.json"))
            payload_fsync_events = []
            for filename in MODULE.SNAPSHOT_FILES:
                payload_fsync_event = events.index(("file", filename))
                payload_fsync_events.append(payload_fsync_event)
                self.assertLess(payload_fsync_event, manifest_event)
            self.assertTrue(
                any(
                    max(payload_fsync_events) < index < manifest_event
                    for index, event in enumerate(events)
                    if event == ("directory",)
                )
            )
            self.assertGreater(
                max(index for index, event in enumerate(events) if event == ("directory",)),
                manifest_event,
            )

            second_root = Path(temporary).resolve() / "second-releases"
            second_root.mkdir(mode=0o700)
            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE, "_fsync_snapshot_file", side_effect=OSError("fsync failed")
            ), mock.patch.object(MODULE, "_atomic_write_at", wraps=MODULE._atomic_write_at) as atomic_write:
                with self.assertRaises(OSError):
                    MODULE.create_release_snapshot(
                        second_root,
                        env_bytes=b"ENV=value\n",
                        compose_bytes=b"services: {}\n",
                        git_sha="a" * 40,
                        build_id="cnb-backup-456",
                        created_at="2026-09-02T01:02:04Z",
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )
            atomic_write.assert_not_called()
            self.assertEqual(list(second_root.rglob("snapshot-manifest.json")), [])

    def test_release_snapshot_removes_manifest_when_publication_fsync_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            manifest_path = release_root / name / "snapshot-manifest.json"
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_fsync_directory = MODULE._fsync_directory_fd
            failed = False

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            def fsync_directory(descriptor):
                nonlocal failed
                if manifest_path.exists() and not failed:
                    failed = True
                    raise OSError("manifest directory fsync failed")
                return real_fsync_directory(descriptor)

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=fsync_directory
            ), self.assertRaises(OSError):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(failed)
            self.assertFalse(manifest_path.exists())

    def test_snapshot_loader_rejects_directory_replacement_outside_release_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
            snapshot_dir = release_root / snapshot_ref.name
            outside_snapshot = Path(temporary).resolve() / "outside-snapshot"
            real_digest = MODULE._snapshot_file_digest_at
            replaced = False

            def digest_then_replace(directory_fd, name, maximum, uid, gid, *, validate_dump=False):
                nonlocal replaced
                result = real_digest(
                    directory_fd,
                    name,
                    maximum,
                    uid,
                    gid,
                    validate_dump=validate_dump,
                )
                if not replaced:
                    replaced = True
                    snapshot_dir.rename(outside_snapshot)
                    snapshot_dir.symlink_to(outside_snapshot, target_is_directory=True)
                return result

            with mock.patch.object(MODULE, "_snapshot_file_digest_at", side_effect=digest_then_replace), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                self._load_snapshot(snapshot_dir, release_root)
            self.assertTrue(replaced)

    def test_snapshot_creation_stays_descriptor_anchored_if_directory_name_is_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            snapshot_dir = release_root / name
            moved_snapshot = Path(temporary).resolve() / "moved-snapshot"
            outside_target = Path(temporary).resolve() / "outside-target"
            outside_target.mkdir(mode=0o700)
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_write_new = MODULE._write_new_at
            replaced = False

            def write_then_replace(directory_fd, filename, data, mode, uid, gid):
                nonlocal replaced
                result = real_write_new(directory_fd, filename, data, mode, uid, gid)
                if filename == "env.before" and not replaced:
                    replaced = True
                    snapshot_dir.rename(moved_snapshot)
                    snapshot_dir.symlink_to(outside_target, target_is_directory=True)
                return result

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            with mock.patch.object(MODULE, "_write_new_at", side_effect=write_then_replace), mock.patch.object(
                MODULE, "_backup_database_at", side_effect=backup_database
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(replaced)
            self.assertEqual(list(outside_target.iterdir()), [])
            self.assertTrue((moved_snapshot / MODULE.SNAPSHOT_INCOMPLETE).exists())
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(moved_snapshot, moved_snapshot.parent)

    def test_snapshot_loader_rejects_same_inode_payload_mutation_during_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
            snapshot_dir = release_root / snapshot_ref.name
            real_digest = MODULE._snapshot_file_digest_at
            mutated = False

            def digest_then_mutate(directory_fd, name, maximum, uid, gid, *, validate_dump=False):
                nonlocal mutated
                result = real_digest(
                    directory_fd,
                    name,
                    maximum,
                    uid,
                    gid,
                    validate_dump=validate_dump,
                )
                if name == "env.before" and not mutated:
                    mutated = True
                    descriptor = os.open(name, os.O_WRONLY | os.O_TRUNC, dir_fd=directory_fd)
                    try:
                        os.write(descriptor, b"BAD=value\n")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                return result

            with mock.patch.object(MODULE, "_snapshot_file_digest_at", side_effect=digest_then_mutate), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                self._load_snapshot(snapshot_dir, release_root)
            self.assertTrue(mutated)

    def test_snapshot_creation_does_not_publish_after_same_inode_payload_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            snapshot_dir = release_root / name
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_digest = MODULE._snapshot_file_digest_at
            mutated = False

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            def digest_then_mutate(directory_fd, filename, maximum, uid, gid, *, validate_dump=False):
                nonlocal mutated
                result = real_digest(
                    directory_fd,
                    filename,
                    maximum,
                    uid,
                    gid,
                    validate_dump=validate_dump,
                )
                if filename == "env.before" and not mutated:
                    mutated = True
                    descriptor = os.open(filename, os.O_WRONLY | os.O_TRUNC, dir_fd=directory_fd)
                    try:
                        os.write(descriptor, b"BAD=value\n")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                return result

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE, "_snapshot_file_digest_at", side_effect=digest_then_mutate
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(mutated)
            self.assertFalse((snapshot_dir / "snapshot-manifest.json").exists())

    def test_snapshot_create_and_load_reject_symlinked_release_root_ancestors(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            actual_parent = base / "actual"
            actual_parent.mkdir(mode=0o700)
            release_root = actual_parent / "releases"
            release_root.mkdir(mode=0o700)
            snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
            (base / "linked").symlink_to(actual_parent, target_is_directory=True)
            linked_root = base / "linked" / "releases"

            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(linked_root / snapshot_ref.name, linked_root)

            dump_bytes = b"PGDMP" + b"x" * 2048

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                MODULE.create_release_snapshot(
                    linked_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="b" * 40,
                    build_id="cnb-backup-456",
                    created_at="2026-09-02T01:02:04Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

    def test_snapshot_create_and_load_reject_release_root_rename_and_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            release_root = base / "create-releases"
            release_root.mkdir(mode=0o700)
            moved_root = base / "moved-create-releases"
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_write_new = MODULE._write_new_at
            replaced = False

            def write_then_replace(directory_fd, filename, data, mode, uid, gid):
                nonlocal replaced
                result = real_write_new(directory_fd, filename, data, mode, uid, gid)
                if filename == "env.before" and not replaced:
                    replaced = True
                    release_root.rename(moved_root)
                    release_root.mkdir(mode=0o700)
                return result

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            with mock.patch.object(MODULE, "_write_new_at", side_effect=write_then_replace), mock.patch.object(
                MODULE, "_backup_database_at", side_effect=backup_database
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(replaced)
            self.assertFalse((release_root / name).exists())

            load_root = base / "load-releases"
            load_root.mkdir(mode=0o700)
            snapshot_ref, _env, _compose, _dump = self._create_snapshot(load_root)
            moved_load_root = base / "moved-load-releases"
            real_digest = MODULE._snapshot_file_digest_at
            load_replaced = False

            def digest_then_replace(directory_fd, filename, maximum, uid, gid, *, validate_dump=False):
                nonlocal load_replaced
                result = real_digest(
                    directory_fd,
                    filename,
                    maximum,
                    uid,
                    gid,
                    validate_dump=validate_dump,
                )
                if not load_replaced:
                    load_replaced = True
                    load_root.rename(moved_load_root)
                    load_root.mkdir(mode=0o700)
                return result

            with mock.patch.object(MODULE, "_snapshot_file_digest_at", side_effect=digest_then_replace), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                self._load_snapshot(load_root / snapshot_ref.name, load_root)
            self.assertTrue(load_replaced)
            self.assertFalse((load_root / snapshot_ref.name).exists())

    def test_snapshot_publication_cleanup_faults_never_leave_a_managed_snapshot(self):
        for label, unlink_fails, cleanup_fsync_fails in (
            ("unlink failure", True, False),
            ("cleanup fsync failure", False, True),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                release_root = Path(temporary).resolve() / "releases"
                release_root.mkdir(mode=0o700)
                name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
                snapshot_dir = release_root / name
                manifest_path = snapshot_dir / "snapshot-manifest.json"
                dump_bytes = b"PGDMP" + b"x" * 2048
                real_fsync = MODULE._fsync_directory_fd
                real_unlink = MODULE.os.unlink
                publication_failed = False
                cleanup_failed = False

                def backup_database(directory_fd, filename, uid, gid):
                    MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                    return hashlib.sha256(dump_bytes).hexdigest()

                def fsync_directory(descriptor):
                    nonlocal publication_failed, cleanup_failed
                    if manifest_path.exists() and not publication_failed:
                        publication_failed = True
                        raise OSError("publication fsync failed")
                    if publication_failed and cleanup_fsync_fails and not cleanup_failed:
                        cleanup_failed = True
                        raise OSError("cleanup fsync failed")
                    return real_fsync(descriptor)

                def unlink(path, *args, **kwargs):
                    if path == MODULE.SNAPSHOT_MANIFEST and unlink_fails:
                        raise OSError("manifest unlink failed")
                    return real_unlink(path, *args, **kwargs)

                with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                    MODULE, "_fsync_directory_fd", side_effect=fsync_directory
                ), mock.patch.object(MODULE.os, "unlink", side_effect=unlink), self.assertRaisesRegex(
                    MODULE.DeploymentError, "^snapshot_publication_cleanup_failed$"
                ):
                    MODULE.create_release_snapshot(
                        release_root,
                        env_bytes=b"ENV=value\n",
                        compose_bytes=b"services: {}\n",
                        git_sha="a" * 40,
                        build_id="cnb-backup-123",
                        created_at="2026-09-02T01:02:03Z",
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )
                self.assertTrue(publication_failed)
                if cleanup_fsync_fails:
                    self.assertTrue(cleanup_failed)
                with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                    self._load_snapshot(snapshot_dir, release_root)

    def test_snapshot_commit_fsync_error_is_terminal_durability_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            snapshot_dir = release_root / name
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_fsync = MODULE._fsync_directory_fd
            commit_fsync_failed = False

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            def fsync_directory(descriptor):
                nonlocal commit_fsync_failed
                if (
                    (snapshot_dir / MODULE.SNAPSHOT_MANIFEST).exists()
                    and not (snapshot_dir / MODULE.SNAPSHOT_INCOMPLETE).exists()
                    and not commit_fsync_failed
                ):
                    commit_fsync_failed = True
                    raise OSError("commit directory fsync failed")
                return real_fsync(descriptor)

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=fsync_directory
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_durability_unknown$"):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(commit_fsync_failed)
            self._load_snapshot(snapshot_dir, release_root)

    def test_snapshot_sentinel_loss_before_commit_is_durably_invalidated(self):
        for timing in ("after manifest read", "unlink raised after effect"):
            with self.subTest(timing=timing), tempfile.TemporaryDirectory() as temporary:
                release_root = Path(temporary).resolve() / "releases"
                release_root.mkdir(mode=0o700)
                name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
                snapshot_dir = release_root / name
                dump_bytes = b"PGDMP" + b"x" * 2048
                real_read = MODULE._read_snapshot_file_at
                real_unlink = MODULE.os.unlink
                sentinel_removed = False

                def backup_database(directory_fd, filename, uid, gid):
                    MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                    return hashlib.sha256(dump_bytes).hexdigest()

                def read_then_remove_sentinel(directory_fd, filename, maximum, uid, gid):
                    nonlocal sentinel_removed
                    result = real_read(directory_fd, filename, maximum, uid, gid)
                    if timing == "after manifest read" and filename == MODULE.SNAPSHOT_MANIFEST:
                        real_unlink(MODULE.SNAPSHOT_INCOMPLETE, dir_fd=directory_fd)
                        sentinel_removed = True
                    return result

                def unlink_after_effect(path, *args, **kwargs):
                    nonlocal sentinel_removed
                    result = real_unlink(path, *args, **kwargs)
                    if timing == "unlink raised after effect" and path == MODULE.SNAPSHOT_INCOMPLETE:
                        sentinel_removed = True
                        raise OSError("sentinel unlink outcome unknown")
                    return result

                with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                    MODULE, "_read_snapshot_file_at", side_effect=read_then_remove_sentinel
                ), mock.patch.object(MODULE.os, "unlink", side_effect=unlink_after_effect), self.assertRaises(
                    (MODULE.DeploymentError, OSError)
                ):
                    MODULE.create_release_snapshot(
                        release_root,
                        env_bytes=b"ENV=value\n",
                        compose_bytes=b"services: {}\n",
                        git_sha="a" * 40,
                        build_id="cnb-backup-123",
                        created_at="2026-09-02T01:02:03Z",
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )
                self.assertTrue(sentinel_removed)
                self.assertIn(MODULE.SNAPSHOT_INCOMPLETE, os.listdir(snapshot_dir))
                with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                    self._load_snapshot(snapshot_dir, release_root)

    def test_snapshot_publication_error_with_lost_sentinel_is_durably_invalidated(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            snapshot_dir = release_root / name
            manifest_path = snapshot_dir / MODULE.SNAPSHOT_MANIFEST
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_fsync = MODULE._fsync_directory_fd
            real_unlink = MODULE.os.unlink
            publication_failed = False

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            def fsync_after_sentinel_loss(descriptor):
                nonlocal publication_failed
                if manifest_path.exists() and not publication_failed:
                    real_unlink(MODULE.SNAPSHOT_INCOMPLETE, dir_fd=descriptor)
                    publication_failed = True
                    raise OSError("publication fsync failed after sentinel loss")
                return real_fsync(descriptor)

            def reject_manifest_cleanup(path, *args, **kwargs):
                if path == MODULE.SNAPSHOT_MANIFEST:
                    raise OSError("manifest cleanup failed")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=fsync_after_sentinel_loss
            ), mock.patch.object(MODULE.os, "unlink", side_effect=reject_manifest_cleanup), self.assertRaises(
                MODULE.DeploymentError
            ):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(publication_failed)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(snapshot_dir, release_root)

    def test_snapshot_staged_install_never_repairs_or_manages_a_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            moved = release_root / "moved-controller-snapshot"
            real_install = MODULE._rename_directory_noreplace_at
            dump_bytes = b"PGDMP" + b"x" * 2048
            swapped = False

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            def install_after_stage_swap(directory_fd, source, destination):
                nonlocal swapped
                if destination == name:
                    os.rename(source, moved.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    os.mkdir(source, mode=0o755, dir_fd=directory_fd)
                    swapped = True
                return real_install(directory_fd, source, destination)

            with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                MODULE,
                "_rename_directory_noreplace_at",
                side_effect=install_after_stage_swap,
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_durability_unknown$"):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertTrue(swapped)
            replacement = release_root / name
            self.assertEqual(stat.S_IMODE(replacement.stat().st_mode), 0o755)
            self.assertEqual(os.listdir(replacement), [])
            self.assertTrue(moved.is_dir())
            self.assertIn(MODULE.SNAPSHOT_INCOMPLETE, os.listdir(moved))
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(replacement, release_root)

    def test_snapshot_staging_rejects_mkdir_to_open_replacement_without_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            replacement = release_root / "replacement"
            replacement.mkdir(mode=0o755)
            moved = release_root / "moved-created-stage"
            real_mkdir = MODULE.os.mkdir
            stage_name = None
            dump_bytes = b"PGDMP" + b"x" * 2048

            def mkdir_then_swap(path, *args, **kwargs):
                nonlocal stage_name
                result = real_mkdir(path, *args, **kwargs)
                if isinstance(path, str) and path.startswith(f".{name}."):
                    os.rename(path, moved.name, src_dir_fd=kwargs["dir_fd"], dst_dir_fd=kwargs["dir_fd"])
                    os.rename(
                        replacement.name,
                        path,
                        src_dir_fd=kwargs["dir_fd"],
                        dst_dir_fd=kwargs["dir_fd"],
                    )
                    stage_name = path
                return result

            def backup_database(directory_fd, filename, uid, gid):
                MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                return hashlib.sha256(dump_bytes).hexdigest()

            with mock.patch.object(MODULE.os, "mkdir", side_effect=mkdir_then_swap), mock.patch.object(
                MODULE.os, "fchown", side_effect=AssertionError("staged replacement must not be repaired")
            ), mock.patch.object(
                MODULE.os, "fchmod", side_effect=AssertionError("staged replacement must not be repaired")
            ), mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertIsNotNone(stage_name)
            self.assertEqual(stat.S_IMODE((release_root / stage_name).stat().st_mode), 0o755)
            self.assertTrue(moved.is_dir())
            self.assertFalse((release_root / name).exists())

    def test_snapshot_final_metadata_mutations_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
            snapshot_dir = release_root / snapshot_ref.name
            real_digest = MODULE._snapshot_file_digest_at
            changed = False

            def digest_then_chmod(directory_fd, filename, maximum, uid, gid, *, validate_dump=False):
                nonlocal changed
                result = real_digest(
                    directory_fd,
                    filename,
                    maximum,
                    uid,
                    gid,
                    validate_dump=validate_dump,
                )
                if not changed:
                    changed = True
                    snapshot_dir.chmod(0o755)
                return result

            with mock.patch.object(MODULE, "_snapshot_file_digest_at", side_effect=digest_then_chmod), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                self._load_snapshot(snapshot_dir, release_root)
            self.assertTrue(changed)

        for mutation in ("mode", "hardlink", "owner"):
            with self.subTest(create_manifest_mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                release_root = base / "releases"
                release_root.mkdir(mode=0o700)
                outside_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
                real_atomic = MODULE._atomic_write_at
                real_open = MODULE._open_snapshot_file_at
                dump_bytes = b"PGDMP" + b"x" * 2048

                def backup_database(directory_fd, filename, uid, gid):
                    MODULE._write_new_at(directory_fd, filename, dump_bytes, 0o600, uid, gid)
                    return hashlib.sha256(dump_bytes).hexdigest()

                def atomic_then_mutate(directory_fd, filename, data, mode, uid, gid):
                    result = real_atomic(directory_fd, filename, data, mode, uid, gid)
                    if mutation == "mode":
                        os.chmod(filename, 0o640, dir_fd=directory_fd, follow_symlinks=False)
                    elif mutation == "hardlink":
                        os.link(
                            filename,
                            "manifest-hardlink",
                            src_dir_fd=directory_fd,
                            dst_dir_fd=outside_fd,
                            follow_symlinks=False,
                        )
                    return result

                def open_with_wrong_manifest_owner(directory_fd, filename, maximum, uid, gid):
                    if mutation == "owner" and filename == MODULE.SNAPSHOT_MANIFEST:
                        return real_open(directory_fd, filename, maximum, uid + 1, gid)
                    return real_open(directory_fd, filename, maximum, uid, gid)

                try:
                    with mock.patch.object(MODULE, "_backup_database_at", side_effect=backup_database), mock.patch.object(
                        MODULE, "_atomic_write_at", side_effect=atomic_then_mutate
                    ), mock.patch.object(
                        MODULE, "_open_snapshot_file_at", side_effect=open_with_wrong_manifest_owner
                    ), self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                        MODULE.create_release_snapshot(
                            release_root,
                            env_bytes=b"ENV=value\n",
                            compose_bytes=b"services: {}\n",
                            git_sha="a" * 40,
                            build_id="cnb-backup-123",
                            created_at="2026-09-02T01:02:03Z",
                            uid=os.getuid(),
                            gid=os.getgid(),
                        )
                finally:
                    os.close(outside_fd)

    def test_snapshot_loader_reaches_file_owner_and_hardlink_checks(self):
        for filename in (*MODULE.SNAPSHOT_FILES, MODULE.SNAPSHOT_MANIFEST):
            with self.subTest(owner=filename), tempfile.TemporaryDirectory() as temporary:
                release_root = Path(temporary).resolve() / "releases"
                release_root.mkdir(mode=0o700)
                snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
                snapshot_dir = release_root / snapshot_ref.name
                real_open = MODULE._open_snapshot_file_at

                def open_with_wrong_owner(directory_fd, name, maximum, uid, gid):
                    if name == filename:
                        return real_open(directory_fd, name, maximum, uid + 1, gid)
                    return real_open(directory_fd, name, maximum, uid, gid)

                with mock.patch.object(
                    MODULE, "_open_snapshot_file_at", side_effect=open_with_wrong_owner
                ), self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                    self._load_snapshot(snapshot_dir, release_root)

            with self.subTest(hardlink=filename), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                release_root = base / "releases"
                release_root.mkdir(mode=0o700)
                snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
                snapshot_dir = release_root / snapshot_ref.name
                os.link(snapshot_dir / filename, base / f"{filename}.hardlink")
                with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                    self._load_snapshot(snapshot_dir, release_root)

    def test_final_file_entry_check_proves_security_metadata_directly(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "payload"
            path.write_bytes(b"payload")
            path.chmod(0o600)
            expected = path.stat()
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for attribute, value in (
                    ("st_nlink", 2),
                    ("st_uid", expected.st_uid + 1),
                    ("st_gid", expected.st_gid + 1),
                    ("st_mode", stat.S_IFREG | 0o640),
                ):
                    with self.subTest(attribute=attribute):
                        current = mock.Mock()
                        for field in (
                            "st_mode",
                            "st_dev",
                            "st_ino",
                            "st_nlink",
                            "st_uid",
                            "st_gid",
                            "st_size",
                            "st_mtime_ns",
                            "st_ctime_ns",
                        ):
                            setattr(current, field, getattr(expected, field))
                        setattr(current, attribute, value)
                        with mock.patch.object(MODULE.os, "stat", return_value=current):
                            self.assertFalse(MODULE._same_file_entry(descriptor, path.name, expected))
            finally:
                os.close(descriptor)

    def test_snapshot_create_rejects_unsafe_existing_release_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o755)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._create_snapshot(release_root)

    def test_private_directory_creation_mutates_only_an_open_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / "backups"
            with mock.patch.object(
                MODULE.os, "chown", side_effect=AssertionError("path chown forbidden")
            ), mock.patch.object(
                MODULE.os, "chmod", side_effect=AssertionError("path chmod forbidden")
            ):
                MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            info = directory.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual((info.st_uid, info.st_gid), (os.getuid(), os.getgid()))

            unsafe = Path(temporary).resolve() / "unsafe-backups"
            unsafe.mkdir(mode=0o755)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                MODULE._safe_mkdir(unsafe, 0o700, os.getuid(), os.getgid())
            self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o755)

    def test_private_directory_creation_cannot_repair_a_post_mkdir_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            directory = base / "backups"
            moved = base / "moved-stage"
            replacement = base / "replacement"
            replacement.mkdir(mode=0o755)
            real_same = MODULE._same_directory_entry
            swapped = False

            def same_then_swap(directory_fd, name, expected):
                nonlocal swapped
                if not swapped and name.startswith(".backups."):
                    os.rename(name, moved.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    os.rename(
                        replacement.name,
                        name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                    swapped = True
                    return False
                return real_same(directory_fd, name, expected)

            with mock.patch.object(MODULE, "_same_directory_entry", side_effect=same_then_swap):
                with self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                    MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            self.assertTrue(swapped)
            self.assertEqual(stat.S_IMODE((base / next(name for name in os.listdir(base) if name.startswith(".backups."))).stat().st_mode), 0o755)
            self.assertTrue(moved.is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / "backups"
            real_install = MODULE._rename_directory_noreplace_at

            def install_after_unsafe_race(directory_fd, source, destination):
                os.mkdir(destination, mode=0o755, dir_fd=directory_fd)
                return real_install(directory_fd, source, destination)

            with mock.patch.object(
                MODULE, "_rename_directory_noreplace_at", side_effect=install_after_unsafe_race
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)

    def test_private_directory_staging_rejects_mkdir_to_open_replacement_without_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            directory = base / "backups"
            replacement = base / "replacement"
            replacement.mkdir(mode=0o755)
            moved = base / "moved-created-stage"
            real_mkdir = MODULE.os.mkdir
            stage_name = None

            def mkdir_then_swap(path, *args, **kwargs):
                nonlocal stage_name
                result = real_mkdir(path, *args, **kwargs)
                if isinstance(path, str) and path.startswith(".backups."):
                    os.rename(path, moved.name, src_dir_fd=kwargs["dir_fd"], dst_dir_fd=kwargs["dir_fd"])
                    os.rename(
                        replacement.name,
                        path,
                        src_dir_fd=kwargs["dir_fd"],
                        dst_dir_fd=kwargs["dir_fd"],
                    )
                    stage_name = path
                return result

            with mock.patch.object(MODULE.os, "mkdir", side_effect=mkdir_then_swap), mock.patch.object(
                MODULE.os, "fchown", side_effect=AssertionError("staged replacement must not be repaired")
            ), mock.patch.object(
                MODULE.os, "fchmod", side_effect=AssertionError("staged replacement must not be repaired")
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            self.assertIsNotNone(stage_name)
            self.assertEqual(stat.S_IMODE((base / stage_name).stat().st_mode), 0o755)
            self.assertTrue(moved.is_dir())
            self.assertFalse(directory.exists())

    def test_private_directory_rejects_parent_path_replacement_during_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            parent = base / "parent"
            parent.mkdir(mode=0o700)
            directory = parent / "backups"
            moved_parent = base / "moved-parent"
            real_install = MODULE._rename_directory_noreplace_at
            replaced = False

            def install_after_parent_replacement(directory_fd, source, destination):
                nonlocal replaced
                parent.rename(moved_parent)
                parent.mkdir(mode=0o700)
                replaced = True
                return real_install(directory_fd, source, destination)

            with mock.patch.object(
                MODULE,
                "_rename_directory_noreplace_at",
                side_effect=install_after_parent_replacement,
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            self.assertTrue(replaced)
            self.assertFalse(directory.exists())

    def test_private_directory_cleanup_never_removes_a_staging_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            directory = base / "backups"
            moved = base / "moved-stage"
            replacement_name = None
            real_same = MODULE._same_directory_entry

            def same_then_replace(directory_fd, name, expected):
                nonlocal replacement_name
                if replacement_name is None and name.startswith(".backups."):
                    os.rename(name, moved.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    os.mkdir(name, mode=0o700, dir_fd=directory_fd)
                    replacement_name = name
                    return False
                return real_same(directory_fd, name, expected)

            with mock.patch.object(MODULE, "_same_directory_entry", side_effect=same_then_replace):
                with self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                    MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            self.assertIsNotNone(replacement_name)
            self.assertTrue((base / replacement_name).is_dir())
            self.assertTrue(moved.is_dir())

    def test_owned_staging_cleanup_is_parent_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / "backups"
            real_install = MODULE._rename_directory_noreplace_at
            real_rmdir = MODULE.os.rmdir
            real_fsync = MODULE._fsync_directory_fd
            events = []

            def install_after_collision(directory_fd, source, destination):
                os.mkdir(destination, mode=0o755, dir_fd=directory_fd)
                return real_install(directory_fd, source, destination)

            def record_rmdir(*args, **kwargs):
                events.append("rmdir")
                return real_rmdir(*args, **kwargs)

            def record_fsync(descriptor):
                events.append("fsync")
                return real_fsync(descriptor)

            with mock.patch.object(
                MODULE, "_rename_directory_noreplace_at", side_effect=install_after_collision
            ), mock.patch.object(MODULE.os, "rmdir", side_effect=record_rmdir), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=record_fsync
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^unsafe_backup_directory$"):
                MODULE._safe_mkdir(directory, 0o700, os.getuid(), os.getgid())
            rmdir_index = events.index("rmdir")
            self.assertIn("fsync", events[rmdir_index + 1 :])

        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            name = MODULE._snapshot_name("2026-09-02T01:02:03Z", "cnb-backup-123")
            (release_root / name).mkdir(mode=0o700)
            real_rmdir = MODULE.os.rmdir
            real_fsync = MODULE._fsync_directory_fd
            events = []

            def record_rmdir(*args, **kwargs):
                events.append("rmdir")
                return real_rmdir(*args, **kwargs)

            def record_fsync(descriptor):
                events.append("fsync")
                return real_fsync(descriptor)

            with mock.patch.object(MODULE.os, "rmdir", side_effect=record_rmdir), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=record_fsync
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_path_exists$"):
                MODULE.create_release_snapshot(
                    release_root,
                    env_bytes=b"ENV=value\n",
                    compose_bytes=b"services: {}\n",
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                    created_at="2026-09-02T01:02:03Z",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            rmdir_index = events.index("rmdir")
            self.assertIn("fsync", events[rmdir_index + 1 :])

    def test_database_backup_digest_reads_only_captured_size_and_detects_growth(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            dump_bytes = b"PGDMP" + b"x" * 2048
            real_read = MODULE.os.read
            total_read = 0

            def fake_run(_argv, *, output, **_kwargs):
                output.write(dump_bytes)
                return b""

            def validate_then_grow(descriptor):
                os.lseek(descriptor, 0, os.SEEK_END)
                os.write(descriptor, b"growth" * 1024)

            def bounded_read(descriptor, amount):
                nonlocal total_read
                block = real_read(descriptor, amount)
                total_read += len(block)
                return block

            try:
                with mock.patch.object(MODULE, "_run", side_effect=fake_run), mock.patch.object(
                    MODULE, "_validate_database_dump_descriptor", side_effect=validate_then_grow
                ), mock.patch.object(MODULE.os, "read", side_effect=bounded_read), self.assertRaisesRegex(
                    MODULE.DeploymentError, "^database_backup_invalid$"
                ):
                    MODULE._backup_database_at(
                        directory_fd,
                        "database.dump",
                        os.getuid(),
                        os.getgid(),
                    )
            finally:
                os.close(directory_fd)
            self.assertLessEqual(total_read, len(dump_bytes) + 1)

    def test_snapshot_manifest_rejects_unsafe_or_mismatched_files_and_metadata(self):
        mutations = (
            ("missing payload", lambda snapshot, manifest: (snapshot / "env.before").unlink()),
            ("extra payload", lambda snapshot, manifest: (snapshot / "extra").write_bytes(b"extra")),
            (
                "symlink payload",
                lambda snapshot, manifest: (
                    (snapshot / "env.before").unlink(),
                    (snapshot / "env.before").symlink_to(snapshot / "docker-compose.before.yml"),
                ),
            ),
            ("group-readable payload", lambda snapshot, manifest: (snapshot / "env.before").chmod(0o640)),
            ("mismatched name", lambda snapshot, manifest: manifest.update(snapshot="wrong-name")),
            ("invalid timestamp", lambda snapshot, manifest: manifest.update(created_at="2026-09-02 01:02:03")),
            (
                "wrong byte count",
                lambda snapshot, manifest: manifest["files"]["env.before"].update(bytes=999),
            ),
            (
                "wrong digest",
                lambda snapshot, manifest: manifest["files"]["env.before"].update(sha256="b" * 64),
            ),
            ("wrong schema", lambda snapshot, manifest: manifest.update(schema="sample-test-backup/v2")),
            ("extra field", lambda snapshot, manifest: manifest.update(path="/opt/apps/sample-test/.env")),
            (
                "manifest-supplied path",
                lambda snapshot, manifest: manifest["files"].update(
                    {"../env.before": manifest["files"].pop("env.before")}
                ),
            ),
            (
                "boolean byte count",
                lambda snapshot, manifest: manifest["files"]["env.before"].update(bytes=True),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                release_root = Path(temporary).resolve() / "releases"
                release_root.mkdir(mode=0o700)
                snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
                snapshot_dir = release_root / snapshot_ref.name
                manifest = json.loads(snapshot_ref.manifest_path.read_text(encoding="ascii"))
                mutate(snapshot_dir, manifest)
                if label not in {"missing payload", "extra payload", "symlink payload", "group-readable payload"}:
                    self._write_manifest(snapshot_dir, manifest)
                with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                    self._load_snapshot(snapshot_dir, release_root)

    def test_snapshot_manifest_rejects_duplicate_keys_owner_directory_mode_invalid_dump_and_out_of_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshot_ref, _env, _compose, _dump = self._create_snapshot(release_root)
            snapshot_dir = release_root / snapshot_ref.name
            original_manifest = snapshot_ref.manifest_path.read_bytes()

            duplicate = original_manifest.replace(
                b'{"build_id":"cnb-backup-123",',
                b'{"build_id":"cnb-backup-123","build_id":"cnb-backup-123",',
                1,
            )
            snapshot_ref.manifest_path.write_bytes(duplicate)
            snapshot_ref.manifest_path.chmod(0o600)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(snapshot_dir, release_root)

            snapshot_ref.manifest_path.write_bytes(original_manifest)
            snapshot_ref.manifest_path.chmod(0o600)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                MODULE.load_snapshot_manifest(
                    snapshot_dir,
                    release_root=release_root,
                    uid=os.getuid() + 1,
                    gid=os.getgid(),
                )

            snapshot_dir.chmod(0o755)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(snapshot_dir, release_root)
            snapshot_dir.chmod(0o700)

            invalid_restore = mock.Mock(returncode=1)
            with mock.patch.object(MODULE.subprocess, "run", return_value=invalid_restore), self.assertRaisesRegex(
                MODULE.DeploymentError, "^snapshot_manifest_invalid$"
            ):
                MODULE.load_snapshot_manifest(
                    snapshot_dir,
                    release_root=release_root,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            outside_root = Path(temporary).resolve() / "other-releases"
            outside_root.mkdir(mode=0o700)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(snapshot_dir, outside_root)

            legacy = release_root / "20260902T010203Z-0123456789abcdef"
            legacy.mkdir(mode=0o700)
            with self.assertRaisesRegex(MODULE.DeploymentError, "^snapshot_manifest_invalid$"):
                self._load_snapshot(legacy, release_root)

    def test_retention_keeps_the_newest_five_valid_managed_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshots = [
                self._create_snapshot(
                    release_root,
                    created_at=f"2026-09-02T01:02:{second:02d}Z",
                )[0]
                for second in range(7)
            ]
            with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)):
                removed = MODULE.prune_release_snapshots(
                    release_root,
                    protected_names=frozenset(),
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            self.assertEqual(removed, tuple(snapshot.name for snapshot in snapshots[:2]))
            self.assertEqual(
                set(os.listdir(release_root)),
                {snapshot.name for snapshot in snapshots[2:]},
            )

    def test_retention_keeps_record_transaction_and_current_snapshots_beyond_the_newest_five(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshots = [
                self._create_snapshot(
                    release_root,
                    created_at=f"2026-09-02T01:03:{second:02d}Z",
                )[0]
                for second in range(9)
            ]
            release_record = self._v2_release_record(snapshots[0])
            release_transaction = self._v2_release_transaction(snapshots[1])
            protected = MODULE.protected_snapshot_names(release_record, release_transaction)
            self.assertEqual(protected, frozenset({snapshots[0].name, snapshots[1].name}))

            with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)):
                removed = MODULE.prune_release_snapshots(
                    release_root,
                    protected_names=protected | {snapshots[2].name},
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            self.assertEqual(removed, (snapshots[3].name,))
            self.assertEqual(
                set(os.listdir(release_root)),
                {snapshot.name for index, snapshot in enumerate(snapshots) if index != 3},
            )

    def test_retention_skips_unknown_unsafe_and_out_of_root_material_without_counting_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            release_root = base / "releases"
            release_root.mkdir(mode=0o700)
            valid = [
                self._create_snapshot(
                    release_root,
                    created_at=f"2026-09-02T01:04:{second:02d}Z",
                )[0]
                for second in range(6)
            ]
            invalid_manifest = self._create_snapshot(
                release_root, created_at="2026-09-02T01:04:10Z"
            )[0]
            invalid_manifest.manifest_path.write_bytes(b"{}\n")
            invalid_manifest.manifest_path.chmod(0o600)
            extra_content = self._create_snapshot(
                release_root, created_at="2026-09-02T01:04:11Z"
            )[0]
            (release_root / extra_content.name / "unexpected").write_bytes(b"preserve me")
            wrong_mode = self._create_snapshot(
                release_root, created_at="2026-09-02T01:04:12Z"
            )[0]
            (release_root / wrong_mode.name).chmod(0o755)
            wrong_owner = self._create_snapshot(
                release_root, created_at="2026-09-02T01:04:13Z"
            )[0]
            legacy_name = "20260902T010420Z-aaaaaaaaaaaaaaaa"
            (release_root / legacy_name).mkdir(mode=0o700)
            outside = base / "outside-snapshot"
            outside.mkdir(mode=0o700)
            outside_evidence = outside / "do-not-delete"
            outside_evidence.write_bytes(b"outside")
            symlink_name = "20260902T010421Z-bbbbbbbbbbbbbbbb"
            (release_root / symlink_name).symlink_to(outside, target_is_directory=True)
            invalid_names = {
                invalid_manifest.name,
                extra_content.name,
                wrong_mode.name,
                wrong_owner.name,
                legacy_name,
                symlink_name,
            }
            real_load = MODULE.load_snapshot_manifest
            real_unlink = MODULE.os.unlink
            unlinked = []

            def load_with_wrong_owner(snapshot_dir, **kwargs):
                if Path(snapshot_dir).name == wrong_owner.name:
                    raise MODULE.DeploymentError("snapshot_manifest_invalid")
                return real_load(snapshot_dir, **kwargs)

            def record_unlink(path, *args, **kwargs):
                unlinked.append(os.fspath(path))
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(MODULE, "load_snapshot_manifest", side_effect=load_with_wrong_owner), mock.patch.object(
                MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)
            ), mock.patch.object(MODULE.os, "unlink", side_effect=record_unlink):
                removed = MODULE.prune_release_snapshots(
                    release_root,
                    protected_names=frozenset(),
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            self.assertEqual(removed, (valid[0].name,))
            self.assertTrue(invalid_names.issubset(set(os.listdir(release_root))))
            self.assertTrue(outside_evidence.exists())
            self.assertFalse(any(name in invalid_names for name in unlinked))
            self.assertEqual(
                {snapshot.name for snapshot in valid[1:]},
                {name for name in os.listdir(release_root) if name in {item.name for item in valid}},
            )

    def test_retention_deletes_only_fixed_payloads_manifest_then_empty_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            release_root = Path(temporary).resolve() / "releases"
            release_root.mkdir(mode=0o700)
            snapshots = [
                self._create_snapshot(
                    release_root,
                    created_at=f"2026-09-02T01:05:{second:02d}Z",
                )[0]
                for second in range(6)
            ]
            root_info = release_root.stat()
            real_unlink = MODULE.os.unlink
            real_rmdir = MODULE.os.rmdir
            real_fsync = MODULE._fsync_directory_fd
            events = []

            def record_unlink(path, *args, **kwargs):
                events.append(("unlink", os.fspath(path)))
                return real_unlink(path, *args, **kwargs)

            def record_rmdir(path, *args, **kwargs):
                events.append(("rmdir", os.fspath(path)))
                return real_rmdir(path, *args, **kwargs)

            def record_fsync(descriptor):
                info = os.fstat(descriptor)
                events.append(("fsync", info.st_dev, info.st_ino))
                return real_fsync(descriptor)

            with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)), mock.patch.object(
                MODULE.os, "unlink", side_effect=record_unlink
            ), mock.patch.object(MODULE.os, "rmdir", side_effect=record_rmdir), mock.patch.object(
                MODULE, "_fsync_directory_fd", side_effect=record_fsync
            ):
                removed = MODULE.prune_release_snapshots(
                    release_root,
                    protected_names=frozenset(),
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            self.assertEqual(removed, (snapshots[0].name,))
            mutation_events = [event for event in events if event[0] in {"unlink", "rmdir"}]
            self.assertEqual(
                mutation_events[:4],
                [
                    ("unlink", "env.before"),
                    ("unlink", "docker-compose.before.yml"),
                    ("unlink", "database.dump"),
                    ("unlink", "snapshot-manifest.json"),
                ],
            )
            self.assertEqual(len(mutation_events), 5)
            self.assertEqual(mutation_events[4][0], "rmdir")
            self.assertTrue(mutation_events[4][1].startswith(MODULE.RETENTION_TOMBSTONE_PREFIX))
            self.assertNotEqual(mutation_events[4][1], snapshots[0].name)
            rmdir_index = events.index(mutation_events[4])
            self.assertIn(
                ("fsync", root_info.st_dev, root_info.st_ino),
                events[rmdir_index + 1 :],
            )

    def test_retention_unlink_or_root_fsync_failure_fails_closed(self):
        for fault in ("unlink", "root fsync"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                release_root = Path(temporary).resolve() / "releases"
                release_root.mkdir(mode=0o700)
                snapshots = [
                    self._create_snapshot(
                        release_root,
                        created_at=f"2026-09-02T01:06:{second:02d}Z",
                    )[0]
                    for second in range(6)
                ]
                root_info = release_root.stat()
                real_unlink = MODULE.os.unlink
                real_fsync = MODULE._fsync_directory_fd

                def fail_unlink(path, *args, **kwargs):
                    if fault == "unlink" and path == "env.before":
                        raise OSError("unlink failed")
                    return real_unlink(path, *args, **kwargs)

                def fail_root_fsync(descriptor):
                    info = os.fstat(descriptor)
                    if (
                        fault == "root fsync"
                        and info.st_dev == root_info.st_dev
                        and info.st_ino == root_info.st_ino
                        and not (release_root / snapshots[0].name).exists()
                    ):
                        raise OSError("root fsync failed")
                    return real_fsync(descriptor)

                with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)), mock.patch.object(
                    MODULE.os, "unlink", side_effect=fail_unlink
                ), mock.patch.object(MODULE, "_fsync_directory_fd", side_effect=fail_root_fsync), self.assertRaisesRegex(
                    MODULE.DeploymentError, "^backup_retention_failed$"
                ):
                    MODULE.prune_release_snapshots(
                        release_root,
                        protected_names=frozenset(),
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )

    def test_retention_detects_validated_file_or_directory_replacement_before_unlink(self):
        for replacement in ("file", "directory"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                release_root = base / "releases"
                release_root.mkdir(mode=0o700)
                snapshots = [
                    self._create_snapshot(
                        release_root,
                        created_at=f"2026-09-02T01:07:{second:02d}Z",
                    )[0]
                    for second in range(6)
                ]
                target = release_root / snapshots[0].name
                moved = base / f"moved-{replacement}"
                real_load = MODULE.load_snapshot_manifest
                replaced = False

                def load_then_replace(snapshot_dir, **kwargs):
                    nonlocal replaced
                    model = real_load(snapshot_dir, **kwargs)
                    if Path(snapshot_dir).name == snapshots[0].name and not replaced:
                        replaced = True
                        if replacement == "file":
                            (target / "env.before").rename(moved)
                            (target / "env.before").write_bytes(b"replacement\n")
                            (target / "env.before").chmod(0o600)
                        else:
                            target.rename(moved)
                            target.mkdir(mode=0o700)
                            (target / "unknown").write_bytes(b"replacement")
                    return model

                with mock.patch.object(MODULE, "load_snapshot_manifest", side_effect=load_then_replace), mock.patch.object(
                    MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)
                ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                    MODULE.prune_release_snapshots(
                        release_root,
                        protected_names=frozenset(),
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )
                self.assertTrue(replaced)
                if replacement == "file":
                    self.assertEqual(moved.read_bytes(), b"ENV=value\n")
                    self.assertEqual((target / "env.before").read_bytes(), b"replacement\n")
                else:
                    self.assertTrue((moved / "snapshot-manifest.json").exists())
                    self.assertEqual((target / "unknown").read_bytes(), b"replacement")

    def test_retention_quarantine_preserves_a_directory_replacement_at_rename_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            release_root = base / "releases"
            release_root.mkdir(mode=0o700)
            snapshots = [
                self._create_snapshot(
                    release_root,
                    created_at=f"2026-09-02T01:09:{second:02d}Z",
                )[0]
                for second in range(6)
            ]
            target = release_root / snapshots[0].name
            moved_original = base / "moved-original-snapshot"
            real_rename = MODULE._rename_directory_noreplace_at
            swapped = False
            quarantine_name = None

            def swap_at_quarantine(directory_fd, source, destination):
                nonlocal swapped, quarantine_name
                if source == snapshots[0].name and destination.startswith(".retention-"):
                    target.rename(moved_original)
                    target.mkdir(mode=0o700)
                    (target / "unknown-bytes").write_bytes(b"preserve replacement")
                    swapped = True
                    quarantine_name = destination
                return real_rename(directory_fd, source, destination)

            with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)), mock.patch.object(
                MODULE, "_rename_directory_noreplace_at", side_effect=swap_at_quarantine
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                MODULE.prune_release_snapshots(
                    release_root,
                    protected_names=frozenset(),
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            self.assertTrue(swapped)
            self.assertTrue((moved_original / "snapshot-manifest.json").exists())
            self.assertIsNotNone(quarantine_name)
            self.assertEqual(
                (release_root / quarantine_name / "unknown-bytes").read_bytes(),
                b"preserve replacement",
            )

    def test_retention_quarantine_detects_unlink_rmdir_and_root_fsync_entry_races(self):
        for race in ("unlink", "rmdir", "root fsync"):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                release_root = base / "releases"
                release_root.mkdir(mode=0o700)
                snapshots = [
                    self._create_snapshot(
                        release_root,
                        created_at=f"2026-09-02T01:11:{second:02d}Z",
                    )[0]
                    for second in range(6)
                ]
                root_info = release_root.stat()
                real_unlink = MODULE.os.unlink
                real_rmdir = MODULE.os.rmdir
                real_fsync = MODULE._fsync_directory_fd
                raced = False
                moved_root = base / "moved-release-root"

                def race_unlink(path, *args, **kwargs):
                    nonlocal raced
                    name = os.fspath(path)
                    if (
                        race == "unlink"
                        and not raced
                        and (
                            name in MODULE.SNAPSHOT_FILES
                            or name.startswith(".retention-file-")
                        )
                    ):
                        directory_fd = kwargs["dir_fd"]
                        os.rename(
                            name,
                            ".preserved-payload",
                            src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd,
                        )
                        descriptor = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=directory_fd,
                        )
                        try:
                            os.write(descriptor, b"unknown replacement")
                        finally:
                            os.close(descriptor)
                        raced = True
                        raise OSError("unlink entry changed")
                    return real_unlink(path, *args, **kwargs)

                def race_rmdir(path, *args, **kwargs):
                    nonlocal raced
                    name = os.fspath(path)
                    if race == "rmdir" and not raced and name.startswith(".retention-"):
                        directory_fd = kwargs["dir_fd"]
                        os.rename(
                            name,
                            ".preserved-empty-snapshot",
                            src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd,
                        )
                        os.mkdir(name, mode=0o700, dir_fd=directory_fd)
                        replacement_fd = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY,
                            dir_fd=directory_fd,
                        )
                        try:
                            descriptor = os.open(
                                "unknown-rmdir-bytes",
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                0o600,
                                dir_fd=replacement_fd,
                            )
                            try:
                                os.write(descriptor, b"preserve at rmdir")
                            finally:
                                os.close(descriptor)
                        finally:
                            os.close(replacement_fd)
                        raced = True
                    return real_rmdir(path, *args, **kwargs)

                def race_root_fsync(descriptor):
                    nonlocal raced
                    info = os.fstat(descriptor)
                    if (
                        race == "root fsync"
                        and not raced
                        and info.st_dev == root_info.st_dev
                        and info.st_ino == root_info.st_ino
                        and not (release_root / snapshots[0].name).exists()
                    ):
                        release_root.rename(moved_root)
                        release_root.symlink_to(moved_root, target_is_directory=True)
                        raced = True
                    return real_fsync(descriptor)

                with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)), mock.patch.object(
                    MODULE.os, "unlink", side_effect=race_unlink
                ), mock.patch.object(MODULE.os, "rmdir", side_effect=race_rmdir), mock.patch.object(
                    MODULE, "_fsync_directory_fd", side_effect=race_root_fsync
                ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                    MODULE.prune_release_snapshots(
                        release_root,
                        protected_names=frozenset(),
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )

                self.assertTrue(raced)
                evidence_root = moved_root if moved_root.exists() else release_root
                if race == "unlink":
                    preserved = [
                        path.read_bytes()
                        for path in evidence_root.rglob("*")
                        if path.is_file()
                    ]
                    self.assertIn(b"unknown replacement", preserved)
                    self.assertIn(b"ENV=value\n", preserved)
                    self.assertTrue(
                        any(path.name.startswith(".retention-") for path in evidence_root.iterdir())
                    )
                elif race == "rmdir":
                    self.assertEqual(
                        next(evidence_root.rglob("unknown-rmdir-bytes")).read_bytes(),
                        b"preserve at rmdir",
                    )
                else:
                    self.assertTrue(release_root.is_symlink())
                    self.assertTrue(moved_root.is_dir())

    def test_retention_held_link_counts_detect_lock_ignoring_syscall_entry_replacements(self):
        for replacement in ("file", "directory"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                release_root = Path(temporary).resolve() / "releases"
                release_root.mkdir(mode=0o700)
                snapshots = [
                    self._create_snapshot(
                        release_root,
                        created_at=f"2026-09-02T01:13:{second:02d}Z",
                    )[0]
                    for second in range(6)
                ]
                real_unlink = MODULE.os.unlink
                real_rmdir = MODULE.os.rmdir
                swapped = False

                def swap_file_at_unlink(path, *args, **kwargs):
                    nonlocal swapped
                    name = os.fspath(path)
                    if replacement == "file" and not swapped and name == "env.before":
                        directory_fd = kwargs["dir_fd"]
                        os.rename(
                            name,
                            ".preserved-expected-file",
                            src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd,
                        )
                        descriptor = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=directory_fd,
                        )
                        os.close(descriptor)
                        swapped = True
                    return real_unlink(path, *args, **kwargs)

                def swap_directory_at_rmdir(path, *args, **kwargs):
                    nonlocal swapped
                    name = os.fspath(path)
                    if (
                        replacement == "directory"
                        and not swapped
                        and name.startswith(MODULE.RETENTION_TOMBSTONE_PREFIX)
                    ):
                        directory_fd = kwargs["dir_fd"]
                        os.rename(
                            name,
                            ".preserved-expected-directory",
                            src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd,
                        )
                        os.mkdir(name, mode=0o700, dir_fd=directory_fd)
                        swapped = True
                    return real_rmdir(path, *args, **kwargs)

                with mock.patch.object(
                    MODULE.os,
                    "unlink",
                    side_effect=swap_file_at_unlink,
                ), mock.patch.object(
                    MODULE.os,
                    "rmdir",
                    side_effect=swap_directory_at_rmdir,
                ), mock.patch.object(
                    MODULE.sys,
                    "platform",
                    "linux",
                ), mock.patch.object(
                    MODULE.subprocess,
                    "run",
                    return_value=mock.Mock(returncode=0),
                ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                    MODULE.prune_release_snapshots(
                        release_root,
                        protected_names=frozenset(),
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )

                self.assertTrue(swapped)
                preserved = release_root.rglob(
                    ".preserved-expected-file"
                    if replacement == "file"
                    else ".preserved-expected-directory"
                )
                self.assertIsNotNone(next(preserved, None))

    def test_retention_authority_change_protects_target_and_blocks_transaction_and_migration(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self._deploy_fixture(temporary) as fixture:
                release_root, snapshots = self._install_v2_deploy_history(fixture)
                target = snapshots[0]
                target_dir = release_root / target.name
                changed_release = self._v2_release_record(
                    target,
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                )
                real_loader = getattr(MODULE, "_load_retention_authority", None)
                calls = 0

                def mutate_authority(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        fixture["release_path"].write_bytes(self._canonical_bytes(changed_release))
                        fixture["release_path"].chmod(0o600)
                    if real_loader is None:
                        return None
                    return real_loader(*args, **kwargs)

                with mock.patch.object(
                    MODULE,
                    "_load_retention_authority",
                    side_effect=mutate_authority,
                    create=True,
                ):
                    returncode = MODULE.deploy([])

                self.assertEqual(returncode, 1)
                self.assertGreaterEqual(calls, 2)
                self.assertEqual(json.loads(fixture["stdout"].getvalue())["reason"], "backup_retention_failed")
                self.assertTrue((target_dir / "env.before").exists())
                self.assertTrue((target_dir / "snapshot-manifest.json").exists())
                self.assertFalse(fixture["transaction_path"].exists())
                migration_calls = [
                    call
                    for call in fixture["compose"].call_args_list
                    if call.args[2][:4] == ["run", "--rm", "--no-deps", "api"]
                ]
                self.assertEqual(migration_calls, [])

    def test_retention_rereads_authority_immediately_after_each_unlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self._deploy_fixture(temporary) as fixture:
                release_root, snapshots = self._install_v2_deploy_history(fixture)
                target = snapshots[0]
                changed_release = self._v2_release_record(
                    target,
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                )
                real_unlink = MODULE.os.unlink
                real_listdir = MODULE.os.listdir
                mutated = False
                post_mutation_directory_reads = 0

                def mutate_after_first_unlink(path, *args, **kwargs):
                    nonlocal mutated
                    result = real_unlink(path, *args, **kwargs)
                    if not mutated and os.fspath(path) in MODULE.SNAPSHOT_FILES:
                        fixture["release_path"].write_bytes(self._canonical_bytes(changed_release))
                        fixture["release_path"].chmod(0o600)
                        mutated = True
                    return result

                def reject_work_before_authority_reread(path):
                    nonlocal post_mutation_directory_reads
                    if mutated:
                        post_mutation_directory_reads += 1
                    return real_listdir(path)

                with mock.patch.object(
                    MODULE.os,
                    "unlink",
                    side_effect=mutate_after_first_unlink,
                ), mock.patch.object(
                    MODULE.os,
                    "listdir",
                    side_effect=reject_work_before_authority_reread,
                ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                    MODULE.enforce_release_snapshot_retention(
                        release_root,
                        current_snapshot=snapshots[-1].name,
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )

                self.assertTrue(mutated)
                self.assertEqual(post_mutation_directory_reads, 0)
                tombstones = [
                    path
                    for path in release_root.iterdir()
                    if path.name.startswith(MODULE.RETENTION_TOMBSTONE_PREFIX)
                ]
                self.assertEqual(len(tombstones), 1)
                self.assertFalse(fixture["transaction_path"].exists())

    def test_second_retention_unlink_failure_preserves_partial_tombstone_before_migration(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self._deploy_fixture(temporary) as fixture:
                release_root, _snapshots = self._install_v2_deploy_history(fixture)
                real_unlink = MODULE.os.unlink
                deletion_unlinks = 0

                def fail_second_unlink(path, *args, **kwargs):
                    nonlocal deletion_unlinks
                    name = os.fspath(path)
                    if name in MODULE.SNAPSHOT_FILES or name.startswith(".retention-file-"):
                        deletion_unlinks += 1
                        if deletion_unlinks == 2:
                            directory_fd = kwargs["dir_fd"]
                            descriptor = os.open(
                                "unknown-partial-evidence",
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                0o600,
                                dir_fd=directory_fd,
                            )
                            try:
                                os.write(descriptor, b"preserve partial evidence")
                            finally:
                                os.close(descriptor)
                            raise OSError("second unlink failed")
                    return real_unlink(path, *args, **kwargs)

                with mock.patch.object(MODULE.os, "unlink", side_effect=fail_second_unlink):
                    returncode = MODULE.deploy([])

                self.assertEqual(returncode, 1)
                self.assertEqual(deletion_unlinks, 2)
                self.assertEqual(json.loads(fixture["stdout"].getvalue())["reason"], "backup_retention_failed")
                tombstones = [
                    path
                    for path in release_root.iterdir()
                    if path.name.startswith(".retention-") and path.is_dir()
                ]
                self.assertTrue(tombstones)
                self.assertEqual(
                    next(release_root.rglob("unknown-partial-evidence")).read_bytes(),
                    b"preserve partial evidence",
                )
                self.assertFalse(fixture["transaction_path"].exists())
                migration_calls = [
                    call
                    for call in fixture["compose"].call_args_list
                    if call.args[2][:4] == ["run", "--rm", "--no-deps", "api"]
                ]
                self.assertEqual(migration_calls, [])

    def test_legacy_release_is_compatible_but_disables_pruning_and_malformed_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            release_root = base / "releases"
            release_root.mkdir(mode=0o700)
            release_path = base / ".release.json"
            transaction_path = base / ".release.transaction.json"
            legacy_raw = self._canonical_bytes(self._legacy_release_record())
            release_path.write_bytes(legacy_raw)
            release_path.chmod(0o600)
            with mock.patch.object(MODULE, "RELEASE_PATH", release_path, create=True), mock.patch.object(
                MODULE, "TRANSACTION_PATH", transaction_path
            ), mock.patch.object(MODULE, "prune_release_snapshots") as prune:
                MODULE.enforce_release_snapshot_retention(
                    release_root,
                    current_snapshot="20260902T010203Z-0123456789abcdef",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            prune.assert_not_called()

            release_path.unlink()
            with mock.patch.object(MODULE, "RELEASE_PATH", release_path, create=True), mock.patch.object(
                MODULE, "TRANSACTION_PATH", transaction_path
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                MODULE.enforce_release_snapshot_retention(
                    release_root,
                    current_snapshot="20260902T010203Z-0123456789abcdef",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            release_path.write_bytes(json.dumps(self._legacy_release_record()).encode("ascii"))
            release_path.chmod(0o600)
            with mock.patch.object(MODULE, "RELEASE_PATH", release_path, create=True), mock.patch.object(
                MODULE, "TRANSACTION_PATH", transaction_path
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                MODULE.enforce_release_snapshot_retention(
                    release_root,
                    current_snapshot="20260902T010203Z-0123456789abcdef",
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            snapshot_ref = self._create_snapshot(
                release_root, created_at="2026-09-02T01:08:00Z"
            )[0]
            mismatched_binding = self._v2_release_record(snapshot_ref)
            mismatched_binding["snapshot_manifest_sha256"] = "e" * 64
            release_path.write_bytes(self._canonical_bytes(mismatched_binding))
            release_path.chmod(0o600)
            with mock.patch.object(MODULE, "RELEASE_PATH", release_path, create=True), mock.patch.object(
                MODULE, "TRANSACTION_PATH", transaction_path
            ), mock.patch.object(
                MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                MODULE.enforce_release_snapshot_retention(
                    release_root,
                    current_snapshot=snapshot_ref.name,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            malformed_v2 = self._v2_release_record(snapshot_ref)
            malformed_v2["database_backup"] = "/caller/controlled/path"
            release_path.write_bytes(self._canonical_bytes(malformed_v2))
            release_path.chmod(0o600)
            with mock.patch.object(MODULE, "RELEASE_PATH", release_path, create=True), mock.patch.object(
                MODULE, "TRANSACTION_PATH", transaction_path
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                MODULE.enforce_release_snapshot_retention(
                    release_root,
                    current_snapshot=snapshot_ref.name,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            release_path.write_bytes(self._canonical_bytes(self._v2_release_record(snapshot_ref)))
            release_path.chmod(0o600)
            malformed_transaction = self._v2_release_transaction(snapshot_ref)
            malformed_transaction["unexpected"] = True
            transaction_path.write_bytes(self._canonical_bytes(malformed_transaction))
            transaction_path.chmod(0o600)
            with mock.patch.object(MODULE, "RELEASE_PATH", release_path, create=True), mock.patch.object(
                MODULE, "TRANSACTION_PATH", transaction_path
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                MODULE.enforce_release_snapshot_retention(
                    release_root,
                    current_snapshot=snapshot_ref.name,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

    def test_v2_release_and_transaction_snapshot_bindings_require_matching_identity(self):
        for mismatch in ("release git", "release build", "transaction git", "transaction build"):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                release_root = base / "releases"
                release_root.mkdir(mode=0o700)
                release_snapshot = self._create_snapshot(
                    release_root, created_at="2026-09-02T01:12:00Z"
                )[0]
                transaction_snapshot = self._create_snapshot(
                    release_root, created_at="2026-09-02T01:12:01Z"
                )[0]
                release = self._v2_release_record(
                    release_snapshot,
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                )
                transaction = self._v2_release_transaction(
                    transaction_snapshot,
                    git_sha="a" * 40,
                    build_id="cnb-backup-123",
                )
                if mismatch == "release git":
                    release["git_sha"] = "b" * 40
                elif mismatch == "release build":
                    release["build_id"] = "cnb-other-release-123"
                elif mismatch == "transaction git":
                    transaction["git_sha"] = "b" * 40
                else:
                    transaction["build_id"] = "cnb-other-transaction-123"
                release_path = base / ".release.json"
                transaction_path = base / ".release.transaction.json"
                release_path.write_bytes(self._canonical_bytes(release))
                release_path.chmod(0o600)
                transaction_path.write_bytes(self._canonical_bytes(transaction))
                transaction_path.chmod(0o600)

                with mock.patch.object(MODULE, "RELEASE_PATH", release_path), mock.patch.object(
                    MODULE, "TRANSACTION_PATH", transaction_path
                ), mock.patch.object(
                    MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)
                ), self.assertRaisesRegex(MODULE.DeploymentError, "^backup_retention_failed$"):
                    MODULE.enforce_release_snapshot_retention(
                        release_root,
                        current_snapshot=transaction_snapshot.name,
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )

    def test_recovery_hierarchy_and_both_fixed_markers_fail_closed_without_reading_marker_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            recovery_root = base / "sample-recovery"
            recovery_state = recovery_root / "state"
            recovery_marker = recovery_state / "sample-test.transaction.json"
            release_marker = base / ".release.transaction.json"
            patches = (
                mock.patch.object(MODULE, "RECOVERY_ROOT", recovery_root, create=True),
                mock.patch.object(MODULE, "RECOVERY_STATE_DIR", recovery_state, create=True),
                mock.patch.object(MODULE, "RECOVERY_TRANSACTION_PATH", recovery_marker, create=True),
                mock.patch.object(MODULE, "TRANSACTION_PATH", release_marker),
            )
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                MODULE._assert_release_unblocked()

                recovery_root.mkdir(mode=0o755)
                with self.assertRaisesRegex(MODULE.DeploymentError, "^recovery_required$"):
                    MODULE._assert_release_unblocked()

                recovery_state.mkdir(mode=0o755)
                with mock.patch.object(MODULE, "_root_owned_public_directory", return_value=True, create=True):
                    MODULE._assert_release_unblocked()
                    recovery_marker.write_bytes(b"root-private-content-must-not-be-read")
                    with mock.patch.object(
                        Path, "read_bytes", side_effect=AssertionError("marker contents must not be read")
                    ), self.assertRaisesRegex(MODULE.DeploymentError, "^recovery_required$"):
                        MODULE._assert_release_unblocked()
                    recovery_marker.unlink()
                    recovery_marker.symlink_to(base / "missing-marker-target")
                    with self.assertRaisesRegex(MODULE.DeploymentError, "^recovery_required$"):
                        MODULE._assert_release_unblocked()
                    recovery_marker.unlink()
                    release_marker.symlink_to(base / "missing-release-target")
                    with self.assertRaisesRegex(MODULE.DeploymentError, "^recovery_required$"):
                        MODULE._assert_release_unblocked()

    def test_recovery_hierarchy_swap_after_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            recovery_root = base / "sample-recovery"
            recovery_state = recovery_root / "state"
            recovery_state.mkdir(parents=True, mode=0o755)
            moved_root = base / "moved-recovery-root"
            release_marker = base / ".release.transaction.json"
            checks = 0

            def validate_then_swap(_info):
                nonlocal checks
                checks += 1
                if checks == 2:
                    recovery_root.rename(moved_root)
                    recovery_root.symlink_to(moved_root, target_is_directory=True)
                return True

            with mock.patch.object(MODULE, "RECOVERY_ROOT", recovery_root), mock.patch.object(
                MODULE, "RECOVERY_STATE_DIR", recovery_state
            ), mock.patch.object(
                MODULE,
                "RECOVERY_TRANSACTION_PATH",
                recovery_state / "sample-test.transaction.json",
            ), mock.patch.object(MODULE, "TRANSACTION_PATH", release_marker), mock.patch.object(
                MODULE, "_root_owned_public_directory", side_effect=validate_then_swap
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^recovery_required$"):
                MODULE._assert_release_unblocked()
            self.assertEqual(checks, 2)
            self.assertTrue(recovery_root.is_symlink())
            self.assertTrue(moved_root.is_dir())

    def test_recovery_marker_injected_during_final_path_rewalk_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            recovery_root = base / "sample-recovery"
            recovery_state = recovery_root / "state"
            recovery_state.mkdir(parents=True, mode=0o755)
            recovery_marker = recovery_state / "sample-test.transaction.json"
            release_marker = base / ".release.transaction.json"
            real_rewalk = MODULE._same_exact_directory_path
            injected = False

            def inject_during_state_rewalk(path, expected, expected_chain):
                nonlocal injected
                result = real_rewalk(path, expected, expected_chain)
                if Path(path) == recovery_state and result and not injected:
                    recovery_marker.write_bytes(b"must remain unread")
                    injected = True
                return result

            with mock.patch.object(MODULE, "RECOVERY_ROOT", recovery_root), mock.patch.object(
                MODULE, "RECOVERY_STATE_DIR", recovery_state
            ), mock.patch.object(
                MODULE, "RECOVERY_TRANSACTION_PATH", recovery_marker
            ), mock.patch.object(MODULE, "TRANSACTION_PATH", release_marker), mock.patch.object(
                MODULE, "_root_owned_public_directory", return_value=True
            ), mock.patch.object(
                MODULE,
                "_same_exact_directory_path",
                side_effect=inject_during_state_rewalk,
            ), mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("recovery marker contents must not be read"),
            ), self.assertRaisesRegex(MODULE.DeploymentError, "^recovery_required$"):
                MODULE._assert_release_unblocked()

            self.assertTrue(injected)
            self.assertTrue(recovery_marker.exists())

    def test_recovery_marker_blocks_deploy_before_candidate_docker_snapshot_or_pruning(self):
        legacy_raw = self._canonical_bytes(self._legacy_release_record())
        for marker_kind in ("regular", "symlink"):
            with self.subTest(marker_kind=marker_kind), tempfile.TemporaryDirectory() as temporary:
                with self._deploy_fixture(temporary, previous_release_bytes=legacy_raw) as fixture:
                    fixture["recovery_state"].mkdir(parents=True, mode=0o755)
                    if marker_kind == "regular":
                        fixture["recovery_marker"].write_bytes(b"private marker")
                    else:
                        fixture["recovery_marker"].symlink_to(Path(temporary) / "missing-target")
                    with mock.patch.object(
                        MODULE, "_root_owned_public_directory", return_value=True, create=True
                    ), mock.patch.object(
                        MODULE, "create_release_snapshot"
                    ) as create_snapshot, mock.patch.object(
                        MODULE, "prune_release_snapshots"
                    ) as prune:
                        returncode = MODULE.deploy([])

                    self.assertEqual(returncode, 1)
                    self.assertEqual(json.loads(fixture["stdout"].getvalue())["reason"], "recovery_required")
                    fixture["preflight"].assert_not_called()
                    fixture["compose"].assert_not_called()
                    fixture["wait_for_runtime"].assert_not_called()
                    fixture["probe_public_urls"].assert_not_called()
                    create_snapshot.assert_not_called()
                    prune.assert_not_called()
                    self.assertEqual(list(fixture["app_dir"].glob("*.candidate.*")), [])
                    self.assertFalse(fixture["transaction_path"].exists())
                    self.assertFalse((fixture["app_dir"] / "backups").exists())

    def test_v2_transaction_and_success_bind_snapshot_and_exact_previous_release_bytes(self):
        previous_raw = self._canonical_bytes(self._legacy_release_record())
        with tempfile.TemporaryDirectory() as temporary:
            with self._deploy_fixture(temporary, previous_release_bytes=previous_raw) as fixture:
                captured_transaction = {}
                events = []

                def compose_side_effect(_compose_path, _env_path, arguments, _images, **_kwargs):
                    if arguments[:4] == ["run", "--rm", "--no-deps", "api"]:
                        events.append("migration")
                        raw = fixture["transaction_path"].read_bytes()
                        captured_transaction["raw"] = raw
                        captured_transaction["model"] = json.loads(raw.decode("ascii"))
                    return b""

                fixture["compose"].side_effect = compose_side_effect
                real_enforce = MODULE.enforce_release_snapshot_retention

                def enforce_then_record(*args, **kwargs):
                    events.append("retention")
                    return real_enforce(*args, **kwargs)

                with mock.patch.object(
                    MODULE, "enforce_release_snapshot_retention", side_effect=enforce_then_record
                ), mock.patch.object(
                    MODULE,
                    "prune_release_snapshots",
                    side_effect=AssertionError("legacy v1 cannot authorize pruning"),
                ):
                    returncode = MODULE.deploy([])

                self.assertEqual(returncode, 0)
                self.assertEqual(events, ["retention", "migration"])
                transaction = captured_transaction["model"]
                self.assertEqual(
                    set(transaction),
                    {
                        "build_id",
                        "controller",
                        "controller_compose_sha256",
                        "controller_program_sha256",
                        "git_sha",
                        "images",
                        "phase",
                        "previous_images",
                        "previous_release_sha256",
                        "schema",
                        "snapshot",
                        "snapshot_manifest_sha256",
                        "status",
                        "updated_at",
                    },
                )
                self.assertEqual(transaction["schema"], "cnb-test-release-transaction/v2")
                self.assertEqual(transaction["previous_images"], self._previous_images())
                self.assertEqual(transaction["previous_release_sha256"], hashlib.sha256(previous_raw).hexdigest())
                self.assertRegex(transaction["snapshot"], MODULE.SNAPSHOT_NAME)
                manifest_path = (
                    fixture["app_dir"]
                    / "backups"
                    / "releases"
                    / transaction["snapshot"]
                    / MODULE.SNAPSHOT_MANIFEST
                )
                self.assertEqual(
                    transaction["snapshot_manifest_sha256"],
                    hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                )
                self.assertEqual(captured_transaction["raw"], self._canonical_bytes(transaction))
                self.assertFalse({"database_backup", "database_backup_sha256", "env_backup", "compose_backup"} & set(transaction))

                success_raw = fixture["release_path"].read_bytes()
                success = json.loads(success_raw.decode("ascii"))
                self.assertEqual(
                    set(success),
                    {
                        "build_id",
                        "controller",
                        "controller_compose_sha256",
                        "controller_program_sha256",
                        "deployed_at",
                        "git_sha",
                        "images",
                        "probes",
                        "schema",
                        "snapshot",
                        "snapshot_manifest_sha256",
                        "status",
                    },
                )
                self.assertEqual(success["schema"], "cnb-test-release/v2")
                self.assertEqual(success["snapshot"], transaction["snapshot"])
                self.assertEqual(success["snapshot_manifest_sha256"], transaction["snapshot_manifest_sha256"])
                self.assertEqual(success_raw, self._canonical_bytes(success))
                self.assertFalse({"database_backup", "database_backup_sha256", "env_backup", "compose_backup"} & set(success))
                result = json.loads(fixture["stdout"].getvalue())
                self.assertRegex(result["database_backup_sha256"], r"^[0-9a-f]{64}$")

    def test_retention_failure_is_reported_before_transaction_or_migration(self):
        previous_raw = self._canonical_bytes(self._v2_release_record(
            SimpleNamespace(
                name="20260901T010203Z-0123456789abcdef",
                manifest_sha256="d" * 64,
            )
        ))
        with tempfile.TemporaryDirectory() as temporary:
            with self._deploy_fixture(temporary, previous_release_bytes=previous_raw) as fixture:
                with mock.patch.object(
                    MODULE,
                    "enforce_release_snapshot_retention",
                    side_effect=MODULE.DeploymentError("backup_retention_failed"),
                ):
                    returncode = MODULE.deploy([])
                self.assertEqual(returncode, 1)
                self.assertEqual(json.loads(fixture["stdout"].getvalue())["reason"], "backup_retention_failed")
                self.assertFalse(fixture["transaction_path"].exists())
                migration_calls = [
                    call
                    for call in fixture["compose"].call_args_list
                    if call.args[2][:4] == ["run", "--rm", "--no-deps", "api"]
                ]
                self.assertEqual(migration_calls, [])

    @contextlib.contextmanager
    def _empty_baseline_fixture(self, temporary):
        with self._deploy_fixture(temporary) as fixture:
            baseline = {
                "schema": "cnb-test-empty-baseline/v1", "status": "empty", "images": {},
                "project": MODULE.POLICY["project"], "environment": MODULE.POLICY["environment"],
                "controller": MODULE.CONTROLLER_ID, "policy_sha256": MODULE.POLICY_SHA256,
                "database": MODULE.POLICY["database"],
                "runtime_env_sha256": hashlib.sha256(fixture["env_path"].read_bytes()).hexdigest(),
                "controller_compose_sha256": MODULE.CONTROLLER_COMPOSE_SHA256,
                "created_at": "2026-09-06T01:02:03Z",
            }
            raw = self._canonical_bytes(baseline)
            fixture["release_path"].write_bytes(raw)
            fixture["release_path"].chmod(0o600)
            with mock.patch.object(MODULE, "read_root_owned_json", return_value=(baseline, hashlib.sha256(raw).hexdigest())), \
                 mock.patch.object(MODULE, "_assert_database_empty") as database_empty:
                fixture["baseline"] = baseline
                fixture["database_empty"] = database_empty
                yield fixture

    def test_explicit_empty_baseline_first_release_records_real_snapshot_and_no_prior_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self._empty_baseline_fixture(temporary) as fixture:
                observed = {}
                def compose(_cp, _ep, arguments, _images, **_kw):
                    if arguments[:4] == ["run", "--rm", "--no-deps", "api"]:
                        observed.update(json.loads(fixture["transaction_path"].read_bytes()))
                    return b""
                fixture["compose"].side_effect = compose
                self.assertEqual(MODULE.deploy([]), 0)
                self.assertEqual(observed["previous_images"], {})
                self.assertEqual(observed["previous_release_sha256"], hashlib.sha256(self._canonical_bytes(fixture["baseline"])).hexdigest())
                snapshot = fixture["app_dir"] / "backups/releases" / observed["snapshot"]
                self.assertTrue((snapshot / "database.dump").read_bytes().startswith(b"PGDMP"))
                self.assertEqual(json.loads(fixture["release_path"].read_bytes())["schema"], MODULE.RELEASE_SCHEMA_V2)
                self.assertFalse(fixture["transaction_path"].exists())
                fixture["database_empty"].assert_called_once()

    def test_empty_baseline_postmigration_failure_blocks_repeat_without_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self._empty_baseline_fixture(temporary) as fixture:
                fixture["probe_public_urls"].side_effect = MODULE.DeploymentError("release_identity_mismatch")
                self.assertEqual(MODULE.deploy([]), 1)
                transaction = json.loads(fixture["transaction_path"].read_bytes())
                self.assertEqual((transaction["status"], transaction["phase"]), ("failed", "probe"))
                self.assertEqual(transaction["previous_images"], {})
                MODULE._validate_release_transaction_model(transaction)
                calls = len(fixture["compose"].call_args_list)
                self.assertEqual(MODULE.deploy([]), 1)
                self.assertEqual(len(fixture["compose"].call_args_list), calls)
                self.assertEqual(json.loads(fixture["stdout"].getvalue().splitlines()[-1])["reason"], "recovery_required")

    def test_empty_baseline_policy_or_database_change_is_rejected_before_pull(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self._empty_baseline_fixture(temporary) as fixture:
                fixture["database_empty"].side_effect = MODULE.DeploymentError("bootstrap_database_not_empty")
                self.assertEqual(MODULE.deploy([]), 1)
                fixture["compose"].assert_not_called()
                self.assertFalse(fixture["transaction_path"].exists())
        with tempfile.TemporaryDirectory() as temporary:
            with self._empty_baseline_fixture(temporary) as fixture:
                fixture["baseline"]["policy_sha256"] = "f" * 64
                self.assertEqual(MODULE.deploy([]), 1)
                fixture["compose"].assert_not_called()
