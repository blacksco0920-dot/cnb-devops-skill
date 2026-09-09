"""Fixed native-Caddy capture/restore session entry."""
import contextlib
import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import ssl
import subprocess
import time
from pathlib import Path
import ssl
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts/rehearse-native-caddy.py"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def synthetic_capture_payload(module, inventory, version):
    files = {"config/Caddyfile": b"{ admin 127.0.0.1:2019 }\n",
             "config/cnb-devops/sample-test.caddy": b"https://sample.invalid { respond 502 }\n",
             "data/caddy/certificates/example/sample.invalid/sample.invalid.crt": b"certificate"}
    archive = module.archive_files(files)
    meta = {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": "0600"}
            for name, raw in files.items()}
    snapshot = {"inventory": inventory, "files": meta}
    return canonical({"schema": "cnb-native-caddy-capture/v1", "status": "captured",
                      "caddy_version": version, "before": snapshot, "after": snapshot,
                      "tls_certificates": {"sample.invalid": hashlib.sha256(b"certificate").hexdigest()},
                      "archive": base64.b64encode(archive).decode()})


class NativeCaddyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "native Caddy recovery entry is missing")
        spec = importlib.util.spec_from_file_location("native_caddy_recovery", SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name, raw in (("identity", b"key"), ("known-hosts", b"host"), ("helper.py", b"def inventory(): return {}\n")):
            (self.root / name).write_bytes(raw)
            (self.root / name).chmod(0o600)
        target = {"host": "host.invalid", "port": 22, "user": "root",
                  "identity_file": str(self.root / "identity"),
                  "known_hosts_file": str(self.root / "known-hosts")}
        (self.root / "target.json").write_bytes(canonical(target))
        (self.root / "target.json").chmod(0o600)
        model = {"schema": "cnb-native-caddy-recovery-spec/v1",
                 "target": str(self.root / "target.json"),
                 "helper": str(self.root / "helper.py"),
                 "helper_sha256": hashlib.sha256((self.root / "helper.py").read_bytes()).hexdigest(),
                 "evidence_dir": str(self.root / "session")}
        (self.root / "spec.json").write_bytes(canonical(model))
        (self.root / "spec.json").chmod(0o600)

    def test_preview_is_offline_and_does_not_create_evidence(self):
        output = io.StringIO()
        with mock.patch.object(self.m.subprocess, "run", side_effect=AssertionError("preview executed process")), contextlib.redirect_stdout(output):
            self.m.main(["capture", "--spec", str(self.root / "spec.json")])
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "preview")
        self.assertEqual(result["action"], "capture")
        self.assertFalse((self.root / "session").exists())

    def test_embedded_root_capture_is_valid_python(self):
        compile(self.m.ROOT_CAPTURE, "/reviewed/native-caddy-capture.py", "exec")

    def test_caddy_version_compares_semver_without_build_string_equality(self):
        self.assertEqual(self.m.caddy_semver("2.6.2"), "2.6.2")
        self.assertEqual(self.m.caddy_semver("v2.6.2 h1:some-build"), "2.6.2")
        with self.assertRaisesRegex(self.m.NativeCaddyError, "CADDY_VERSION_INVALID"):
            self.m.caddy_semver("latest")

    def test_archive_rejects_links_traversal_and_duplicate_members(self):
        for kind in ("symlink", "hardlink", "traversal", "duplicate"):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                names = ["config/Caddyfile", "config/Caddyfile"] if kind == "duplicate" else ["../escape" if kind == "traversal" else "config/Caddyfile"]
                for name in names:
                    item = tarfile.TarInfo(name)
                    if kind == "symlink":
                        item.type, item.linkname = tarfile.SYMTYPE, "/etc/passwd"
                    elif kind == "hardlink":
                        item.type, item.linkname = tarfile.LNKTYPE, "config/other"
                    else:
                        item.size = 1
                    archive.addfile(item, None if item.islnk() or item.issym() else io.BytesIO(b"x"))
            with self.subTest(kind=kind), self.assertRaisesRegex(self.m.NativeCaddyError, "ARCHIVE_INVALID"):
                self.m.validate_archive(output.getvalue())

    def test_capture_persists_bound_manifest_and_reuses_completed_stage(self):
        plan = self.m.prepare(self.m.parse_args(["capture", "--spec", str(self.root / "spec.json"), "--apply"]))
        inventory = {"schema": "cnb-native-caddy-inventory/v1", "status": "verified",
                     "main_sha256": "1" * 64, "base_sha256": "2" * 64,
                     "running_sha256": "3" * 64,
                     "sites": [{"project": "sample", "environment": "test", "path": "/etc/caddy/cnb-devops/sample-test.caddy",
                                "site_sha256": "4" * 64, "policy_sha256": "5" * 64,
                                "domains": ["sample.invalid"], "loopback_ports": [13080]}]}
        payload = synthetic_capture_payload(self.m, inventory, "v2.8.4")
        transport = mock.Mock(return_value=payload)
        first = self.m.capture(plan, transport)
        second = self.m.capture(plan, transport)
        self.assertEqual(first, second)
        self.assertEqual(transport.call_count, 1)
        manifest = json.loads((plan.evidence_dir / "capture-manifest.json").read_bytes())
        self.assertEqual(manifest["source_target_sha256"], plan.target_sha256)
        self.assertEqual(manifest["source_inventory_sha256"], hashlib.sha256(canonical(inventory)).hexdigest())
        self.assertEqual((plan.evidence_dir / "state.json").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.environ.get("RUN_NATIVE_CADDY_DOCKER_TEST") == "1", "explicit local Docker integration")
    def test_real_local_docker_restore_has_tls_config_and_isolation(self):
        caddy = "caddy@sha256:25a0097607868fb05a89a5ab9fea2f2ea4cecdc89d887d7dcee8c778a21b9e1f"
        node = "node@sha256:f32b81066cde10a75dbac96646099533316d94bac4150c55da1636e1f0ffdc46"
        caddy_version = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "--pull=never", caddy, "caddy", "version"],
            check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        config, data = self.root / "source-config", self.root / "source-data"
        config.mkdir(); data.mkdir()
        caddyfile = b"{\n\tadmin 127.0.0.1:2019\n}\nhttps://sample.invalid {\n\ttls internal\n\trespond 200\n}\n"
        (config / "Caddyfile").write_bytes(caddyfile)
        source_name = "native-caddy-source-" + os.urandom(4).hex()
        subprocess.run(["docker", "run", "-d", "--name", source_name, "--network=none", "--restart=no",
                        "-v", f"{config}:/etc/caddy:ro", "-v", f"{data}:/data", caddy,
                        "caddy", "run", "--config", "/etc/caddy/Caddyfile"], check=True, stdout=subprocess.PIPE)
        self.addCleanup(lambda: subprocess.run(["docker", "rm", "-f", source_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for _ in range(30):
            check = subprocess.run(["docker", "exec", source_name, "wget", "-Y", "off", "-qO-", "http://127.0.0.1:2019/config/"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if check.returncode == 0: break
            time.sleep(0.1)
        self.assertEqual(check.returncode, 0)
        running = json.loads(check.stdout)
        running_sha = hashlib.sha256(canonical(running)).hexdigest()
        for _ in range(30):
            certs = list(data.glob("caddy/certificates/*/sample.invalid/sample.invalid.crt"))
            if certs: break
            time.sleep(0.1)
        self.assertEqual(len(certs), 1)
        leaf = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", certs[0].read_text(), re.S)
        self.assertIsNotNone(leaf)
        der = ssl.PEM_cert_to_DER_cert(leaf.group(0))
        cert_sha = hashlib.sha256(der).hexdigest()
        subprocess.run(["docker", "stop", source_name], check=True, stdout=subprocess.PIPE)
        files = {"config/Caddyfile": caddyfile}
        for path in data.rglob("*"):
            if path.is_file(): files["data/" + str(path.relative_to(data))] = path.read_bytes()
        archive = self.m.archive_files(files)
        meta = {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": "0600"}
                for name, raw in files.items()}
        inventory = {"schema":"cnb-native-caddy-inventory/v1","status":"verified","main_sha256":hashlib.sha256(caddyfile).hexdigest(),
                     "base_sha256":hashlib.sha256(caddyfile).hexdigest(),"running_sha256":running_sha,
                     "sites":[{"project":"sample","environment":"test","path":"/etc/caddy/Caddyfile","site_sha256":hashlib.sha256(caddyfile).hexdigest(),
                               "policy_sha256":"5"*64,"domains":["sample.invalid"],"loopback_ports":[13080]}]}
        snap = {"inventory": inventory, "files": meta}
        payload = canonical({"schema":"cnb-native-caddy-capture/v1","status":"captured","caddy_version":caddy_version,
                             "before":snap,"after":snap,"tls_certificates":{"sample.invalid":cert_sha},"archive":base64.b64encode(archive).decode()})
        capture_plan = self.m.prepare(self.m.parse_args(["capture","--spec",str(self.root/"spec.json"),"--apply"]))
        captured = self.m.capture(capture_plan, mock.Mock(return_value=payload))
        restored_name = "cnb-native-caddy-" + captured["archive_sha256"][:20]
        self.addCleanup(lambda: subprocess.run(["docker", "rm", "-f", restored_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        restore_spec = json.loads((self.root/"spec.json").read_bytes()); restore_spec.update({"caddy_image":caddy,"node_image":node})
        (self.root/"restore-spec.json").write_bytes(canonical(restore_spec)); (self.root/"restore-spec.json").chmod(0o600)
        restore_plan = self.m.prepare(self.m.parse_args(["restore","--spec",str(self.root/"restore-spec.json"),"--apply"]))
        receipt = self.m.restore(restore_plan)
        self.assertTrue(all(receipt[key] for key in ("source_unchanged","config_restored","tls_restored","isolated")))


if __name__ == "__main__":
    unittest.main()
