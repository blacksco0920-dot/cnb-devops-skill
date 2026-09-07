import copy
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'assets/cnb-tcr-tat/host/configure-native-caddy.py'


class NativeCaddyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SCRIPT.is_file():
            return
        spec = importlib.util.spec_from_file_location('native_caddy', SCRIPT)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'The first-host Caddy configurator is missing')
        self.m = self.module
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for key, value in [('ROOT', self.root), ('OWNER', os.getuid()), ('GROUP', os.getgid())]:
            p = patch.object(self.m, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.policy = {'schema': 'cnb-devops-host-policy/v1', 'project': 'demo', 'environment': 'test',
                       'services': {}, 'identity_probes': []}
        for service, domain, port in [('api', 'api.example.com', 13000), ('h5', 'test.example.com', 13080),
                                      ('ocr', 'ocr.example.com', 18001)]:
            self.policy['services'][service] = {'loopback_port': {'host_ip': '127.0.0.1', 'protocol': 'tcp',
                                                                'published': port, 'target': 3000}}
            self.policy['identity_probes'].append({'service': service, 'url': 'https://' + domain + '/release.json'})
        self.config, self.site, policy_path = self.m.paths('demo')
        for path in (self.config.parent, policy_path.parent):
            path.mkdir(parents=True)
        self.original = b'# Existing site\n:80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n'
        self.config.write_bytes(self.original)
        self.config.chmod(0o644)
        policy_path.write_text(json.dumps(self.policy))
        self.policy_sha = self.m.sha(policy_path.read_bytes())
        self.baseline_sha = self.m.sha(self.original)
        self.base_json = {'apps': {'http': {'servers': {'srv0': {'listen': [':80'], 'routes': [
            {'handle': [{'handler': 'vars', 'root': '/usr/share/caddy'}, {'handler': 'file_server'}]}]}}}}}
        self.current = copy.deepcopy(self.base_json)
        self.candidate_json = {**self.base_json, 'test_candidate': True}
        self.fail_reload = False
        self.fail_validate = False
        self.reload_count = 0
        def command(args, data=None):
            if args[1] == 'adapt':
                return json.dumps(self.base_json if data == self.original else self.candidate_json).encode()
            if args[1] == 'validate':
                if self.fail_validate:
                    raise self.m.CaddyError('CADDY_COMMAND_FAILED')
                return b''
            if args[1] == 'reload':
                self.reload_count += 1
                if self.fail_reload and self.reload_count == 1:
                    self.current = copy.deepcopy(self.candidate_json)  # Lost response after application.
                    raise self.m.CaddyError('CADDY_COMMAND_FAILED')
                self.current = copy.deepcopy(self.base_json if self.config.read_bytes() == self.original else self.candidate_json)
                return b''
            self.fail('unexpected external operation')
        for name, value in [('command', command), ('running_config', lambda: self.current),
                            ('check_system', lambda: None)]:
            p = patch.object(self.m, name, value)
            p.start()
            self.addCleanup(p.stop)

    def run_config(self, apply=False):
        return self.m.configure('demo', self.policy_sha, self.baseline_sha, apply=apply)

    def test_production_routes_use_only_production_policy_and_site(self):
        production = copy.deepcopy(self.policy)
        production['environment'] = 'production'
        policy_path = self.root / 'opt/cnb-devops/demo/production/v1/host-policy.json'
        policy_path.parent.mkdir(parents=True)
        policy_path.write_text(json.dumps(production))
        policy_sha = self.m.sha(policy_path.read_bytes())
        result = self.m.configure('demo', policy_sha, self.baseline_sha, apply=True, environment='production')
        production_site = self.root / 'etc/caddy/cnb-devops/demo-production.caddy'
        self.assertEqual(result['environment'], 'production')
        self.assertEqual(result['site_path'], str(production_site))
        self.assertEqual(self.config.read_bytes(), self.original + ('\nimport ' + str(production_site) + '\n').encode())
        self.assertFalse(self.site.exists())
        self.assertEqual(self.m.configure('demo', policy_sha, self.baseline_sha, apply=True, environment='production')['status'], 'unchanged')
        self.assertEqual(self.reload_count, 1)

    def test_production_selector_rejects_test_policy_and_unknown_environment(self):
        policy_path = self.root / 'opt/cnb-devops/demo/production/v1/host-policy.json'
        policy_path.parent.mkdir(parents=True)
        policy_path.write_text(json.dumps(self.policy))
        with self.assertRaises(self.m.CaddyError):
            self.m.configure('demo', self.policy_sha, self.baseline_sha, apply=True, environment='production')
        with self.assertRaises(self.m.CaddyError):
            self.m.paths('demo', '../test')
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.site.parent.exists())

    def test_preview_maps_domains_to_actual_loopback_ports_without_writes(self):
        result = self.run_config()
        self.assertEqual(result['status'], 'planned')
        self.assertIn('https://api.example.com {\n\treverse_proxy 127.0.0.1:13000', result['site'])
        self.assertIn('reverse_proxy 127.0.0.1:13080', result['site'])
        self.assertIn('reverse_proxy 127.0.0.1:18001', result['site'])
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.site.parent.exists())
        self.assertEqual(self.reload_count, 0)

    def test_success_preserves_original_bytes_and_repeat_does_not_reload(self):
        self.assertEqual(self.run_config(True)['status'], 'installed')
        expected = self.original + ('\nimport ' + str(self.site) + '\n').encode()
        self.assertEqual(self.config.read_bytes(), expected)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.site.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.run_config(True)['status'], 'unchanged')
        self.assertEqual(self.reload_count, 1)

    def test_failed_reload_restores_disk_and_running_baseline(self):
        self.fail_reload = True
        with self.assertRaisesRegex(self.m.CaddyError, 'ROLLED_BACK'):
            self.run_config(True)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.current, self.base_json)
        self.assertFalse(self.site.exists())
        self.assertEqual(self.reload_count, 2)

    def test_failed_validation_leaves_original_files(self):
        self.fail_validate = True
        with self.assertRaises(self.m.CaddyError):
            self.run_config(True)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.site.exists())
        self.assertEqual(self.reload_count, 0)

    def test_ubuntu_caddy_26_reads_adapt_and_validate_from_dev_stdin(self):
        original_command = self.m.command
        observed = []
        def command(args, data=None):
            if args[1] in ('adapt', 'validate'):
                self.assertEqual(args[args.index('--config') + 1], '/dev/stdin')
                observed.append(args[1])
            return original_command(args, data)
        with patch.object(self.m, 'command', side_effect=command):
            self.assertEqual(self.run_config(True)['status'], 'installed')
        self.assertEqual(observed, ['adapt', 'adapt', 'validate'])

    def test_baseline_or_live_config_drift_refuses_before_writes(self):
        for drift in ['file', 'live', 'policy']:
            with self.subTest(drift=drift):
                if drift == 'file':
                    self.config.write_bytes(self.original + b'# changed\n')
                elif drift == 'live':
                    self.current = {}
                else:
                    self.policy_sha = '0' * 64
                with self.assertRaises(self.m.CaddyError):
                    self.run_config(True)
                self.assertFalse(self.site.exists())
                self.config.write_bytes(self.original)
                self.current = copy.deepcopy(self.base_json)

    def test_unknown_existing_project_file_is_never_adopted(self):
        self.site.parent.mkdir()
        self.site.write_bytes(b'# someone else\n')
        with self.assertRaisesRegex(self.m.CaddyError, 'PROJECT_FILE'):
            self.run_config(True)
        self.assertEqual(self.site.read_bytes(), b'# someone else\n')
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_host_conflicts_wildcards_and_https_catchall_refuse(self):
        for server in [
            {'listen': [':80'], 'routes': [{'match': [{'host': ['api.example.com']}]}]},
            {'listen': [':80'], 'routes': [{'match': [{'host': ['*.example.com']}]}]},
            {'listen': [':443'], 'routes': [{'handle': [{'handler': 'file_server'}]}]},
        ]:
            with self.subTest(server=server):
                with self.assertRaisesRegex(self.m.CaddyError, 'CONFLICT'):
                    self.m.check_conflicts({'apps': {'http': {'servers': {'srv0': server}}}}, ['api.example.com'])

    def test_import_or_environment_baseline_is_outside_scope(self):
        for extra in [b'\nimport /etc/caddy/other\n', b'\n# config uses {$SECRET}\n']:
            self.config.write_bytes(self.original + extra)
            self.baseline_sha = self.m.sha(self.config.read_bytes())
            with self.assertRaisesRegex(self.m.CaddyError, 'BASELINE_SCOPE'):
                self.run_config(True)
            self.assertFalse(self.site.exists())

    def test_only_automatic_stdin_file_server_hide_is_corrected(self):
        model = {'handler': 'subroute', 'routes': [{'handle': [
            {'handler': 'file_server', 'hide': ['/dev/stdin', 'private.txt'], 'browse': {}},
            {'handler': 'other', 'hide': ['/dev/stdin']},
            {'handler': 'file_server', 'hide': ['unexpected-file']},
        ]}]}
        with patch.object(self.m, 'command', return_value=json.dumps(model).encode()):
            actual = self.m.adapt(self.original)
        expected = copy.deepcopy(model)
        expected['routes'][0]['handle'][0]['hide'][0] = str(self.config)
        self.assertEqual(actual, expected)

    def test_bad_domain_or_missing_loopback_mapping_is_rejected(self):
        for key, value in [('url', 'https://*.example.com/release.json'), ('url', 'https://user@api.example.com/'),
                           ('url', 'http://api.example.com/'), ('service', 'unknown')]:
            p = copy.deepcopy(self.policy)
            p['identity_probes'][0][key] = value
            with self.assertRaises(self.m.CaddyError):
                self.m.render_sites(p, 'demo', self.policy_sha)

    def test_symlink_and_writable_policy_fail_closed(self):
        path = self.m.paths('demo')[2]
        path.chmod(0o666)
        with self.assertRaises(self.m.CaddyError):
            self.run_config()
        path.chmod(0o644)
        self.site.parent.mkdir()
        self.site.symlink_to(self.config)
        with self.assertRaises(self.m.CaddyError):
            self.run_config(True)
        self.assertEqual(self.config.read_bytes(), self.original)


@unittest.skipUnless(os.environ.get('CNB_CADDY_TEST_IMAGE'), 'requires an explicitly selected local Caddy image')
class RealCaddyAdaptTests(unittest.TestCase):
    def test_default_file_server_stdin_matches_real_named_file_adapter(self):
        spec = importlib.util.spec_from_file_location('native_caddy_real', SCRIPT)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        docker = shutil.which('docker') or '/usr/local/bin/docker'
        image = os.environ['CNB_CADDY_TEST_IMAGE']
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / 'Caddyfile'
            for suffix in [b'file_server', b'file_server {\n hide private.txt\n }']:
                raw = b':80 {\n root * /usr/share/caddy\n ' + suffix + b'\n}\n'
                config.write_bytes(raw)
                prefix = [docker, 'run', '--rm', '--pull=never', '--network', 'none',
                          '--workdir', '/etc/caddy', '--mount',
                          'type=bind,source=' + str(config) + ',target=/etc/caddy/Caddyfile,readonly',
                          '-i', image, 'caddy']
                def command(args, data=None):
                    return subprocess.run(prefix + args[1:], input=data, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, timeout=30, check=True).stdout
                named = json.loads(command([helper.CADDY, 'adapt', '--config', '/etc/caddy/Caddyfile',
                                            '--adapter', 'caddyfile']))
                with patch.object(helper, 'command', side_effect=command):
                    self.assertEqual(helper.adapt(raw), named)


if __name__ == '__main__':
    unittest.main()
