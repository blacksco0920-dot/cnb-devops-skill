import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('production_release', ROOT / 'assets/cnb-tcr-tat/host/production-release.py')
production = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production)


class ProductionContractTests(unittest.TestCase):
    def authority(self):
        return dict(schema='cnb-production-authority/v1', project='sample', environment='production',
                    controller_program_sha256='a'*64, host_policy_sha256='b'*64,
                    controller_compose_sha256='c'*64, approval_public_key_sha256='d'*64)

    def test_authority_exact_production_scope_and_hashes(self):
        authority = self.authority()
        self.assertEqual(production.validate_authority(authority), authority)
        for changes in ({'environment': 'test'}, {'unused': True}, {'controller_program_sha256': 'latest'}):
            with self.subTest(changes=changes), self.assertRaises(production.ProductionError):
                production.validate_authority(dict(authority, **changes))

    def test_template_pins_entry_and_authority_and_only_one_parameter(self):
        policy = dict(install_dir='/opt/cnb-devops/sample/production/v1', release_user='ubuntu', release_home='/home/ubuntu')
        raw = production.render_tat_template(policy, 'e'*64, 'f'*64)
        self.assertEqual(raw.count(b'{{release_request_b64url}}'), 1)
        self.assertIn(b'e'*64, raw)
        self.assertIn(b'f'*64, raw)
        self.assertIn(b'production-release.py', raw)
        self.assertNotIn(b'InvokeCommand', raw)

    def test_canonical_json_has_single_lf_and_rejects_alternate_bytes(self):
        self.assertEqual(production.canonical({'z': 1, 'a': {'b': True}}), b'{"a":{"b":true},"z":1}\n')
        self.assertEqual(production.parse_canonical(b'{"a":1}\n'), {'a': 1})
        for raw in (b'{"a":1,"a":2}\n', b'{"a":1.0}\n', b'{"a":1}', b'{"a":NaN}\n'):
            with self.subTest(raw=raw), self.assertRaises(production.ProductionError):
                production.parse_canonical(raw)


if __name__ == '__main__':
    unittest.main()
