import contextlib
import importlib.util
import io
import json
import os
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "cnb.py"
SPEC = importlib.util.spec_from_file_location("cnb_cli", SCRIPT)
cnb = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(cnb)


class CnbCliTests(unittest.TestCase):
    def capture(self, function, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            function(args)
        return json.loads(output.getvalue())

    def test_create_repository_is_private_by_default(self):
        args = types.SimpleNamespace(
            slug="team",
            name="sample",
            description="",
            public=False,
        )
        with mock.patch.object(cnb, "api", return_value={"name": "sample"}) as api:
            self.capture(cnb.cmd_create_repo, args)

        api.assert_called_once_with(
            "POST",
            "/team/-/repos",
            {"name": "sample", "description": "", "visibility": "private"},
        )

    def test_public_repository_requires_explicit_flag(self):
        args = types.SimpleNamespace(
            slug="team",
            name="sample",
            description="docs",
            public=True,
        )
        with mock.patch.object(cnb, "api", return_value={"name": "sample"}) as api:
            self.capture(cnb.cmd_create_repo, args)

        self.assertEqual(api.call_args.args[2]["visibility"], "public")

    def test_ensure_repository_reuses_existing_repository(self):
        args = types.SimpleNamespace(
            slug="team",
            name="sample",
            description="",
            public=False,
        )
        with mock.patch.object(
            cnb,
            "api",
            return_value={"data": [{"name": "sample", "visibility": "private"}]},
        ) as api:
            result = self.capture(cnb.cmd_ensure_repo, args)

        self.assertFalse(result["created"])
        api.assert_called_once_with("GET", "/team/-/repos")

    def test_ensure_repository_creates_when_missing(self):
        args = types.SimpleNamespace(
            slug="team",
            name="sample",
            description="",
            public=False,
        )
        responses = [
            {"data": []},
            {"name": "sample", "visibility": "private"},
        ]
        with mock.patch.object(cnb, "api", side_effect=responses) as api:
            result = self.capture(cnb.cmd_ensure_repo, args)

        self.assertTrue(result["created"])
        self.assertEqual(api.call_count, 2)

    def test_trigger_rejects_unsafe_git_reference_before_api_call(self):
        args = types.SimpleNamespace(
            repo="team/sample",
            branch="main;echo-secret",
            event="api_trigger_staging",
            title="test",
            sha="",
            tag="",
        )
        with mock.patch.object(cnb, "api") as api:
            with self.assertRaisesRegex(cnb.CnbError, "safe Git reference"):
                cnb.cmd_trigger(args)
        api.assert_not_called()

    def test_production_promotion_requires_full_commit_sha(self):
        args = types.SimpleNamespace(
            repo="team/sample",
            branch="main",
            event="api_trigger_production",
            title="promote",
            sha="abc1234",
        )
        with mock.patch.object(cnb, "api") as api:
            with self.assertRaisesRegex(cnb.CnbError, "full 40 or 64"):
                cnb.cmd_promote(args)
        api.assert_not_called()

    def test_error_redaction_removes_token(self):
        with mock.patch.dict(os.environ, {"CNB_TOKEN": "top-secret-token"}):
            message = cnb.redact("upstream echoed top-secret-token")
        self.assertEqual(message, "upstream echoed [REDACTED]")


if __name__ == "__main__":
    unittest.main()
