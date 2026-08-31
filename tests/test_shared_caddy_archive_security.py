import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "deploydesk_caddy_apply.py"
ALLOWLIST = (
    "caddy/declaration.json",
    "caddy/site.caddy",
    "caddy/helper-requirement.json",
    "caddy/bundle-provenance.json",
    "runtime/compose.json",
)


def load_helper():
    spec = importlib.util.spec_from_file_location("archive_security_helper", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def regular(name, data=b"{}\n", pax=None):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o644
    member.mtime = 0
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    member.pax_headers = dict(pax or {})
    return member, data


def typed(name, member_type, linkname=""):
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.linkname = linkname
    member.size = 0
    return member, None


def make_archive(entries, archive_format=tarfile.GNU_FORMAT):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=archive_format) as archive:
            for member, data in entries:
                archive.addfile(member, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def make_truncated_tar_after_valid_prefix(entries, valid_members=2):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for member, data in entries:
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    # Each tiny regular member occupies one 512-byte header and one 512-byte
    # data block. Keep valid prefixes plus a truncated following header.
    return gzip.compress(raw.getvalue()[:valid_members * 1024 + 100], mtime=0)


@unittest.skipUnless(HELPER_PATH.is_file(), "helper not implemented yet")
class SharedCaddyArchiveSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = load_helper()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.layout = self.h.Layout.for_test_root(root)
        self.intake = root / "intake"
        self.intake.mkdir()
        self.archive = root / "hostile.tar.gz"
        self.subject = self.h.SharedCaddyHelper(self.layout, executable_path=HELPER_PATH)

    def tearDown(self):
        self.temporary.cleanup()

    def extract(self, entries, archive_format=tarfile.GNU_FORMAT):
        self.archive.write_bytes(make_archive(entries, archive_format))
        self.subject._extract_archive(self.archive, self.intake)

    def assert_rejected(self, entries, archive_format=tarfile.GNU_FORMAT):
        with self.assertRaises(self.h.SecurityError):
            self.extract(entries, archive_format)
        self.assertEqual([], list(self.intake.rglob("*")), "rejected archive left partial output")

    def valid_entries(self, data=b"{}\n"):
        return [regular(name, data) for name in ALLOWLIST]

    def test_valid_exact_five_member_archive_extracts(self):
        self.extract(self.valid_entries())
        self.assertEqual(set(ALLOWLIST), {
            str(path.relative_to(self.intake))
            for path in self.intake.rglob("*") if path.is_file()
        })

    def test_duplicate_logical_member_is_rejected(self):
        entries = [*self.valid_entries(), regular(ALLOWLIST[0], b"late duplicate")]
        self.assert_rejected(entries)

    def test_symlink_and_hardlink_members_are_rejected(self):
        for member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(member_type=member_type):
                self.assert_rejected([
                    typed(ALLOWLIST[0], member_type, ALLOWLIST[1]),
                    *self.valid_entries()[1:],
                ])

    def test_fifo_device_and_other_special_members_are_rejected(self):
        for member_type in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, b"s"):
            with self.subTest(member_type=member_type):
                self.assert_rejected([
                    typed(ALLOWLIST[0], member_type),
                    *self.valid_entries()[1:],
                ])

    def test_absolute_and_parent_traversal_paths_are_rejected(self):
        for hostile_name in ("/caddy/declaration.json", "../caddy/declaration.json"):
            with self.subTest(hostile_name=hostile_name):
                entries = self.valid_entries()[1:]
                self.assert_rejected([regular(hostile_name), *entries])

    def test_pax_path_override_and_collision_are_rejected(self):
        override = regular("ignored", pax={"path": ALLOWLIST[0]})
        self.assert_rejected([override, *self.valid_entries()[1:]], tarfile.PAX_FORMAT)
        collision = [
            regular("first", pax={"path": ALLOWLIST[0]}),
            regular("second", pax={"path": ALLOWLIST[0]}),
            *self.valid_entries()[1:],
        ]
        self.assert_rejected(collision, tarfile.PAX_FORMAT)

    def test_unexpected_extra_member_is_rejected(self):
        self.assert_rejected([
            regular("unexpected.txt"),
            *self.valid_entries()[1:],
        ])

    def test_per_file_size_limit_is_enforced(self):
        oversized = b"x" * (8 * 1024 * 1024 + 1)
        self.assert_rejected([
            regular(ALLOWLIST[0], oversized),
            *self.valid_entries()[1:],
        ])

    def test_aggregate_size_limit_is_enforced_below_per_file_limit(self):
        five_megabytes = b"x" * (5 * 1024 * 1024)
        self.assert_rejected(self.valid_entries(five_megabytes))

    def test_file_count_overflow_is_rejected(self):
        self.assert_rejected([*self.valid_entries(), regular("fifth")])

    def test_missing_member_is_rejected_without_partial_output(self):
        self.assert_rejected(self.valid_entries()[:-1])

    def test_malformed_tail_after_valid_prefix_is_rejected_without_partial_output(self):
        self.archive.write_bytes(make_truncated_tar_after_valid_prefix(self.valid_entries()))
        with self.assertRaises(self.h.SecurityError):
            self.subject._extract_archive(self.archive, self.intake)
        self.assertEqual([], list(self.intake.rglob("*")))

    def test_malformed_and_nonregular_allowlisted_member_are_rejected(self):
        self.archive.write_bytes(gzip.compress(b"not a tar archive"))
        with self.assertRaises(self.h.SecurityError):
            self.subject._extract_archive(self.archive, self.intake)
        self.assertEqual([], list(self.intake.rglob("*")))
        self.assert_rejected([
            typed(ALLOWLIST[0], tarfile.DIRTYPE),
            *self.valid_entries()[1:],
        ])

    def test_between_pass_path_replacement_cannot_change_extracted_bytes(self):
        self.archive.write_bytes(make_archive(self.valid_entries(b"original\n")))
        called = []

        def replace_path():
            called.append(True)
            replacement = make_archive(self.valid_entries(b"replacement\n"))
            self.archive.unlink()
            self.archive.write_bytes(replacement)

        self.subject.archive_validation_hook = replace_path
        self.subject._extract_archive(self.archive, self.intake)
        self.assertEqual([True], called)
        for relative in ALLOWLIST:
            self.assertEqual(b"original\n", (self.intake / relative).read_bytes())


if __name__ == "__main__":
    unittest.main()
