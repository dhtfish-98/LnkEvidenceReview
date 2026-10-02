import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lnk_evidence_review.cli import main
from lnk_evidence_review.files import InputOpen, read_snapshot
from fixtures import header, u32


class FilesCliTests(unittest.TestCase):
    def setUp(self):
        # /var is itself a symlink on macOS; supported fixtures use a real ancestor.
        self.directory = tempfile.TemporaryDirectory(
            dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
        )
        self.base = Path(self.directory.name)
        self.file = self.base / "fixture.lnk"
        self.data = header() + u32(0)
        self.file.write_bytes(self.data)

    def tearDown(self):
        self.directory.cleanup()

    def invoke(self, argv):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main(argv)
        self.assertEqual(error.getvalue(), "")
        return code, json.loads(output.getvalue()), output.getvalue()

    def test_regular_snapshot_and_installed_cli_semantics(self):
        self.assertEqual(read_snapshot(str(self.file), 1024), self.data)
        for data, status, exitcode in (
            (self.data, "PASS", 0),
            (b"bad", "FAIL", 1),
            (self.data + b"opaque", "OPEN", 2),
        ):
            self.file.write_bytes(data)
            code, report, output = self.invoke([str(self.file)])
            self.assertEqual((code, report["status"]), (exitcode, status))
            self.assertNotIn(str(self.file), output)
            self.assertEqual(self.file.read_bytes(), data)

    def test_symlink_leaf_ancestor_and_dotdot_rejected(self):
        leaf = self.base / "leaf"
        leaf.symlink_to(self.file)
        directory = self.base / "alias"
        directory.symlink_to(self.base, target_is_directory=True)
        for path in (
            leaf,
            directory / self.file.name,
            self.base / ".." / self.base.name / self.file.name,
        ):
            with self.subTest(path=path):
                with self.assertRaises(InputOpen):
                    read_snapshot(str(path), 1024)
                code, r, _ = self.invoke([str(path)])
                self.assertEqual((code, r["status"]), (2, "OPEN"))
                self.assertFalse(r["input"]["admitted"])

    def test_directory_fifo_missing_and_input_budget(self):
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        for path in (self.base, fifo, self.base / "missing"):
            with self.assertRaises(InputOpen):
                read_snapshot(str(path), 1024)
        code, r, _ = self.invoke([str(self.file), "--input-bytes", "1"])
        self.assertEqual((code, r["status"]), (2, "OPEN"))
        self.assertIsNone(r["input"]["sha256"])

    def test_every_required_platform_flag_missing(self):
        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            value = getattr(os, name)
            delattr(os, name)
            try:
                with self.assertRaises(InputOpen) as caught:
                    read_snapshot(str(self.file), 1024)
                self.assertEqual(caught.exception.code, "snapshot_platform_unsupported")
            finally:
                setattr(os, name, value)

    def test_modified_fd_snapshot_is_open(self):
        original = os.read
        changed = [False]

        def read(descriptor, amount):
            data = original(descriptor, amount)
            if not changed[0]:
                changed[0] = True
                self.file.write_bytes(self.data + b"x")
            return data

        with patch("lnk_evidence_review.files.os.read", side_effect=read):
            with self.assertRaises(InputOpen) as caught:
                read_snapshot(str(self.file), 1024)
        self.assertEqual(caught.exception.code, "input_changed_during_snapshot")

    def test_invalid_arguments_emit_fixed_private_json(self):
        sensitive = "PRIVATE_INPUT_名字"
        for argv in (
            [],
            ["--unknown", sensitive],
            [sensitive, "--report-bytes", "²"],
            [sensitive, "--report-bytes", "2047"],
            [sensitive, "--input-bytes", "9999999999"],
            [sensitive, "--ansi-codepage", "SECRET_CODEC"],
        ):
            code, r, output = self.invoke(argv)
            self.assertEqual((code, r["status"]), (2, "OPEN"))
            self.assertEqual(r["findings"][0]["code"], "invalid_arguments")
            self.assertNotIn("PRIVATE_INPUT", output)
            self.assertNotIn("SECRET_CODEC", output)
            self.assertTrue(all(value == "OPEN" for value in r["assumptions"].values()))


if __name__ == "__main__":
    unittest.main()
