"""Unit tests for compare module."""

import tempfile
import unittest
from pathlib import Path
from cti_toolbox.utils import compare


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.f1 = Path(self.tmpdir.name) / "feed1.txt"
        self.f2 = Path(self.tmpdir.name) / "feed2.txt"

        self.f1.write_text("192.168.1.100 malicious scanner\n10.0.0.1 internal host\n", encoding="utf-8")
        self.f2.write_text("192.168.1.100 attack detected\n8.8.8.8 dns\n", encoding="utf-8")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_compare_files(self):
        stats = compare.compare_files(self.f1, self.f2, verbose=False)
        self.assertEqual(stats["file1_lines"], 2)
        self.assertEqual(stats["file2_lines"], 2)
        self.assertGreaterEqual(stats["matches"], 1)


if __name__ == "__main__":
    unittest.main()
