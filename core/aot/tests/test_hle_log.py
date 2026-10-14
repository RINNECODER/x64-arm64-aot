"""The HLE-boundary call log is written by the Rosetta stub runtime (C), by the native compiler's
emitted HleLogCall/HleLogReturn calls, and read by tools/native/hle_diff.py. These tests pin the
record layout those three share and the diff tool's divergence report, which the end-to-end title
runs only exercise implicitly. A writer/reader disagreement about the field order or the name
padding would make the tool silently mis-align the two logs and report no divergence at all.
"""
import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools" / "native"))
import hle_diff  # noqa: E402

MAGIC = 0x474F4C48


def write_log(path, calls):
    """Write a log in the documented layout. calls: (thread, name, args, result); None omits the return."""
    with open(path, "wb") as handle:
        handle.write(struct.pack("<II", MAGIC, 1))
        for sequence, (thread, name, args, result) in enumerate(calls, start=1):
            raw = name.encode()
            padded = tuple(args) + (0,) * (6 - len(args))
            handle.write(struct.pack("<QQII", sequence, thread, len(raw), 0))
            handle.write(struct.pack("<6Q", *padded))
            handle.write(struct.pack("<Q", 0))
            handle.write(raw + b"\0" * ((8 - len(raw) % 8) % 8))
            if result is not None:
                handle.write(struct.pack("<QQII", sequence, thread, 0, 1))
                handle.write(struct.pack("<6Q", *([0] * 6)))
                handle.write(struct.pack("<Q", result))
    return path


class HleLogTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def run_tool(self, left, right, *extra):
        output = io.StringIO()
        argv = ["hle_diff.py", str(left), str(right), *extra]
        with contextlib.redirect_stdout(output), mock.patch.object(sys, "argv", argv):
            code = hle_diff.main()
        return code, output.getvalue()

    def test_identical_logs_report_no_divergence(self):
        calls = [(7, "nidA", (1, 2, 3), 0x10), (7, "nidB", (4,), 0)]
        left = write_log(self.root / "left.log", calls)
        right = write_log(self.root / "right.log", calls)
        code, text = self.run_tool(left, right)
        self.assertEqual(code, 0)
        self.assertIn("0 of 1 thread pairs diverge", text)

    def test_first_divergence_is_the_changed_return(self):
        calls = [(7, "nidA", (1, 2, 3), 0x10), (7, "nidB", (4,), 0), (7, "nidC", (5,), 0x20)]
        left = write_log(self.root / "left.log", calls)
        right = write_log(self.root / "right.log", calls[:2] + [(7, "nidC", (5,), 0x21)])
        code, text = self.run_tool(left, right)
        self.assertEqual(code, 1)
        self.assertIn("first differing call 2: return", text)
        self.assertIn("result=0x20", text)
        self.assertIn("result=0x21", text)

    def test_changed_argument_outranks_a_later_changed_name(self):
        calls = [(7, "nidA", (1, 2, 3), 0), (7, "nidB", (4,), 0)]
        left = write_log(self.root / "left.log", calls)
        right = write_log(self.root / "right.log", [(7, "nidA", (9, 2, 3), 0), (7, "nidZ", (4,), 0)])
        code, text = self.run_tool(left, right)
        self.assertEqual(code, 1)
        self.assertIn("first differing call 0: args", text)


if __name__ == "__main__":
    unittest.main()
