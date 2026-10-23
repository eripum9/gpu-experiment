"""Focused tests for the pinned PSP SOS embedding generator."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("embed_psp.py")
SPEC = importlib.util.spec_from_file_location("embed_psp", SCRIPT)
assert SPEC and SPEC.loader
embed_psp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = embed_psp
SPEC.loader.exec_module(embed_psp)


class EmbedPspTests(unittest.TestCase):
    def test_unchecked_render_is_deterministic_and_declares_const_view(self):
        rendered = embed_psp.render_cpp_unchecked(bytes((0x00, 0x7f, 0x80, 0xff)))
        self.assertEqual(rendered, embed_psp.render_cpp_unchecked(bytes((0, 127, 128, 255))))
        self.assertIn("alignas(16) const uint8_t kPsp1402Firmware[]", rendered)
        self.assertIn("return {kPsp1402Firmware, sizeof(kPsp1402Firmware)};", rendered)
        self.assertIn("0x00, 0x7f, 0x80, 0xff,", rendered)
        self.assertIn("const uint8_t *data;", (SCRIPT.parents[2] / "src/navi44-survey/src/psp_firmware.hpp").read_text())

    def test_cli_rejects_missing_and_bad_input_without_changing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "existing.cpp"
            sentinel = b"keep existing output intact"
            output.write_bytes(sentinel)
            missing = subprocess.run(
                [sys.executable, str(SCRIPT), "--input", str(root / "missing.bin"), "--output", str(output)],
                text=True, capture_output=True,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(output.read_bytes(), sentinel)

            bad_input = root / "bad.bin"
            bad_input.write_bytes(b"not the pinned package")
            bad = subprocess.run(
                [sys.executable, str(SCRIPT), "--input", str(bad_input), "--output", str(output)],
                text=True, capture_output=True,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("does not match pinned PSP", bad.stderr)
            self.assertEqual(output.read_bytes(), sentinel)
            self.assertEqual(list(root.glob(".existing.cpp.*.tmp")), [])

    def test_generated_factory_reports_exact_bytes_and_const_storage(self):
        compiler = os.environ.get("CXX") or next(
            (shutil.which(name) for name in ("clang++", "g++", "c++") if shutil.which(name)), None
        )
        if not compiler:
            self.skipTest("no host C++ compiler available")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "psp_firmware.hpp").write_bytes(
                (SCRIPT.parents[2] / "src/navi44-survey/src/psp_firmware.hpp").read_bytes()
            )
            (root / "firmware.cpp").write_text(embed_psp.render_cpp_unchecked(b"\x12\x34\x56"))
            driver = root / "check.cpp"
            driver.write_text(
                '#include "psp_firmware.hpp"\n'
                '#include <type_traits>\n'
                'static_assert(std::is_same<decltype(cobalt::survey::FirmwareView::data), const uint8_t *>::value, "view must be immutable");\n'
                'int main() { auto fw = cobalt::survey::psp1402Firmware(); '
                'return fw.size == 3 && fw.data[0] == 0x12 && fw.data[1] == 0x34 && fw.data[2] == 0x56 ? 0 : 1; }\n'
            )
            executable = root / ("check.exe" if os.name == "nt" else "check")
            subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root),
                 str(root / "firmware.cpp"), str(driver), "-o", str(executable)],
                check=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_same_size_corruption_is_rejected_before_creating_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "wrong.bin"
            source.write_bytes(b"\0" * embed_psp.PINNED_SIZE)
            output = root / "absent" / "firmware.cpp"
            with self.assertRaisesRegex(ValueError, "does not match pinned PSP"):
                embed_psp.generate(source, output)
            self.assertFalse(output.parent.exists())

    def test_actual_pinned_input_when_present(self):
        source = embed_psp.DEFAULT_INPUT
        if not source.is_file():
            self.skipTest("pinned firmware is not present locally")
        data = source.read_bytes()
        embed_psp.verify_pinned(data)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "psp_firmware.cpp"
            embed_psp.generate(source, output)
            rendered = output.read_text()
            byte_literals = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", rendered))
            self.assertEqual(byte_literals, data)
            first = output.read_bytes()
            embed_psp.generate(source, output)
            self.assertEqual(output.read_bytes(), first)
        self.assertEqual(hashlib.sha256(data).hexdigest(), embed_psp.PINNED_SHA256)


if __name__ == "__main__":
    unittest.main()
