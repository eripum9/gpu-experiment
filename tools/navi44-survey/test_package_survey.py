"""Reject accidental driver substitution in the survey's distributable bundle."""
import importlib.util
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "package_survey", Path(__file__).parents[1] / "ci/package_survey_artifact.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class SurveyPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.kext = self.root / "survey.kext"
        self.executable = self.kext / "Contents/MacOS/CobaltNavi44Survey"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 11, 0, 0, 0, 0))
        self.reset_client = self.root / "mode1-reset"
        self.reset_client.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0, 0))
        signature = self.kext / "Contents/_CodeSignature/CodeResources"
        signature.parent.mkdir()
        signature.write_bytes(b"fixture-signature-resource")
        self.info = {
            "CFBundleIdentifier": "com.cobalt.navi44-survey",
            "CFBundleExecutable": "CobaltNavi44Survey",
            "IOKitPersonalities": {"Survey": {
                "IOClass": "CobaltNavi44Survey", "IOProviderClass": "IOPCIDevice",
                "IOPCIPrimaryMatch": "0x75901002", "IOMatchCategory": "CobaltNavi44Survey"}},
        }
        for relative in ("tools/navi44-survey/collect-survey.sh", "tools/navi44-survey/test-software-reset.sh", "docs/NAVI44-SURVEY.md", "docs/MODE1-RESET.md",
                         "tools/navi44-survey/install-early-reset-test.sh", "tools/navi44-survey/capture-early-reset.sh", "docs/EARLY-MODE1-RESET.md",
                         "src/navi48-bringup/LICENSE", "src/navi48-bringup/NOTICE",
                         "src/navi48-bringup/firmware/LICENSE.amdgpu",
                         "third-party/THIRD-PARTY-LICENSES.txt"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture\n")
        self.addCleanup(patch.stopall)
        patch.object(PACKAGE, "ROOT", self.root).start()
        patch.object(PACKAGE, "KEXT", self.kext).start()
        patch.object(PACKAGE, "RESET_CLIENT", self.reset_client).start()
        patch.object(PACKAGE.subprocess, "check_output", return_value="a" * 40).start()

    def payload(self):
        (self.kext / "Contents/Info.plist").write_bytes(plistlib.dumps(self.info))
        return PACKAGE.payload()

    def test_payload_contains_manifest_and_firmware_license(self):
        files = self.payload()
        self.assertIn("collect-gpu-survey.sh", files)
        self.assertIn("SHA256SUMS.txt", files)
        self.assertEqual(len(files), 17)
        self.assertEqual(files["mode1-reset"], self.reset_client.read_bytes())
        self.assertIn("test-software-reset.sh", files)
        self.assertIn("MODE1-RESET.md", files)
        self.assertIn("EARLY-MODE1-RESET.md", files)
        self.assertIn("install-early-reset-test.sh", files)
        self.assertIn("capture-early-reset.sh", files)
        self.assertIn(b"Optional cobalt-survey-mode1boot=1", files["BUILD-INFO.txt"])
        self.assertEqual(files["licenses/LICENSE.amdgpu"], b"fixture\n")
        self.assertIn("licenses/THIRD-PARTY-LICENSES.txt", files)
        self.assertIn(b"Contains embedded AMD firmware", files["BUILD-INFO.txt"])
        self.assertIn(b"Optional cobalt-survey-spl=1", files["BUILD-INFO.txt"])
        self.assertIn(b"Optional cobalt-survey-presos=1", files["BUILD-INFO.txt"])
        self.assertIn(b"Optional cobalt-survey-sos=1", files["BUILD-INFO.txt"])
        self.assertIn(b"never resets at boot", files["BUILD-INFO.txt"])
        self.assertNotIn(b"Contains no GPU firmware", files["BUILD-INFO.txt"])
        self.assertNotIn("Navi48Bringup", " ".join(files))
        manifest = files["SHA256SUMS.txt"].decode()
        for name, data in files.items():
            if name != "SHA256SUMS.txt":
                self.assertIn(f"{PACKAGE.hashlib.sha256(data).hexdigest()}  {name}\n", manifest)

    def test_missing_firmware_license_refuses_packaging(self):
        (self.root / "src/navi48-bringup/firmware/LICENSE.amdgpu").unlink()
        with self.assertRaises(FileNotFoundError):
            self.payload()

    def test_missing_or_wrong_reset_client_refuses_packaging(self):
        for magic, cpu, kind in ((0xFEEDFACF, 0x0100000C, 2),
                                 (0xFEEDFACF, 0x01000007, 11),
                                 (0, 0x01000007, 2)):
            self.reset_client.write_bytes(struct.pack("<8I", magic, cpu, 3, kind, 0, 0, 0, 0))
            with self.assertRaisesRegex(ValueError, "Mach-O executable"):
                self.payload()
        self.reset_client.unlink()
        with self.assertRaises(FileNotFoundError):
            self.payload()

    def test_wrong_bundle_architecture_and_personality_are_rejected(self):
        self.info["CFBundleIdentifier"] = "com.navi48.bringup"
        with self.assertRaisesRegex(ValueError, "identity"):
            self.payload()
        self.info["CFBundleIdentifier"] = "com.cobalt.navi44-survey"
        self.executable.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 11, 0, 0, 0, 0))
        with self.assertRaisesRegex(ValueError, "x86_64"):
            self.payload()
        self.executable.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 11, 0, 0, 0, 0))
        self.info["IOKitPersonalities"]["Survey"]["IOPCIPrimaryMatch"] = "0x75501002 0x75901002"
        with self.assertRaisesRegex(ValueError, "isolated"):
            self.payload()

    def test_extra_payload_and_missing_signature_are_rejected(self):
        extra = self.kext / "Contents/firmware.bin"
        extra.write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected.*file"):
            self.payload()
        extra.unlink()
        (self.kext / "Contents/_CodeSignature/CodeResources").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self.payload()


if __name__ == "__main__":
    unittest.main()
