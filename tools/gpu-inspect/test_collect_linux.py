"""Offline fake-sysfs tests for collect-linux.py; no GPU or Linux required."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("collect-linux.py")
SPEC = importlib.util.spec_from_file_location("collect_linux", SCRIPT)
collector = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(collector)
PRODUCTION_BDF_PATTERN = collector.BDF_PATTERN

TARGET = "0000_03_00_0"
OTHER = "0000_04_00_0"
WRONG = "0000_05_00_0"
REQUIRED = (11, 255, 1, 42, 271)


class FakeSysfs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fake-sysfs-")
        self.addCleanup(self.temp.cleanup)
        self.bdf_patch = mock.patch.object(
            collector,
            "BDF_PATTERN",
            re.compile(r"[0-9a-fA-F]{4}_[0-9a-fA-F]{2}_[0-9a-fA-F]{2}_[0-7]\Z"),
        )
        self.bdf_patch.start()
        self.addCleanup(self.bdf_patch.stop)
        self.root = Path(self.temp.name)
        self.device = self.root / "bus/pci/devices" / TARGET
        self.device.mkdir(parents=True)
        self.write(self.device / "vendor", "0x1002\n")
        self.write(self.device / "device", "0x7590\n")
        (self.device / "driver").mkdir()
        for name, value in {
            "revision": "0x01", "subsystem_vendor": "0x1043", "subsystem_device": "0x0001",
            "class": "0x030000", "mem_info_vram_total": "17179869184",
            "mem_info_vis_vram_total": "17179869184", "mem_info_gtt_total": "8589934592",
            "vbios_version": "113-D70201-001",
        }.items():
            self.write(self.device / name, value)
        self.write(self.root / "module/amdgpu/version", "6.12.0\n")
        self.write(self.device / "ip_discovery/die/0/num_ips", str(len(REQUIRED)))
        for hw_id in REQUIRED:
            self.add_ip(hw_id)
        # Named aliases in the real kernel tree must not be treated as duplicate
        # numeric hardware blocks.
        self.write(self.device / "ip_discovery/die/0/GC/11/major", "99")
        (self.device / "ip_discovery/die/0/GC").mkdir(parents=True, exist_ok=True)
        self.card = self.root / "class/drm/card0"
        self.card.mkdir(parents=True)
        (self.card / "device").mkdir()
        self.write(self.card / "dev", "226:0\n")
        self.connector = self.root / "class/drm/card0-DP-1"
        self.connector.mkdir()
        self.write(self.connector / "status", "connected\n")
        self.write(self.connector / "enabled", "enabled\n")
        self.write(self.connector / "modes", "3840x2160\n")
        self.write(self.connector / "edid", b"fake-edid\x00", binary=True)
        self.write(self.root / "kernel/debug/dri/0/amdgpu_discovery", b"exact-cached-discovery", binary=True)
        self.write(self.root / "kernel/debug/dri/0/amdgpu_firmware_info", "fixture firmware versions\n")

    @staticmethod
    def write(path: Path, value, binary=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="ascii")

    def add_ip(self, hw_id, *, instance=0, count=1, bases="0x12345000\n", major=11):
        path = self.device / "ip_discovery/die/0" / str(hw_id) / str(instance)
        for name, value in {
            "hw_id": str(hw_id), "num_instance": str(instance), "major": str(major),
            "minor": "2", "revision": "3", "harvest": "0x0",
            "num_base_addresses": str(count), "base_addr": bases,
        }.items():
            self.write(path / name, value)
        return path

    def collect(self, *, bdf=None, patch_io=True):
        # Real sysfs uses symlinks. Mock resolution so the tests remain portable
        # on Windows hosts where creating symlinks may require elevated rights.
        original_resolve = Path.resolve

        def resolve(path, *args, **kwargs):
            if path.name == "device" and path.parent.name == "card0":
                return self.device
            if path.name == "device" and path.parent.name == "card1":
                return self.root / "unrelated-pci-device"
            return original_resolve(path, *args, **kwargs)

        def readlink(path):
            if path == self.device / "driver" and path.exists():
                return "../../../bus/pci/drivers/amdgpu"
            raise OSError("not a symlink")

        fake_bdf = re.compile(r"[0-9a-fA-F]{4}_[0-9a-fA-F]{2}_[0-9a-fA-F]{2}_[0-7]\Z")
        with mock.patch.object(Path, "resolve", resolve), mock.patch.object(collector.os, "readlink", readlink), \
                mock.patch.object(collector, "BDF_PATTERN", fake_bdf):
            return collector.collect(self.root, bdf)

    def test_valid_rx9060_capture_ignores_named_alias_and_has_raw_blob(self):
        report = self.collect()
        self.assertTrue(report["complete"])
        self.assertEqual(report["gpu"]["ip_discovery"]["enumerated_num_ips"], len(REQUIRED))
        self.assertEqual(report["capture_level"], "raw-and-sysfs")
        ip = report["gpu"]["ip_discovery"]["dies"][0]["ips"][0]
        self.assertTrue(ip["valid"])
        self.assertEqual(ip["base_addresses"], ["0x12345000"])
        raw = report["gpu"]["cached_ip_discovery_blob"]["cards"][0]
        payload = base64.b64decode(raw["data"])
        self.assertEqual(payload, b"exact-cached-discovery")
        self.assertEqual(raw["sha256"], hashlib.sha256(payload).hexdigest())

    def test_unrelated_gpu_and_drm_connectors_are_ignored(self):
        unrelated = self.root / "bus/pci/devices" / OTHER
        unrelated.mkdir(parents=True)
        self.write(unrelated / "vendor", "0x10de")
        self.write(unrelated / "device", "0x2684")
        other_card = self.root / "class/drm/card1"
        other_card.mkdir()
        (other_card / "device").mkdir()
        self.write(other_card / "dev", "226:1")
        self.write(self.root / "kernel/debug/dri/1/amdgpu_discovery", b"unrelated-cached-blob", binary=True)
        other_connector = self.root / "class/drm/card1-HDMI-A-1"
        other_connector.mkdir()
        self.write(other_connector / "status", "connected")
        report = self.collect()
        self.assertEqual(report["gpu"]["bdf"], TARGET)
        self.assertEqual([x["name"] for x in report["gpu"]["drm_connectors"]], ["card0-DP-1"])
        blobs = report["gpu"]["cached_ip_discovery_blob"]["cards"]
        self.assertEqual([item["card"] for item in blobs], ["card0"])
        self.assertNotEqual(base64.b64decode(blobs[0]["data"]), b"unrelated-cached-blob")

    def test_multiple_target_gpus_require_exact_bdf_and_validate_choice(self):
        second = self.root / "bus/pci/devices" / OTHER
        second.mkdir(parents=True)
        self.write(second / "vendor", "0x1002")
        self.write(second / "device", "0x7590")
        with self.assertRaisesRegex(collector.CollectionError, "multiple RX 9060 XT"):
            collector.collect(self.root)
        report = collector.collect(self.root, TARGET)
        self.assertEqual(report["gpu"]["bdf"], TARGET)
        wrong = self.root / "bus/pci/devices" / WRONG
        wrong.mkdir(parents=True)
        self.write(wrong / "vendor", "0x10de")
        self.write(wrong / "device", "0x2684")
        with self.assertRaisesRegex(collector.CollectionError, "expected 1002:7590"):
            collector.collect(self.root, WRONG)

    def test_missing_driver_and_ip_data_are_partial(self):
        (self.device / "driver").rmdir()
        import shutil
        shutil.rmtree(self.device / "ip_discovery/die/0")
        report = self.collect()
        self.assertFalse(report["complete"])
        self.assertIn("sysfs-only", report["capture_level"])
        self.assertTrue(any("amdgpu driver" in warning for warning in report["warnings"]))
        self.assertTrue(any("Required valid" in warning for warning in report["warnings"]))

    def test_malformed_count_version_base_and_path_mismatch_are_invalid(self):
        path = self.device / "ip_discovery/die/0/11/0"
        self.write(path / "num_base_addresses", "2")
        self.write(path / "base_addr", "0x12345000\n")
        self.write(path / "major", "256")
        self.write(path / "hw_id", "12")
        report = self.collect()
        ip = next(item for item in report["gpu"]["ip_discovery"]["dies"][0]["ips"] if item["hw_id_path"] == 11)
        self.assertFalse(ip["valid"])
        self.assertTrue(any("declares 2 addresses" in error["error"] for error in report["errors"]))
        self.assertTrue(any("fit in one byte" in error["error"] for error in report["errors"]))
        self.assertTrue(any("does not match numeric path ID" in error["error"] for error in report["errors"]))

    def test_read_error_is_recorded_without_escalation(self):
        original = collector._bounded_bytes

        def deny_major(path, limit):
            if path.name == "major" and path.parent.name == "0":
                raise PermissionError("fixture denied")
            return original(path, limit)

        with mock.patch.object(collector, "_bounded_bytes", deny_major):
            report = self.collect()
        self.assertTrue(any(error["error"].startswith("permission denied") for error in report["errors"]))
        self.assertFalse(report["complete"])

    def test_raw_blob_permission_denial_keeps_sysfs_and_suggests_sudo(self):
        original = collector._bounded_bytes

        def deny_blob(path, limit):
            if path.name == "amdgpu_discovery":
                raise PermissionError("fixture denied")
            return original(path, limit)

        with mock.patch.object(collector, "_bounded_bytes", deny_blob):
            report = self.collect()
        self.assertEqual(report["capture_level"], "sysfs-only")
        self.assertTrue(any("permission denied reading cached" in error["error"] for error in report["errors"]))
        self.assertTrue(any("with sudo" in warning for warning in report["warnings"]))

    def test_production_bdf_pattern_accepts_real_address_not_fixture_name(self):
        self.assertTrue(PRODUCTION_BDF_PATTERN.fullmatch("0000:03:00.0"))
        self.assertFalse(PRODUCTION_BDF_PATTERN.fullmatch(TARGET))

    def test_edid_is_retained_only_for_target_connector(self):
        report = self.collect()
        self.assertEqual(report["gpu"]["cached_ip_discovery_blob"]["cards"][0]["firmware_info"], "fixture firmware versions")
        connector = report["gpu"]["drm_connectors"][0]
        self.assertEqual(base64.b64decode(connector["edid"]["data"]), b"fake-edid\x00")
        self.assertEqual(connector["edid"]["sha256"], hashlib.sha256(b"fake-edid\x00").hexdigest())


class CliTests(unittest.TestCase):
    def test_output_is_exclusive_and_partial_exit_is_nonzero(self):
        report = {"complete": False, "gpu": {"bdf": TARGET, "ip_discovery": {"enumerated_num_ips": 0}}}
        with tempfile.TemporaryDirectory(prefix="capture-output-") as tmp:
            output = Path(tmp) / "capture.json"
            with mock.patch.object(collector.sys, "platform", "linux"), mock.patch.object(collector, "collect", return_value=report):
                self.assertEqual(collector.main(["--output", str(output)]), 1)
                self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
                self.assertEqual(collector.main(["--output", str(output)]), 2)
                self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)

    def test_non_linux_refuses_to_collect(self):
        with mock.patch.object(collector.sys, "platform", "win32"), mock.patch.object(collector, "collect") as collect_mock:
            self.assertEqual(collector.main([]), 2)
            collect_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
