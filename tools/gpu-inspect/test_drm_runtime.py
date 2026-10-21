"""Offline tests for the bounded DRM runtime capture ABI and device selection."""
from __future__ import annotations

import base64
import ctypes
import importlib.util
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("drm_runtime.py")
SPEC = importlib.util.spec_from_file_location("drm_runtime", MODULE_PATH)
drm = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(drm)


class DecodeTests(unittest.TestCase):
    def test_dev_info_decodes_per_field_offsets_and_wide_values(self):
        raw = bytearray(drm.DEV_INFO_SIZE)
        values = {
            "device_id": (0, 0x7590), "num_shader_engines": (20, 0x11223344),
            "cu_active_number": (48, 0x55667788), "cu_bitmap[2][1]": (56 + (2 * 4 + 1) * 4, 0xA1B2C3D4),
            "ids_flags": (136, 0x1122334455667788), "vram_bit_width": (180, 256),
            "cu_ao_bitmap[3][2]": (272 + (3 * 4 + 2) * 4, 0xFEDCBA98),
            "high_va_offset": (336, 0x0123456789ABCDEF), "tcc_disabled_mask": (360, 0xFEDCBA9876543210),
            "min_engine_clock": (368, 0x1020304050607080), "tcp_cache_size": (384, 0x33445566),
            "gl2c_cache_size": (404, 0x778899AA), "mall_size": (408, 0x8877665544332211),
            "userq_ip_mask": (436, 0xCAFEBABE),
        }
        for _, (offset, value) in values.items():
            struct.pack_into("<Q" if value > 0xFFFFFFFF else "<I", raw, offset, value)
        result = drm.decode_dev_info(raw)
        self.assertEqual(result["device_id"], 0x7590)
        self.assertEqual(result["num_shader_engines"], 0x11223344)
        self.assertEqual(result["cu_active_number"], 0x55667788)
        self.assertEqual(result["cu_bitmap"][2][1], 0xA1B2C3D4)
        self.assertEqual(result["ids_flags"], 0x1122334455667788)
        self.assertEqual(result["vram_bit_width"], 256)
        self.assertEqual(result["cu_ao_bitmap"][3][2], 0xFEDCBA98)
        self.assertEqual(result["high_va_offset"], 0x0123456789ABCDEF)
        self.assertEqual(result["tcc_disabled_mask"], 0xFEDCBA9876543210)
        self.assertEqual(result["min_engine_clock"], 0x1020304050607080)
        self.assertEqual(result["tcp_cache_size"], 0x33445566)
        self.assertEqual(result["gl2c_cache_size"], 0x778899AA)
        self.assertEqual(result["mall_size"], 0x8877665544332211)
        self.assertEqual(result["userq_ip_mask"], 0xCAFEBABE)

    def test_hw_ip_and_fw_decoders_preserve_full_fields(self):
        hw = struct.pack("<IIQIIII", 0x12345678, 0x87654321, 0x1122334455667788,
                         0xAABBCCDD, 0x01020304, 0x55667788, 0x99AABBCC)
        self.assertEqual(drm.decode_hw_ip(hw), {
            "hw_ip_version_major": 0x12345678, "hw_ip_version_minor": 0x87654321,
            "capabilities_flags": 0x1122334455667788, "ib_start_alignment": 0xAABBCCDD,
            "ib_size_alignment": 0x01020304, "available_rings": 0x55667788,
            "ip_discovery_version": 0x99AABBCC,
        })
        self.assertEqual(drm.decode_fw(struct.pack("<II", 0x11223344, 0xAABBCCDD)),
                         {"version": 0x11223344, "feature": 0xAABBCCDD})

    def test_short_payloads_are_rejected(self):
        with self.assertRaises(ValueError):
            drm.decode_dev_info(bytes(drm.DEV_INFO_SIZE - 1))
        with self.assertRaises(ValueError):
            drm.decode_hw_ip(bytes(drm.HW_IP_INFO_SIZE - 1))
        with self.assertRaises(ValueError):
            drm.decode_fw(bytes(drm.FW_INFO_SIZE - 1))


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fake-drm-sysfs-")
        self.addCleanup(self.temp.cleanup)
        self.original_resolve = Path.resolve
        self.root = Path(self.temp.name)
        # Windows cannot create path components containing the PCI BDF colons;
        # the production code matches the resolved sysfs target, not this name.
        self.device = self.root / "pci/target-device"
        self.device.mkdir(parents=True)
        self.render = self.root / "class/drm/renderD141"
        self.render.mkdir(parents=True)
        (self.render / "device").mkdir()
        (self.render / "dev").write_text("226:141\n", encoding="ascii")
        self.dev_root = self.root / "dev/dri"
        self.dev_root.mkdir(parents=True)
        self.expected_path = self.dev_root / "renderD141"

    def resolver(self, path, *args, **kwargs):
        if path == self.render / "device":
            return self.device
        return self.original_resolve(path, *args, **kwargs)

    def execute(self, *, ioctl_fn=None, fstat=None, open_fn=None, close_fn=None):
        with mock.patch.object(Path, "resolve", lambda path, *args, **kwargs: self.resolver(path, *args, **kwargs)):
            return drm.collect_drm_runtime(self.root, self.device, dev_root=self.dev_root,
                                           ioctl_fn=ioctl_fn, fstat_fn=fstat,
                                           open_fn=open_fn, close_fn=close_fn)

    def test_selects_exact_rendernode_passes_known_ioctl_and_closes_fd(self):
        calls = []
        closed = []

        def fake_ioctl(fd, request, arg, mutate):
            self.assertEqual(fd, 57)
            self.assertEqual(request, 0x40206445)
            self.assertTrue(mutate)
            pointer, size, query = struct.unpack_from("<QII", arg)
            selector = struct.unpack_from("<4I", arg, 16)
            expected_size = drm.DEV_INFO_SIZE if query == drm.INFO_DEV_INFO else (
                drm.HW_IP_INFO_SIZE if query == drm.INFO_HW_IP_INFO else (
                    4 if query == drm.INFO_READ_MMR_REG else drm.FW_INFO_SIZE))
            self.assertEqual(size, expected_size)
            calls.append((query, selector, size))
            payload = bytearray(size)
            if query == drm.INFO_DEV_INFO:
                struct.pack_into("<I", payload, 0, 0x7590)
                struct.pack_into("<I", payload, 180, 256)
                struct.pack_into("<Q", payload, 360, 0x123456789ABCDEF0)
            elif query == drm.INFO_HW_IP_INFO:
                struct.pack_into("<Q", payload, 8, 0xFEDCBA9876543210)
            elif query == drm.INFO_READ_MMR_REG:
                struct.pack_into("<I", payload, 0, 0x12345678)
            else:
                struct.pack_into("<II", payload, 0, 0x1234, 0x5678)
            ctypes.memmove(pointer, bytes(payload), size)
            return 0

        report = self.execute(ioctl_fn=fake_ioctl,
                              open_fn=lambda path, flags: self.assert_open(path, flags),
                              fstat=lambda fd: self.fake_stat(226, 141), close_fn=closed.append)
        self.assertTrue(report["complete"])
        self.assertEqual(len(calls), 2 + len(drm.HW_IP_TYPES) + len(drm.FW_TYPES))
        self.assertEqual(calls[0], (drm.INFO_DEV_INFO, (0, 0, 0, 0), drm.DEV_INFO_SIZE))
        self.assertIn((drm.INFO_HW_IP_INFO, (0, 0, 0, 0), drm.HW_IP_INFO_SIZE), calls)
        self.assertIn((drm.INFO_FW_VERSION, (4, 0, 0, 0), drm.FW_INFO_SIZE), calls)
        mmr_queries = [call for call in calls if call[0] == drm.INFO_READ_MMR_REG]
        self.assertEqual(mmr_queries, [(drm.INFO_READ_MMR_REG, (0x263E, 1, 0xFFFFFFFF, 0), 4)])
        self.assertEqual(closed, [57])
        self.assertEqual(report["decoded"]["dev_info"]["device_id"], 0x7590)
        self.assertEqual(report["decoded"]["dev_info"]["vram_bit_width"], 256)
        self.assertEqual(report["decoded"]["dev_info"]["tcc_disabled_mask"], 0x123456789ABCDEF0)
        self.assertEqual(report["decoded"]["gb_addr_config"], {"gb_addr_config": 0x12345678})
        raw = base64.b64decode(report["queries"][0]["data"])
        self.assertEqual(len(raw), drm.DEV_INFO_SIZE)

    def assert_open(self, path, flags):
        self.assertEqual(path, self.expected_path)
        self.assertEqual(flags & 3, os.O_RDONLY)
        if getattr(os, "O_CLOEXEC", 0):
            self.assertTrue(flags & os.O_CLOEXEC)
        return 57

    @staticmethod
    def fake_stat(major, minor):
        return type("Stat", (), {"st_mode": stat.S_IFCHR | 0o600,
                                 "st_rdev": drm._device_number(major, minor)})()

    def test_wrong_node_type_or_rdev_refuses_ioctl_and_closes(self):
        called = []
        closed = []
        report = self.execute(ioctl_fn=lambda *args: called.append(args),
                              open_fn=lambda *args: 9,
                              fstat=lambda fd: self.fake_stat(226, 142), close_fn=closed.append)
        self.assertFalse(report["complete"])
        self.assertEqual(called, [])
        self.assertEqual(closed, [9])
        self.assertIn("expected character device", report["errors"][0]["error"])

    def test_native_ioctl_path_is_guarded_to_linux_64bit_little_endian(self):
        with mock.patch.object(drm.sys, "platform", "win32"):
            report = drm.collect_drm_runtime(self.root, self.device,
                                             open_fn=lambda *args: self.fail("must not open"))
        self.assertFalse(report["complete"])
        self.assertIn("64-bit little-endian Linux", report["errors"][0]["error"])

    def test_missing_and_ambiguous_mappings_refuse_to_open(self):
        with mock.patch.object(Path, "resolve", lambda path, *args, **kwargs: self.resolver(path, *args, **kwargs)):
            (self.render / "dev").unlink()
            no_node = drm.collect_drm_runtime(self.root, self.device, dev_root=self.dev_root,
                                              ioctl_fn=lambda *args: self.fail("must not ioctl"),
                                              open_fn=lambda *args: self.fail("must not open"))
            self.assertFalse(no_node["complete"])
            (self.render / "dev").write_text("226:141", encoding="ascii")
            second = self.root / "class/drm/renderD142"
            second.mkdir()
            (second / "device").mkdir()
            (second / "dev").write_text("226:142", encoding="ascii")
            # Both mappings are represented as resolving to the selected PCI device.
            original = self.original_resolve
            def both(path, *args, **kwargs):
                if path in (self.render / "device", second / "device"):
                    return self.device
                return original(path, *args, **kwargs)
            with mock.patch.object(Path, "resolve", both):
                multiple = drm.collect_drm_runtime(self.root, self.device, dev_root=self.dev_root,
                                                   ioctl_fn=lambda *args: self.fail("must not ioctl"),
                                                   open_fn=lambda *args: self.fail("must not open"))
            self.assertFalse(multiple["complete"])
            self.assertIn("refusing to choose automatically", multiple["errors"][0]["error"])

    def test_ioctl_failure_is_reported_and_fd_closed(self):
        closed = []
        report = self.execute(ioctl_fn=lambda *args: (_ for _ in ()).throw(OSError("denied")),
                              open_fn=lambda *args: 3, fstat=lambda fd: self.fake_stat(226, 141),
                              close_fn=closed.append)
        self.assertFalse(report["complete"])
        self.assertIn("denied", report["errors"][0]["error"])
        self.assertEqual(report["queries"][0]["query"], drm.INFO_DEV_INFO)
        self.assertTrue(report["queries"][0]["required"])
        self.assertIn("denied", report["queries"][0]["error"])
        self.assertEqual(closed, [3])

    def _query_fixture(self, fail_query=None, device_id=0x7590):
        def fake_ioctl(fd, request, arg, mutate):
            pointer, size, query = struct.unpack_from("<QII", arg)
            selector = struct.unpack_from("<4I", arg, 16)
            if (query, selector[0]) == fail_query:
                raise OSError("unsupported query")
            payload = bytearray(size)
            if query == drm.INFO_DEV_INFO:
                struct.pack_into("<I", payload, 0, device_id)
            ctypes.memmove(pointer, bytes(payload), size)
        return self.execute(ioctl_fn=fake_ioctl, open_fn=lambda *args: 3,
                            fstat=lambda fd: self.fake_stat(226, 141), close_fn=lambda fd: None)

    def test_unsupported_optional_query_does_not_make_capture_partial(self):
        report = self._query_fixture(fail_query=(drm.INFO_FW_VERSION, drm.FW_TYPES["gfx_ce"]))
        self.assertTrue(report["complete"])
        self.assertTrue(any(error.get("severity") == "optional" for error in report["errors"]))
        failed = next(item for item in report["queries"] if item["name"] == "fw_gfx_ce")
        self.assertFalse(failed["required"])
        self.assertIn("unsupported query", failed["error"])

    def test_gb_addr_config_is_one_fixed_optional_register_query(self):
        calls = []
        def fake_ioctl(fd, request, arg, mutate):
            pointer, size, query = struct.unpack_from("<QII", arg)
            selector = struct.unpack_from("<4I", arg, 16)
            calls.append((query, selector, size))
            payload = bytearray(size)
            if query == drm.INFO_DEV_INFO:
                struct.pack_into("<I", payload, 0, 0x7590)
            elif query == drm.INFO_READ_MMR_REG:
                struct.pack_into("<I", payload, 0, 0xA1B2C3D4)
            ctypes.memmove(pointer, bytes(payload), size)
        report = self.execute(ioctl_fn=fake_ioctl, open_fn=lambda *args: 3,
                              fstat=lambda fd: self.fake_stat(226, 141), close_fn=lambda fd: None)
        mmr = [call for call in calls if call[0] == drm.INFO_READ_MMR_REG]
        self.assertEqual(mmr, [(drm.INFO_READ_MMR_REG, (0x263E, 1, 0xFFFFFFFF, 0), 4)])
        self.assertEqual(report["decoded"]["gb_addr_config"]["gb_addr_config"], 0xA1B2C3D4)
        self.assertEqual(report["decoded"]["gb_addr_config"], {"gb_addr_config": 0xA1B2C3D4})
        self.assertTrue(report["complete"])

    def test_failed_required_query_makes_capture_partial(self):
        report = self._query_fixture(fail_query=(drm.INFO_FW_VERSION, drm.FW_TYPES["gfx_me"]))
        self.assertFalse(report["complete"])
        failed = next(item for item in report["queries"] if item["name"] == "fw_gfx_me")
        self.assertTrue(failed["required"])
        self.assertTrue(any(error.get("severity") == "required" for error in report["errors"]))

    def test_dev_info_identity_mismatch_makes_capture_partial(self):
        report = self._query_fixture(device_id=0x1234)
        self.assertFalse(report["complete"])
        self.assertTrue(any("does not match selected GPU 7590" in error["error"]
                            for error in report["errors"]))

    def test_response_overrun_canary_is_detected(self):
        closed = []
        def overrun(fd, request, arg, mutate):
            pointer, size, _ = struct.unpack_from("<QII", arg)
            ctypes.c_ubyte.from_address(pointer + size).value = 0
        report = self.execute(ioctl_fn=overrun, open_fn=lambda *args: 3,
                              fstat=lambda fd: self.fake_stat(226, 141), close_fn=closed.append)
        self.assertFalse(report["complete"])
        self.assertIn("exceeded declared return_size", report["errors"][0]["error"])
        self.assertEqual(report["queries"][0]["size"], drm.DEV_INFO_SIZE)
        self.assertEqual(closed, [3])


if __name__ == "__main__":
    unittest.main(verbosity=2)
