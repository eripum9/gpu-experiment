"""Bounded read-only AMDGPU_INFO runtime queries for a selected PCI function.

ABI constants and layouts follow the repository's pinned Mesa drm-uapi/amdgpu_drm.h.
Only DRM_IOCTL_AMDGPU_INFO is issued; no user-controlled ioctl/query values are accepted.
The fixed GB_ADDR_CONFIG query uses the driver's allowlisted cached tiling metadata,
not a direct MMIO mapping.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Any, Callable


# drm_amdgpu_info has a 16-byte fixed header followed by a 16-byte union.
# DRM_IOW('d', DRM_COMMAND_BASE + DRM_AMDGPU_INFO, struct drm_amdgpu_info)
INFO_IOCTL = 0x40206445
INFO_HW_IP_INFO = 0x02
INFO_FW_VERSION = 0x0E
INFO_READ_MMR_REG = 0x15
INFO_DEV_INFO = 0x16
GB_ADDR_CONFIG_OFFSET = 0x263E
FW_TYPES = {
    "gfx_me": 0x04, "gfx_pfp": 0x05, "gfx_ce": 0x06, "gfx_rlc": 0x07,
    "gfx_mec": 0x08, "sdma": 0x0B, "psp_sos": 0x0C, "vcn": 0x0E,
    "gfx_rlcp": 0x17, "gfx_rlcv": 0x18, "mes_kiq": 0x19,
    "mes": 0x1A, "imu": 0x1B, "vpe": 0x1C,
}
HW_IP_TYPES = {"gfx": 0, "compute": 1, "dma": 2, "vcn_dec": 6, "vcn_enc": 7, "vcn_jpeg": 8, "vpe": 9}
DEV_INFO_SIZE = 448
HW_IP_INFO_SIZE = 32
FW_INFO_SIZE = 8
MAX_RAW_TOTAL = DEV_INFO_SIZE + len(HW_IP_TYPES) * HW_IP_INFO_SIZE + len(FW_TYPES) * FW_INFO_SIZE + 4
DEVNAME = re.compile(r"renderD[0-9]+\Z")
REQUIRED_QUERIES = {"dev_info", "hw_ip_gfx", "hw_ip_compute", "fw_gfx_me", "fw_gfx_pfp", "fw_gfx_mec"}
EXPECTED_DEVICE_ID = 0x7590


def _u32(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<I", raw, offset)[0]


def _u64(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", raw, offset)[0]


def _device_number(major: int, minor: int) -> int:
    """Linux new_encode_dev encoding, also usable by offline tests on Windows."""
    return ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & ~0xFF) << 12) | ((major & ~0xFFF) << 32)


def decode_dev_info(raw: bytes) -> dict[str, Any]:
    """Decode known fields by their UAPI offsets; reject short or long payloads."""
    if len(raw) != DEV_INFO_SIZE:
        raise ValueError(f"DEV_INFO returned {len(raw)} bytes; expected {DEV_INFO_SIZE}")
    u32_fields = {
        "device_id": 0, "chip_rev": 4, "external_rev": 8, "pci_rev": 12,
        "family": 16, "num_shader_engines": 20, "num_shader_arrays_per_engine": 24,
        "gpu_counter_freq_khz": 28, "cu_active_number": 48, "cu_ao_mask": 52,
        "enabled_rb_pipes_mask": 120, "num_rb_pipes": 124, "num_hw_gfx_contexts": 128,
        "pcie_gen": 132, "virtual_address_alignment": 160, "pte_fragment_size": 164,
        "gart_page_size": 168, "ce_ram_size": 172, "vram_type": 176,
        "vram_bit_width": 180, "vce_harvest_config": 184, "gc_double_offchip_lds_buf": 188,
        "prim_buf_size": 224, "pos_buf_size": 228, "cntl_sb_buf_size": 232,
        "param_buf_size": 236, "wave_front_size": 240, "num_shader_visible_vgprs": 244,
        "num_cu_per_sh": 248, "num_tcc_blocks": 252, "gs_vgt_table_depth": 256,
        "gs_prim_buffer_depth": 260, "max_gs_waves_per_vgt": 264, "pcie_num_lanes": 268,
        "pa_sc_tile_steering_override": 352, "tcp_cache_size": 384,
        "num_sqc_per_wgp": 388,
    }
    result: dict[str, Any] = {name: _u32(raw, offset) for name, offset in u32_fields.items()}
    result.update({
        "max_engine_clock": _u64(raw, 32), "max_memory_clock": _u64(raw, 40),
        "cu_bitmap": [[_u32(raw, 56 + (se * 4 + sa) * 4) for sa in range(4)] for se in range(4)],
        "ids_flags": _u64(raw, 136), "virtual_address_offset": _u64(raw, 144),
        "virtual_address_max": _u64(raw, 152), "prim_buf_gpu_addr": _u64(raw, 192),
        "pos_buf_gpu_addr": _u64(raw, 200), "cntl_sb_buf_gpu_addr": _u64(raw, 208),
        "param_buf_gpu_addr": _u64(raw, 216),
        "cu_ao_bitmap": [[_u32(raw, 272 + (se * 4 + sa) * 4) for sa in range(4)] for se in range(4)],
        "high_va_offset": _u64(raw, 336), "high_va_max": _u64(raw, 344),
        "tcc_disabled_mask": _u64(raw, 360), "min_engine_clock": _u64(raw, 368),
        "min_memory_clock": _u64(raw, 376),
        "sqc_data_cache_size": _u32(raw, 392), "sqc_inst_cache_size": _u32(raw, 396),
        "gl1c_cache_size": _u32(raw, 400), "gl2c_cache_size": _u32(raw, 404),
        "mall_size": _u64(raw, 408), "enabled_rb_pipes_mask_hi": _u32(raw, 416),
        "shadow_size": _u32(raw, 420), "shadow_alignment": _u32(raw, 424),
        "csa_size": _u32(raw, 428), "csa_alignment": _u32(raw, 432),
        "userq_ip_mask": _u32(raw, 436), "pad": _u32(raw, 440),
    })
    return result


def decode_hw_ip(raw: bytes) -> dict[str, int]:
    if len(raw) != HW_IP_INFO_SIZE:
        raise ValueError(f"HW_IP_INFO returned {len(raw)} bytes; expected {HW_IP_INFO_SIZE}")
    return {"hw_ip_version_major": _u32(raw, 0), "hw_ip_version_minor": _u32(raw, 4),
            "capabilities_flags": _u64(raw, 8), "ib_start_alignment": _u32(raw, 16),
            "ib_size_alignment": _u32(raw, 20), "available_rings": _u32(raw, 24),
            "ip_discovery_version": _u32(raw, 28)}


def decode_fw(raw: bytes) -> dict[str, int]:
    if len(raw) != FW_INFO_SIZE:
        raise ValueError(f"FW_VERSION returned {len(raw)} bytes; expected {FW_INFO_SIZE}")
    return {"version": _u32(raw, 0), "feature": _u32(raw, 4)}


def decode_gb_addr_config(raw: bytes) -> dict[str, int]:
    if len(raw) != 4:
        raise ValueError(f"GB_ADDR_CONFIG returned {len(raw)} bytes; expected 4")
    return {"gb_addr_config": _u32(raw, 0)}


def _render_nodes(sys_root: Path, device: Path) -> list[tuple[str, int, int]]:
    drm_root = sys_root / "class/drm"
    target = device.resolve()
    found = []
    for entry in drm_root.iterdir():
        if not DEVNAME.fullmatch(entry.name):
            continue
        try:
            if (entry / "device").resolve() != target:
                continue
            text = (entry / "dev").read_text(encoding="ascii").strip()
            major_s, minor_s = text.split(":", 1)
            major, minor = int(major_s), int(minor_s)
            if major < 0 or minor < 0:
                raise ValueError("negative device number")
            found.append((entry.name, major, minor))
        except (OSError, UnicodeError, ValueError):
            continue
    return sorted(found)


def _request(query: int, response: bytearray, return_size: int, selector: tuple[int, ...] = (),
             ioctl_fn: Callable[..., Any] | None = None, fd: int = -1) -> bytes:
    # drm_amdgpu_info: __u64 return_pointer; __u32 return_size, query;
    # 16-byte union. Pointer is native little-endian 64-bit on supported Linux.
    if ioctl_fn is None:
        import fcntl
        ioctl_fn = fcntl.ioctl
    address = ctypes.addressof((ctypes.c_ubyte * len(response)).from_buffer(response))
    union = tuple(selector) + (0,) * (4 - len(selector))
    arg = bytearray(struct.pack("<QII4I", address, return_size, query, *union))
    ioctl_fn(fd, INFO_IOCTL, arg, True)
    if response[return_size:] != b"\xA5" * (len(response) - return_size):
        raise ValueError("kernel response exceeded declared return_size")
    return bytes(response[:return_size])


def collect_drm_runtime(sys_root: Path, device: Path, *, dev_root: Path = Path("/dev/dri"),
                        expected_device_id: int = EXPECTED_DEVICE_ID,
                        open_fn: Callable[..., int] | None = None,
                        ioctl_fn: Callable[..., Any] | None = None,
                        fstat_fn: Callable[[int], Any] | None = None,
                        close_fn: Callable[[int], Any] | None = None) -> dict[str, Any]:
    """Capture the selected device's runtime UAPI payloads; errors are local to this record."""
    errors: list[dict[str, str]] = []
    queries: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "complete": False, "errors": errors, "queries": queries,
        "render_nodes": [], "decoded": {},
        "response_note": ("AMDGPU_INFO provides no returned-byte count. Each raw payload is the fixed requested buffer; "
                          "older kernels may copy only a prefix, leaving trailing zero-filled fields indistinguishable."),
    }
    if ioctl_fn is None and (not sys.platform.startswith("linux") or struct.calcsize("P") != 8 or sys.byteorder != "little"):
        errors.append({"severity": "required", "error": "native AMDGPU_INFO ABI requires a 64-bit little-endian Linux process"})
        return result
    try:
        nodes = _render_nodes(Path(sys_root), Path(device))
    except OSError as exc:
        errors.append({"error": f"cannot enumerate target render nodes: {exc}"})
        return result
    result["render_nodes"] = [{"name": name, "major": major, "minor": minor} for name, major, minor in nodes]
    if len(nodes) != 1:
        if len(nodes) > 1:
            message = "multiple render nodes map to selected PCI device; refusing to choose automatically"
        else:
            message = "no render node maps to selected PCI device"
        errors.append({"error": message + f" (found {len(nodes)})"})
        return result
    name, major, minor = nodes[0]
    path = Path(dev_root) / name
    fd = -1
    try:
        if open_fn is None:
            open_fn = os.open
        if fstat_fn is None:
            fstat_fn = os.fstat
        if close_fn is None:
            close_fn = os.close
        fd = open_fn(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        info = fstat_fn(fd)
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != _device_number(major, minor):
            errors.append({"error": f"{path} is not the expected character device {major}:{minor}"})
            return result
        def query(name: str, query_id: int, size: int, selector: tuple[int, ...] = (), decode=None):
            required = name in REQUIRED_QUERIES
            record: dict[str, Any] = {"name": name, "query": query_id, "selector": list(selector),
                                      "size": size, "requested_size": size, "required": required}
            response = bytearray(size + 8)
            response[size:] = b"\xA5" * 8  # canary catches unexpected writes past return_size
            try:
                payload = _request(query_id, response, size, selector, ioctl_fn, fd)
            except (OSError, ValueError) as exc:
                record["error"] = str(exc)
                queries.append(record)
                errors.append({"query": name, "severity": "required" if required else "optional", "error": str(exc)})
                return
            raw = payload[:size]
            record.update({"encoding": "base64", "data": base64.b64encode(raw).decode("ascii"),
                           "sha256": hashlib.sha256(raw).hexdigest()})
            queries.append(record)
            if decode:
                try:
                    decoded = decode(raw)
                    result["decoded"][name] = decoded
                    if name == "dev_info" and decoded["device_id"] != expected_device_id:
                        raise ValueError(
                            f"returned PCI device ID {decoded['device_id']:04x} does not match selected GPU {expected_device_id:04x}"
                        )
                except ValueError as exc:
                    errors.append({"query": name, "severity": "required" if required else "optional", "error": str(exc)})
        query("dev_info", INFO_DEV_INFO, DEV_INFO_SIZE, decode=decode_dev_info)
        for name, hw_type in HW_IP_TYPES.items():
            query("hw_ip_" + name, INFO_HW_IP_INFO, HW_IP_INFO_SIZE, (hw_type, 0), decode=decode_hw_ip)
        for name, fw_type in FW_TYPES.items():
            query("fw_" + name, INFO_FW_VERSION, FW_INFO_SIZE, (fw_type, 0, 0, 0), decode=decode_fw)
        # The pinned Linux v6.19 amdgpu_soc24 path allowlists this register and
        # serves its cached tiling value when available; it does not map MMIO.
        query("gb_addr_config", INFO_READ_MMR_REG, 4,
              (GB_ADDR_CONFIG_OFFSET, 1, 0xFFFFFFFF, 0), decode=decode_gb_addr_config)
    except OSError as exc:
        errors.append({"error": f"DRM runtime query failed: {exc}"})
    finally:
        if fd >= 0:
            try:
                close_fn(fd)
            except OSError as exc:
                errors.append({"error": f"failed to close render node: {exc}"})
    successful_required = {
        record["name"] for record in queries
        if record["name"] in REQUIRED_QUERIES and "data" in record
    }
    required_errors = any(error.get("severity") == "required" for error in errors)
    result["complete"] = successful_required == REQUIRED_QUERIES and not required_errors
    return result
