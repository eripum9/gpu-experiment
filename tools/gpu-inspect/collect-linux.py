#!/usr/bin/env python3
"""Collect bounded, read-only Linux metadata for an AMD RX 9060 XT.

This tool reads the target PCI function's standard sysfs attributes, its IP
Discovery tree, target DRM connector metadata/EDIDs, and only the driver's
cached amdgpu_discovery snapshot associated with that DRM device. It never
mounts debugfs, accesses ROM or PCI configuration, installs software, or
uploads the report.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
from datetime import datetime, timezone
from typing import Any


TARGET_VENDOR = 0x1002
TARGET_DEVICE = 0x7590
MAX_TEXT = 64 * 1024
MAX_EDID = 32 * 1024
MAX_DISCOVERY_BLOB = 256 * 1024
NUMERIC_NAME = re.compile(r"(?:0|[1-9][0-9]*)\Z")
BDF_PATTERN = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\Z")
REQUIRED_IPS = {11: "GC", 255: "MP0", 1: "MP1", 42: "SDMA", 271: "DMU"}


class CollectionError(Exception):
    """An error that prevents selecting a safe target device or writing report."""


def _bounded_bytes(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError(f"exceeds {limit}-byte read limit")
    return value


def _read_text(path: Path, errors: list[dict[str, str]], *, limit: int = MAX_TEXT) -> str | None:
    try:
        return _bounded_bytes(path, limit).decode("utf-8", errors="strict").strip()
    except FileNotFoundError:
        errors.append({"path": str(path), "error": "not present"})
    except PermissionError:
        errors.append({"path": str(path), "error": "permission denied"})
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append({"path": str(path), "error": str(exc)})
    return None


def _parse_integer(raw: str | None, field: str, errors: list[dict[str, str]], path: Path,
                   *, base: int = 10, maximum: int = 0xFFFFFFFFFFFFFFFF) -> int | None:
    if raw is None:
        return None
    try:
        value = int(raw, base)
        if value < 0 or value > maximum:
            raise ValueError("outside allowed numeric range")
        return value
    except ValueError as exc:
        errors.append({"path": str(path), "error": f"invalid {field}: {exc}"})
        return None


def _attribute(directory: Path, name: str, errors: list[dict[str, str]], *, required: bool = False) -> dict[str, Any]:
    path = directory / name
    raw = _read_text(path, errors)
    result: dict[str, Any] = {"raw": raw, "value": None}
    if raw is not None:
        try:
            result["value"] = int(raw, 10)
        except ValueError:
            errors.append({"path": str(path), "error": f"invalid decimal {name}"})
    elif not required:
        # Optional sysfs attributes are still useful to show as absent, but
        # their absence is not itself a capture failure.
        if errors and errors[-1].get("path") == str(path) and errors[-1].get("error") == "not present":
            errors.pop()
    return result


def _target_devices(sys_root: Path) -> list[tuple[str, Path]]:
    pci_root = sys_root / "bus/pci/devices"
    found: list[tuple[str, Path]] = []
    try:
        entries = list(pci_root.iterdir())
    except OSError as exc:
        raise CollectionError(f"Cannot read {pci_root}: {exc}. Boot native Ubuntu and ensure /sys is mounted.") from exc
    for entry in entries:
        if not BDF_PATTERN.fullmatch(entry.name):
            continue
        vendor_path, device_path = entry / "vendor", entry / "device"
        try:
            vendor = int(_bounded_bytes(vendor_path, 32).decode("ascii").strip(), 16)
            device = int(_bounded_bytes(device_path, 32).decode("ascii").strip(), 16)
        except (OSError, UnicodeError, ValueError):
            continue
        if vendor == TARGET_VENDOR and device == TARGET_DEVICE:
            found.append((entry.name, entry))
    return found


def _select_device(sys_root: Path, bdf: str | None) -> tuple[str, Path]:
    if bdf is not None:
        if not BDF_PATTERN.fullmatch(bdf):
            raise CollectionError("--bdf must be a PCI address such as 0000:03:00.0")
        normalized = bdf.lower()
        path = sys_root / "bus/pci/devices" / normalized
        try:
            vendor = int(_bounded_bytes(path / "vendor", 32).decode("ascii").strip(), 16)
            device = int(_bounded_bytes(path / "device", 32).decode("ascii").strip(), 16)
        except (OSError, UnicodeError, ValueError) as exc:
            raise CollectionError(f"Cannot read PCI identity for {normalized}: {exc}") from exc
        if (vendor, device) != (TARGET_VENDOR, TARGET_DEVICE):
            raise CollectionError(f"{normalized} is {vendor:04x}:{device:04x}, expected 1002:7590 (RX 9060 XT)")
        return normalized, path
    candidates = _target_devices(sys_root)
    if not candidates:
        raise CollectionError("No AMD 1002:7590 RX 9060 XT found in Linux PCI sysfs. Boot native Ubuntu with the card installed; WSL does not expose the real GPU.")
    if len(candidates) > 1:
        addresses = ", ".join(bdf for bdf, _ in candidates)
        raise CollectionError(f"Found multiple RX 9060 XT devices ({addresses}); choose one with --bdf.")
    return candidates[0]


def _read_ip(directory: Path, die_id: int, hw_id_path: int, instance_path: int,
             errors: list[dict[str, str]]) -> dict[str, Any]:
    names = ("hw_id", "num_instance", "major", "minor", "revision", "harvest", "num_base_addresses", "base_addr")
    raw: dict[str, str | None] = {name: _read_text(directory / name, errors) for name in names}
    parsed: dict[str, Any] = {}

    def decimal(name: str, maximum: int = 0xFFFFFFFF) -> int | None:
        return _parse_integer(raw[name], name, errors, directory / name, maximum=maximum)

    for field in ("hw_id", "num_instance", "major", "minor", "revision"):
        parsed[field] = decimal(field, 0xFFFFFFFF)
    parsed["harvest"] = _parse_integer(raw["harvest"], "harvest", errors, directory / "harvest", base=0)

    count = decimal("num_base_addresses", 256)
    addresses: list[int] = []
    bases_raw = raw["base_addr"]
    if bases_raw is not None:
        lines = [line.strip() for line in bases_raw.splitlines() if line.strip()]
        for index, line in enumerate(lines):
            try:
                value = int(line, 0)
                if not 0 <= value <= 0xFFFFFFFF:
                    raise ValueError("outside DWORD range")
                addresses.append(value)
            except ValueError as exc:
                errors.append({"path": str(directory / "base_addr"), "error": f"invalid base address line {index + 1}: {exc}"})
    # Discovery can describe an IP with no MMIO segments (for example HWID
    # 10 in the captured Navi 44 table). Zero is valid metadata, not a failed
    # read; consumers must still refuse register access to absent segments.
    if count is not None and (count < 0 or count > 256):
        errors.append({"path": str(directory / "num_base_addresses"), "error": "must be between 0 and 256"})
    if count is not None and len(addresses) != count:
        errors.append({"path": str(directory / "base_addr"), "error": f"declares {count} addresses but contains {len(addresses)}"})

    if parsed["hw_id"] is not None and parsed["hw_id"] != hw_id_path:
        errors.append({"path": str(directory / "hw_id"), "error": f"value {parsed['hw_id']} does not match numeric path ID {hw_id_path}"})
    if parsed["num_instance"] is not None and parsed["num_instance"] != instance_path:
        errors.append({"path": str(directory / "num_instance"), "error": f"value {parsed['num_instance']} does not match numeric path instance {instance_path}"})

    for field in ("major", "minor", "revision"):
        value = parsed[field]
        if value is not None and value > 255:
            errors.append({"path": str(directory / field), "error": f"{field} must fit in one byte"})
    return {
        "die": die_id,
        "hw_id_path": hw_id_path,
        "instance_path": instance_path,
        "attributes": raw,
        "parsed": parsed,
        "base_addresses": [f"0x{address:08x}" for address in addresses],
        "valid": all(parsed[field] is not None for field in ("hw_id", "num_instance", "major", "minor", "revision", "harvest"))
                 and count is not None and 0 <= count <= 256 and len(addresses) == count
                 and all(parsed[field] <= 255 for field in ("major", "minor", "revision") if parsed[field] is not None)
                 and parsed["hw_id"] == hw_id_path and parsed["num_instance"] == instance_path,
    }


def _numeric_children(path: Path) -> list[tuple[int, Path]]:
    try:
        children = list(path.iterdir())
    except OSError:
        return []
    return sorted(((int(child.name), child) for child in children if NUMERIC_NAME.fullmatch(child.name)), key=lambda item: item[0])


def _collect_ip_discovery(device: Path, errors: list[dict[str, str]], warnings: list[str]) -> dict[str, Any]:
    root = device / "ip_discovery"
    dies: list[dict[str, Any]] = []
    all_ips: list[dict[str, Any]] = []
    for die_id, die_path in _numeric_children(root / "die"):
        ips = []
        for hw_id, hw_path in _numeric_children(die_path):
            for instance, instance_path in _numeric_children(hw_path):
                ip = _read_ip(instance_path, die_id, hw_id, instance, errors)
                ips.append(ip)
                all_ips.append(ip)
        declared_path = die_path / "num_ips"
        declared_raw = _read_text(declared_path, errors)
        declared = _parse_integer(declared_raw, "num_ips", errors, declared_path, maximum=65536) if declared_raw is not None else None
        if declared is None:
            if errors and errors[-1].get("path") == str(declared_path) and errors[-1].get("error") == "not present":
                errors.pop()
            warnings.append(f"Linux did not expose die {die_id} num_ips; count is based on numeric sysfs entries.")
        elif declared != len(ips):
            warnings.append(f"Linux die {die_id} declares {declared} IP blocks but {len(ips)} numeric blocks were enumerated; Linux may omit invalid entries.")
        dies.append({"die": die_id, "declared_num_ips": declared, "enumerated_num_ips": len(ips), "ips": ips})
    return {"enumerated_num_ips": len(all_ips), "dies": dies}


def _read_optional(directory: Path, name: str, errors: list[dict[str, str]]) -> str | None:
    path = directory / name
    value = _read_text(path, errors)
    if value is None and errors and errors[-1].get("path") == str(path) and errors[-1].get("error") == "not present":
        errors.pop()
    return value


def _matching_drm_cards(sys_root: Path, device: Path, errors: list[dict[str, str]]) -> list[Path]:
    drm_root = sys_root / "class/drm"
    try:
        entries = list(drm_root.iterdir())
    except OSError as exc:
        errors.append({"path": str(drm_root), "error": str(exc)})
        return []
    device_real = device.resolve()
    cards: list[Path] = []
    for entry in entries:
        if not re.fullmatch(r"card[0-9]+", entry.name):
            continue
        try:
            if (entry / "device").resolve() == device_real:
                cards.append(entry)
        except OSError:
            continue
    return cards


def _drm_connectors(sys_root: Path, device: Path, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    drm_root = sys_root / "class/drm"
    connectors: list[dict[str, Any]] = []
    try:
        entries = list(drm_root.iterdir())
    except OSError as exc:
        errors.append({"path": str(drm_root), "error": str(exc)})
        return connectors
    target_cards = {card.name for card in _matching_drm_cards(sys_root, device, errors)}
    for entry in entries:
        if not re.fullmatch(r"card[0-9]+-[^/]+", entry.name):
            continue
        card = entry.name.split("-", 1)[0]
        if card not in target_cards:
            continue
        connector: dict[str, Any] = {"name": entry.name}
        for attr in ("status", "enabled", "modes"):
            connector[attr] = _read_optional(entry, attr, errors)
        edid_path = entry / "edid"
        try:
            edid = _bounded_bytes(edid_path, MAX_EDID)
            connector["edid"] = {
                "encoding": "base64",
                "data": base64.b64encode(edid).decode("ascii"),
                "sha256": hashlib.sha256(edid).hexdigest(),
                "bytes": len(edid),
            }
        except FileNotFoundError:
            connector["edid"] = None
        except PermissionError:
            errors.append({"path": str(edid_path), "error": "permission denied; EDID not captured"})
            connector["edid"] = None
        except (OSError, ValueError) as exc:
            errors.append({"path": str(edid_path), "error": str(exc)})
            connector["edid"] = None
        connectors.append(connector)
    return sorted(connectors, key=lambda item: item["name"])


def _cached_discovery_blob(sys_root: Path, device: Path, errors: list[dict[str, str]],
                           warnings: list[str]) -> dict[str, Any] | None:
    """Read the driver's cached blob through the exact DRM card to PCI mapping."""
    note = ("Raw cached IP Discovery blob unavailable; the sysfs report is still usable. "
            "Running the same collector with sudo may permit reading the existing snapshot; "
            "the collector does not mount debugfs.")
    cards = _matching_drm_cards(sys_root, device, errors)
    if not cards:
        warnings.append(note)
        return None
    captures: list[dict[str, Any]] = []
    for card in cards:
        dev_path = card / "dev"
        value = _read_text(dev_path, errors)
        if value is None:
            warnings.append(note)
            continue
        match = re.fullmatch(r"([0-9]+):([0-9]+)", value)
        if not match or int(match.group(1)) != 226:
            errors.append({"path": str(dev_path), "error": "expected DRM device number 226:<minor>"})
            warnings.append(note)
            continue
        minor = int(match.group(2))
        blob_path = sys_root / "kernel/debug/dri" / str(minor) / "amdgpu_discovery"
        try:
            blob = _bounded_bytes(blob_path, MAX_DISCOVERY_BLOB)
            if not blob:
                raise ValueError("cached amdgpu_discovery snapshot is empty")
            captures.append({
                "card": card.name,
                "drm_minor": minor,
                "source_path": str(blob_path),
                "encoding": "base64",
                "data": base64.b64encode(blob).decode("ascii"),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "bytes": len(blob),
                "firmware_info": _read_optional(blob_path.parent, "amdgpu_firmware_info", errors),
            })
        except FileNotFoundError:
            errors.append({"path": str(blob_path), "error": "cached amdgpu_discovery snapshot is not present (debugfs may not be mounted or this kernel may not expose it)"})
            warnings.append(note)
        except PermissionError:
            errors.append({"path": str(blob_path), "error": "permission denied reading cached amdgpu_discovery snapshot"})
            warnings.append(note)
        except (OSError, ValueError) as exc:
            errors.append({"path": str(blob_path), "error": str(exc)})
            warnings.append(note)
    return {"cards": captures} if captures else None


def collect(sys_root: Path = Path("/sys"), bdf: str | None = None) -> dict[str, Any]:
    """Collect a report from an injectable sysfs root, for offline testing."""
    sys_root = Path(sys_root)
    selected_bdf, device = _select_device(sys_root, bdf)
    errors: list[dict[str, str]] = []
    warnings: list[str] = []
    fields: dict[str, Any] = {}
    for name in ("vendor", "device", "revision", "subsystem_vendor", "subsystem_device", "class",
                 "mem_info_vram_total", "mem_info_vis_vram_total", "mem_info_gtt_total", "vbios_version"):
        fields[name] = _read_optional(device, name, errors)

    driver_path = device / "driver"
    try:
        driver = Path(os.readlink(driver_path)).name
    except FileNotFoundError:
        driver = None
    except OSError as exc:
        driver = None
        errors.append({"path": str(driver_path), "error": str(exc)})
    module_version = _read_optional(sys_root / "module/amdgpu", "version", errors)
    ip_discovery = _collect_ip_discovery(device, errors, warnings)
    connectors = _drm_connectors(sys_root, device, errors)
    raw_discovery = _cached_discovery_blob(sys_root, device, errors, warnings) if driver == "amdgpu" else None

    seen_required: dict[int, bool] = {hw_id: False for hw_id in REQUIRED_IPS}
    for ip in (ip for die in ip_discovery["dies"] if die["die"] == 0 for ip in die["ips"] if ip["instance_path"] == 0):
        hw_id = ip["parsed"].get("hw_id")
        if hw_id in seen_required and ip["valid"]:
            seen_required[hw_id] = True
    missing = [name for hw_id, name in REQUIRED_IPS.items() if not seen_required[hw_id]]
    all_blocks_valid = all(ip["valid"] for die in ip_discovery["dies"] for ip in die["ips"])
    complete = driver == "amdgpu" and not missing and all_blocks_valid
    if driver != "amdgpu":
        warnings.append(f"Target is bound to {driver or 'no driver'}; required amdgpu driver is not active.")
    if missing:
        warnings.append("Required valid die 0 instance 0 IP blocks missing: " + ", ".join(missing))
    if not all_blocks_valid:
        warnings.append("One or more enumerated IP blocks has invalid or unreadable attributes; review errors before using the capture.")

    try:
        kernel = platform.release()
        machine = platform.machine()
    except Exception:
        kernel = None
        machine = None
    return {
        "schema_version": 1,
        "captured_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "Linux normalized IP Discovery sysfs plus the driver's cached amdgpu_discovery binary snapshot when available",
        "capture_level": "raw-and-sysfs" if raw_discovery else "sysfs-only",
        "complete": complete,
        "system": {"kernel_release": kernel, "machine": machine},
        "gpu": {
            "bdf": selected_bdf,
            "pci": fields,
            "driver": driver,
            "amdgpu_module_version": module_version,
            "ip_discovery": ip_discovery,
            "cached_ip_discovery_blob": raw_discovery,
            "drm_connectors": connectors,
        },
        "warnings": warnings,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bdf", help="exact target PCI address if more than one RX 9060 XT is installed")
    parser.add_argument("--output", default="gpu-capture.json", help="new JSON report path (will never overwrite; default: gpu-capture.json)")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        print("This collector must run on native Linux; WSL does not expose the physical GPU's sysfs data.", file=sys.stderr)
        return 2
    try:
        report = collect(Path("/sys"), args.bdf)
    except CollectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    output = Path(args.output)
    try:
        # x mode provides atomic exclusive creation and refuses overwrite.
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError:
        print(f"Refusing to overwrite existing report: {output}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Cannot create report {output}: {exc}", file=sys.stderr)
        return 2
    state = "complete" if report["complete"] else "partial"
    count = report["gpu"]["ip_discovery"]["enumerated_num_ips"]
    print(f"Saved {state} RX 9060 XT sysfs capture ({report['gpu']['bdf']}, {count} IP blocks) to {output}")
    if not report["complete"]:
        print("Capture is partial; inspect warnings/errors in the JSON report.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
