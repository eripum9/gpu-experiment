#!/usr/bin/env python3
"""Package the standalone Navi 44 survey, without the bring-up driver."""
from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path
import plistlib
import struct
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
KEXT = ROOT / "src/navi44-survey/build/CobaltNavi44Survey.kext"
BUNDLE_FILES = {
    "Contents/Info.plist", "Contents/MacOS/CobaltNavi44Survey",
    "Contents/_CodeSignature/CodeResources",
}


def payload() -> dict[str, bytes]:
    info = plistlib.loads((KEXT / "Contents/Info.plist").read_bytes())
    if (info.get("CFBundleIdentifier") != "com.cobalt.navi44-survey"
            or info.get("CFBundleExecutable") != "CobaltNavi44Survey"):
        raise ValueError("unexpected survey bundle identity")
    personalities = info.get("IOKitPersonalities", {})
    if len(personalities) != 1:
        raise ValueError("survey must contain exactly one personality")
    personality = next(iter(personalities.values()))
    if (personality.get("IOClass") != "CobaltNavi44Survey"
            or personality.get("IOProviderClass") != "IOPCIDevice"
            or personality.get("IOPCIPrimaryMatch") != "0x75901002"
            or personality.get("IOMatchCategory") != "CobaltNavi44Survey"):
        raise ValueError("survey personality must match only the isolated Navi 44 service")
    binary = (KEXT / "Contents/MacOS/CobaltNavi44Survey").read_bytes()
    if len(binary) < 32:
        raise ValueError("survey executable is truncated")
    magic, cpu, _, kind = struct.unpack_from("<IIII", binary)
    if (magic, cpu, kind) != (0xFEEDFACF, 0x01000007, 11):
        raise ValueError("survey executable must be an x86_64 Mach-O kext bundle")
    files = {}
    for path in sorted(KEXT.rglob("*")):
        if path.is_symlink():
            raise ValueError("survey bundle contains a symlink")
        if path.is_file():
            relative = path.relative_to(KEXT).as_posix()
            if relative not in BUNDLE_FILES:
                raise ValueError(f"unexpected survey bundle file: {relative}")
            files["CobaltNavi44Survey.kext/" + relative] = path.read_bytes()
    if len(files) != len(BUNDLE_FILES):
        raise ValueError("survey bundle is missing an executable, plist, or signature resource")
    extras = {
        "collect-gpu-survey.sh": ROOT / "tools/navi44-survey/collect-survey.sh",
        "SURVEY-TEST.md": ROOT / "docs/NAVI44-SURVEY.md",
        "licenses/LICENSE": ROOT / "src/navi48-bringup/LICENSE",
        "licenses/NOTICE": ROOT / "src/navi48-bringup/NOTICE",
    }
    for name, path in extras.items():
        files[name] = path.read_bytes()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    files["BUILD-INFO.txt"] = (
        "CobaltNavi44Survey hardware-test candidate\n"
        f"Source revision: {revision}\n"
        "Architecture: x86_64\n"
        "Scope: default read-only PCI/direct-memory survey; separately gated indexed VRAM reads permit address-selector writes; optional passive PSP/MMHUB state and console observations; separately gated 16-byte VRAM roundtrip permits bounded VRAM and HDP flush writes\n"
        "Hardware validation: not yet loaded on the target GPU\n"
        "Acceleration: unavailable; Navi 44 bring-up remains disabled\n"
        "Contains no GPU firmware or Navi48Bringup executable\n"
    ).encode("utf-8")
    files["SHA256SUMS.txt"] = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items())
    ).encode("utf-8")
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    files = payload()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o755 if name.endswith("/CobaltNavi44Survey") else 0o644
            archive.addfile(item, io.BytesIO(data))
    with tarfile.open(args.output, "r:gz") as archive:
        if archive.getnames() != sorted(files):
            raise ValueError("survey archive contents differ from the intended payload")
        for name, data in files.items():
            stream = archive.extractfile(name)
            if stream is None or stream.read() != data:
                raise ValueError(f"survey archive verification failed: {name}")
    print(f"Verified {len(files)} survey payload files: {args.output}")


if __name__ == "__main__":
    main()
