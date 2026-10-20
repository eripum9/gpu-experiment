#!/usr/bin/env python3
"""Package the compile-only kext with provenance and applicable notices."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
KEXT = ROOT / "src" / "navi48-bringup" / "build" / "Navi48Bringup.kext"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not KEXT.is_dir():
        parser.error(f"compiled kext not found: {KEXT}")
    binary = KEXT / "Contents" / "MacOS" / "Navi48Bringup"
    if not binary.is_file():
        parser.error(f"compiled kext executable not found: {binary}")

    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    source = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
        check=True, text=True, capture_output=True,
    ).stdout.strip()
    metadata = (
        "Cobalt64 Navi48Bringup compile check\n"
        f"Source revision: {revision}\n"
        f"Source short revision: {source}\n"
        "Target architecture: x86_64\n"
        "Validation: compiled and ad-hoc signed by the Makefile; not loaded or installed\n"
        "Hardware status: RX 9060 XT / Navi 44 support remains disabled and unvalidated\n"
    ).encode("utf-8")
    notices = [ROOT / "src" / "navi48-bringup" / "LICENSE", ROOT / "src" / "navi48-bringup" / "NOTICE"]
    firmware_license = ROOT / "src" / "navi48-bringup" / "firmware" / "LICENSE.amdgpu"
    if not firmware_license.is_file():
        parser.error("AMD firmware redistribution license is missing")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as handle:
        temp_path = Path(handle.name)
    try:
        with tarfile.open(temp_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            archive.add(KEXT, arcname="Navi48Bringup.kext", recursive=True)
            for notice in notices:
                if notice.is_file():
                    archive.add(notice, arcname="licenses/" + notice.name)
            archive.add(firmware_license, arcname="licenses/LICENSE.amdgpu")
            info = tarfile.TarInfo("BUILD-INFO.txt")
            info.size = len(metadata)
            info.mode = 0o644
            import io
            archive.addfile(info, io.BytesIO(metadata))
        os.replace(temp_path, args.output)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    print(f"Packaged compile-only artifact: {args.output}")


if __name__ == "__main__":
    main()
