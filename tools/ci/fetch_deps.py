#!/usr/bin/env python3
"""Fetch the small, pinned input set required by the macOS compile check.

This downloads only the MacKernelSDK headers/libraries used by the Makefile and
the ten AMD firmware blobs it embeds. It does not clone linux-firmware or run
third-party build scripts.
"""
from __future__ import annotations

import base64
import hashlib
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SDK_COMMIT = "05094e5e88cec7caedbfb35e8449ed0db94bf95b"
SDK_ARCHIVE_URL = (
    "https://codeload.github.com/acidanthera/MacKernelSDK/tar.gz/"
    + SDK_COMMIT
)
SDK_ARCHIVE_SHA256 = "c208d230b62c9c4a88d101b09da2523da47dc387b73c17dd1dcd50057e7cc101"
LINUX_FIRMWARE_COMMIT = "9a80a04181713da7f8187ec928c15160137f3262"
GITLAB_RAW = (
    "https://gitlab.com/kernel-firmware/linux-firmware/-/raw/"
    + LINUX_FIRMWARE_COMMIT
    + "/"
)
GOOGLESOURCE_RAW = (
    "https://kernel.googlesource.com/pub/scm/linux/kernel/git/firmware/"
    "linux-firmware/+/%s/" % LINUX_FIRMWARE_COMMIT
)

# SHA-256 values are for the exact files at LINUX_FIRMWARE_COMMIT. The
# Googlesource mirror returns base64 with ?format=TEXT, so it is decoded before
# checking against these same hashes.
FIRMWARE = {
    "gc_12_0_1_imu.bin": (132352, "b3b301fb636efc77b63ce4d2ced0f90c851d03c19681852faa45598e6f5773fd"),
    "gc_12_0_1_me.bin": (267600, "fd5eb0f205a3bb7ec41f42e83a54bdc69151706b02bbee073fa775b8270e4bec"),
    "gc_12_0_1_mec.bin": (259584, "83fe5e7bffe639ec9771219cde5c9809689168f769b147c86dfd5a1ca991c1a2"),
    "gc_12_0_1_pfp.bin": (159616, "490bcd26a62e389b3f58acf5c087d324d2324b3188797ff6a36b7a6cdf1ca9ff"),
    "gc_12_0_1_rlc.bin": (150848, "6ba4459532246a5c415d3cb33c9b1248294e48f67b827e2accb292a8d1a5c0ec"),
    "gc_12_0_1_uni_mes.bin": (299408, "309d60ad4a0210f8a68e27cae88beddb22b5ae900d70848b1e8ca0eac9d1decd"),
    "psp_14_0_3_sos.bin": (435632, "28469a0857c813c54a0492423cdf0b0caf757428400036377e19c47e5af62478"),
    "psp_14_0_3_ta.bin": (291372, "fff8b0b56f21bf1d34c8d1fcf6cc903c2dbb5ef88eb06157c9f08baf95124883"),
    "sdma_7_0_1.bin": (47104, "73c29e1c1714ebc95d2221ba56e187910902891593010653bf9518937e414a59"),
    "smu_14_0_3.bin": (333236, "7624724231b0986b59f59705e7c854c482193f6b3b591ebdda58cb62af81c010"),
}
LICENSE = (
    "LICENSES/LICENSE.amdgpu",
    2938,
    "572872598565dc3513470de971a32bf9db301f47afeef3636345eadae33b2eee",
)

MAX_SDK_ARCHIVE = 100 * 1024 * 1024
MAX_SDK_EXPANDED = 80 * 1024 * 1024


def fetch(url: str, max_bytes: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Cobalt64-CI/1"})
    with urllib.request.urlopen(request, timeout=90) as response:
        chunks = []
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(f"download exceeded {max_bytes} byte limit: {url}")
            chunks.append(chunk)
    return b"".join(chunks)


def checked_bytes(label: str, data: bytes, size: int, digest: str) -> bytes:
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != size or actual != digest:
        raise RuntimeError(
            f"{label} did not match the pinned input: "
            f"got {len(data)} bytes sha256={actual}; expected {size} bytes sha256={digest}"
        )
    return data


def fetch_firmware(path: str, size: int, digest: str) -> bytes:
    errors = []
    for name, url, decode in (
        ("GitLab", GITLAB_RAW + path, False),
        ("kernel.org mirror", GOOGLESOURCE_RAW + path + "?format=TEXT", True),
    ):
        try:
            data = fetch(url, size * 2 + 1024)
            if decode:
                data = base64.b64decode(data, validate=True)
            return checked_bytes(path, data, size, digest)
        except (OSError, urllib.error.URLError, ValueError, RuntimeError) as error:
            errors.append(f"{name}: {error}")
    raise RuntimeError(f"could not fetch pinned {path}: " + " | ".join(errors))


def safe_sdk_extract(archive_bytes: bytes, destination: Path) -> None:
    """Extract only Headers/, Library/x86_64/, and the SDK license safely."""
    # Verify the final absolute replacement target before recursive removal,
    # including on Windows; reject redirected parent directories as well.
    expected = ROOT.resolve() / "build" / "ci-deps" / "MacKernelSDK"
    if destination.resolve() != expected:
        raise RuntimeError(f"SDK target must stay at the repository build directory: {destination}")
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise RuntimeError(f"refusing to replace non-directory SDK target: {destination}")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    expanded = 0
    with tarfile.open(fileobj=BytesIO(archive_bytes), mode="r:gz") as archive:
        members = archive.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            raise RuntimeError("SDK archive has an unexpected root layout")
        root = next(iter(roots))
        if root in (".", ".."):
            raise RuntimeError("SDK archive root is unsafe")

        selected = []
        for member in members:
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or "\\" in member.name:
                raise RuntimeError(f"unsafe SDK archive path: {member.name}")
            if any(part in (".", "..") for part in member_path.parts):
                raise RuntimeError(f"unsafe SDK archive path: {member.name}")
            relative = PurePosixPath(member.name).relative_to(root)
            if not relative.parts:
                continue
            if relative.is_absolute() or any(part in (".", "..") for part in relative.parts):
                raise RuntimeError(f"unsafe SDK archive path: {member.name}")
            path = relative.as_posix()
            allowed = (
                path == "LICENSE.txt"
                or path == "Headers"
                or path.startswith("Headers/")
                or path == "Library"
                or path == "Library/x86_64"
                or path.startswith("Library/x86_64/")
            )
            if not allowed:
                continue
            if not (member.isdir() or member.isfile()):
                raise RuntimeError(f"unsupported SDK archive entry: {member.name}")
            if member.isfile():
                expanded += member.size
                if expanded > MAX_SDK_EXPANDED:
                    raise RuntimeError("selected SDK files exceed the 80 MiB extraction limit")
            selected.append((member, relative))

        for member, relative in selected:
            target = destination.joinpath(*relative.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise RuntimeError(f"SDK archive path escaped destination: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"could not read SDK archive entry: {member.name}")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)

    if not (destination / "Headers").is_dir() or not (destination / "Library/x86_64").is_dir():
        raise RuntimeError("SDK archive did not contain the headers and x86_64 libraries")
    license_path = destination / "LICENSE.txt"
    if not license_path.is_file():
        raise RuntimeError("SDK archive did not contain LICENSE.txt")


def write_verified(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temp_path = Path(handle.name)
        handle.write(data)
    os.replace(temp_path, path)


def main() -> None:
    sdk_dir = ROOT / "build" / "ci-deps" / "MacKernelSDK"
    firmware_dir = ROOT / "src" / "navi48-bringup" / "firmware"
    print(f"Fetching MacKernelSDK at {SDK_COMMIT}", flush=True)
    sdk_archive = checked_bytes(
        "MacKernelSDK archive",
        fetch(SDK_ARCHIVE_URL, MAX_SDK_ARCHIVE),
        2679223,
        SDK_ARCHIVE_SHA256,
    )
    safe_sdk_extract(sdk_archive, sdk_dir)
    print(f"Extracted only MacKernelSDK Headers, x86_64 libraries, and LICENSE.txt to {sdk_dir}")

    firmware_dir.mkdir(parents=True, exist_ok=True)
    for filename, (size, digest) in FIRMWARE.items():
        path = firmware_dir / filename
        write_verified(path, fetch_firmware("amdgpu/" + filename, size, digest))
        print(f"Verified {filename}: {size} bytes sha256={digest}", flush=True)

    license_name, license_size, license_digest = LICENSE
    license_data = fetch_firmware(license_name, license_size, license_digest)
    write_verified(firmware_dir / "LICENSE.amdgpu", license_data)
    print(f"Verified LICENSE.amdgpu: {license_size} bytes sha256={license_digest}")
    print("Pinned compile dependencies are ready. No firmware or SDK files were added to Git tracking.")


if __name__ == "__main__":
    main()
