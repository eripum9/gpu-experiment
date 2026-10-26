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
RESET_CLIENT = ROOT / "src/navi44-survey/build/mode1-reset"
CAPTURE_APP = ROOT / "src/navi44-survey/build/CobaltEarlyCapture.app"
CAPTURE_APP_FILES = {
    "Contents/Info.plist", "Contents/MacOS/CobaltEarlyCapture",
    "Contents/_CodeSignature/CodeResources",
}
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
    if RESET_CLIENT.is_symlink():
        raise ValueError("reset client must not be a symlink")
    reset_client = RESET_CLIENT.read_bytes()
    if len(reset_client) < 32 or struct.unpack_from("<IIII", reset_client)[:2] != (0xFEEDFACF, 0x01000007):
        raise ValueError("reset client must be an x86_64 Mach-O executable")
    if struct.unpack_from("<I", reset_client, 12)[0] != 2:
        raise ValueError("reset client must be an x86_64 Mach-O executable")
    files["mode1-reset"] = reset_client
    app_info = plistlib.loads((CAPTURE_APP / "Contents/Info.plist").read_bytes())
    if (app_info.get("CFBundleIdentifier") != "com.cobalt.early-capture"
            or app_info.get("CFBundleExecutable") != "CobaltEarlyCapture"
            or app_info.get("CFBundlePackageType") != "APPL"
            or app_info.get("CFBundleVersion") != "1.0.0"):
        raise ValueError("unexpected capture app identity")
    app_binary = (CAPTURE_APP / "Contents/MacOS/CobaltEarlyCapture").read_bytes()
    if (len(app_binary) < 32
            or struct.unpack_from("<IIII", app_binary)[:2] != (0xFEEDFACF, 0x01000007)
            or struct.unpack_from("<I", app_binary, 12)[0] != 2):
        raise ValueError("capture app must be an x86_64 Mach-O executable")
    app_files = {}
    for path in sorted(CAPTURE_APP.rglob("*")):
        if path.is_symlink():
            raise ValueError("capture app contains a symlink")
        if path.is_file():
            name = path.relative_to(CAPTURE_APP).as_posix()
            if name not in CAPTURE_APP_FILES:
                raise ValueError(f"unexpected capture app file: {name}")
            app_files["CobaltEarlyCapture.app/" + name] = path.read_bytes()
    if len(app_files) != len(CAPTURE_APP_FILES):
        raise ValueError("capture app is missing a required signed bundle file")
    files.update(app_files)
    extras = {
        "collect-gpu-survey.sh": ROOT / "tools/navi44-survey/collect-survey.sh",
        "test-software-reset.sh": ROOT / "tools/navi44-survey/test-software-reset.sh",
        "install-early-reset-test.sh": ROOT / "tools/navi44-survey/install-early-reset-test.sh",
        "capture-early-reset.sh": ROOT / "tools/navi44-survey/capture-early-reset.sh",
        "SURVEY-TEST.md": ROOT / "docs/NAVI44-SURVEY.md",
        "MODE1-RESET.md": ROOT / "docs/MODE1-RESET.md",
        "EARLY-MODE1-RESET.md": ROOT / "docs/EARLY-MODE1-RESET.md",
        "EARLY-RESET-SOS.md": ROOT / "docs/EARLY-RESET-SOS.md",
        "licenses/LICENSE": ROOT / "src/navi48-bringup/LICENSE",
        "licenses/NOTICE": ROOT / "src/navi48-bringup/NOTICE",
        "licenses/LICENSE.amdgpu": ROOT / "src/navi48-bringup/firmware/LICENSE.amdgpu",
        "licenses/THIRD-PARTY-LICENSES.txt": ROOT / "third-party/THIRD-PARTY-LICENSES.txt",
    }
    for name, path in extras.items():
        files[name] = path.read_bytes()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    files["BUILD-INFO.txt"] = (
        "CobaltNavi44Survey hardware-test candidate\n"
        f"Source revision: {revision}\n"
        "Architecture: x86_64\n"
        "Scope: default read-only PCI/direct-memory survey; separately gated indexed VRAM reads permit address-selector writes; optional passive PSP/MMHUB state and console observations; separately gated 16-byte aperture or full 1 MiB synthetic staging experiment permits bounded VRAM and HDP flush writes through an existing isolated or discovery-derived native NBIF route, with saved-original restoration checks\n"
        "Hardware validation: not yet loaded on the target GPU\n"
        "Acceleration: unavailable; Navi 44 bring-up remains disabled\n"
        "Optional cobalt-survey-initboot=1: exclusive early compound Mode1 reset, fresh discovery and guarded eight-image PSP/SOS checkpoint in one provider session; requires only survey/indexed/state and every other experiment off; native capture plan TestKind=reset-sos; preserves firmware buffers after mailbox ownership; Ready and ColdCycleReplacementValidated remain false\n"
        "Optional cobalt-survey-kdb=1: one PSP KDB command using embedded pinned PSP 14.0.2 firmware; requires all five prior survey flags; no remaining firmware chain or SOS startup\n"
        "Optional cobalt-survey-spl=1: prepare two separate 1 MiB windows, then issue only KDB and SPL; requires all six prior survey flags; preserves both windows after any mailbox attempt; no SYS or SOS startup\n"
        "Optional cobalt-survey-presos=1: prepare all seven separate 1 MiB windows before the complete pinned pre-SOS batch; requires all seven prior survey flags; preserves every window after any mailbox attempt; no SOS startup\n"
        "Optional cobalt-survey-sos=1: prepare all eight separate 1 MiB windows before the seven pre-SOS commands and final SOS command; requires all eight prior survey flags; no writes after SOS command; observes a fresh readable nonzero SOS transition only; no queues, display programming or acceleration\n"
        "Optional cobalt-survey-mode1=1: arms a manually triggered administrator-only SMU debug Mode 1 reset test; requires survey/indexed/state flags and all firmware/staging experiments off; never resets at boot; test helper captures before/after and attempts a normal reboot; hardware recovery and cold-cycle equivalence remain unvalidated\n"
        "Optional cobalt-survey-mode1boot=1: separately selected early-boot Mode 1 reset attempt inside service start, before publication; requires survey/indexed/state and manual/firmware modes off; strict live ownership checks and OS console pause remain required; install the one-time capture agent from a passive bootstrap first; a hang before userland can prevent automatic capture/disarming\n"
        "Capture helper: signed CobaltEarlyCapture.app 1.0.0 provides a dedicated background identity; macOS Full Disk Access must be granted explicitly to this app and a same-launchd-context USB read/write probe must pass before arming; unavailable USB access saves local evidence without an automatic reboot\n"
        "Contains embedded AMD firmware under licenses/LICENSE.amdgpu; no Navi48Bringup executable\n"
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
            item.mode = 0o755 if name.endswith(("/CobaltNavi44Survey", "/CobaltEarlyCapture")) or name == "mode1-reset" or name.endswith(".sh") else 0o644
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
