#!/usr/bin/env python3
"""Apply the Darwin patch series to pinned Mesa and check its native backend.

The default fetches the exact upstream commit into a temporary checkout. A local
Git repository can supply those same objects with --mesa-git. No GPU is accessed.
On macOS, --build-radv also links the full ACO-based RADV driver and saves a
compile-only artifact; it does not install an ICD or load a kernel extension.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MESA_COMMIT = "f5cb8ee032adabef599ae892ec4e42d796b84da9"
MESA_REMOTE = "https://gitlab.freedesktop.org/mesa/mesa.git"


def run(command, cwd):
    command = [str(part) for part in command]
    print("+", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def check_headers(mesa):
    normalize = lambda path: path.read_bytes().replace(b"\r\n", b"\n")
    for filename in ("gpu_info.h", "gfx_runtime.h"):
        authoritative = ROOT / "src/navi48-bringup/src" / filename
        mirrored = mesa / "include/darwin" / ("cobalt_" + filename)
        if normalize(authoritative) != normalize(mirrored):
            raise RuntimeError(f"Mesa's {filename} differs from the kernel's shared header")


def host_checks(mesa, cc):
    includes = ["-Iinclude", "-Iinclude/darwin", "-Isrc/amd", "-Isrc/amd/common/darwin"]
    common = [cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"]
    tests = mesa / "host-checks"
    tests.mkdir()
    darwin = Path("src/amd/common/darwin")
    cases = [
        ("acd_budget_test", [darwin / "test/acd_budget_test.c"], []),
        ("acd_kext_test", [darwin / "test/acd_kext_test.c", darwin / "ac_darwin_kext.c"], []),
        ("acd_identity_test", [darwin / "test/acd_identity_test.c"], []),
        ("acd_runtime_test", [darwin / "test/acd_runtime_test.c"], []),
        ("acd_iokit_test", [darwin / "test/acd_iokit_test.c", darwin / "ac_darwin_iokit.c",
                            darwin / "ac_darwin_kext.c"],
         ["-Isrc/amd/common/darwin/test/iokit-stubs", "-include",
          darwin / "test/iokit-stubs/acd_test_alloc.h"]),
    ]
    for name, sources, extra in cases:
        output = tests / name
        run([*common, *extra, *includes, *sources, "-o", output], mesa)
        run([output], mesa)
    if sys.platform == "darwin":
        # Compile against Apple's real headers as well as the simulated IOKit.
        run([*common, *includes, "-fsyntax-only", darwin / "ac_darwin_iokit.c"], mesa)


def build_radv(mesa, output):
    if sys.platform != "darwin":
        raise RuntimeError("--build-radv requires macOS")
    build = mesa / "radv-build"
    run(["meson", "setup", build, "--buildtype=release", "--cross-file=cross-x86_64.ini",
         "-Dgallium-drivers=[]", "-Dvulkan-drivers=amd", "-Dplatforms=[]",
         "-Dllvm=disabled", "-Damd-use-llvm=false", "-Dopengl=false",
         "-Dgles1=disabled", "-Dgles2=disabled", "-Degl=disabled", "-Dglx=disabled",
         "-Dgbm=disabled", "-Dvideo-codecs=[]", "-Dzstd=disabled",
         "-Dlibunwind=disabled", "-Dvalgrind=disabled", "-Dbuild-tests=false"], mesa)
    run(["meson", "compile", "-C", build, "-j", "3", "vulkan_radeon"], mesa)
    library = build / "src/amd/vulkan/libvulkan_radeon.dylib"
    if not library.is_file():
        raise RuntimeError("Mesa completed without the expected RADV dylib")
    if output.exists():
        raise RuntimeError(f"Refusing to overwrite existing artifact directory: {output}")
    output.mkdir(parents=True)
    shutil.copy2(library, output / library.name)
    shutil.copytree(mesa / "licenses", output / "licenses")
    shutil.copy2(mesa / "docs/license.rst", output / "MESA-LICENSE.rst")
    patches = ROOT / "mesa-patches"
    shutil.copytree(patches, output / "mesa-patches")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    info = {"source_revision": revision, "mesa_base": MESA_COMMIT,
            "compile_only": True, "navi44_enabled": False,
            "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "patches": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(patches.glob("*.patch"))}}
    (output / "BUILD-INFO.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mesa-git", type=Path, help="local repository containing the pinned Mesa commit")
    parser.add_argument("--apply-only", action="store_true", help="check application and decoder parity without compiling")
    parser.add_argument("--build-radv", action="store_true")
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--output", type=Path, default=ROOT / "build/mesa-radv-compile-check")
    args = parser.parse_args()
    if args.apply_only and args.build_radv:
        parser.error("--apply-only cannot be combined with --build-radv")
    origin = str(args.mesa_git.resolve()) if args.mesa_git else MESA_REMOTE
    with tempfile.TemporaryDirectory(prefix="cobalt-mesa-check-") as directory:
        mesa = Path(directory)
        run(["git", "init", "-q"], mesa)
        run(["git", "config", "core.autocrlf", "false"], mesa)
        run(["git", "remote", "add", "origin", origin], mesa)
        run(["git", "fetch", "--filter=blob:none", "--depth=1", "origin", MESA_COMMIT], mesa)
        run(["git", "checkout", "--detach", MESA_COMMIT], mesa)
        patches = sorted((ROOT / "mesa-patches").glob("*.patch"))
        if len(patches) != 11:
            raise RuntimeError(f"Expected eleven ordered Mesa patches, found {len(patches)}")
        for patch in patches:
            run(["git", "-c", "core.whitespace=cr-at-eol", "apply", "--check", patch], mesa)
            run(["git", "apply", "--whitespace=nowarn", patch], mesa)
        check_headers(mesa)
        if not args.apply_only:
            host_checks(mesa, args.cc)
        if args.build_radv:
            build_radv(mesa, args.output.resolve())
    print("Pinned Mesa patch checks passed.", flush=True)


if __name__ == "__main__":
    main()
