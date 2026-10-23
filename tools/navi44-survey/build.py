#!/usr/bin/env python3
"""Compile and run the actual survey service with minimal fake IOKit APIs.

Windows: run in a VS developer shell and pass --cxx cl.
macOS/Linux: defaults to CXX or clang++/g++/c++.
The fake API instruments provider ownership, fixed-purpose selector and HDP
flush accesses, bounded synthetic staging-window transfers, and the two
allowlisted PSP C2P mailbox writes. It has no general PCI/config-write,
MM_DATA-write, DMA, IRQ, or GPU activation APIs.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "src/navi44-survey"
SHARED = ROOT / "src/navi48-bringup/src"
BUILD = SERVICE / "build/hosttest"


def run(parts):
    command = [str(part) for part in parts]
    print("+", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX"))
    parser.add_argument("--kdb-only", action="store_true", help="run only focused KDB service-host checks")
    parser.add_argument("--spl-only", action="store_true", help="run only focused KDB-to-SPL service-host checks")
    args = parser.parse_args()
    cxx = args.cxx or next((name for name in ("clang++", "g++", "c++", "cl") if shutil.which(name)), None)
    if not cxx:
        parser.error("No host C++17 compiler found; use --cxx in a compiler developer shell.")
    BUILD.mkdir(parents=True, exist_ok=True)
    sources = [
        ("survey_host_service", SERVICE / "hosttest/service_test.cpp"),
        ("survey_host_adapter", SERVICE / "src/CobaltNavi44Survey.cpp"),
        ("survey_host_ipdiscovery", SHARED / "ipdiscovery.cpp"),
        ("survey_host_psp", SHARED / "psp.cpp"),
    ]
    includes = [SERVICE / "hosttest/shim", SERVICE / "src", SHARED]
    executable = BUILD / ("survey-service-test.exe" if os.name == "nt" else "survey-service-test")
    if Path(cxx).stem.lower() in ("cl", "clang-cl"):
        objects = []
        for object_name, source in sources:
            obj = BUILD / (object_name + ".obj")
            run([cxx, "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX", "/Zc:__cplusplus",
                 "/DCOBALT_SURVEY_HOSTTEST=1", *[f"/I{path}" for path in includes], "/c", source, f"/Fo{obj}"])
            objects.append(obj)
        run([cxx, "/nologo", *objects, f"/Fe{executable}"])
    else:
        run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1", "-DCOBALT_SURVEY_HOSTTEST=1",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             *[part for path in includes for part in ("-I", path)], *[source for _, source in sources], "-o", executable])
    focused = "--spl-only" if args.spl_only else "--kdb-only" if args.kdb_only else None
    run([executable, focused] if focused else [executable])
    if args.kdb_only or args.spl_only:
        return

    # Keep the pure aperture planner check independent from the service test:
    # it needs no IOKit shims and is safe to run on ordinary host toolchains.
    plan_source = SERVICE / "hosttest/aperture_plan_test.cpp"
    plan_executable = BUILD / ("aperture-plan-test.exe" if os.name == "nt" else "aperture-plan-test")
    if Path(cxx).stem.lower() in ("cl", "clang-cl"):
        plan_object = BUILD / "aperture_plan_test.obj"
        run([cxx, "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX", "/Zc:__cplusplus",
             f"/I{SERVICE / 'src'}", "/c", plan_source, f"/Fo{plan_object}"])
        run([cxx, "/nologo", plan_object, f"/Fe{plan_executable}"])
    else:
        run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             "-I", SERVICE / "src", plan_source, "-o", plan_executable])
    run([plan_executable])


if __name__ == "__main__":
    main()
