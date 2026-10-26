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
import time

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "src/navi44-survey"
SHARED = ROOT / "src/navi48-bringup/src"
BUILD = SERVICE / "build/hosttest"


def run(parts):
    command = [str(part) for part in parts]
    print("+", subprocess.list2cmdline(command), flush=True)
    started = time.monotonic()
    with subprocess.Popen(command, cwd=ROOT) as process:
        while True:
            try:
                result = process.wait(timeout=30)
                break
            except subprocess.TimeoutExpired:
                # Child output is inherited; phase messages identify actual
                # test progress. This heartbeat only reports process liveness.
                print(f"[host runner] {Path(command[0]).name} still running "
                      f"after {time.monotonic() - started:.0f}s", flush=True)
        if result:
            raise subprocess.CalledProcessError(result, command)
    print(f"[host runner] {Path(command[0]).name} completed in "
          f"{time.monotonic() - started:.1f}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX"))
    parser.add_argument("--kdb-only", action="store_true", help="run only focused KDB service-host checks")
    parser.add_argument("--spl-only", action="store_true", help="run only focused KDB-to-SPL service-host checks")
    parser.add_argument("--presos-only", action="store_true", help="run only focused complete pre-SOS service-host checks")
    parser.add_argument("--sos-only", action="store_true", help="run only focused SOS-startup service-host checks")
    parser.add_argument("--mode1-only", action="store_true", help="run only focused software Mode 1 reset service-host checks")
    parser.add_argument("--early-init-only", action="store_true", help="run only focused early reset and SOS service-host checks")
    args = parser.parse_args()
    if sum((args.kdb_only, args.spl_only, args.presos_only, args.sos_only, args.mode1_only, args.early_init_only)) > 1:
        parser.error("focused service-test selectors are mutually exclusive")
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
            run([cxx, "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX", "/Zc:__cplusplus", "/O1",
                 "/DCOBALT_SURVEY_HOSTTEST=1", *[f"/I{path}" for path in includes], "/c", source, f"/Fo{obj}"])
            objects.append(obj)
        run([cxx, "/nologo", *objects, f"/Fe{executable}"])
    else:
        # Speed optimization matters for the exhaustive instrumented transfers;
        # keep both sanitizers and every service test enabled.
        run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2", "-DCOBALT_SURVEY_HOSTTEST=1",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             *[part for path in includes for part in ("-I", path)], *[source for _, source in sources], "-o", executable])
    focused = "--early-init-only" if args.early_init_only else "--mode1-only" if args.mode1_only else "--sos-only" if args.sos_only else "--presos-only" if args.presos_only else "--spl-only" if args.spl_only else "--kdb-only" if args.kdb_only else None
    run([executable, focused] if focused else [executable])
    if args.kdb_only or args.spl_only or args.presos_only or args.sos_only or args.mode1_only or args.early_init_only:
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

    # Keep the portable reset-protocol contract test in the normal host suite;
    # it remains independent from IOKit shims and never touches hardware.
    mode1_source = SERVICE / "hosttest/mode1_reset_test.cpp"
    mode1_executable = BUILD / ("mode1-reset-test.exe" if os.name == "nt" else "mode1-reset-test")
    if Path(cxx).stem.lower() in ("cl", "clang-cl"):
        mode1_object = BUILD / "mode1_reset_test.obj"
        run([cxx, "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX", "/Zc:__cplusplus",
             f"/I{SERVICE / 'src'}", "/c", mode1_source, f"/Fo{mode1_object}"])
        run([cxx, "/nologo", mode1_object, f"/Fe{mode1_executable}"])
    else:
        run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             "-I", SERVICE / "src", mode1_source, "-o", mode1_executable])
    run([mode1_executable])


if __name__ == "__main__":
    main()
