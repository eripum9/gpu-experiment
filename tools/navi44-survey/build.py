#!/usr/bin/env python3
"""Compile and run the actual survey service with minimal fake IOKit APIs.

Windows: run in a VS developer shell and pass --cxx cl.
macOS/Linux: defaults to CXX or clang++/g++/c++.
The fake API instruments selector writes and provider ownership. It deliberately
has no PCI/config writes, MM_DATA writes, DMA, IRQ, or GPU activation APIs.
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
    args = parser.parse_args()
    cxx = args.cxx or next((name for name in ("clang++", "g++", "c++", "cl") if shutil.which(name)), None)
    if not cxx:
        parser.error("No host C++17 compiler found; use --cxx in a compiler developer shell.")
    BUILD.mkdir(parents=True, exist_ok=True)
    sources = [SERVICE / "hosttest/service_test.cpp", SERVICE / "src/CobaltNavi44Survey.cpp", SHARED / "ipdiscovery.cpp"]
    includes = [SERVICE / "hosttest/shim", SERVICE / "src", SHARED]
    executable = BUILD / ("survey-service-test.exe" if os.name == "nt" else "survey-service-test")
    if Path(cxx).stem.lower() in ("cl", "clang-cl"):
        objects = []
        for source in sources:
            obj = BUILD / (source.stem + ".obj")
            run([cxx, "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX", "/Zc:__cplusplus",
                 "/DCOBALT_SURVEY_HOSTTEST=1", *[f"/I{path}" for path in includes], "/c", source, f"/Fo{obj}"])
            objects.append(obj)
        run([cxx, "/nologo", *objects, f"/Fe{executable}"])
    else:
        run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1", "-DCOBALT_SURVEY_HOSTTEST=1",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             *[part for path in includes for part in ("-I", path)], *sources, "-o", executable])
    run([executable])


if __name__ == "__main__":
    main()
