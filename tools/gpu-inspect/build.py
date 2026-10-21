#!/usr/bin/env python3
"""Build and test the offline inspector with a host C++17 compiler.

Windows: run from a Visual Studio developer shell with --cxx cl.
macOS/Linux: uses CXX or the first available clang++/g++/c++.
This builds host programs only, never a kext or deployment artifact.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src/navi48-bringup/src"
TESTS = ROOT / "src/navi48-bringup/tests"
BUILD = ROOT / "build/gpu-inspect"


def run(command):
    print("+", subprocess.list2cmdline([str(part) for part in command]), flush=True)
    subprocess.run([str(part) for part in command], check=True, cwd=ROOT)


def compile_host(cxx, name, sources):
    output = BUILD / (name + (".exe" if os.name == "nt" else ""))
    is_c = all(Path(source).suffix == ".c" for source in sources)
    if Path(cxx).stem.lower() in ("cl", "clang-cl"):
        # Separate object names also allow later incremental builds safely.
        objects = []
        for source in sources:
            obj = BUILD / f"{name}_{Path(source).stem}.obj"
            language = ["/std:c11", "/TC"] if is_c else ["/std:c++17", "/EHsc", "/Zc:__cplusplus"]
            run([cxx, "/nologo", *language, "/W4", "/WX",
                 f"/I{SRC}", "/c", source, f"/Fo{obj}"])
            objects.append(obj)
        run([cxx, "/nologo", *objects, f"/Fe{output}"])
    else:
        language = ["-x", "c", "-std=c11"] if is_c else ["-std=c++17"]
        run([cxx, *language, "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-I", SRC, *sources, "-o", output])
    return output


def inspect_json(executable, arguments, expected_return):
    result = subprocess.run([str(executable), *map(str, arguments)],
                            capture_output=True, text=True, cwd=ROOT)
    if result.returncode != expected_return:
        raise AssertionError(f"Inspector returned {result.returncode}, expected {expected_return}: "
                             f"{result.stdout}\n{result.stderr}")
    return json.loads(result.stdout)


def test_smu_transport(cxx):
    # Compile actual SMU/DAL code against simulated PMFW/kernel shims.
    # The simulation forks an isolated child per scenario and needs POSIX.
    if os.name == "nt":
        print("SMU transport simulation requires POSIX; macOS CI runs it.")
        return
    output = BUILD / "smu-transport-test"
    run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O1",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-pthread",
         "-D__asm__=0;", "-D__volatile__(...)=",
         "-I", TESTS / "dalshim", "-I", SRC, "-I", SRC / "amd",
         TESTS / "native_s2_dal_test.cpp", SRC / "amd/smu_dal.cpp",
         SRC / "amd/smu_v14_0.cpp", "-o", output])
    run([output, ROOT])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "all"), nargs="?", default="all")
    parser.add_argument("--cxx", default=os.environ.get("CXX"))
    args = parser.parse_args()
    cxx = args.cxx or next((candidate for candidate in ("clang++", "g++", "c++", "cl")
                            if shutil.which(candidate)), None)
    if not cxx:
        parser.error("No C++ compiler found. Use a VS developer shell (--cxx cl), or install clang++/g++.")
    BUILD.mkdir(parents=True, exist_ok=True)
    inspector = compile_host(cxx, "gpu-inspect", [ROOT / "tools/gpu-inspect/main.cpp", SRC / "ipdiscovery.cpp"])
    if args.action == "build":
        return
    profile_test = compile_host(cxx, "gpu-profile-test", [TESTS / "gpu_profile_test.cpp"])
    discovery_test = compile_host(cxx, "ipdiscovery-test", [TESTS / "ipdiscovery_test.cpp", SRC / "ipdiscovery.cpp"])
    firmware_test = compile_host(cxx, "fw-profile-test", [TESTS / "fw_profile_test.cpp",
                                                       TESTS / "fw_stub_data.cpp", SRC / "amd/fw_table.cpp"])
    topology_test = compile_host(cxx, "gfx-topology-test", [TESTS / "gfx_topology_test.cpp"])
    smu_test = compile_host(cxx, "smu-protocol-test", [TESTS / "smu_protocol_test.cpp"])
    identity_test = compile_host(cxx, "gpu-info-test", [TESTS / "gpu_info_test.cpp"])
    identity_c_test = compile_host(cxx, "gpu-info-c-test", [TESTS / "gpu_info_c_test.c"])
    runtime_test = compile_host(cxx, "gfx-runtime-test", [TESTS / "gfx_runtime_test.cpp"])
    runtime_c_test = compile_host(cxx, "gfx-runtime-c-test", [TESTS / "gfx_runtime_c_test.c"])
    run([runtime_test])
    run([runtime_c_test])
    run([identity_test])
    run([identity_c_test])
    run([smu_test])
    run([topology_test])
    run([firmware_test])
    run([profile_test])
    run([discovery_test])
    with tempfile.TemporaryDirectory(prefix="fixtures-", dir=BUILD) as temporary:
        fixtures = Path(temporary)
        run([discovery_test, "--write-fixtures", fixtures])
        for filename, pci, enabled in (("navi44.bin", "1002:7590", False),
                                       ("navi48.bin", "1002:7550", True),
                                       ("navi48.bin", "1002:7551", True)):
            result = inspect_json(inspector, [fixtures / filename, "--pci", pci], 0)
            assert result["ok"] and result["profile"]["gc_compatible"]
            assert result["bringup_enabled"] is enabled
            assert result["ip_count"] == len(result["ips"]) == 2
            assert result["gc_topology"]["status"] == "capacity"
            assert result["gc_topology"]["max_compute_units"] == 32
        for filename, pci, status in (("navi44.bin", "1002:7550", 4),
                                      ("navi48.bin", "1002:7590", 4),
                                      ("missing-gc.bin", "1002:7590", 4),
                                      ("navi44.bin", "10de:7590", 3),
                                      ("navi44.bin", "1002:ffff", 3),
                                      ("malformed.bin", "1002:7590", 2),
                                      ("navi44.bin", "1002:7590-extra", 2)):
            result = inspect_json(inspector, [fixtures / filename, "--pci", pci], status)
            assert not result["ok"] and result["error"]
            assert result["bringup_enabled"] is False
        result = inspect_json(inspector, [fixtures / "navi44.bin"], 0)
        assert result["ok"] and result["profile"] is None
        assert result["bringup_enabled"] is False
        # Verify path quoting is preserved in the emitted JSON.
        quoted = fixtures / ('space name.bin' if os.name == "nt" else 'quote"name.bin')
        shutil.copyfile(fixtures / "navi44.bin", quoted)
        assert inspect_json(inspector, [quoted], 0)["source"] == str(quoted)
        oversized = fixtures / "oversized.bin"
        with oversized.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        assert not inspect_json(inspector, [oversized], 2)["ok"]
        assert not inspect_json(inspector, [fixtures / "does-not-exist.bin"], 2)["ok"]
    print("CLI JSON, PCI selection, disabled-target, mismatch, malformed-input and size-limit checks passed.")
    test_smu_transport(cxx)
    print("Host tests passed. These checks do not establish GPU acceleration or hardware compatibility.")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, AssertionError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
