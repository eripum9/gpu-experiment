# Navi 44 work in progress

Baseline: Almosst-DEV/Cobalt64 `d1f7bad8408a0a2c016b067c477422975a59de44`.
This branch starts an RX 9060 XT (`1002:7590`, Navi 44 / gfx1200) investigation.
It does not implement an accelerated Navi 44 driver.

## Implemented

- Shared, freestanding GPU profiles distinguish Navi 48 / gfx1201 from
  Navi 44 / gfx1200. Navi 44 is recognized but driver bring-up remains disabled.
- Both probe and start reject disabled or unknown devices before hardware
  initialization. Existing IOKit PCI matching is unchanged.
- Startup requires the discovered GC, PSP, SMU, SDMA, and DCN IP versions to
  match the enabled profile before the PSP/SMU/interrupt stages, and cleans
  up failed discovery state.
- The offline inspector reuses the kernel's IP Discovery parser to report
  IP versions, instances, register bases, and GC/profile agreement as JSON.
  The supported input format is binary v1.3, IPDS v3, single die 0, with
  32-bit bases. Other formats are explicitly rejected.
- The parser validates container bounds, both checksums, complete IP records,
  and register-offset arithmetic. Fixture tests run without a GPU or macOS.
- Optional GC_INFO v1.0 through v1.3 parsing reports maximum SE/SA/WGP/CU
  capacity after validating its bounds and checksum. It does not report
  harvested or active CU counts.
- The runtime GFX setup uses this discovered capacity instead of fixed
  Navi 48 geometry. It requires a supported GC_INFO table before PSP/SMU
  initialization and checks that SE/SA dimensions and CU/RB masks fit the
  current implementation. Missing or incompatible topology has no fallback.
  GFX initialization propagates failure before register access; active units
  still come from the existing hardware harvest decoding.
- Firmware lookup uses an explicit per-device family with separate embedded
  sets. Unknown families and missing slots return no firmware. Host tests
  exercise the actual lookup implementation with synthetic blob symbols.
- SMU dispatch validates family and discovered MP1 version. The verified
  shared 14.0.2/14.0.3 message map permits only three diagnostic messages
  for the disabled Navi 44 candidate; Navi 48 power policies and DAL
  experiments are excluded from that candidate. See [SMU14.md](SMU14.md).

The inspector opens an existing file only. It never reads hardware, enables
the driver, or extracts a ROM. A conventional expansion VBIOS dump may not
contain IP Discovery; a full flash/discovery capture is required.

## Host build and inspection

With Python 3 and a C++17 compiler:

```
python3 tools/gpu-inspect/build.py all
build/gpu-inspect/gpu-inspect /path/to/full-rom.bin --pci 1002:7590
```

On Windows, use a Visual Studio developer shell and
`python tools/gpu-inspect/build.py all --cxx cl`; the executable has `.exe`.
An optional OS-metadata inventory can be collected with:

```
powershell -File tools/gpu-inspect/collect-windows.ps1 -OutputPath hardware.json
```

Keep hardware reports and real ROMs out of the public repository. Test
fixtures are synthetic. A private native-Linux capture from the target card
also passed the binary/IPDS checksums, all 42 IP records, and GC_INFO parsing;
all record versions and bases agreed with the same capture's Linux sysfs.

Inspector exit codes: 0 = parsed and requested GC agrees (if specified),
2 = invalid arguments/file/format, 3 = unknown PCI ID, 4 = missing or mismatched
GC for a known PCI profile. `bringup_enabled` is policy metadata; the inspector
itself never performs bring-up. Navi 44 remains false even for a matching GC.

## Remaining implementation work

For a native Ubuntu capture from the target desktop, see [CAPTURE.md](CAPTURE.md).

1. Validate the GFX initialization and its harvest decoding on hardware.
   The captured GC_INFO v1.3 advertises
   2 SE, 2 arrays per SE, 4 WGP per array, and maximum capacity of 32 CUs.
   Capacity now flows into runtime configuration; this does not establish
   that all GFX registers and harvest semantics work on Navi 44.
2. Implement and verify the Navi 44 power policy and memory initialization.
   Linux shares the PPSMC message/clock map between 14.0.2 and 14.0.3, but
   that does not validate the existing feature sequencing, table handling,
   calibration, or clock policy on the target card.
3. Verify PSP/SDMA/GFX initialization against the captured versions and
   stage hardware testing before claiming support.
4. Validate display routing and output programming. The captured DCN 4.1.0
   segment bases match the current driver, but this does not prove that its
   board-specific mode/monitor captures and output routing are suitable.
5. Replace the RADV Darwin backend's canned gfx1201 device/PCI identity and
   carry verified target information through the Metal bundle.
6. Build and test on macOS, then perform staged hardware validation on the
   target desktop before enabling Navi 44 acceleration.

## Reference evidence

The target capture identifies GC 12.0.0, PSP/SMU 14.0.2, SDMA 7.0.0, and
DCN 4.1.0. The matching candidate firmware set is `gc_12_0_0_*`,
`psp_14_0_2_{sos,ta}`, `smu_14_0_2`, and `sdma_7_0_0`; UNI_MES is the
choice used by the existing Cobalt load ladder. Firmware inputs are pinned
by size and SHA-256 in the CI dependency fetcher. Embedding them does not
enable Navi 44 or implement its hardware-specific protocols.

Linux v6.19 dispatches both GC 12.0.0 and 12.0.1 to the GFX12 implementation,
but selects PSP/SMU/SDMA handlers using discovered versions. See
[amdgpu_discovery.c](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c),
[gfx_v12_0.c](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/gfx_v12_0.c),
[firmware naming](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_ucode.c),
and [the discovery format](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/include/discovery.h).
These references establish code reuse opportunities; the target versions
above come from the private capture. Register/protocol compatibility still
requires implementation and hardware validation.

For hosted build setup and the compile-only artifacts, see [CI.md](CI.md).
