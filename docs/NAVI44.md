# Navi 44 work in progress

Baseline: Almosst-DEV/Cobalt64 `d1f7bad8408a0a2c016b067c477422975a59de44`.
This branch starts an RX 9060 XT (`1002:7590`, Navi 44 / gfx1200) investigation.
It does not implement an accelerated Navi 44 driver.

## Implemented

- Shared, freestanding GPU profiles distinguish Navi 48 / gfx1201 from
  Navi 44 / gfx1200. Navi 44 is recognized but driver bring-up remains disabled.
- Both probe and start reject disabled or unknown devices before hardware
  initialization. Existing IOKit PCI matching is unchanged.
- Startup requires the discovered GC IP to match the enabled profile before
  the PSP/SMU/interrupt stages, and cleans up failed discovery state.
- The offline inspector reuses the kernel's IP Discovery parser to report
  IP versions, instances, register bases, and GC/profile agreement as JSON.
  The supported input format is binary v1.3, IPDS v3, single die 0, with
  32-bit bases. Other formats are explicitly rejected.
- The parser validates container bounds, both checksums, complete IP records,
  and register-offset arithmetic. Fixture tests run without a GPU or macOS.

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
fixtures are synthetic; a successful fixture run does not establish that
the stricter parser accepts any particular physical card's data.

Inspector exit codes: 0 = parsed and requested GC agrees (if specified),
2 = invalid arguments/file/format, 3 = unknown PCI ID, 4 = missing or mismatched
GC for a known PCI profile. `bringup_enabled` is policy metadata; the inspector
itself never performs bring-up. Navi 44 remains false even for a matching GC.

## Remaining implementation work

For a native Ubuntu capture from the target desktop, see [CAPTURE.md](CAPTURE.md).

1. Obtain this card's actual discovery data, firmware requirements, harvested
   SE/SH/CU topology, and display routing. Extend the parser if the real
   capture uses a different documented format.
2. Select firmware by verified per-block IP versions. The existing embedded
   GFX firmware is `gc_12_0_1_*`; the candidate requires the gfx1200 path.
   The exact PSP/SMU/SDMA versions must not be guessed from the PCI ID.
3. Adapt GFX initialization, memory and power management to verified data.
4. Replace Navi48-specific DCN bases, mode/monitor captures, and output routing.
5. Replace the RADV Darwin backend's canned gfx1201 device/PCI identity and
   carry verified target information through the Metal bundle.
6. Build and test on macOS, then perform staged hardware validation on the
   target desktop before enabling Navi 44 acceleration.

## Reference evidence

Linux v6.19 dispatches both GC 12.0.0 and 12.0.1 to the GFX12 implementation,
but selects PSP/SMU/SDMA handlers using discovered versions. See
[amdgpu_discovery.c](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c),
[gfx_v12_0.c](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/gfx_v12_0.c),
[firmware naming](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_ucode.c),
and [the discovery format](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/include/discovery.h).
These references establish code reuse opportunities, not exact versions
or register compatibility for an uninspected card.

For hosted build setup and the compile-only artifacts, see [CI.md](CI.md).
