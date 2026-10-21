# Active GFX layout handoff

`Cobalt,GfxRuntime-v1` is a separate, 96-byte OSData property on the owning
Navi48Bringup service. `gfx_runtime.h` defines its C11/C++ record and decoder.
It carries the cached GC version, GB_ADDR_CONFIG, discovered SE/SA/CU/RB
capacity, active shader-array and render-backend masks, per-SE/SA active CU
bitmaps, and their popcount. It does not add or resize an N48N ABI structure.

The producer clears an old record before an actual bring-up attempt and
publishes only after the GFXInit stage has completed and `GFXConfig.inited`
is true. It copies the existing harvest readouts; publication performs no
additional MMIO. Start, profile rejection, and stop remove the record.
An unavailable, inconsistent, or unpublishable snapshot stays absent.

The decoder checks the record against the existing GPU identity/capacity
property: exact version/size/flags, matching GC and dimensions, nonzero
address configuration, bounded masks, complete WGP pairs, zero unused CU
entries and reserved words, and an active CU count equal to the bitmap
popcount. RBs must belong to active shader arrays in engines with active
CUs. The valid flag describes a consistent layout snapshot, not firmware,
queue, display, or acceleration readiness.

Mesa patch 0011 requires both properties from the same selected owner
before opening a real native connection. It retains both snapshots and
keeps a per-core device description, with live capacity, harvested CU/RB
information, GC IP version, and tiling configuration. Device and MMR queries
use that description. The handshake checks the runtime GC and GB_ADDR_CONFIG
against live QueryInfo; an environment override cannot bypass disagreement.
Explicit MOCK and HOST_BO modes retain their synthetic descriptions.

Mesa patch 0012 adds a gfx1200 reference description for the verified
2-SE, 2-SA, 32-CU capacity. It sets the family revision, 128-bit GDDR6 bus,
16 TCC blocks, 4-MiB L2 and 32-MiB MALL, cache geometry and reported clock
limits from the target's native Linux queries. The runtime overlay supplies
the active masks and tiling configuration. This is a reference for this
device configuration; other gfx1200 capacities are refused.

The reference preserves the platform template's VM ranges, heaps, flags
and link policy. Its CP firmware versions are zero: the captured Linux
ME/PFP/MEC versions (2930/3010/3250) differ from the pinned macOS blobs
(3110/3220/3490). Neither Linux firmware versions nor the old gfx1201
template can describe firmware actually loaded by a future macOS path.
Patch 0013 separately requires the CP firmware property described in
`CP-FIRMWARE.md` and overlays its validated versions for native queries.
gfx1200 remains refused before IOServiceOpen and disabled in the kernel.

The full Mesa CI build runs `acd_gpu_info_test` against Mesa's actual
chip identification, memory-info and hardware-info functions. It checks
both families, cache sizes, unit conversions, a harvested gfx1200 engine,
and preservation of platform memory policy. Standalone tests also check
invalid metadata and templates without enabling a native gfx1200 device.

## Collecting the missing hardware description

The Linux collector has an optional `--drm-info` mode. It opens only the
render node mapped to the selected PCI function, verifies its character
device number, and uses only DRM_IOCTL_AMDGPU_INFO queries. It records the
fixed UAPI request sizes, selectors, raw response buffers and hashes, and
decoded device, IP and firmware metadata. It submits no command buffers,
writes no GPU registers, and changes no drivers or mounts.
One optional READ_MMR query requests only GB_ADDR_CONFIG at absolute dword
offset 0x263e. The pinned Linux soc24 driver allowlists this register and
returns its cached value when available. No arbitrary register offset is
accepted. Unsupported optional queries remain visible in the report.

For the current card, from the collector directory on native Ubuntu:

```sh
sudo python3 collect-linux.py --bdf 0000:09:00.0 --drm-info --output gpu-capture-drm.json
```

Keep `drm_runtime.py` beside `collect-linux.py`. The output must not already
exist. The default sysfs capture retains its existing `complete` meaning;
`gpu.drm_runtime.complete` separately describes the required runtime queries.
Absent optional engines/firmware are recorded without invalidating successful
required queries. Old kernels may leave new trailing UAPI fields zero, so
these buffers do not establish availability of every field.

A private native Ubuntu capture from the target RX 9060 XT completed all
queries. Raw query sizes, SHA-256 digests and decoded fields were checked.
It reports 32 active CUs, RB mask 0xff and GB_ADDR_CONFIG 0x08200545.
All 42 parsed IP records and the GC topology match the earlier capture;
the changed cached-blob bytes are outside its declared discovery binary.
This establishes Linux-reported hardware data, not macOS initialization.

Linux's VM address ranges and heap policy are diagnostic data, not values to
copy into the macOS allocator. macOS memory-pool sizes, budgets and VA limits
continue to come from its own native context and QueryInfo. Actual captures
remain private and must not be committed or uploaded with CI inputs.
