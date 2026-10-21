# GPU identity and capacity record

The driver publishes a 128-byte `OSData` property named `Cobalt,GpuInfo-v1`
on its own IOService after validating the PCI profile, critical IP versions,
and GC_INFO topology. It removes an old record at the start of every start
attempt, on profile rejection, and on stop. Allocation/publication failure
leaves the record absent; it does not substitute canned data.

The existing N48N user-client ABI, selectors, and structure sizes are
unchanged. Navi 44 remains disabled in probe/start and excluded from IOKit
matching, so this change does not attach the driver to a candidate card.

## Format and meaning

`src/navi48-bringup/src/gpu_info.h` defines the C11/C++ wire structure and
decoder. The record uses little-endian 32-bit fields, natural alignment,
version 1, and exact size 128. It carries actual PCI vendor/device/revision
and subsystem IDs read from PCI configuration space, the selected gfx1200
or gfx1201 target, the discovered GC version, and validated SE/SA/WGP/CU/RB
capacity. A device ID of 7551 is preserved rather than changed to 7550.

`CAPACITY_VALID` means the capacity passed format and implementation bounds
checks. `BRINGUP_ENABLED` describes the source profile's policy; it does not
mean initialization completed or that acceleration works. The v1 reader
rejects a record that claims enabled Navi 44 support. Both flags describe
metadata, not permission to attach a driver or program hardware.

Maximum CU capacity is not an active or harvested CU count. The record has
no active-unit masks, VRAM size, usable memory-pool sizes, clocks, output
routing, or readiness status. Those must come from their actual runtime
sources. A failed PCI configuration read may retain the standard all-ones
value in a revision/subsystem field; no board identity is guessed.

## Consumer requirements

Read the property from the selected driver service and call
`cobalt_gpu_info_v1_decode(bytes, length, &info)` before interpreting it.
The decoder accepts unaligned input and overlapping input/output, checks
exact size/version, IDs and matching GC/target, flags, reserved fields,
dimension/mask bounds, and derived capacity arithmetic. It clears output
on failure. Unknown or malformed records have no fallback through this
decoder. Hardware readiness still requires a separate runtime check.

## Integration status

Mesa patch 0010 reads the property before opening the native IOKit client.
It uses the selected Navi48Bringup service, or the exact provider chain
Navi48Accelerator -> Navi48MetalNub -> Navi48Bringup for the sandboxed route.
It does not search globally for an unrelated driver's metadata. The decoder
is mirrored from the shared header; CI checks that the copies agree.

The native connection retains a decoded identity snapshot. RADV enumeration
and its device-info query use the actual PCI device/revision and subsystem
IDs rather than always identifying as 1002:7550. The native marketing name
is neutral because PCI identity alone does not establish an XT board model.
The handshake separately checks the live QueryInfo GC version and retains
the existing ABI, address-configuration, VA-range and readiness checks.

Missing, malformed, disabled, and gfx1200 records are refused before
IOServiceOpen. Older kernels without the property must be updated together
with the backend. Explicit MOCK and HOST_BO modes retain synthetic data;
they do not establish hardware compatibility.

Mesa patch 0011 separately requires the post-GFXInit active-layout property
described in `GFX-RUNTIME.md`. It replaces canned CU/RB masks and tiling
configuration with validated runtime values and cross-checks live QueryInfo.
Maximum CU capacity is never substituted for the active-unit count.

The pinned Mesa base has a canned gfx1201 device record. Patch 0012 derives
a separate gfx1200 reference using verified target hardware data and the
runtime overlay. Platform VM policy stays unchanged; runtime memory pools
and budgets continue to come from QueryInfo. The gfx1200 reference leaves
CP firmware versions unset and cannot pass the native identity gate.
See `GFX-RUNTIME.md` for the reference's scope and hardware-info checks.

Mesa remains external at the revision in `mesa-patches/README.txt`; the
Metal build script also consumes an external RADV dylib. CI now applies
the complete patch series, runs simulated native-transport tests, checks
the IOKit source against Apple's real headers, and builds the full x86_64
RADV library. Its artifact is a compile check, with Navi 44 still disabled.

Synthetic C and C++ host tests cover both families, preserved device IDs,
malformed records, bounds, capacity consistency, and unaligned/overlapping
decoding. Passing them does not establish target hardware compatibility.
