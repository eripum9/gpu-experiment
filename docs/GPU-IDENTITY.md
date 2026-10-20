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

The Mesa Darwin patches still select canned gfx1201 information and PCI
1002:7550. They do not consume this property yet. Mesa itself is external,
at the revision described in `mesa-patches/README.txt`; the Metal build
script also consumes an external RADV dylib. This step supplies the missing
kernel data and shared decoder, while backend selection and replacement of
canned active-unit and memory information remain separate work.

Synthetic C and C++ host tests cover both families, preserved device IDs,
malformed records, bounds, capacity consistency, and unaligned/overlapping
decoding. Passing them does not establish target hardware compatibility.
