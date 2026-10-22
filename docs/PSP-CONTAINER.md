# PSP container reuse and validation

The first selected reuse from the newer RX4Darwin code is its freestanding
PSP package parsing approach. `psp_container.hpp` adapts that approach into
one allocation-free parser shared by the pre-SOS `PspLoader` and the later
`amdgpu::psp_parse_sos_microcode` v2 path. Both consume the same validated
views into their caller-owned firmware buffer.

The reference is
[AMDRadeonRDNA4 `amdfw.cpp`](https://github.com/RX4Darwin/AMDRadeonRDNA4.kext/blob/49f7f20c00dd154384418078f8a09e79c400a06a/src/amdfw.cpp),
revision `49f7f20c00dd154384418078f8a09e79c400a06a`. The adapted helper retains
its BSD-3-Clause notice. Its validation policy is deliberately narrower than
a general AMD firmware reader: supported packages are PSP v2.0 and v2.1,
with primary SOS and SYS_DRV components. The existing legacy v1 path in the
later loader remains separate.

The parser checks little-endian header fields, declared container and header
sizes, descriptor-table bounds, and each selected component's extent within
the declared microcode payload. It rejects empty or duplicate known primary
components and unsupported v2 header revisions. Unknown primary types can be
skipped only after their ranges have been checked. Failure clears the output;
neither adapter may retain a partially parsed v2 package or stale blob metadata.

For v2.1, primary-package selection follows the pinned
[Linux v6.19 `psp_init_sos_microcode`](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_psp.c):
the normal, non-auxiliary selection uses `count - psp_aux_fw_bin_index`
descriptors from the beginning. The complete descriptor table remains bounded,
and auxiliary descriptors cannot replace primary components. Auxiliary SOS
selection is not implemented. This policy is explicit because other readers
use different interpretations; neither matching field names nor a working
package from another board establishes the intended selection on this target.

These are structural checks. They do not validate the CRC or authenticate
firmware, establish PSP protocol compatibility, or prove that the GPU executed
the images. The dependency fetcher separately pins complete firmware blobs by
size and SHA-256. No register sequence, firmware-loading order, profile gate,
or standalone survey behavior changes as part of this integration.

## Pre-SOS protocol checks

The pre-SOS loader additionally requires an explicitly configured 1 MiB staging
offset and a fresh successful preflight before one chain attempt. Parsing or
reconfiguring the offset invalidates that authorization, and every attempt
consumes it. An invalid offset clears its configuration rather than retaining
a previous location. Explicit offset zero is an input, not a default grant of
permission to overwrite the boot framebuffer.

Preflight validates the complete selected chain against the parsed container,
including all component sizes, before any image is staged. The loader repeats
that check before the first write; its public inspection slots cannot replace
the parsed pointer, length or version. MC address addition, the complete staging
extent and the address representation accepted by the mailbox are checked.

The host protocol test executes the production `PspLoader` with a simulated
`HwAccess`. It checks command order, addresses, staging data, readiness polling,
secure-OS sign-of-life transitions and failures. CI also supplies both pinned
PSP packages to this simulation after fetching them. These checks exercise CPU
code and a simulated bus; they do not execute GPU firmware.

The caller still owns the source buffer's lifetime, the device and mappings,
the exclusion of console/firmware reservations, BAR0-to-MC translation and
visibility of CPU writes to the PSP. A posted MC window and a bootloader-ready
bit do not establish those requirements. Navi 44 remains disabled in the main
driver while its memory policy and hardware adapter are being prepared.

## Next reuse boundary

[tinygrad's AM driver](https://github.com/tinygrad/tinygrad/blob/042156664964dd594fa7caed3bacdc2384995a9b/docs/developer/am.md)
and the newer RX4Darwin compute code are references for a possible direct MEC
experiment. They demonstrate that MES-managed queue creation and loading MES
firmware are separate questions. Cobalt's current shader test dispatches on
the GFX ring; its normal PM4 stage uses MES to make that ring usable. A direct
MEC route would therefore be a separate queue-ownership design, not merely
skipping the MES stage.

Before adding that route, reconcile firmware readiness, VM mappings, MQD/HQD
ownership, doorbells, fences, and failed-dispatch buffer lifetime. The other
drivers' VRAM-backed queues and board constants cannot substitute for Cobalt's
system-memory/GART policy or Navi 44's discovered IP layout. Navi 44 remains
disabled in the bring-up driver while these requirements are unresolved.
