# Navi 44 macOS survey

`CobaltNavi44Survey.kext` is a separate diagnostic for `1002:7590`.
It does not enable Navi 44 in `Navi48Bringup`, run that driver's startup
ladder or provide graphics acceleration. A successful boot
with this survey will still have the current basic display performance.
Its default mode is read-only. Separately gated experiments permit bounded
address-selector writes, a 16-byte VRAM transport test, and a full 1 MiB
synthetic staging test, described below. Version 0.7.0 additionally includes
a separately armed one-command KDB firmware diagnostic. Embedding firmware
does not activate that mode. Version 0.8.0 adds a separately armed KDB and SPL
diagnostic using two buffers. Version 0.9.0 adds the complete pinned pre-SOS
batch, separately armed with seven independent buffers. Version 0.10.0 adds
a separately armed SOS-startup checkpoint with eight buffers. Version 0.11.0
also provides a separate [manual software-reset test](MODE1-RESET.md).
Version 0.11.1 records the initial reset ownership census and adds a read-only
provider-child inventory to explain refusals without relaxing the check.
Version 0.12.0 adds a separate [early-boot reset experiment](EARLY-MODE1-RESET.md)
with passive bootstrap and a one-time capture helper.
Version 0.13.0 adds the exclusive
[early reset and PSP/SOS checkpoint](EARLY-RESET-SOS.md), with fresh discovery
between reset and firmware startup under one provider session. It retains
`Ready=false` and does not establish a cold-cycle replacement or acceleration.

## One-command KDB checkpoint (0.7.0)

`cobalt-survey-kdb=1` requires all five existing flags to equal numeric 1:
`cobalt-survey`, `cobalt-survey-indexed`, `cobalt-survey-state`,
`cobalt-survey-aperture`, and `cobalt-survey-staging`. It selects the KDB
checkpoint instead of either synthetic VRAM experiment. The diagnostic
calls the shared `PspLoader::runKeyDatabase()` API with the immutable pinned
PSP 14.0.2 container. Only its 6,816-byte KDB component is submitted; the
remaining firmware chain and SOS startup are excluded.

The existing aperture policy selects a 1 MiB window at least 64 MiB into VRAM,
outside the observed console and conservative protected intervals. CPU and
indexed readback tests establish transport consistency. They do not reserve
that window exclusively or prove that the PSP sees the same GPU address.
This is an experimental firmware transaction, with possible hangs or resets.

Before mutation, two matching six-register observations must show the
expected posted memory window, matching low 24-bit MMHUB/DCN framebuffer
bases, an idle boot mailbox and SOS down. FB offset is recorded and pinned
separately. Stable PCI, BAR, ownership, remap and framebuffer observations
are guarded independently of the intentionally changing boot mailbox.
Unusable context is latched; it cannot recover permission to write.
The provider records a persistent attempt before new selector writes.

The staging helper clears the full window, copies exactly the KDB component,
flushes through the validated HDP endpoint, and verifies the full CPU window
plus indexed page-edge samples before the two allowed mailbox stores.
Only the calculated address and KDB command `0x00080000` are allowed, once
each. Attempt state is committed before each store.

Before a command store is attempted, original VRAM may be restored only
through a still-valid context. After any command attempt, staging is preserved
even on timeout or a failed post-store check. There is no command retry,
mailbox rollback, automatic reset, later firmware component, or SOS startup.
Any mailbox attempt or unverified cleanup reports a required cold reset. Selector restoration is
separately bounded and may be skipped after context loss or an SOS change.
Do not repeat a firmware test without a full cold reset.

KDB properties contain scalar observations and counts, never firmware or
saved VRAM bytes. Schema 7 means the command returned the ready bit while
SOS was observed down. It does not prove firmware authentication, GPU DMA,
execution, display support, or Metal acceleration. `Ready` remains false.
The embedded package is distributed under the included AMD firmware license.
If discovery, passive state, or console publication fails first, the existing
failure status is retained and no KDB transaction or KDB result is produced.

## KDB and SPL checkpoint (0.8.0)

`cobalt-survey-spl=1` requires all six earlier survey flags, including
`cobalt-survey-kdb=1`, to equal numeric 1. It selects this pair instead of
the KDB-only or synthetic staging tests. Missing prerequisites refuse the pair
without falling through to an earlier write experiment.

The checked planner selects two adjacent, distinct 1 MiB windows. Both must
fit the CPU aperture, conservative usable-VRAM exclusions and posted MC range.
The second window is checked in full; space for the first alone is insufficient.
This extends the existing experimental placement policy, without establishing
an exclusive VRAM allocation or PSP address translation.

Both originals are read twice and cross-checked through indexed page-edge
samples before mutation. The actual shared `runKeyDatabaseAndSpl()` method
then clears and copies both payloads, with full CPU and indexed verification,
before any mailbox store. KDB uses the first window and SPL the second. The
pinned components are respectively 6,816 and 832 bytes; no later firmware
component or SOS is started.

Only four mailbox stores are allowed: KDB address and command, then SPL
address and command. SPL requires a KDB-ready observation from direct protocol
reads followed by SOS down. Resource-guard reads alone cannot authorize it.
Each attempt is recorded before its store, so a failed post-store check cannot
authorize a retry. Readable boot-ready and SOS-down checks precede each store;
device, framebuffer, console, remap and ownership guards remain active.

After **any mailbox attempt**, including an address-only failure, neither
window may be written, flushed or restored. Both are preserved until a cold
reset. Before that boundary, dirty originals may be restored only through a
valid guarded context and with verification. Selector cleanup is separate and
may be skipped after context loss. A mailbox attempt or unverified cleanup
requires a full cold reset. The KDB-only and pair attempt markers exclude each
other for the lifetime of the provider.

Results use the separate `KdbSpl` property prefix. Schema 8 records a completely
published two-command ready observation with verified staging and cleanup;
`Ready` remains false. Refusals or failures retain the earlier console schema.
If discovery, state or console collection fails before this mode can run,
that earlier failure is retained and no pair transaction is attempted.
An unreadable or changed context permanently revokes writes, even if a later
sample looks valid. The result does not establish authentication, GPU execution,
display support or Metal acceleration. Repeat attempts require review and a
cold reset; the ordinary boot configuration should be restored after capture.

## Complete pre-SOS checkpoint (0.9.0)

`cobalt-survey-presos=1` requires all seven earlier survey flags, including
`cobalt-survey-spl=1`, to equal numeric 1. It selects this batch instead of
the pair, KDB-only or synthetic experiments. Missing prerequisites refuse
without falling through; earlier discovery/state/console failures retain
their existing diagnostics before a batch transaction can begin.

The immutable, hash-pinned PSP 14.0.2 package contains seven selected pre-SOS
images, submitted in this order:

| Image | Bytes | Fixed command |
| --- | ---: | --- |
| KDB | 6,816 | `0x00080000` |
| SPL | 832 | `0x10000000` |
| SYS_DRV | 78,272 | `0x00010000` |
| SOC_DRV | 103,792 | `0x000b0000` |
| INTF_DRV | 37,280 | `0x000d0000` |
| HAD/DBG_DRV | 53,344 | `0x000c0000` |
| IPKEYMGR | 12,848 | `0x000f0000` |

RAS is absent in this pinned package. SOS and TOC are not submitted. The
adapter requires the exact seven source pointers, lengths and versions from
the pinned manifest. It calls the shared `runPreSos()` protocol once, without
entering the existing full-chain startup path.

The planner checks the entire seven-window region against BAR0, conservative
usable-VRAM exclusions and the posted MC range. All seven originals are read
twice and checked through indexed page edges. Each window is then cleared,
flushed, copied and verified through full CPU readback and indexed samples.
**Every window is prepared before the first mailbox address is attempted.**
These checks retain the experimental placement policy; they do not establish
exclusive allocation or complete PSP address translation.

Only fourteen mailbox stores are permitted: one address and one fixed command
per image. The next image requires a direct protocol boot-ready observation
followed by direct SOS down. Resource-guard reads cannot authorize a phase
transition. Attempt state advances before each store, and unreadable or changed
context permanently stops writes. Busy completion polling can become ready;
an unexpected direct busy observation after established completion aborts.

After **any mailbox attempt**, including an address-only failure, all seven
buffers remain preserved until a cold reset, without CPU writes, flushing or
restoration. Before that boundary, dirty originals may be restored only through
a valid context with verification. Selector cleanup is separately guarded and
may be skipped after context loss. The provider attempt marker excludes the
older firmware modes. Repeat attempts require review and a full cold reset.

Results use `PreSos` aggregate properties and per-image prefixes. Schema 9
requires all seven ready observations, fourteen stores, verified staging and
cleanup, valid context and complete metadata publication. Failure or refusal
retains the earlier console schema; stale success is revoked before fallible
fallback publication. `Ready` remains false. No SOS startup, GPU queues,
display programming or acceleration is enabled by this checkpoint. Returned
ready observations do not prove authentication or GPU execution.

## Bounded SOS-startup checkpoint (0.10.0)

`cobalt-survey-sos=1` requires all eight preceding survey flags, including
`cobalt-survey-presos=1`, to equal numeric 1. It selects this checkpoint
instead of the earlier firmware modes. Missing prerequisites refuse without
falling through. Earlier discovery/state/console failures can stop the service
before the firmware transaction begins.

The exact seven pre-SOS images are followed by the pinned SOS image: 125,472
bytes at package offset `0x14d60`, version `0x003b0f0d`, command `0x00020000`.
All eight independent 1 MiB windows, including SOS, are cleared, copied,
flushed and checked before the first mailbox attempt. The shared
`runSosCheckpoint()` API validates the complete source inventory and placement;
it does not continue an earlier attempt or reuse a buffer after dispatch.
The conservative placement policy remains an experiment, not proof of
exclusive allocation or complete PSP memory translation.

The seven pre-SOS commands retain their strict direct boot-ready and SOS-down
checks. The last two stores are the SOS address and fixed SOS command, each
preceded by fresh ready/SOS-down checks. After that command, **no further
mailbox, selector, CPU-window or flush writes are permitted**. Following the
existing 20 ms startup delay, bounded direct SOS reads seek a transition from
zero to a readable nonzero value. An unreadable `0xffffffff` sample aborts
immediately. A preexisting nonzero SOS value is refused; it is not adopted as
a successful attempt. Bootloader-ready after SOS is not required.

Expected SOS startup may change its status register and clear boot-ready.
Other ownership, PCI, BAR, console, remap, memory-size and pinned framebuffer
changes still revoke the transaction. Guard reads cannot authorize success:
only the direct SOS response can establish the observed transition. Context
loss is sticky, and a return to zero after a direct alive observation revokes
the result. No later GPU initialization is attempted.

Every staging buffer is preserved after any mailbox attempt, including an
address-only failure. Before the SOS command, selector restoration retains
the existing guarded SOS-down policy. After its command, selector cleanup is
intentionally skipped and reported as `preserved-after-sos-command`; no write
is issued to improve the cleanup label. A cold reset is required before reuse.

Results use `SosBoot` aggregate properties and per-image prefixes. Schema 10
requires all eight staged images, seven direct pre-SOS completions, sixteen
stores, a direct readable nonzero SOS transition, valid context, the cleanup
policy above and complete metadata publication. The aggregate
`SosBootAliveObserved` and the SOS image's `SosBootSosAliveObserved` record the
transition; its `ReadyObserved` remains false because post-SOS boot-ready is
not measured. Stale success is revoked before fallible fallback
publication. Global `Ready` remains false. This checkpoint enables no queues,
interrupts, display programming or Metal acceleration; a status-register
transition does not validate GPU workloads or firmware authentication.

## What the test measures

The service requires `cobalt-survey=1` in both probe and start. It reports the
PCI identity and assigned BAR resources. Only when PCI memory decoding is
already enabled and BAR5 agrees with its IOKit descriptor does it map the
register window read-only and read `RCC_CONFIG_MEMSIZE` twice. The full
discovery path adds bounded reads of that same register around the snapshot
to reject a changed size. A disagreement or invalid size stops the memory
observations.

The reported size is a bounded MiB extent, which need not be a power of two.
Discovery addressing uses that exact extent without rounding it up to the
card's nominal installed capacity, following Linux's discovery calculation.

Unique physical subrange mappings can use a newly allocated backing
descriptor. The survey validates that descriptor's physical interval and
length against the requested BAR subrange, together with the map's physical
interval and permissions. It does not require the new descriptor to be the
same object as the original BAR descriptor. Failed mapping checks publish
their specific reason and observed metadata before any memory dereference.
This follows [XNU's `makeMapping` implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp).

If the existing BAR0 window covers the entire reported VRAM, the service
can read the 10 KiB discovery table 64 KiB below the end of VRAM directly.
It validates the binary and table checksums, critical IP versions, and GC
capacity using the existing parser. This direct path never changes the BAR
size or uses indirect VRAM index/data registers. A limited window is an expected report
condition, not evidence that the GPU cannot work. In particular, an OpenCore
configuration restricting the Apple-visible BAR to 256 MiB cannot expose
the discovery table at the end of a 16 GiB card through this direct path.

The register address and discovery placement follow
[Linux's discovery implementation](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c).
The default mode performs no PCI configuration, GPU register, VRAM, display,
or power-state writes. These observations do not establish that GPU engines
can execute work, and do not publish the accelerator's runtime records.

## Indexed discovery experiment

`cobalt-survey-indexed=1` additionally permits indexed discovery when the
existing BAR0 window is too small. It also requires `cobalt-survey=1` and the
exact Navi 44 PCI identity. A full direct BAR0 window still uses the read-only
path. This opt-in does not resize any BAR or change the BIOS configuration.

The experiment opens the PCI provider with normal options zero and refuses
an occupied provider, inactive device, or other direct service clients.
Provider open coordinates clients that follow IOKit's ownership rules; it
does not exclude firmware, reset/removal, or drivers bypassing those rules.
Configuration and descriptor checks are repeated after opening the provider
and throughout the transfer. The provider records an attempt before the
first selector write, preventing another attempt until a fresh boot.

The only writable mapping is the first 4 KiB page of the validated BAR5.
Only `MM_INDEX` at byte offset `0` and `MM_INDEX_HI` at byte offset `0x18`
may be written. `MM_DATA` at byte offset `4` is always read-only at the
accessor level. The transfer derives its own fixed 10 KiB discovery interval
from the exact validated VRAM extent and reads that interval twice.
The low-selector, high-selector, data sequence follows
[Linux's indexed VRAM reader](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c).
There is no arbitrary address or write interface.

The service sets `ReadOnly=false` before using the writable selector path
and keeps `Ready=false`. It records the access method, selector-write count,
and cleanup outcome. It samples the old selectors and checks the programmed
selectors before reading data. On exit it makes one bounded attempt to
restore the sampled selectors, provided the same device, mapping, and
ownership checks still hold. It reports observed matching readbacks, a
restore readback mismatch, or a skipped restore after device-state change.
Readback observations are experimental evidence, not a guarantee that every
hardware state was unchanged. No restore is issued through a stale mapping.

The snapshot is discarded on any transfer, state, comparison, or cleanup
failure. Publication requires two identical complete passes, final size and
PCI checks, and the same discovery checksum, IP, and topology validation as
the direct path. Maps are released and the provider is closed before
publication. This path does not write GPU memory or data registers, load
firmware, start queues, allocate DMA, or program display or power state.

## Deployment and collection

### Passive PSP and memory-window state

`cobalt-survey-state=1` requests an additional passive observation after the
discovery snapshot passes its checksums, critical IP checks and GC topology
validation. It still requires `cobalt-survey=1`. On a limited BAR0 aperture,
the existing indexed-discovery flag is also needed to obtain that snapshot.

The read set is fixed to four dwords: PSP MPASP `C2PMSG_35` and `C2PMSG_81`,
and MMHUB `MMMC_VM_FB_LOCATION_BASE` and `TOP`. Their byte offsets come from
the validated discovery records, with the register-offset and segment pairs
from Linux v6.19's
[MP 14.0.2 header](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/include/asic_reg/mp/mp_14_0_2_offset.h)
and [MMHUB 4.1.0 header](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/include/asic_reg/mmhub/mmhub_4_1_0_offset.h).
The selected instances must be unique and match those versions. No register
base from another board is substituted when discovery is missing or invalid.

The extra mappings are read-only, uncached, bounded BAR5 pages. All addresses
and mappings are validated before the first additional register read. The
service checks the PCI identity, configuration, active state and BAR
descriptors around every read, and requires two identical four-register
passes. An unreadable register, changed device, changed values, or failed
mapping prevents publication of a state result. State failure is reported
separately from a successfully captured discovery table.

The state properties report raw values and resolved byte offsets, together
with their separate read-only scope and completion status. They do not mean
that the PSP is ready for a new firmware package or that its memory window
is available for driver allocations. The inherited GOP/firmware state still
needs interpretation before any initialization test. In particular, this
mode sends no SMU query, PSP mailbox command, or firmware upload. It adds no
GPU, VRAM, PCI configuration or selector writes; an explicitly enabled
indexed-discovery pass retains its previously documented selector writes.
The implementation maps one page per selected IP pair and refuses a pair
that crosses that page boundary. Successful state publication uses survey
schema 3; discovery-only read-only and indexed observations retain their
existing schemas. Removing the state flag preserves the previous read set.

### Passive OS console geometry

The state mode also samples the OS console description twice using
`IOPlatformExpert::getConsoleInfo`. This adds no GPU register reads, memory
maps, or writes. It records the raw address, row bytes, dimensions, depth,
display mode, offset, length, rotation and scale. The platform pointer is
borrowed; the service neither changes the console nor maps its pixels.

The scalar observations must agree and the target PCI identity, configuration
and BAR descriptors must remain unchanged. Console failures have a separate
status and preserve valid discovery and PSP/MMHUB observations. Successful
console metadata uses schema 4; a state result without console metadata
retains schema 3. The collector captures either result without additional
privileges or commands.

A derived BAR0-relative interval is reported only for a physical-tagged
address whose decoded base is page-aligned, zero console offset and rotation,
graphics display mode, consistent
nonzero geometry, checked arithmetic, and a complete interval inside the same
validated BAR0 descriptor. A zero
explicit length uses row bytes times height; a nonzero explicit length must
cover that span and is included in the containment check. Other stable console
descriptions retain their raw fields with a refusal reason. With VM running,
[XNU's console implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/console/video_console.c#L2678-L2686)
uses bit 0 to distinguish a physical address from a virtual address and clears
the low two bits to obtain that physical address. The survey follows that
decoding while preserving the original raw scalar. Untagged addresses and
remaining alignment bits are refused; it does not clear an arbitrary page's
worth of low bits. Nonzero console offsets are still not guessed.

This describes a console interval, not a reserved firmware buffer. It does
not prove all firmware/display reservations, establish BAR0-to-GPU address
translation, or authorize a firmware upload. The separate aperture experiment
uses the interval as one of its exclusion checks. The API and scalar layout follow
[XNU's platform expert](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOPlatformExpert.cpp)
and [x86 console implementation](https://github.com/apple-oss-distributions/xnu/blob/main/pexpert/i386/pe_init.c).

### Bounded aperture transport experiment

`cobalt-survey-aperture=1` requests one additional, finite write experiment.
It requires all three existing survey, indexed and state flags set to numeric
`1`, validated discovery and state, and a stable, interpretable physical
console interval. Omitting the new flag preserves the previous modes.
This mode submits no GPU firmware and keeps `Ready=false`.

This first checkpoint is restricted to PCI `1002:7590`, revision `c0`,
subsystem `1eae:8601`, with a 256 MiB BAR0 and a 512 KiB BAR5. It requires
unique NBIF 6.3.1 and HDP 7.0.0 discovery records. It uses a conservative
516 MiB firmware reserve for that board profile, excludes the first 64 MiB,
and leaves at least 16 MiB after the observed console. A pure checked-arithmetic
planner selects a 1 MiB interval aligned to 1 MiB inside the aperture, usable
VRAM and observed MC range. Only its first 4 KiB is mapped, and only its first
four dwords can be written. These margins are experimental policy; they do
not prove that firmware has no other VRAM users or establish an allocation
contract for a general graphics driver.

Before any new selector or VRAM write, the service opens the provider,
checks for other direct clients, rechecks the console and PSP/MMHUB state,
and validates all mappings. NBIF's memory-size and HDP-flush-remap register
offsets are resolved from the validated discovery segment. Two remap reads
must agree and equal either `0x7f000` or the independently resolved native
NBIF memory-flush register. An absent, different or changing remap refuses
the experiment; the service never programs the remap register. Every later
guard requires that same selected value, including when a change would select
the other otherwise supported route.
The offset and segment pairs follow Linux v6.19's
[NBIF header](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/include/asic_reg/nbif/nbif_6_3_1_offset.h).

The native register is `BIF_BX_PF0_HDP_MEM_COHERENCY_FLUSH_CNTL`, dword
offset `0xf7` in NBIF segment 2. Its byte address is calculated through
discovery; a captured remap value alone cannot authorize an arbitrary target.
Linux's [NBIF remap selection](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/nbif_v6_3_1.c)
uses this native target for its VF or large-page fallback, and selects the
isolated `0x7f000` hole for a non-VF system with 4 KiB pages. The survey can
use either already configured route without changing that configuration.

The writable mappings are restricted to the existing selector page, one
VRAM page, and one 4 KiB flush page. With the isolated route, the NBIF
guard page remains mapped read-only and the flush word is the first dword
of its separate page. With the native route, the flush word shares the NBIF
guard page: the service releases its read-only preflight view before creating
a single writable replacement. This avoids simultaneous read-only/writable
aliases. The page has writable hardware permissions; fixed-purpose accessors
only read the two guard registers and only write zero to the resolved flush
word. It is not described as a read-only hardware mapping.

A CPU memory barrier precedes that write; a read of NBIF's memory-size
register posts it. This sequence follows Linux's
[aperture access](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c)
and [HDP flush](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_hdp.c)
paths. It does not infer a valid remap from the HDP version alone.

A separate persistent provider attempt marker is claimed before the first
new selector write. Two CPU and indexed samples must agree on the original
16 bytes. The transaction then writes a bounded test pattern, flushes it,
and compares CPU and indexed readbacks. It restores the original bytes,
flushes them and verifies both read paths before restoring the selectors.
There is no arbitrary address interface, firmware upload, mailbox command,
queue startup, display programming or automatic retry.

Identity, active state, BAR configuration and descriptors, ownership,
peer clients, memory size and remap guards apply throughout the transaction
and cleanup. If a guard changes, further writes through that context are
skipped and incomplete cleanup is reported. A failed pattern comparison
with valid guards still attempts restoration. A matching readback reports
an observation, not a guarantee against concurrent firmware access or reset.
The provider-open contract has the same limitations as indexed discovery.

Aperture operation counters and VRAM/selector cleanup results are separate
from the discovery counters. The selected route, native and selected flush
byte offsets, and guard-page mapping policy are reported separately. No
original VRAM contents are published.
Maps are released and the provider is closed before the result is published.
A complete successful result uses schema 5; refusals and failures preserve
the independently valid discovery/state/console observations. `Ready` stays
false even when the roundtrip succeeds. Hardware success would establish a
small transport checkpoint, not PSP startup or graphics acceleration.

### Full staging-window experiment

`cobalt-survey-staging=1` selects a separate synthetic transfer experiment
instead of the 16-byte test. It also requires all four existing survey,
indexed, state and aperture flags to equal numeric `1`. Removing this extra
flag preserves the smaller aperture experiment. The service never interprets
a missing prerequisite as permission to proceed with the larger transfer.

This test uses the same board, IP, console, memory-window, ownership and
existing HDP-route checks. It additionally retains read-only PSP and MMHUB
state mappings and pins the four observed state values throughout the longer
transfer and cleanup. A changed or unreadable value latches context loss.
It maps the complete planned 1 MiB VRAM interval
with validated physical bounds and uncached permissions. Heap allocation and
mapping failures stop before any VRAM write. Two complete CPU reads must
agree on the original contents; indexed reads cross-check the first and last
dword of each 4 KiB page. These observations and the provider-open contract
do not establish exclusive ownership against firmware or drivers that bypass
IOKit coordination.

The test exercises the actual bounded `StagingWindow` helper: clear the full
1 MiB, flush, then copy a deterministic 125472-byte synthetic prefix and
flush again. The prefix size exercises the largest selected image extent in
the pinned PSP 14.0.2 package; the bytes contain no firmware. CPU readbacks
check the entire zeroed window and the complete copied prefix plus zero
padding. Indexed samples cross-check each page at both stages. Transfers and
full-window reads use chunks of at most 4 KiB with context guards around
each chunk. No PSP mailbox is written and no GPU work is submitted.

Cleanup uses the saved original contents through a separate bounded path.
It restores the entire window, flushes, checks the complete CPU readback and
indexed samples, then restores and checks the saved selectors. A comparison
failure with a still-valid context permits this restoration attempt. A
latched device-context failure prevents further writes, including cleanup;
an incomplete restoration is reported. The failed staging helper is never
retried to perform cleanup.

The experiment has its own persistent provider attempt marker and separate
`Staging*` properties. Counters describe issued operations, including failing
calls; they are not a claim that every byte completed. No original VRAM bytes
or source buffers are published. Maps are released before provider close and
result publication. A complete successful result uses schema 6 and keeps
`Ready=false`. It establishes an observed synthetic CPU/indexed transfer and
restoration, not GPU-side MC translation, PSP authentication or acceleration.

### Installing the selected diagnostic mode

The CI artifact is a hardware-test candidate. Keep the known working EFI
backup before adding it to a separate test configuration. Do not substitute
`Navi48Bringup.kext`, enable its boot arguments, or install the Mesa/Metal
artifacts as part of this test.

For OpenCore injection, the bundle path is `CobaltNavi44Survey.kext`, the
executable path is `Contents/MacOS/CobaltNavi44Survey`, and the plist path is
`Contents/Info.plist`. Add `cobalt-survey=1` to the existing boot arguments.
Use the normal working boot configuration, including its Bluetooth panic
fix. No SIP change or installation into the macOS system volume is needed
for this OpenCore injection test.

An indexed-discovery test additionally adds `cobalt-survey-indexed=1` only
after its candidate has passed source review, host checks, and the native
build. Leave the existing BAR settings in place. The extra argument permits
the selector writes described above; omitting it preserves the default
read-only behavior. The ordinary collector works for either mode.

An aperture test additionally adds `cobalt-survey-state=1` and
`cobalt-survey-aperture=1` after source review, host fault tests and the native
build pass. Keep the same working EFI backup and BAR settings. Inspect its
reported result in Windows before progressing to a firmware-load test.

After the smaller aperture result has been reviewed, a separately reviewed
and natively built staging candidate can add `cobalt-survey-staging=1` to
those same four arguments. Inspect its transfer and restoration results in
Windows before another experiment. This mode still loads no GPU firmware.

Copy the packaged `collect-gpu-survey.sh` to the root of a writable FAT32
USB volume named TAHOE. In the installed macOS environment, open Terminal:

```
sh /Volumes/TAHOE/collect-gpu-survey.sh
```

The collector writes a timestamped folder beside itself, including the
targeted service registry and bounded kernel log. It does not load a kext
or change the boot configuration. Run it in the installed system that
booted with the survey; a report from a different Recovery session does
not describe the installed system's kernel state. If account setup is not
finished, complete it before this collection step.

Keep the captured output private. Bring the USB report back to Windows
for review before progressing to initialization or acceleration tests.
To remove the survey, restore the saved EFI or remove its Kernel/Add entry,
bundle, and `cobalt-survey=1` argument. No internal ESP changes are required.
Remove `cobalt-survey-indexed=1`, `cobalt-survey-state=1` and
`cobalt-survey-aperture=1`, `cobalt-survey-staging=1`, and
`cobalt-survey-kdb=1`, `cobalt-survey-spl=1`, `cobalt-survey-presos=1` and
`cobalt-survey-sos=1` as well
when disabling those experiments.

## Build

With the same pinned MacKernelSDK and firmware as the main compile check:

```
python3 tools/navi44-survey/build.py
python3 -m unittest discover -s tools/navi44-survey -p 'test_*.py' -v
python3 tools/ci/fetch_deps.py
make -C src/navi44-survey MKSDK="$PWD/build/ci-deps/MacKernelSDK" all
python3 tools/ci/package_survey_artifact.py --output build/CobaltNavi44Survey-hardware-test.tar.gz
```

This standalone target embeds the pinned PSP 14.0.2 SOS container. Its generator
verifies the exact package size and SHA-256 before writing generated C++ into
the ignored build directory. The artifact includes `licenses/LICENSE.amdgpu`.
CI compiles and signs the bundle; it cannot test the desktop's GPU hardware.
