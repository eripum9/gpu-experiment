# Navi 44 macOS survey

`CobaltNavi44Survey.kext` is a separate diagnostic for `1002:7590`.
It does not enable Navi 44 in `Navi48Bringup`, run that driver's startup
ladder, upload firmware, or provide graphics acceleration. A successful boot
with this survey will still have the current basic display performance.
Its default mode is read-only. A separately gated indexed-discovery experiment
permits a bounded set of address-selector writes, described below.

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

A derived BAR0-relative interval is reported only for a page-aligned raw
address, zero console offset and rotation, graphics display mode, consistent
nonzero geometry, checked arithmetic, and a complete interval inside the same
validated BAR0 descriptor. A zero
explicit length uses row bytes times height; a nonzero explicit length must
cover that span and is included in the containment check. Other stable console
descriptions retain their raw fields with a refusal reason. In particular,
address low bits are not silently masked and nonzero offsets are not guessed.

This describes a console interval, not a reserved firmware buffer. It does
not select a scratch address, prove all firmware/display reservations, establish
BAR0-to-GPU address translation, or authorize a firmware upload. Those remain
separate initialization prerequisites. The API and scalar layout follow
[XNU's platform expert](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOPlatformExpert.cpp)
and [x86 console implementation](https://github.com/apple-oss-distributions/xnu/blob/main/pexpert/i386/pe_init.c).

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
Remove `cobalt-survey-indexed=1` and `cobalt-survey-state=1` as well when
disabling those experiments.

## Build

With the same pinned MacKernelSDK as the main compile check:

```
python3 tools/navi44-survey/build.py
python3 -m unittest discover -s tools/navi44-survey -p 'test_*.py' -v
make -C src/navi44-survey MKSDK="$PWD/build/ci-deps/MacKernelSDK" all
python3 tools/ci/package_survey_artifact.py --output build/CobaltNavi44Survey-hardware-test.tar.gz
```

This standalone target embeds no firmware. CI compiles and signs the bundle;
it cannot test the desktop's GPU hardware.
