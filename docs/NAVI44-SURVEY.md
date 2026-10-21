# First Navi 44 macOS survey

`CobaltNavi44Survey.kext` is a separate diagnostic for `1002:7590`.
It does not enable Navi 44 in `Navi48Bringup`, run that driver's startup
ladder, upload firmware, or provide graphics acceleration. A successful boot
with this survey will still have the current basic display performance.

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
capacity using the existing parser. It never changes the BAR size or uses
indirect VRAM index/data registers. A limited window is an expected report
condition, not evidence that the GPU cannot work. In particular, an OpenCore
configuration restricting the Apple-visible BAR to 256 MiB cannot expose
the discovery table at the end of a 16 GiB card through this direct path.

The register address and discovery placement follow
[Linux's discovery implementation](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c).
No PCI configuration, GPU register, VRAM, display, or power-state writes
are part of the survey. These observations do not establish that GPU engines
can execute work, and do not publish the accelerator's runtime records.

## Deployment and collection

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
