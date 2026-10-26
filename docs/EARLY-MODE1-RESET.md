# Early-boot Mode 1 reset experiment

Version 0.12.0 provides an explicit early-boot test for a machine whose
desktop reset request is blocked by attached graphics services. It preserves
the existing requirement that the survey be the GPU's only attached
IOService client. It does not detach, terminate or whitelist other drivers.

This mode can issue a reset during the diagnostic boot. It is separate from
the manual `cobalt-survey-mode1=1` interface and must not be combined with it.
It is not a graphics acceleration or complete GPU initialization feature.

## Bootstrap and one test boot

The hardware-specific private test payload includes verified bootstrap,
armed and baseline EFI configurations, a `plan.plist` with file hashes and
machine/USB identity, and the capture scripts. The public artifact alone is
not an armed installation and contains no machine identity or private EFI.

The capture helper uses the signed `CobaltEarlyCapture.app` bundle, installed
at `/Applications/CobaltEarlyCapture.app`, as its background process identity.
Grant **this app** Full Disk Access in System Settings → Privacy & Security
before allowing the test to arm. The installer does not grant that permission
or change the privacy database. It does not require granting access to a
general-purpose shell.

Before arming, the installer launches a temporary probe through `launchd`,
the native app, and the same child script used by the real capture job. The
probe checks the planned machine, USB identity and bootstrap config, then
proves read, write and rename access using its own nonce files. It leaves
the active configuration unchanged. Permission from an interactive Terminal
session is insufficient evidence: a background process has a separate access
context. If this probe fails, setup remains unarmed and explains how to grant
the app access before trying setup again. The app remains installed for that
selection; newly created incomplete capture setup is cleaned up.

The bootstrap configuration loads only the existing passive observation
path, with `cobalt-survey`, `cobalt-survey-indexed` and `cobalt-survey-state`
equal to 1. Indexed discovery still uses its existing selector stores; no
reset, PCI mutation or firmware experiment is selected. Save work and boot
that configuration to the desktop before installing the one-time helper:

```sh
sudo sh /Volumes/TAHOE/gpu-early-test/install-early-reset-test.sh --install-and-reboot
```

The installer validates the private plan, machine and USB identity, checks
the passive boot and background USB probe, and saves a baseline capture. It installs a root-owned
capture job for the next boot before replacing the USB configuration with
the verified armed configuration. It then attempts a normal reboot.

Select the SanDisk USB and Macintosh HD for the **one diagnostic boot**.
The armed configuration selects exactly:

```
cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-mode1boot=1
```

The capture job checks that this is the intended boot. Once the expected USB
is available, it restores the baseline configuration before collecting the
result. It does not request any GPU reset itself. It saves available output
under `EARLY-RESET-<SessionID>`, disables its future launch and attempts a
normal reboot. Select Windows Boot Manager directly from the firmware menu.
The display need not remain available for that user-space collection.

If USB access fails before baseline restoration in the intended test boot, available driver and
collector evidence is saved locally under the root-owned capture directory.
The job does not automatically reboot while the USB remains armed. Recover
the known working configuration from Windows before another macOS boot, then
retrieve the local evidence. An access failure is reported as such, rather
than being interpreted as a changed configuration or a successful capture.

The first tested shell-only job was denied access to the USB configuration
even though its installer could access it from Terminal. Root credentials do
not establish that the background job has removable-volume consent. The app
and preflight address that observed failure; successful background access
still needs to be established on the target Mac before a further reset boot.

References: [Apple DTS on helper-process access](https://developer.apple.com/forums/thread/802650),
[Apple DTS on app bundles and Full Disk Access](https://developer.apple.com/forums/thread/118508),
and [Apple's removable-volume permission description](https://developer.apple.com/documentation/bundleresources/information-property-list/nsremovablevolumesusagedescription).

A hard hang or panic before user space can prevent the job from collecting
or restoring the baseline configuration. The kernel's attempt marker is
per boot and cannot prevent another boot repeating an enabled early flag.
If the test hangs, recover into Windows, restore the known working USB
configuration, and do not repeat the diagnostic boot before review.

## Kernel boundary

The reset runs inside the survey's synchronous `start()`, after validated
discovery, passive state and console observations and before service
publication. That timing uses an observed early ownership window; it does
not guarantee matching order or imply that no other candidate has probed
the device. A fresh strict census must still pass. The provider remains
cooperatively open through the existing fixed reset protocol and recovery.
All later ownership, PCI, mapping and layout guards remain in place.

The early path asks the platform to pause OS console/progress rendering
before the fixed debug burst and checks the API result. No console call,
log, guard or other driver I/O is inserted between the three stores or
during the following one-second quiet interval. The console is resumed
only after restored PCI state and stable full postflight observations.
An unsafe or failed recovery leaves it paused for headless capture.
Pausing OS rendering does not prove exclusion of firmware or every other
hardware accessor, and does not itself reinitialize the display engine.

The manual path remains explicit and desktop-triggered. The early path
does not accept a second manual reset request. Neither path retries a
reset or follows it with firmware, queue, VRAM or display programming.

## Result interpretation

`BuildVersion`, `Mode1ResetEarlyRequested` and `Mode1ResetTrigger` distinguish
the selected boot from a manual request. The existing census, PCI, store,
recovery and raw-register properties remain evidence for the actual attempt.
Additional console pause/resume attempt and result properties describe that
OS boundary. A complete successful early result commits schema 12; manual
success retains schema 11. Failure or incomplete publication cannot retain
an early success commit. `Ready` and `ColdCycleReplacementValidated` remain
false, including when recovery is observed.

These are diagnostic checkpoints. A readable recovery state, or initial and
final SOS values that are both zero, does not prove a reset occurred or that
the method can replace a cold cycle for subsequent firmware initialization.

## Platform references

The platform boundary was reviewed against public XNU `xnu-12377.1.9`, which
is in the target kernel's family but is not its exact runtime source build:

- [Service matching and synchronous candidate startup](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOService.cpp)
- [Platform console operations](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/pexpert/i386/pe_init.c)
- [Console and progress pause implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/console/video_console.c)

The underlying SMU protocol references remain pinned in
[the manual reset document](MODE1-RESET.md#primary-references).
