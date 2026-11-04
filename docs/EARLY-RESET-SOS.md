# Early reset and PSP/SOS checkpoint

The 0.13.0 standalone survey adds a separately armed experiment that runs an
early Mode1 request followed by fresh discovery and the bounded eight-image
PSP/SOS startup checkpoint. It runs synchronously before service publication.
It does not enable rendering, Metal, queues, interrupts or display programming.

The earlier isolated Mode1 test can issue its three stores and observe stable
PCI, memory and console recovery without observing a reset transition. That
result alone cannot establish readiness for firmware initialization or
equivalence to a cold power cycle. This compound experiment records the next
firmware checkpoint under its own authorization.

## Explicit selection

The only active experiment flag is:

```
cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-initboot=1
```

All other experiment flags, including manual and early Mode1, aperture,
staging, KDB, SPL, pre-SOS and standalone SOS, must be off. Invalid mixes
refuse before indexed access. Default and standalone modes retain their
separate gates. No userspace request starts this compound transaction.

The native one-shot capture workflow is shared with the
[early reset test](EARLY-MODE1-RESET.md), using a version 0.14.0 private plan
with `TestKind=reset-sos`. A missing `TestKind` selects the standalone Mode1
capture contract; an unknown value is refused. The bootstrap remains passive.
The background native-app USB permission probe must succeed before baseline
capture, installation of the one-shot job, or arming. The capture job restores
the working configuration before collecting either successful or failed
hardware evidence. This source document does not supply a machine-specific
EFI, private identity, plan, or permission grant.

## Single operation and fresh proof

A private phase authorization binds the service, PCI device and continuously
held provider session. Its provider attempt marker excludes every standalone
mutation path. It cannot be supplied by a client or used as a generic marker
bypass. A failed reset never falls through into firmware startup.

The fixed reset burst, quiet interval, PCI restore, recovery observations and
console guards are retained. Reset mappings are released before fresh firmware
mappings. Discovery is then read twice through the bounded indexed route;
both reads must agree with each other and the retained validated identity.
Fresh parsing, endpoint checks, device resources, memory size, layout, console
and peer observations are required before the firmware phase. Uncertain
selector cleanup invalidates the refreshed proof.

The firmware phase reuses the existing
[SOS checkpoint](PSP-CHECKPOINT.md): all eight selected images are prepared
in separate validated windows before the first PSP mailbox attempt. A prior
pre-SOS operation cannot be followed by staging SOS into an owned buffer.
Every uncertain mailbox outcome preserves the complete staging contents;
there is no overwrite, restoration, retry or automatic reset. The final SOS
command is the final adapter staging, selector, mailbox or flush write.
Only a direct, readable SOS zero-to-nonzero observation can establish the
protocol's startup result; all-ones is never success.

The OS console remains paused through both phases. It resumes only after a
successful firmware protocol and fresh safe postflight observations, followed
by a read-only recheck. This platform console boundary does not authorize
another adapter hardware write. Uncertain compound failures leave the console
paused for capture. If the check after resume fails, a single platform re-pause
is attempted and its actual result is recorded; no adapter retry is allowed.
Cooperative provider ownership and peer checks do not
prove exclusion of firmware or every other hardware accessor, nor do
conservative window exclusions constitute an exclusive VRAM allocator.

## Result interpretation

`EarlyInitRequested` and `EarlyInitTrigger` identify the selected boot even
when the operation refuses. `EarlyInitAttempted`, `EarlyInitPhase`,
`EarlyInitStatus` and `EarlyInitSuccess` describe the compound result; the
existing Mode1 and SOS properties retain their individual diagnostics.

Schema 13 commits only after the complete operation and required publication.
Nested standalone schemas 12 and 10 are suppressed during this operation;
failure cannot retain a successful compound commit. Global `Ready` and
`ColdCycleReplacementValidated` remain false, including after observed SOS
startup. A successful checkpoint is firmware evidence, not authentication,
graphics execution, a daily-driver stability claim or an established power-cycle
replacement.

## Graphics bring-up preflight

Version 0.14.0 adds a read-only register snapshot after the successful
console resume and its postflight check. The original provider session and
peer checks still apply. The fresh discovery table resolves the GC 12.0.0
registers to the target's known BAR5 addresses and resolves the PSP ring
mailbox registers on the same page as the verified SOS register.

`CobaltSurvey,GfxPreflightStatus=observed` commits the snapshot. Each
`CobaltSurvey,GfxPreflight*` numeric property packs two 32-bit samples, with
the first in the low half and the second in the high half. The samples cover
CP status, RLC bootload status, GRBM status, GB address configuration, and
PSP mailbox registers 64, 67, 69–71 and 81. Each SOS sample must match the
live value observed after firmware startup. A bad layout, unreadable register,
or changed context leaves the snapshot incomplete and the earlier firmware
result intact.

The PSP ring samples show the ready response and any preexisting ring state
that a subsequent firmware loader would have to account for. CP status and
the RLC bootload bit provide the same observations used by the
[Linux GC12 autoload wait](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/gfx_v12_0.c).
A later command test still requires a validated firmware load path, isolated
queue memory, and proof that the command processor consumed the packet.

## PSP command ring checkpoint

The host test runs the create and stop protocol against a simulated mailbox.
It requires two agreeing idle snapshots and a dedicated zeroed 4 KiB page
with a verified PSP-visible address. It writes the address and size, checks
their readback, and then issues the kernel-mode ring create command. Each
command gets a 20 ms settling delay. Two agreeing replies must follow an
observed pending command or a new acknowledgement that echoes the command.
The test issues stop only after confirming create. It keeps the page leased
for the boot once programming starts, including on timeout and after a stop
acknowledgement. It never advances the ring write pointer.

The standalone survey's BAR0 window planner checks ranges and exclusions.
The live adapter still needs an allocator that owns a separate page across
the entire transaction, including an uncertain stop. The eight SOS staging
windows must remain reserved for their firmware contents. Linux allocates
a buffer object for its ring. The older Cobalt path uses a fixed VRAM offset,
which is insufficient evidence that the survey owns that page.
[Linux PSP buffer allocation](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_psp.c)
and [Linux PSP v14 ring protocol](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/psp_v14_0.c).
