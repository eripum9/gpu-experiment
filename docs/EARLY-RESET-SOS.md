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
[early reset test](EARLY-MODE1-RESET.md), using a version 0.13.0 private plan
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
