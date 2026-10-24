# Manual SMU Mode 1 reset diagnostic

Version 0.11.0 adds a separate, manually triggered software-reset experiment
for Navi44 / MP1 14.0.2. It tests the SMU debug route selected by Linux for
this hardware. It does not enable graphics acceleration, load firmware after
the reset, or establish that software reset can replace a cold power cycle.

Version 0.11.1 adds diagnostics for the initial provider-client ownership
check. It preserves the requirement that the survey be the GPU's only attached
IOService client and does not add any peer exceptions or reset retries.

## Arming and running

The diagnostic requires these four boot arguments, each equal to numeric 1:

```
cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-mode1=1
```

All other writable survey modes must be off: `aperture`, `staging`, `kdb`,
`spl`, `presos`, and `sos`. Mixed configurations refuse before the survey
performs its indexed accesses. An armed boot collects the existing discovery,
passive state and console information; **it never issues a reset at boot**.
The service must reach the valid passive-console checkpoint before accepting
a manual request.

The package contains `mode1-reset` and `test-software-reset.sh`. On the test
installation, save work and run the wrapper from the mounted USB:

```sh
sudo sh /Volumes/TAHOE/test-software-reset.sh --run
```

The wrapper captures the initial state, requests one reset, captures the
result even when the request fails, saves logs on the USB, and attempts a
normal reboot. Select Windows Boot Manager afterwards. A GPU reset can blank
the display; the wrapper is intended to continue collecting without desktop
interaction. A kernel panic or hard hang can still require manual recovery.
Running the helper with `--help` performs no reset or reboot.

The underlying client requires administrator privilege and an explicit
`--run-mode1-reset` argument. It sends a single fixed request dictionary to
the unique survey service. The kernel repeats the privilege, arming,
dictionary, provider and one-attempt checks. This interface accepts no raw
register addresses or arbitrary command values.

## Hardware sequence

The kernel reparses its retained, validated discovery snapshot and resolves
three MP1 segment-1 register indices: parameter `0x75`, message `0x8b`, and
response `0x76`. They correspond to C2PMSG 53, 75, and 54. They are not the
normal PPSMC mailbox: normal opcode `0x02` means GetSmuVersion, and is never
repurposed as a reset command.

Fresh PCI identity, BAR descriptors, cooperative ownership, console layout,
PSP state and framebuffer geometry are checked before dispatch. Initial SOS
may be zero or a readable nonzero value. All-ones preflight reads refuse.
The driver saves PCI state and disables bus mastering, checking readback;
the SDK's bus-master setter returns the previous bit, rather than success.

The debug burst is fixed: parameter 0, Mode 1 message 2, then response 0.
There are no test-driver reads, guards or logs between the stores. The driver
then fences and sleeps for one second without accessing the device. It
restores PCI state once and checks identity, command and BAR state before
resuming MMIO observations. No retry, alternative reset method, VBIOS
execution, VRAM clear, framebuffer reprogramming or firmware load follows.

Recovery polling is bounded to 5,000 samples. Two consecutive samples must
show a readable PSP bootloader-ready bit, SOS zero and the original plausible
memory size. Transitional busy or all-ones register values after reset may
be polled; loss of provider ownership or PCI/BAR context ends the attempt.
Final console and framebuffer-layout checks must also pass. All temporary
maps and ownership are released before result publication.

## Interpreting results

A request can reach the driver and still return an IOKit error before any
reset operation. In particular, `Reason=peer-refused`, `Status=not-run`,
`StoresIssued=0` and `PciMutationAttempted=false` mean that the initial
ownership check refused the request. They do not establish which peer or
iterator condition caused the refusal. The `Mode1ResetPeerCensus` properties
record that exact check's iterator state, bounded counts and first unexpected
class, and distinguish an extra client from an unavailable or invalid census.
An invalid iterator's partial counts cannot establish that peers are absent.

The helper also supports a read-only inspection:

```sh
/Volumes/TAHOE/mode1-reset --inspect-peers
```

This lists the survey's PCI provider and its direct IOService-plane children
without requesting a reset or opening the device. The trigger prints this
inventory before its single request, and the collector saves it when the
helper is available. These user-space observations happen at a different time
from the kernel check and do not override its decision.

`Mode1Reset` properties record the attempted writes, PCI save/restore,
quiet interval, initial/final raw observations, recovery polling and status.
Schema 11 requires complete publication and successful recovery/postflight
checks. Failure cannot retain an earlier schema-11 success. Global `Ready`
remains false.

`RecoveryObserved` means the required post-command state was observed.
`ResetTransitionObserved` additionally requires initial SOS nonzero and final
SOS zero. An initial and final zero value cannot prove a reset occurred.
`ColdCycleReplacementValidated` remains false in this standalone diagnostic:
neither a successful MMIO store nor readable recovery establishes the full
firmware-buffer lifetime boundary or successful subsequent initialization.

Ownership is cooperative, including the existing self-only client census;
the test cannot guarantee exclusion of independent firmware or OS console
accesses. Linux's complete recovery also reinitializes GPU subsystems. This
experiment observes whether the minimal reset path recovers on this machine.

## Primary references

Protocol facts are pinned to Linux commit
`5b0764a53235d3c77e1ed674e836e1b3fe1a4b1f`:

- [SOC24 reset selection](https://github.com/torvalds/linux/blob/5b0764a53235d3c77e1ed674e836e1b3fe1a4b1f/drivers/gpu/drm/amd/amdgpu/soc24.c)
- [SMU14 reset and debug mailbox configuration](https://github.com/torvalds/linux/blob/5b0764a53235d3c77e1ed674e836e1b3fe1a4b1f/drivers/gpu/drm/amd/pm/swsmu/smu14/smu_v14_0_2_ppt.c)
- [Debug store ordering](https://github.com/torvalds/linux/blob/5b0764a53235d3c77e1ed674e836e1b3fe1a4b1f/drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c)
- [Generated MP1 register definitions](https://github.com/torvalds/linux/blob/5b0764a53235d3c77e1ed674e836e1b3fe1a4b1f/drivers/gpu/drm/amd/include/asic_reg/mp/mp_14_0_2_offset.h)
- [PCI and PSP recovery](https://github.com/torvalds/linux/blob/5b0764a53235d3c77e1ed674e836e1b3fe1a4b1f/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c)
