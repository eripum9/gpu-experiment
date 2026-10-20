# SMU 14 protocol preparation

Navi 44 remains disabled in the PCI profile and excluded from IOKit matching.
These protocol definitions do not authorize driver attachment or establish
that power management works on an RX 9060 XT.

## Verified common interface

Linux commit `05f7e89ab9731565d8a62e3b5d1ec206485eeb0b` dispatches both
SMU 14.0.2 and 14.0.3 through `smu_v14_0_2_set_ppt_funcs`. They share the
twenty PPSMC operations currently used by this driver and expected driver
interface version `0x2E`. No separate 14.0.3 opcode map is assumed.

`smu_protocol.hpp` selects an immutable descriptor from the device family
and discovered MP1 version. Unknown families and mismatched versions have
no fallback. The mailbox uses MP1 segment 1 and dword offsets `0x82`,
`0x92`, `0x9A` for message, argument, and response. Clock IDs include
GFX=0 and SOC=1; the firmware power-source enum is AC=0, DC=1.

The previous setup sent 1 while labelling it AC. Setup now takes the AC
value from the verified descriptor.

## Limited candidate capabilities

| Identity | Available operations in this phase |
| --- | --- |
| Navi 44 + MP1 14.0.2 | TestMessage, GetSmuVersion, GetDriverIfVersion |
| Navi 48 + MP1 14.0.3 | Existing verified opcode set and legacy policies |
| Other family/version combinations | Refused before mailbox access |

Candidate Navi 44 operations exclude table addressing and transfer, feature
control, frequency changes, calibration, default powerplay tables, metrics
decoding and DAL display-clock experiments. High-level refusals precede
VRAM staging as well as mailbox writes. The optional startup survey uses
the same validated transport and lock instead of a separate raw sender.

The shared opcode map does not validate a power policy. Linux has additional
version-specific behavior: its GFX-only feature enable is available on
14.0.2 with parameter 4 and unsupported on 14.0.3. That operation is not
introduced here. Existing Navi 48 feature sequencing and its legacy clock
policy are retained, apart from the AC encoding correction.

The target's actual GetDriverIfVersion reply is still unmeasured. Enabling
power management requires validating that reply, table layout and size,
feature selection, VBIOS power data, calibration, and recovery behavior.

## Primary references

- [Version dispatch](https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/drivers/gpu/drm/amd/pm/swsmu/amdgpu_smu.c)
- [Common PPSMC messages](https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v14_0_2_ppsmc.h)
- [Clock and power-source enums](https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu14_driver_if_v14_0.h)
- [Expected driver interface versions](https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/drivers/gpu/drm/amd/pm/swsmu/inc/smu_v14_0.h)
- [PPT functions and feature behavior](https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/drivers/gpu/drm/amd/pm/swsmu/smu14/smu_v14_0_2_ppt.c)
