# Bounded PSP checkpoints

`n48::PspLoader::runKeyDatabase()` is the protocol entry point for an isolated
first-command test. The standalone survey's separately armed 0.7.0 KDB mode
uses it through a bounded hardware adapter; see [the survey documentation](NAVI44-SURVEY.md).
The existing full-chain entry point remains separate.

The method consumes the same fresh preflight authorization as `runChain()`.
Success or rejection prevents another invocation of either method from using
that authorization. It revalidates the container views and complete staging
window, and requires a present KDB image. The caller retains the complete,
immutable package for the entire operation.

The only permitted component sequence is a full 1 MiB staging clear, KDB
copy, MC address write to `C2PMSG_36`, and KDB command `0x00080000` to
`C2PMSG_35`, followed by a bounded ready poll. There is no fallthrough into
SPL, SYS, another component or SOS. The strict path rejects a nonzero or
unreadable SOS observation instead of treating an already running SOS as a
successful skip. An unreadable bootloader status aborts its poll immediately.

The ready observation follows the bit-31 condition used in the pinned
[Linux v6.19 PSP v14 implementation](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/psp_v14_0.c).
A busy sample is not required because completion may precede the first poll.
The raw status must be retained. A returned ready bit is not interpreted here
as proof of authentication, correct GPU MC translation or GPU execution.

The hardware adapter requires discovered and whitelisted register
endpoints, fresh six-register preflight, validated live mappings, the bounded
staging and HDP visibility path, and one persistent provider attempt marker.
Its stable-resource guards must be separate from the PSP protocol state that
the command intentionally changes. Conservative console and firmware-memory
exclusions do not constitute an exclusive VRAM allocation.

Once a command has been dispatched, a timeout or failed read can leave PSP
access to the staging data unresolved. The one-command adapter must not
overwrite that window, replay the command, continue into the chain, restore mailboxes or
reset the GPU automatically. Such a result needs recorded diagnostics and a
known reset boundary before another hardware attempt. The protocol API alone
cannot enforce that provider lifetime or recovery policy.

## Offline KDB and SPL checkpoint

`runKeyDatabaseAndSpl(splOffset)` prepares the next bounded sequence. It is
host-tested protocol code only: the 0.7.0 survey does not call it, and this
change adds no firmware boot flag or hardware deployment.

The configured `fw_pri` offset selects the KDB window. `splOffset` must select
a second disjoint, aligned, complete 1 MiB window inside the validated MC
range, with a representable mailbox address. All source views and both windows
are validated before preparation. Entry consumes the same one-use preflight
authorization as the KDB-only and full-chain methods, including on refusal.

Both windows are cleared and their exact component views copied before the
first mailbox store. The method then sends KDB `0x00080000`, waits for ready
with SOS down, sends SPL `0x10000000` using the second window's address, and
waits for ready again. It issues no VRAM writes after the first mailbox
attempt, including on a timeout or an unreadable register. It never enters
SYS, another component, or SOS, and does not retry either command.

Keeping separate buffers avoids overwriting data already handed to the PSP.
The pinned PSP 14.0.2 SPL component is 832 bytes, version `0x01003b00`, at
package offset `0x66a20`. A successful return reports two ready observations;
it does not prove authentication or GPU execution. A future hardware adapter
still needs separate bounded mappings, ownership and visibility checks for
both buffers, a single persistent attempt marker, and preservation of both
buffers after dispatch. The KDB-only hardware result does not supply those
new proofs or establish an exclusive allocation for either window.
