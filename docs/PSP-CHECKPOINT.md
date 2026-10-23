# One-command PSP checkpoint

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
access to the staging data unresolved. The adapter must not overwrite that
window, replay the command, continue into the chain, restore mailboxes or
reset the GPU automatically. Such a result needs recorded diagnostics and a
known reset boundary before another hardware attempt. The protocol API alone
cannot enforce that provider lifetime or recovery policy.
