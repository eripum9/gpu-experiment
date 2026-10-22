# Bounded PSP firmware staging

`src/navi48-bringup/src/psp_staging.hpp` provides the bounds and ordering part
of a future firmware staging backend. It is tested on the host alongside the
production `PspLoader`, and is not wired into either kext. It adds no boot
argument, hardware enablement, embedded firmware or deployment change.

The helper accepts an explicit, 1 MiB-aligned VRAM offset whose full 1 MiB
extent cannot overflow. Explicit offset zero is structurally valid; the
caller must establish whether that interval is actually available. There is
no unknown-console fallback or implicit default address.

Each image starts with `zero(base, 1 MiB)`. A successful clear and flush grants
one `copy(base, source, length)` of a nonempty prefix no larger than 1 MiB.
The copy consumes that permission before calling the backend. A subsequent
image needs a new successful clear. Wrong offsets, sizes, source pointers or
call order permanently fail that helper instance before any further backend
access. Clearing invalidates the previous payload-completion state.

Transfers use chunks of at most 4 KiB. A context check surrounds each chunk
and the completion flush. A failing check, transfer or flush permanently
latches the first error and clears all completion flags. A later good check
cannot resume the transfer. There is no automatic retry, rollback or cleanup
write through a failed context. Issued-byte, chunk and flush counters include
failing backend calls and do not claim that a partial write completed.

The caller must serialize access, keep the helper and source buffers alive,
and supply non-throwing backend callbacks. A callback that reenters `zero` or
`copy` on the same helper permanently fails it. Copying and moving the helper
are disabled so its clear permission cannot be duplicated that way.

For a real GPU backend, the caller still needs to establish all of the following:

- The target PCI identity, IP versions, provider ownership and other clients.
- A validated live mapping of the entire selected staging window, exclusions
  for the console and firmware reservations, and the correct GPU MC address.
- One-attempt authorization and fresh protocol/state checks in that same boot.
- Bounded mapped I/O and device-state guards within each backend operation.
- CPU store fencing, the validated HDP flush endpoint and its posted completion
  read before `flushWrites()` returns success.
- Safe source-buffer lifetime for every validated firmware component.

`payloadVisible()` records successful local transfer completion. It is not a
live ownership test, proof of runtime VRAM availability, or permission to send
a PSP mailbox command. The future register backend must validate its own
accesses. A host simulation likewise cannot validate BAR-to-MC translation,
actual HDP behavior, PSP firmware authentication or graphics acceleration.

The deployed Navi 44 aperture diagnostic remains a separate hardware
checkpoint. Its captured result must be reviewed before this helper is
connected to a hardware-writing PSP adapter. The current Navi 44 bring-up
and acceleration gates remain disabled.
