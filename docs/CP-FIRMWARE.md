# CP firmware metadata

`Cobalt,CpFirmware-v1` is a separate 64-byte OSData record on the owning
Navi48Bringup service. `cp_firmware.h` defines its C11/C++ wire layout and
decoder. It carries the GC version and ME, PFP and MEC firmware versions
and feature versions. It does not extend the N48N user-client ABI.

The producer reads metadata from the same embedded CP blobs used by the
firmware loader. It requires complete, valid GC12 headers and all seven
expected payloads: PFP code and P0 stack, ME code and P0 stack, and MEC
code plus P0/P1 stacks. Every entry must match its source bytes and size,
be unique, and have been staged by the actual loader. Publication also
requires successful completion of the PSPFwLoad stage. Merely finding a
blob or finishing its extraction cannot publish the record.

The flag means the PSP load sequence completed for these payloads. It does
not prove that CP executed them, that queues work, or that acceleration
is available. CP initialization and PM4 execution tests remain separate.

Service metadata clears on start, rejection, a new bring-up attempt and
stop. A successful fresh load also saves the record on its IOPCIDevice,
alongside the existing same-boot provisioning marker. When adopting firmware
already provisioned this boot, the service may restore only that saved,
validated record. It never substitutes the current build's blob versions
for firmware loaded earlier. An older provisioning attempt without saved
metadata requires a fresh boot before the updated native Mesa path can open.

Mesa patch 0013 requires the property from the same owner as GPU identity
and GFX runtime metadata, before IOServiceOpen. Missing, malformed or
GC-mismatched data refuses native initialization. Mesa retains an owned
snapshot and replaces only its CP firmware query fields. Explicit MOCK
and HOST_BO modes keep their existing synthetic firmware data.

The current pinned blobs contain ME 3110, PFP 3220 and MEC 3490, with feature
version 29, for both embedded families. The target's Linux capture reports
2930/3010/3250 instead; those Linux versions are not macOS inputs. The
gfx1200 reference starts with zero firmware metadata, and a separate
validated firmware overlay is tested for both families. Native Navi 44
attachment remains disabled.

Host tests cover strict blob bounds, missing/duplicate/unstaged payloads,
publication/adoption conditions, exact wire size, GC matching, invalid
flags/reserved fields, and unaligned or overlapping buffers. Mesa tests
exercise owner selection, pre-open refusals, snapshot ownership and
firmware overlays. CI still builds compile-only artifacts without loading
the driver or accessing GPU hardware.
