Mesa patches (RADV Darwin / macOS port for the Navi 48 native kext)
===================================================================

These twelve patches add a macOS backend to Mesa's RADV Vulkan driver so that it
talks to the Navi48 bring-up kext (user-client ABI "N48N") instead of a DRM
node. Only our changes are included, not the Mesa tree.

Upstream base (apply on top of exactly this commit):
    mesa  f5cb8ee032adabef599ae892ec4e42d796b84da9   (VERSION 26.3.0-devel)
    https://gitlab.freedesktop.org/mesa/mesa.git

Licence: Mesa is MIT licensed. These patches are changes to Mesa and are
released under the same licence (see Mesa's docs/license.rst and
third-party/THIRD-PARTY-LICENSES.txt).

Apply:
    git clone https://gitlab.freedesktop.org/mesa/mesa.git
    cd mesa
    git checkout f5cb8ee032adabef599ae892ec4e42d796b84da9
    for patch in /path/to/Navi48-MacOS/mesa-patches/*.patch; do
        git apply "$patch" || exit 1
    done
Apply in filename order. Patches 0010 through 0012 are plain diffs; earlier patches
also contain mail headers with placeholder author/date fields.

Order matters: 0001 .. 0012. The kext ABI header that patches 0002-0004 mirror
is src/navi48-bringup/src/Navi48NativeABI.h in this repository; Mesa's copy and
the kext's copy must be the same ABI version (currently 1.11 or newer).

Patch 0010 consumes the validated Cobalt,GpuInfo-v1 identity property and
preserves actual native PCI identity. It requires a matching Cobalt kernel
driver and refuses gfx1200/Navi 44; it does not create a gfx1200 device record
or replace canned active-unit information. See docs/GPU-IDENTITY.md.

Patch 0011 requires Cobalt,GfxRuntime-v1 from the same owner and uses the
validated active CU/RB masks, dimensions, GC version and tiling configuration.
It checks those values against live QueryInfo. Other gfx1201 parameters remain
template-based and gfx1200 remains disabled. See docs/GFX-RUNTIME.md.

Patch 0012 adds the verified gfx1200 hardware reference for offline/runtime
overlay tests. It preserves platform memory policy, leaves CP firmware
versions unset, and keeps the native gfx1200 refusal. Full Mesa CI runs the
real chip, memory and hardware-info functions for both families.

Check patch application and shared-header parity without compiling:
    python tools/ci/check_mesa_patches.py --apply-only

On macOS with clang, Meson, Ninja, Mako, packaging, PyYAML and glslang available:
    python tools/ci/check_mesa_patches.py --build-radv
This runs native transport simulations, compiles the full x86_64 RADV dylib,
and executes the device-info integration test linked to Mesa's AMD common code.
It saves a compile-only artifact under build/mesa-radv-compile-check; it does
not install the library or an ICD. GitHub Actions runs this beside the kext
compile job. Passing these checks is not a GPU acceleration test.
