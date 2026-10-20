#include "../src/gpu_profile.hpp"

using cobalt::Family;
using cobalt::Version;

static_assert(cobalt::profile_for_pci(0x1002, 0x7550) != nullptr, "RX 9070 must be recognized");
static_assert(cobalt::profile_for_pci(0x1002, 0x7550)->family == Family::Navi48, "7550 is Navi48");
static_assert(cobalt::profile_for_pci(0x1002, 0x7550)->bringupEnabled, "Navi48 path remains enabled");
static_assert(cobalt::profile_for_pci(0x1002, 0x7551)->gfxTarget[4] == '2', "7551 is gfx1201");
static_assert(cobalt::profile_for_pci(0x1002, 0x7590) != nullptr, "user RX 9060 XT must be recognized");
static_assert(cobalt::profile_for_pci(0x1002, 0x7590)->family == Family::Navi44, "7590 is Navi44");
static_assert(!cobalt::profile_for_pci(0x1002, 0x7590)->bringupEnabled, "Navi44 remains disabled");
static_assert(cobalt::profile_for_pci(0x1002, 0x7590)->gc.major == 12 &&
	          cobalt::profile_for_pci(0x1002, 0x7590)->gc.minor == 0 &&
	          cobalt::profile_for_pci(0x1002, 0x7590)->gc.revision == 0, "Navi44 GC expected version");
static_assert(cobalt::profile_for_pci(0x1002, 0x7550)->gc.revision == 1, "Navi48 GC expected version");
static_assert(cobalt::profile_for_pci(0x10de, 0x7590) == nullptr, "wrong vendor rejected");
static_assert(cobalt::profile_for_pci(0x1002, 0xffff) == nullptr, "unknown AMD device rejected");
static_assert(cobalt::gc_matches(*cobalt::profile_for_pci(0x1002, 0x7550), {12, 0, 1}), "matching Navi48 GC accepted");
static_assert(!cobalt::gc_matches(*cobalt::profile_for_pci(0x1002, 0x7550), {12, 0, 0}), "mismatching GC rejected");
static_assert(!cobalt::gc_matches(*cobalt::profile_for_pci(0x1002, 0x7550), {0, 0, 0}), "missing GC rejected");

int main() { return 0; }
