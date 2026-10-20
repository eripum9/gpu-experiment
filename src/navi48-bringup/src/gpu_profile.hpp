#ifndef Cobalt64_gpu_profile_hpp
#define Cobalt64_gpu_profile_hpp

#include <stdint.h>

namespace cobalt {

enum class Family : uint8_t { Unknown, Navi44, Navi48 };

struct Version {
	uint8_t major;
	uint8_t minor;
	uint8_t revision;
};

struct GpuProfile {
	Family family;
	const char *name;
	const char *gfxTarget;
	Version gc;
	bool bringupEnabled;
};

inline constexpr GpuProfile kNavi48Profile = {
	Family::Navi48, "Navi 48", "gfx1201", {12, 0, 1}, true
};
inline constexpr GpuProfile kNavi44Profile = {
	Family::Navi44, "Navi 44", "gfx1200", {12, 0, 0}, false
};

constexpr const GpuProfile *profile_for_pci(uint16_t vendor, uint16_t device) {
	if (vendor != 0x1002) return nullptr;
	if (device == 0x7550 || device == 0x7551) return &kNavi48Profile;
	if (device == 0x7590) return &kNavi44Profile;
	return nullptr;
}

constexpr bool gc_matches(const GpuProfile &profile, Version version) {
	return profile.gc.major == version.major &&
	       profile.gc.minor == version.minor &&
	       profile.gc.revision == version.revision;
}

} // namespace cobalt

#endif
