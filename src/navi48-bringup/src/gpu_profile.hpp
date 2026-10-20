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
	Version psp;
	Version smu;
	Version sdma;
	Version dcn;
};

inline constexpr GpuProfile kNavi48Profile = {
	Family::Navi48, "Navi 48", "gfx1201", {12, 0, 1}, true,
	{14, 0, 3}, {14, 0, 3}, {7, 0, 1}, {4, 1, 0}
};
inline constexpr GpuProfile kNavi44Profile = {
	Family::Navi44, "Navi 44", "gfx1200", {12, 0, 0}, false,
	{14, 0, 2}, {14, 0, 2}, {7, 0, 0}, {4, 1, 0}
};

constexpr const GpuProfile *profile_for_pci(uint16_t vendor, uint16_t device) {
	if (vendor != 0x1002) return nullptr;
	if (device == 0x7550 || device == 0x7551) return &kNavi48Profile;
	if (device == 0x7590) return &kNavi44Profile;
	return nullptr;
}

constexpr bool version_matches(Version expected, Version actual) {
	return expected.major == actual.major && expected.minor == actual.minor &&
	       expected.revision == actual.revision;
}

constexpr bool gc_matches(const GpuProfile &profile, Version version) {
	return version_matches(profile.gc, version);
}

constexpr bool critical_ips_match(const GpuProfile &profile, Version gc,
                                 Version psp, Version smu, Version sdma, Version dcn) {
	return gc_matches(profile, gc) && version_matches(profile.psp, psp) &&
	       version_matches(profile.smu, smu) && version_matches(profile.sdma, sdma) &&
	       version_matches(profile.dcn, dcn);
}

} // namespace cobalt

#endif
