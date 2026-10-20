#ifndef Cobalt64_gfx_topology_hpp
#define Cobalt64_gfx_topology_hpp

#include "gpu_profile.hpp"
#include "ipdiscovery.hpp"

namespace cobalt {

inline constexpr uint32_t kGfxMaxShaderEngines = 4;
inline constexpr uint32_t kGfxMaxShaderArraysPerEngine = 2;
inline constexpr uint32_t kGfxMaxComputeUnitsPerArray = 32;
inline constexpr uint32_t kGfxMaxRenderBackends = 32;

// Check that the discovered GC capacity is internally consistent and fits
// the limits of the current GFX configuration structures.
inline bool gfx_topology_compatible(Family family, Version actualGc,
                                    const IpDiscovery::GcTopology &topology) {
	const GpuProfile *profile = nullptr;
	switch (family) {
	case Family::Navi44: profile = &kNavi44Profile; break;
	case Family::Navi48: profile = &kNavi48Profile; break;
	default: return false;
	}
	if (!gc_matches(*profile, actualGc)) return false;

	if (topology.shaderEngines == 0 ||
	    topology.shaderArraysPerEngine == 0 ||
	    topology.wgpPerArray == 0 ||
	    topology.renderBackendsPerEngine == 0 ||
	    topology.maxWavesPerSimd == 0 ||
	    topology.cuPerArray == 0 ||
	    topology.maxComputeUnits == 0)
		return false;

	if (topology.shaderEngines > kGfxMaxShaderEngines ||
	    topology.shaderArraysPerEngine > kGfxMaxShaderArraysPerEngine ||
	    topology.wgpPerArray > 16 ||
	    topology.maxWavesPerSimd > 1024 ||
	    topology.cuPerArray > kGfxMaxComputeUnitsPerArray)
		return false;

	if (topology.renderBackendsPerEngine % topology.shaderArraysPerEngine != 0)
		return false;
	// Check the bound before multiplying, so hostile UINT32_MAX data cannot
	// wrap the render-backend mask capacity check.
	if (topology.renderBackendsPerEngine >
	    kGfxMaxRenderBackends / topology.shaderEngines)
		return false;

	if (topology.wgpPerArray * 2u != topology.cuPerArray)
		return false;
	const uint32_t totalComputeUnits = topology.shaderEngines *
		topology.shaderArraysPerEngine * topology.cuPerArray;
	return totalComputeUnits == topology.maxComputeUnits;
}

} // namespace cobalt

#endif
