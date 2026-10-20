#ifndef Cobalt64_gpu_info_builder_hpp
#define Cobalt64_gpu_info_builder_hpp

#include "gpu_info.h"
#include "gpu_profile.hpp"
#include "gfx_topology.hpp"

namespace cobalt {

inline bool make_gpu_info(uint16_t vendor, uint16_t device, uint8_t revision,
                          uint16_t subsystemVendor, uint16_t subsystemDevice,
                          Version actualGc, const IpDiscovery::GcTopology &topology,
                          struct cobalt_gpu_info_v1 &out)
{
	out = {};
	const GpuProfile *profile = profile_for_pci(vendor, device);
	if (profile == nullptr || !gc_matches(*profile, actualGc) ||
	    !gfx_topology_compatible(profile->family, actualGc, topology)) return false;

	uint32_t target;
	switch (profile->family) {
	case Family::Navi44: target = COBALT_GPU_GFX_TARGET_1200; break;
	case Family::Navi48: target = COBALT_GPU_GFX_TARGET_1201; break;
	default: return false;
	}

	out.version = COBALT_GPU_INFO_VERSION;
	out.size = sizeof(out);
	out.flags = COBALT_GPU_INFO_CAPACITY_VALID |
		(profile->bringupEnabled ? COBALT_GPU_INFO_BRINGUP_ENABLED : 0u);
	out.pci_vendor = vendor;
	out.pci_device = device;
	out.pci_revision = revision;
	out.pci_subsystem_vendor = subsystemVendor;
	out.pci_subsystem_device = subsystemDevice;
	out.gfx_target = target;
	out.gc_major = actualGc.major;
	out.gc_minor = actualGc.minor;
	out.gc_revision = actualGc.revision;
	out.shader_engines = topology.shaderEngines;
	out.shader_arrays_per_engine = topology.shaderArraysPerEngine;
	out.wgp_per_array = topology.wgpPerArray;
	out.cu_per_array = topology.cuPerArray;
	out.max_compute_units = topology.maxComputeUnits;
	out.render_backends_per_engine = topology.renderBackendsPerEngine;
	out.max_waves_per_simd = topology.maxWavesPerSimd;
	return true;
}

} // namespace cobalt

#endif
