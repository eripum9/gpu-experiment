#include "../src/gpu_info_builder.hpp"

#include <stdio.h>
#include <string.h>

namespace {
unsigned failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
	printf("FAIL line %d: %s\n", __LINE__, #expr); ++failures; \
} } while (0)

IpDiscovery::GcTopology topology(uint32_t se = 4, uint32_t sa = 2,
	uint32_t wgp = 4, uint32_t rb = 4, uint32_t waves = 32,
	uint32_t cu = 8, uint32_t maxCu = 64) {
	IpDiscovery::GcTopology t = { se, sa, wgp, rb, waves, cu, maxCu };
	return t;
}

bool decodes(const cobalt_gpu_info_v1 &info) {
	cobalt_gpu_info_v1 output;
	return cobalt_gpu_info_v1_decode(&info, sizeof(info), &output) != 0;
}
}

int main() {
	cobalt_gpu_info_v1 info;
	CHECK(cobalt::make_gpu_info(0x1002, 0x7550, 0x01, 0x1002, 0x0e3a,
		{12, 0, 1}, topology(), info));
	CHECK(info.pci_device == 0x7550 && info.gfx_target == COBALT_GPU_GFX_TARGET_1201);
	CHECK(info.max_compute_units == 64 &&
		(info.flags & COBALT_GPU_INFO_BRINGUP_ENABLED) != 0);
	CHECK(decodes(info));
	cobalt_gpu_info_v1 navi48 = info;
	navi48.flags &= ~COBALT_GPU_INFO_BRINGUP_ENABLED;
	CHECK(decodes(navi48));
	CHECK(cobalt_gpu_info_v1_decode(&navi48, sizeof(navi48), &navi48));
	CHECK(navi48.pci_device == 0x7550 && navi48.max_compute_units == 64);
	union OverlapBuffer {
		cobalt_gpu_info_v1 aligned;
		unsigned char bytes[sizeof(cobalt_gpu_info_v1) + 1];
	} overlap;
	memcpy(overlap.bytes + 1, &info, sizeof(info));
	CHECK(cobalt_gpu_info_v1_decode(overlap.bytes + 1, sizeof(info), &overlap.aligned));
	CHECK(overlap.aligned.pci_device == 0x7550 && overlap.aligned.max_compute_units == 64);

	CHECK(cobalt::make_gpu_info(0x1002, 0x7551, 0x02, 0x1002, 0x0e3a,
		{12, 0, 1}, topology(), info));
	CHECK(info.pci_device == 0x7551 && decodes(info));

	CHECK(cobalt::make_gpu_info(0x1002, 0x7590, 0x03, 0x1002, 0x0e3a,
		{12, 0, 0}, topology(2, 2, 4, 4, 16, 8, 32), info));
	CHECK(info.gfx_target == COBALT_GPU_GFX_TARGET_1200 && info.max_compute_units == 32);
	CHECK((info.flags & COBALT_GPU_INFO_BRINGUP_ENABLED) == 0 && decodes(info));

	char unaligned[sizeof(info) + 1];
	memcpy(unaligned + 1, &info, sizeof(info));
	cobalt_gpu_info_v1 decoded;
	CHECK(cobalt_gpu_info_v1_decode(unaligned + 1, sizeof(info), &decoded));
	CHECK(decoded.pci_device == info.pci_device && decoded.max_compute_units == 32);
	CHECK(!cobalt_gpu_info_v1_decode(nullptr, sizeof(info), &decoded));
	CHECK(decoded.version == 0 && decoded.pci_device == 0);
	CHECK(!cobalt_gpu_info_v1_decode(&info, sizeof(info) - 1, &decoded));
	CHECK(!cobalt_gpu_info_v1_decode(&info, sizeof(info) + 1, &decoded));
	CHECK(!cobalt_gpu_info_v1_decode(&info, sizeof(info), nullptr));

	cobalt_gpu_info_v1 bad = info;
	bad.version = 2; CHECK(!decodes(bad));
	bad = info; bad.size = 127; CHECK(!decodes(bad));
	bad = info; bad.flags |= 4; CHECK(!decodes(bad));
	bad = info; bad.flags &= ~COBALT_GPU_INFO_CAPACITY_VALID; CHECK(!decodes(bad));
	bad = info; bad.reserved[12] = 1; CHECK(!decodes(bad));
	bad = info; bad.pci_device = 0xffff; CHECK(!decodes(bad));
	bad = info; bad.pci_vendor = 0x10de; CHECK(!decodes(bad));
	bad = info; bad.gc_revision = 1; CHECK(!decodes(bad));
	bad = info; bad.gfx_target = COBALT_GPU_GFX_TARGET_1201; CHECK(!decodes(bad));
	bad = info; bad.flags |= COBALT_GPU_INFO_BRINGUP_ENABLED; CHECK(!decodes(bad));
	bad = info; bad.pci_revision = 0x100; CHECK(!decodes(bad));
	bad = info; bad.pci_subsystem_device = 0x10000; CHECK(!decodes(bad));

	for (unsigned i = 0; i < 7; ++i) {
		bad = info;
		switch (i) {
		case 0: bad.shader_engines = 0; break;
		case 1: bad.shader_arrays_per_engine = 0; break;
		case 2: bad.wgp_per_array = 0; break;
		case 3: bad.render_backends_per_engine = 0; break;
		case 4: bad.max_waves_per_simd = 0; break;
		case 5: bad.cu_per_array = 0; break;
		default: bad.max_compute_units = 0; break;
		}
		CHECK(!decodes(bad));
	}
	bad = info; bad.shader_engines = 5; CHECK(!decodes(bad));
	bad = info; bad.shader_arrays_per_engine = 3; CHECK(!decodes(bad));
	bad = info; bad.wgp_per_array = 17; CHECK(!decodes(bad));
	bad = info; bad.cu_per_array = 33; CHECK(!decodes(bad));
	bad = info; bad.max_waves_per_simd = 1025; CHECK(!decodes(bad));
	bad = info; bad.render_backends_per_engine = 18; CHECK(!decodes(bad));
	bad = info; bad.render_backends_per_engine = 3; CHECK(!decodes(bad));
	bad = info; bad.wgp_per_array = UINT32_MAX; CHECK(!decodes(bad));
	bad = info; bad.shader_engines = UINT32_MAX; CHECK(!decodes(bad));
	bad = info; bad.max_compute_units = UINT32_MAX; CHECK(!decodes(bad));
	bad = info; bad.cu_per_array = 7; CHECK(!decodes(bad));
	bad = info; bad.max_compute_units = 63; CHECK(!decodes(bad));

	IpDiscovery::GcTopology invalid = topology();
	invalid.shaderEngines = UINT32_MAX;
	info.pci_device = 0x7550;
	CHECK(!cobalt::make_gpu_info(0x1002, 0x7550, 0, 0, 0, {12, 0, 1}, invalid, info));
	CHECK(info.version == 0 && info.pci_device == 0);
	CHECK(!cobalt::make_gpu_info(0x1002, 0x7550, 0, 0, 0, {12, 0, 0}, topology(), info));
	CHECK(!cobalt::make_gpu_info(0x1002, 0xffff, 0, 0, 0, {12, 0, 1}, topology(), info));

	if (failures == 0) printf("gpu info tests passed\n");
	return static_cast<int>(failures);
}
