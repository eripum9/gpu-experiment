#include "../src/gfx_runtime.h"

#include <stdio.h>
#include <string.h>

namespace {
unsigned failures;
#define CHECK(expr) do { if (!(expr)) { \
	printf("FAIL line %d: %s\n", __LINE__, #expr); ++failures; \
} } while (0)

cobalt_gpu_info_v1 identity(uint32_t device, uint32_t se, uint32_t sa,
	uint32_t cu, uint32_t rb, uint32_t max_cu) {
	cobalt_gpu_info_v1 info = {};
	info.version = COBALT_GPU_INFO_VERSION;
	info.size = sizeof(info);
	info.flags = COBALT_GPU_INFO_CAPACITY_VALID;
	if (device != 0x7590) info.flags |= COBALT_GPU_INFO_BRINGUP_ENABLED;
	info.pci_vendor = 0x1002;
	info.pci_device = device;
	info.gfx_target = device == 0x7590 ? COBALT_GPU_GFX_TARGET_1200 : COBALT_GPU_GFX_TARGET_1201;
	info.gc_major = 12;
	info.gc_revision = device == 0x7590 ? 0 : 1;
	info.shader_engines = se;
	info.shader_arrays_per_engine = sa;
	info.wgp_per_array = cu / 2;
	info.cu_per_array = cu;
	info.max_compute_units = max_cu;
	info.render_backends_per_engine = rb;
	info.max_waves_per_simd = 16;
	return info;
}

cobalt_gfx_runtime_v1 full_runtime(const cobalt_gpu_info_v1 &id) {
	cobalt_gfx_runtime_v1 r = {};
	r.version = COBALT_GFX_RUNTIME_VERSION;
	r.size = sizeof(r);
	r.flags = COBALT_GFX_RUNTIME_VALID;
	r.gc_version = (id.gc_major << 16) | (id.gc_minor << 8) | id.gc_revision;
	r.gb_addr_config = 0x2a;
	r.shader_engines = id.shader_engines;
	r.shader_arrays_per_engine = id.shader_arrays_per_engine;
	r.cu_per_array = id.cu_per_array;
	r.render_backends_per_engine = id.render_backends_per_engine;
	r.active_sa_mask = (1u << (id.shader_engines * id.shader_arrays_per_engine)) - 1u;
	r.active_rb_mask = id.shader_engines * id.render_backends_per_engine == 32
		? UINT32_MAX : ((1u << (id.shader_engines * id.render_backends_per_engine)) - 1u);
	for (unsigned se = 0; se < id.shader_engines; ++se) {
		for (unsigned sa = 0; sa < id.shader_arrays_per_engine; ++sa) {
			r.cu_bitmap[se][sa] = id.cu_per_array == 32 ? UINT32_MAX : ((1u << id.cu_per_array) - 1u);
			r.active_cu_count += id.cu_per_array;
		}
	}
	return r;
}

bool decodes(const cobalt_gfx_runtime_v1 &r, const cobalt_gpu_info_v1 &id) {
	cobalt_gfx_runtime_v1 decoded;
	return cobalt_gfx_runtime_v1_decode(&r, sizeof(r), &id, &decoded) != 0;
}
}

int main() {
	/* Full 4 x 2 x 32 layout exercises width-32 masks without undefined shifts. */
	cobalt_gpu_info_v1 max_id = identity(0x7550, 4, 2, 32, 8, 256);
	cobalt_gfx_runtime_v1 maximum = full_runtime(max_id);
	CHECK(maximum.active_rb_mask == UINT32_MAX && maximum.active_cu_count == 256);
	CHECK(decodes(maximum, max_id));

	/* Disabled 0x7590 identity remains valid for a harvested active snapshot. */
	cobalt_gpu_info_v1 disabled = identity(0x7590, 2, 2, 8, 4, 32);
	cobalt_gfx_runtime_v1 harvested = {};
	harvested.version = COBALT_GFX_RUNTIME_VERSION;
	harvested.size = sizeof(harvested);
	harvested.flags = COBALT_GFX_RUNTIME_VALID;
	harvested.gc_version = 12u << 16;
	harvested.gb_addr_config = 1;
	harvested.shader_engines = 2;
	harvested.shader_arrays_per_engine = 2;
	harvested.cu_per_array = 8;
	harvested.render_backends_per_engine = 4;
	harvested.active_sa_mask = 1;
	harvested.active_rb_mask = 3;
	harvested.active_cu_count = 4;
	harvested.cu_bitmap[0][0] = 0x0f;
	CHECK(decodes(harvested, disabled));
	cobalt_gfx_runtime_v1 harvested_sa_without_cu = harvested;
	harvested_sa_without_cu.active_sa_mask |= 2u;
	CHECK(decodes(harvested_sa_without_cu, disabled));
	cobalt_gfx_runtime_v1 rb_on_empty_engine = harvested;
	rb_on_empty_engine.active_rb_mask |= 1u << 4;
	CHECK(!decodes(rb_on_empty_engine, disabled));
	cobalt_gpu_info_v1 bad_capacity = disabled;
	bad_capacity.max_compute_units--;
	cobalt_gfx_runtime_v1 should_clear;
	memset(&should_clear, 0xa5, sizeof(should_clear));
	CHECK(!cobalt_gfx_runtime_v1_decode(&harvested, sizeof(harvested), &bad_capacity, &should_clear));
	CHECK(should_clear.version == 0 && should_clear.active_cu_count == 0);

	/* A one-SA identity must reject data in the unused second wire slot. */
	cobalt_gpu_info_v1 one_sa_id = identity(0x7590, 2, 1, 8, 2, 16);
	cobalt_gfx_runtime_v1 one_sa = {};
	one_sa.version = COBALT_GFX_RUNTIME_VERSION;
	one_sa.size = sizeof(one_sa);
	one_sa.flags = COBALT_GFX_RUNTIME_VALID;
	one_sa.gc_version = 12u << 16;
	one_sa.gb_addr_config = 1;
	one_sa.shader_engines = 2;
	one_sa.shader_arrays_per_engine = 1;
	one_sa.cu_per_array = 8;
	one_sa.render_backends_per_engine = 2;
	one_sa.active_sa_mask = 1;
	one_sa.active_rb_mask = 1;
	one_sa.active_cu_count = 2;
	one_sa.cu_bitmap[0][0] = 3;
	CHECK(decodes(one_sa, one_sa_id));
	cobalt_gfx_runtime_v1 one_sa_bad = one_sa;
	one_sa_bad.cu_bitmap[0][1] = 3;
	CHECK(!decodes(one_sa_bad, one_sa_id));
	one_sa_bad = one_sa;
	one_sa_bad.cu_bitmap[0][0] |= 1u << 8;
	CHECK(!decodes(one_sa_bad, one_sa_id));

	char unaligned[sizeof(maximum) + 1];
	memcpy(unaligned + 1, &maximum, sizeof(maximum));
	cobalt_gfx_runtime_v1 decoded;
	CHECK(cobalt_gfx_runtime_v1_decode(unaligned + 1, sizeof(maximum), &max_id, &decoded));
	CHECK(decoded.active_cu_count == 256);
	CHECK(cobalt_gfx_runtime_v1_decode(&maximum, sizeof(maximum), &max_id, &maximum));
	CHECK(maximum.active_cu_count == 256);

	cobalt_gfx_runtime_v1 bad = maximum;
	bad.flags |= 2; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.gc_version ^= 1; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.shader_engines--; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.gb_addr_config = 0; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.gb_addr_config = UINT32_MAX; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.active_sa_mask |= 0x100; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.active_rb_mask = 0; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.active_cu_count--; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.cu_bitmap[0][0] = 1; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.cu_bitmap[0][0] = 0; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.cu_bitmap[0][0] = 0x55555555; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.cu_bitmap[0][0] = 0xffffffff; bad.active_cu_count++; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.cu_bitmap[0][0] = 0; bad.active_sa_mask &= ~1u; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.active_rb_mask = 1; bad.active_sa_mask &= ~1u; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.active_rb_mask = 1; bad.cu_bitmap[0][0] = 0; bad.cu_bitmap[0][1] = 0; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.cu_bitmap[0][0] = 1; bad.reserved[0] = 1; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.reserved[3] = 1; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.version++; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.size--; CHECK(!decodes(bad, max_id));
	bad = maximum; bad.active_rb_mask = 0x80000000; CHECK(decodes(bad, max_id));
	CHECK(!cobalt_gfx_runtime_v1_decode(&maximum, sizeof(maximum) - 1, &max_id, &decoded));
	CHECK(decoded.version == 0 && decoded.active_cu_count == 0);
	CHECK(!cobalt_gfx_runtime_v1_decode(&maximum, sizeof(maximum), nullptr, &decoded));
	CHECK(decoded.version == 0);

	if (failures == 0) printf("gfx runtime tests passed\n");
	return static_cast<int>(failures);
}
