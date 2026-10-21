/* Verify the GFX runtime wire decoder remains usable as C11. */
#include "../src/gfx_runtime.h"

static struct cobalt_gpu_info_v1 make_identity(uint32_t device)
{
	struct cobalt_gpu_info_v1 id = {0};
	id.version = COBALT_GPU_INFO_VERSION;
	id.size = sizeof(id);
	id.flags = COBALT_GPU_INFO_CAPACITY_VALID;
	if (device != 0x7590u) id.flags |= COBALT_GPU_INFO_BRINGUP_ENABLED;
	id.pci_vendor = 0x1002u;
	id.pci_device = device;
	id.gfx_target = device == 0x7590u ? COBALT_GPU_GFX_TARGET_1200 : COBALT_GPU_GFX_TARGET_1201;
	id.gc_major = 12u;
	id.gc_revision = device == 0x7590u ? 0u : 1u;
	id.shader_engines = device == 0x7590u ? 2u : 4u;
	id.shader_arrays_per_engine = 2u;
	id.wgp_per_array = device == 0x7590u ? 4u : 16u;
	id.cu_per_array = device == 0x7590u ? 8u : 32u;
	id.max_compute_units = device == 0x7590u ? 32u : 256u;
	id.render_backends_per_engine = device == 0x7590u ? 4u : 8u;
	id.max_waves_per_simd = 16u;
	return id;
}

static struct cobalt_gfx_runtime_v1 make_runtime(const struct cobalt_gpu_info_v1 *id)
{
	struct cobalt_gfx_runtime_v1 r = {0};
	unsigned se, sa;
	r.version = COBALT_GFX_RUNTIME_VERSION;
	r.size = sizeof(r);
	r.flags = COBALT_GFX_RUNTIME_VALID;
	r.gc_version = (id->gc_major << 16) | (id->gc_minor << 8) | id->gc_revision;
	r.gb_addr_config = 1u;
	r.shader_engines = id->shader_engines;
	r.shader_arrays_per_engine = id->shader_arrays_per_engine;
	r.cu_per_array = id->cu_per_array;
	r.render_backends_per_engine = id->render_backends_per_engine;
	r.active_sa_mask = (1u << (id->shader_engines * id->shader_arrays_per_engine)) - 1u;
	r.active_rb_mask = UINT32_MAX;
	for (se = 0; se < id->shader_engines; ++se) {
		for (sa = 0; sa < id->shader_arrays_per_engine; ++sa) {
			r.cu_bitmap[se][sa] = id->cu_per_array == 32u
				? UINT32_MAX : ((1u << id->cu_per_array) - 1u);
			r.active_cu_count += id->cu_per_array;
		}
	}
	return r;
}

int main(void)
{
	struct cobalt_gpu_info_v1 id = make_identity(0x7550u);
	struct cobalt_gfx_runtime_v1 r = make_runtime(&id), decoded;
	unsigned char unaligned[sizeof(r) + 1];
	if (r.active_rb_mask != UINT32_MAX ||
	    !cobalt_gfx_runtime_v1_decode(&r, sizeof(r), &id, &decoded) ||
	    decoded.active_cu_count != 256u) return 1;
	memcpy(unaligned + 1, &r, sizeof(r));
	if (!cobalt_gfx_runtime_v1_decode(unaligned + 1, sizeof(r), &id, &decoded)) return 2;
	if (!cobalt_gfx_runtime_v1_decode(&r, sizeof(r), &id, &r)) return 3;

	id = make_identity(0x7590u);
	r = make_runtime(&id);
	/* Reduce to two active CUs on one SA while retaining capacity metadata. */
	r.active_sa_mask = 1u;
	r.active_rb_mask = 3u;
	r.cu_bitmap[0][0] = 3u;
	r.cu_bitmap[0][1] = 0;
	r.cu_bitmap[1][0] = 0;
	r.cu_bitmap[1][1] = 0;
	r.active_cu_count = 2u;
	if (!cobalt_gfx_runtime_v1_decode(&r, sizeof(r), &id, &decoded)) return 4;
	r.active_cu_count = 3u;
	if (cobalt_gfx_runtime_v1_decode(&r, sizeof(r), &id, &decoded) ||
	    decoded.version != 0u) return 5;
	return 0;
}
