#ifndef COBALT_GFX_RUNTIME_H
#define COBALT_GFX_RUNTIME_H

#include "gpu_info.h"

#define COBALT_GFX_RUNTIME_VERSION 1u
#define COBALT_GFX_RUNTIME_PROPERTY "Cobalt,GfxRuntime-v1"
#define COBALT_GFX_RUNTIME_VALID 1u

struct cobalt_gfx_runtime_v1 {
	uint32_t version;
	uint32_t size;
	uint32_t flags;
	uint32_t gc_version;
	uint32_t gb_addr_config;
	uint32_t shader_engines;
	uint32_t shader_arrays_per_engine;
	uint32_t cu_per_array;
	uint32_t render_backends_per_engine;
	uint32_t active_sa_mask;
	uint32_t active_rb_mask;
	uint32_t active_cu_count;
	uint32_t cu_bitmap[4][2];
	uint32_t reserved[4];
};

#if defined(__cplusplus)
static_assert(sizeof(struct cobalt_gfx_runtime_v1) == 96, "gfx runtime v1 wire size");
static_assert(offsetof(struct cobalt_gfx_runtime_v1, cu_bitmap) == 48, "gfx runtime CU bitmap offset");
static_assert(offsetof(struct cobalt_gfx_runtime_v1, reserved) == 80, "gfx runtime reserved offset");
#else
_Static_assert(sizeof(struct cobalt_gfx_runtime_v1) == 96, "gfx runtime v1 wire size");
_Static_assert(offsetof(struct cobalt_gfx_runtime_v1, cu_bitmap) == 48, "gfx runtime CU bitmap offset");
_Static_assert(offsetof(struct cobalt_gfx_runtime_v1, reserved) == 80, "gfx runtime reserved offset");
#endif

static inline uint32_t cobalt_gfx_runtime_v1_low_mask(uint32_t width)
{
	return width >= 32u ? UINT32_MAX : ((1u << width) - 1u);
}

static inline unsigned cobalt_gfx_runtime_v1_popcount(uint32_t bits)
{
	unsigned count = 0;
	while (bits != 0) {
		bits &= bits - 1u;
		++count;
	}
	return count;
}

static inline int cobalt_gfx_runtime_v1_decode(
	const void *bytes, size_t length,
	const struct cobalt_gpu_info_v1 *identity,
	struct cobalt_gfx_runtime_v1 *out)
{
	struct cobalt_gfx_runtime_v1 record;
	struct cobalt_gpu_info_v1 checked_identity;
	uint32_t total_sa, total_rb, rb_per_sa, cu_total = 0;
	uint32_t valid_sa_mask, valid_rb_mask;
	unsigned se, sa, i;

	if (out == NULL) return 0;
	if (bytes == NULL || length != sizeof(record)) {
		memset(out, 0, sizeof(*out));
		return 0;
	}
	memcpy(&record, bytes, sizeof(record));
	memset(out, 0, sizeof(*out));
	if (identity == NULL ||
	    !cobalt_gpu_info_v1_decode(identity, sizeof(*identity), &checked_identity)) goto invalid;

	if (record.version != COBALT_GFX_RUNTIME_VERSION || record.size != sizeof(record) ||
	    record.flags != COBALT_GFX_RUNTIME_VALID) goto invalid;
	if (checked_identity.gc_major > 0xffffu || checked_identity.gc_minor > 0xffu ||
	    checked_identity.gc_revision > 0xffu ||
	    record.gc_version != ((checked_identity.gc_major << 16) |
	                          (checked_identity.gc_minor << 8) |
	                          checked_identity.gc_revision)) goto invalid;
	if (record.gb_addr_config == 0 || record.gb_addr_config == UINT32_MAX) goto invalid;
	if (record.shader_engines != checked_identity.shader_engines ||
	    record.shader_arrays_per_engine != checked_identity.shader_arrays_per_engine ||
	    record.cu_per_array != checked_identity.cu_per_array ||
	    record.render_backends_per_engine != checked_identity.render_backends_per_engine) goto invalid;

	total_sa = checked_identity.shader_engines * checked_identity.shader_arrays_per_engine;
	total_rb = checked_identity.shader_engines * checked_identity.render_backends_per_engine;
	rb_per_sa = checked_identity.render_backends_per_engine /
	            checked_identity.shader_arrays_per_engine;
	valid_sa_mask = cobalt_gfx_runtime_v1_low_mask(total_sa);
	valid_rb_mask = cobalt_gfx_runtime_v1_low_mask(total_rb);
	if ((record.active_sa_mask & ~valid_sa_mask) != 0 ||
	    record.active_sa_mask == 0 || (record.active_rb_mask & ~valid_rb_mask) != 0 ||
	    record.active_rb_mask == 0) goto invalid;

	for (se = 0; se < checked_identity.shader_engines; ++se) {
		int se_has_cu = 0;
		for (sa = 0; sa < checked_identity.shader_arrays_per_engine; ++sa) {
			uint32_t sa_index = se * checked_identity.shader_arrays_per_engine + sa;
			uint32_t bits = record.cu_bitmap[se][sa];
			uint32_t valid_cu_mask = cobalt_gfx_runtime_v1_low_mask(checked_identity.cu_per_array);
			if ((record.active_sa_mask & (1u << sa_index)) == 0) {
				if (bits != 0) goto invalid;
			} else if ((bits & ~valid_cu_mask) != 0) {
				goto invalid;
			}
			for (i = 0; i < checked_identity.cu_per_array; i += 2u) {
				uint32_t pair = (bits >> i) & 3u;
				if (pair != 0 && pair != 3u) goto invalid;
			}
			cu_total += cobalt_gfx_runtime_v1_popcount(bits);
			if (bits != 0) se_has_cu = 1;
		}
		for (sa = 0; sa < checked_identity.shader_arrays_per_engine; ++sa) {
			uint32_t sa_index = se * checked_identity.shader_arrays_per_engine + sa;
			uint32_t rb_start = se * checked_identity.render_backends_per_engine + sa * rb_per_sa;
			uint32_t rb_mask = cobalt_gfx_runtime_v1_low_mask(rb_per_sa) << rb_start;
			if ((record.active_rb_mask & rb_mask) != 0 &&
			    ((record.active_sa_mask & (1u << sa_index)) == 0 || !se_has_cu)) goto invalid;
		}
	}
	for (se = 0; se < checked_identity.shader_engines; ++se)
		for (sa = checked_identity.shader_arrays_per_engine; sa < 2u; ++sa)
			if (record.cu_bitmap[se][sa] != 0) goto invalid;
	for (se = checked_identity.shader_engines; se < 4u; ++se)
		for (sa = 0; sa < 2u; ++sa)
			if (record.cu_bitmap[se][sa] != 0) goto invalid;
	for (i = 0; i < 4u; ++i) if (record.reserved[i] != 0) goto invalid;
	if (cu_total == 0 || cu_total != record.active_cu_count ||
	    cu_total > checked_identity.max_compute_units) goto invalid;

	*out = record;
	return 1;

invalid:
	memset(out, 0, sizeof(*out));
	return 0;
}

#endif
