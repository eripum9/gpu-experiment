#ifndef COBALT_GPU_INFO_H
#define COBALT_GPU_INFO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define COBALT_GPU_INFO_VERSION 1u
#define COBALT_GPU_INFO_PROPERTY "Cobalt,GpuInfo-v1"
#define COBALT_GPU_INFO_CAPACITY_VALID 1u
#define COBALT_GPU_INFO_BRINGUP_ENABLED 2u
#define COBALT_GPU_GFX_TARGET_1200 1200u
#define COBALT_GPU_GFX_TARGET_1201 1201u

struct cobalt_gpu_info_v1 {
	uint32_t version;
	uint32_t size;
	uint32_t flags;
	uint32_t pci_vendor;
	uint32_t pci_device;
	uint32_t pci_revision;
	uint32_t pci_subsystem_vendor;
	uint32_t pci_subsystem_device;
	uint32_t gfx_target;
	uint32_t gc_major;
	uint32_t gc_minor;
	uint32_t gc_revision;
	uint32_t shader_engines;
	uint32_t shader_arrays_per_engine;
	uint32_t wgp_per_array;
	uint32_t cu_per_array;
	uint32_t max_compute_units;
	uint32_t render_backends_per_engine;
	uint32_t max_waves_per_simd;
	uint32_t reserved[13];
};

/* Wire values use native little-endian uint32_t encoding on the x86 target.
 * max_compute_units is discovered capacity, not active CUs or readiness. */
#if defined(__cplusplus)
static_assert(sizeof(struct cobalt_gpu_info_v1) == 128, "gpu info v1 wire size");
static_assert(offsetof(struct cobalt_gpu_info_v1, gfx_target) == 32, "gpu info target offset");
static_assert(offsetof(struct cobalt_gpu_info_v1, gc_major) == 36, "gpu info GC offset");
static_assert(offsetof(struct cobalt_gpu_info_v1, reserved) == 76, "gpu info reserved offset");
#else
_Static_assert(sizeof(struct cobalt_gpu_info_v1) == 128, "gpu info v1 wire size");
_Static_assert(offsetof(struct cobalt_gpu_info_v1, gfx_target) == 32, "gpu info target offset");
_Static_assert(offsetof(struct cobalt_gpu_info_v1, gc_major) == 36, "gpu info GC offset");
_Static_assert(offsetof(struct cobalt_gpu_info_v1, reserved) == 76, "gpu info reserved offset");
#endif

/* Decode an exact v1 wire record. The source may be unaligned. */
static inline int cobalt_gpu_info_v1_decode(
	const void *bytes, size_t length, struct cobalt_gpu_info_v1 *out)
{
	struct cobalt_gpu_info_v1 record;
	uint32_t total_rb;
	uint32_t expected_target;
	uint32_t expected_gc_revision;
	int must_be_disabled;
	unsigned i;

	if (out == NULL) return 0;
	if (bytes == NULL || length != sizeof(record)) {
		memset(out, 0, sizeof(*out));
		return 0;
	}
	/* Copy first so bytes may alias or partially overlap out. */
	memcpy(&record, bytes, sizeof(record));
	must_be_disabled = 0;

	if (record.version != COBALT_GPU_INFO_VERSION || record.size != sizeof(record)) goto invalid;
	if ((record.flags & ~(COBALT_GPU_INFO_CAPACITY_VALID | COBALT_GPU_INFO_BRINGUP_ENABLED)) != 0 ||
	    (record.flags & COBALT_GPU_INFO_CAPACITY_VALID) == 0) goto invalid;
	if (record.pci_vendor != 0x1002u || record.pci_revision > 0xffu ||
	    record.pci_subsystem_vendor > 0xffffu || record.pci_subsystem_device > 0xffffu) goto invalid;
	if (record.pci_device == 0x7550u || record.pci_device == 0x7551u) {
		expected_target = COBALT_GPU_GFX_TARGET_1201;
		expected_gc_revision = 1;
	} else if (record.pci_device == 0x7590u) {
		expected_target = COBALT_GPU_GFX_TARGET_1200;
		expected_gc_revision = 0;
		must_be_disabled = 1;
	} else {
		goto invalid;
	}
	if (record.gfx_target != expected_target || record.gc_major != 12 ||
	    record.gc_minor != 0 || record.gc_revision != expected_gc_revision ||
	    (must_be_disabled && (record.flags & COBALT_GPU_INFO_BRINGUP_ENABLED) != 0)) goto invalid;

	if (record.shader_engines == 0 || record.shader_engines > 4 ||
	    record.shader_arrays_per_engine == 0 || record.shader_arrays_per_engine > 2 ||
	    record.wgp_per_array == 0 || record.wgp_per_array > 16 ||
	    record.cu_per_array == 0 || record.cu_per_array > 32 ||
	    record.max_waves_per_simd == 0 || record.max_waves_per_simd > 1024 ||
	    record.render_backends_per_engine == 0 || record.max_compute_units == 0) goto invalid;
	if (record.render_backends_per_engine > 32u / record.shader_engines ||
	    record.render_backends_per_engine % record.shader_arrays_per_engine != 0) goto invalid;
	if (record.wgp_per_array > UINT32_MAX / 2u ||
	    record.wgp_per_array * 2u != record.cu_per_array) goto invalid;
	if (record.shader_engines > UINT32_MAX / record.shader_arrays_per_engine) goto invalid;
	total_rb = record.shader_engines * record.shader_arrays_per_engine;
	if (total_rb > UINT32_MAX / record.cu_per_array ||
	    total_rb * record.cu_per_array != record.max_compute_units) goto invalid;
	for (i = 0; i < 13; ++i) if (record.reserved[i] != 0) goto invalid;

	*out = record;
	return 1;

invalid:
	memset(out, 0, sizeof(*out));
	return 0;
}

#endif

