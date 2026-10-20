/* Verify the backend-facing wire reader builds and works as C11. */
#include "../src/gpu_info.h"

int main(void)
{
    struct cobalt_gpu_info_v1 record = {0};
    struct cobalt_gpu_info_v1 decoded;
    unsigned char unaligned[129];
    record.version = COBALT_GPU_INFO_VERSION;
    record.size = sizeof(record);
    record.flags = COBALT_GPU_INFO_CAPACITY_VALID;
    record.pci_vendor = 0x1002;
    record.pci_device = 0x7590;
    record.gfx_target = COBALT_GPU_GFX_TARGET_1200;
    record.gc_major = 12;
    record.shader_engines = 2;
    record.shader_arrays_per_engine = 2;
    record.wgp_per_array = 4;
    record.cu_per_array = 8;
    record.max_compute_units = 32;
    record.render_backends_per_engine = 4;
    record.max_waves_per_simd = 16;
    memcpy(unaligned + 1, &record, sizeof(record));
    if (!cobalt_gpu_info_v1_decode(unaligned + 1, sizeof(record), &decoded) ||
        decoded.pci_device != 0x7590 || decoded.max_compute_units != 32) return 1;
    if (!cobalt_gpu_info_v1_decode(&decoded, sizeof(decoded), &decoded)) return 2;
    record.reserved[0] = 1;
    if (cobalt_gpu_info_v1_decode(&record, sizeof(record), &decoded) ||
        decoded.version != 0) return 3;
    return 0;
}
