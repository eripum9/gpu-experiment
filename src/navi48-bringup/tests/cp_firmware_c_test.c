#include "../src/cp_firmware.h"
#include <stdio.h>

int main(void) {
    struct cobalt_gpu_info_v1 id = {0};
    struct cobalt_cp_firmware_v1 record = {0}, out;
    unsigned char unaligned[65];
    unsigned i;
    id.version = 1; id.size = sizeof(id); id.flags = COBALT_GPU_INFO_CAPACITY_VALID;
    id.pci_vendor = 0x1002; id.pci_device = 0x7590; id.gfx_target = 1200; id.gc_major = 12;
    id.shader_engines = 2; id.shader_arrays_per_engine = 2;
    id.wgp_per_array = 4; id.cu_per_array = 8; id.max_compute_units = 32;
    id.render_backends_per_engine = 4; id.max_waves_per_simd = 16;
    record.version = 1; record.size = sizeof(record);
    record.flags = COBALT_CP_FIRMWARE_PSP_LOAD_COMPLETED; record.gc_version = 12u << 16;
    record.me_version = 3110; record.pfp_version = 3220; record.mec_version = 3490;
    record.me_feature = record.pfp_feature = record.mec_feature = 29;
    memcpy(unaligned + 1, &record, sizeof(record));
    if (!cobalt_cp_firmware_v1_decode(unaligned + 1, sizeof(record), &id, &out) ||
        memcmp(&record, &out, sizeof(record))) return 1;
    if (!cobalt_cp_firmware_v1_decode(&record, sizeof(record), &id, &record)) return 2;
    for (i = 0; i < 6; ++i) {
        record.reserved[i] = 1;
        memset(&out, 0xa5, sizeof(out));
        if (cobalt_cp_firmware_v1_decode(&record, sizeof(record), &id, &out)) return 3;
        {
            const unsigned char *bytes = (const unsigned char *)&out;
            unsigned j;
            for (j = 0; j < sizeof(out); ++j) if (bytes[j]) return 4;
        }
        record.reserved[i] = 0;
    }
    if (cobalt_cp_firmware_v1_decode(&record, sizeof(record), &id, NULL)) return 5;
    puts("cp_firmware_c_test: PASS");
    return 0;
}
