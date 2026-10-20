#include "../src/fw/fw_table.h"
#include <stdio.h>
#include <string.h>

using amdgpu::FwId;
using cobalt::Family;

struct Expected { FwId id; const char *name; bool present; };
static const Expected kExpected[2][static_cast<unsigned>(FwId::Count)] = {
    {
        {FwId::PSP_SOS, "psp_14_0_3_sos", true},
        {FwId::PSP_TA, "psp_14_0_3_ta", true},
        {FwId::GC_IMU, "gc_12_0_1_imu", true},
        {FwId::GC_PFP, "gc_12_0_1_pfp", true},
        {FwId::GC_ME, "gc_12_0_1_me", true},
        {FwId::GC_MEC, "gc_12_0_1_mec", true},
        {FwId::GC_MES, "gc_12_0_1_mes", false},
        {FwId::GC_MES1, "gc_12_0_1_mes1", false},
        {FwId::GC_UNI_MES, "gc_12_0_1_uni_mes", true},
        {FwId::GC_RLC, "gc_12_0_1_rlc", true},
        {FwId::GC_TOC, "gc_12_0_1_toc", false},
        {FwId::SMU, "smu_14_0_3", true},
        {FwId::SDMA, "sdma_7_0_1", true},
    },
    {
        {FwId::PSP_SOS, "psp_14_0_2_sos", true},
        {FwId::PSP_TA, "psp_14_0_2_ta", true},
        {FwId::GC_IMU, "gc_12_0_0_imu", true},
        {FwId::GC_PFP, "gc_12_0_0_pfp", true},
        {FwId::GC_ME, "gc_12_0_0_me", true},
        {FwId::GC_MEC, "gc_12_0_0_mec", true},
        {FwId::GC_MES, "gc_12_0_0_mes", false},
        {FwId::GC_MES1, "gc_12_0_0_mes1", false},
        {FwId::GC_UNI_MES, "gc_12_0_0_uni_mes", true},
        {FwId::GC_RLC, "gc_12_0_0_rlc", true},
        {FwId::GC_TOC, "gc_12_0_0_toc", false},
        {FwId::SMU, "smu_14_0_2", true},
        {FwId::SDMA, "sdma_7_0_0", true},
    },
};
static int failures;
static void check(bool ok, const char *message) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", message); ++failures; }
}
int main() {
    const Family families[] = {Family::Navi48, Family::Navi44};
    const uint8_t sentinels[] = {0x48, 0x44};
    // Exercise name lookup before indexed lookup initializes either table.
    check(amdgpu::fw_find_by_name("smu_14_0_2") != nullptr, "name lookup initializes tables");
    for (unsigned f = 0; f < 2; ++f) {
        unsigned present = 0;
        for (unsigned i = 0; i < static_cast<unsigned>(FwId::Count); ++i) {
            const Expected &expected = kExpected[f][i];
            const amdgpu::FwBlob *blob = amdgpu::fw_get(families[f], expected.id);
            check(blob != nullptr, "in-range row exists");
            if (!blob) continue;
            check(blob->id == expected.id, "row id matches");
            check(strcmp(blob->name, expected.name) == 0, "exact family firmware name");
            check(amdgpu::fw_find_by_name(expected.name) == blob, "name lookup returns same family row");
            if (expected.present) {
                ++present;
                check(blob->data != nullptr && blob->size == 2, "real row uses linked bytes and size");
                if (blob->data && blob->size == 2) {
                    check(blob->data[0] == sentinels[f], "bytes belong to requested family");
                    check(blob->data[1] == i, "bytes belong to requested firmware id");
                }
            } else {
                check(blob->data == nullptr && blob->size == 0, "optional packaging has no cross-family fallback");
            }
            const amdgpu::FwBlob *other = amdgpu::fw_get(families[1-f], expected.id);
            check(other && other != blob && strcmp(other->name, blob->name) != 0, "families have independent rows");
            check(amdgpu::fw_get(families[f], expected.id) == blob, "interleaved family lookup is stable");
        }
        check(present == 10, "exactly ten embedded blobs per family");
        check(amdgpu::fw_get(families[f], FwId::Count) == nullptr, "count sentinel rejected");
        check(amdgpu::fw_get(families[f], static_cast<FwId>(0xffffffffu)) == nullptr, "invalid firmware id rejected");
    }
    check(amdgpu::fw_get(Family::Unknown, FwId::PSP_SOS) == nullptr, "unknown family has no fallback");
    check(amdgpu::fw_get(static_cast<Family>(255), FwId::PSP_SOS) == nullptr, "invalid family rejected");
    check(amdgpu::fw_find_by_name(nullptr) == nullptr, "null name rejected");
    check(amdgpu::fw_find_by_name("") == nullptr, "empty name rejected");
    check(amdgpu::fw_find_by_name("smu_14_0_2_kicker") == nullptr, "unembedded variant has no fallback");
    check(amdgpu::fw_find_by_name("gc_12_0_0_imu.bin") == nullptr, "name matching is exact");
    if (!failures) puts("firmware profile tests passed");
    return failures ? 1 : 0;
}
