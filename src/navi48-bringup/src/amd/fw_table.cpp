// Family-specific firmware; runtime sizes require ordinary assignments rather
// than C++ global constructors. amd/ is included by the existing Makefile glob.
#include "../fw/fw_table.h"

namespace amdgpu {
extern "C" {
extern const uint8_t fw_psp_14_0_3_sos[];
extern const size_t fw_psp_14_0_3_sos_size;
extern const uint8_t fw_psp_14_0_3_ta[];
extern const size_t fw_psp_14_0_3_ta_size;
extern const uint8_t fw_gc_12_0_1_imu[];
extern const size_t fw_gc_12_0_1_imu_size;
extern const uint8_t fw_gc_12_0_1_pfp[];
extern const size_t fw_gc_12_0_1_pfp_size;
extern const uint8_t fw_gc_12_0_1_me[];
extern const size_t fw_gc_12_0_1_me_size;
extern const uint8_t fw_gc_12_0_1_mec[];
extern const size_t fw_gc_12_0_1_mec_size;
extern const uint8_t fw_gc_12_0_1_uni_mes[];
extern const size_t fw_gc_12_0_1_uni_mes_size;
extern const uint8_t fw_gc_12_0_1_rlc[];
extern const size_t fw_gc_12_0_1_rlc_size;
extern const uint8_t fw_smu_14_0_3[];
extern const size_t fw_smu_14_0_3_size;
extern const uint8_t fw_sdma_7_0_1[];
extern const size_t fw_sdma_7_0_1_size;
extern const uint8_t fw_psp_14_0_2_sos[];
extern const size_t fw_psp_14_0_2_sos_size;
extern const uint8_t fw_psp_14_0_2_ta[];
extern const size_t fw_psp_14_0_2_ta_size;
extern const uint8_t fw_gc_12_0_0_imu[];
extern const size_t fw_gc_12_0_0_imu_size;
extern const uint8_t fw_gc_12_0_0_pfp[];
extern const size_t fw_gc_12_0_0_pfp_size;
extern const uint8_t fw_gc_12_0_0_me[];
extern const size_t fw_gc_12_0_0_me_size;
extern const uint8_t fw_gc_12_0_0_mec[];
extern const size_t fw_gc_12_0_0_mec_size;
extern const uint8_t fw_gc_12_0_0_uni_mes[];
extern const size_t fw_gc_12_0_0_uni_mes_size;
extern const uint8_t fw_gc_12_0_0_rlc[];
extern const size_t fw_gc_12_0_0_rlc_size;
extern const uint8_t fw_smu_14_0_2[];
extern const size_t fw_smu_14_0_2_size;
extern const uint8_t fw_sdma_7_0_0[];
extern const size_t fw_sdma_7_0_0_size;
}
namespace {
constexpr uint32_t kCount = static_cast<uint32_t>(FwId::Count);
constexpr uint32_t kFamilies = 2;
FwBlob g_tables[kFamilies][kCount]; // .bss, no global constructors
bool g_built;

// Bring-up is serialized before loading. Each lookup names its family;
// there is no mutable global selection that can redirect another device.
void build_tables() {
    if (g_built) return;
    // Navi48: UNI_MES follows the current ladder's packaging.
    g_tables[0][static_cast<uint32_t>(FwId::PSP_SOS)] =
        FwBlob{fw_psp_14_0_3_sos, fw_psp_14_0_3_sos_size, "psp_14_0_3_sos", FwId::PSP_SOS};
    g_tables[0][static_cast<uint32_t>(FwId::PSP_TA)] =
        FwBlob{fw_psp_14_0_3_ta, fw_psp_14_0_3_ta_size, "psp_14_0_3_ta", FwId::PSP_TA};
    g_tables[0][static_cast<uint32_t>(FwId::GC_IMU)] =
        FwBlob{fw_gc_12_0_1_imu, fw_gc_12_0_1_imu_size, "gc_12_0_1_imu", FwId::GC_IMU};
    g_tables[0][static_cast<uint32_t>(FwId::GC_PFP)] =
        FwBlob{fw_gc_12_0_1_pfp, fw_gc_12_0_1_pfp_size, "gc_12_0_1_pfp", FwId::GC_PFP};
    g_tables[0][static_cast<uint32_t>(FwId::GC_ME)] =
        FwBlob{fw_gc_12_0_1_me, fw_gc_12_0_1_me_size, "gc_12_0_1_me", FwId::GC_ME};
    g_tables[0][static_cast<uint32_t>(FwId::GC_MEC)] =
        FwBlob{fw_gc_12_0_1_mec, fw_gc_12_0_1_mec_size, "gc_12_0_1_mec", FwId::GC_MEC};
    g_tables[0][static_cast<uint32_t>(FwId::GC_MES)] =
        FwBlob{nullptr, 0, "gc_12_0_1_mes", FwId::GC_MES};
    g_tables[0][static_cast<uint32_t>(FwId::GC_MES1)] =
        FwBlob{nullptr, 0, "gc_12_0_1_mes1", FwId::GC_MES1};
    g_tables[0][static_cast<uint32_t>(FwId::GC_UNI_MES)] =
        FwBlob{fw_gc_12_0_1_uni_mes, fw_gc_12_0_1_uni_mes_size, "gc_12_0_1_uni_mes", FwId::GC_UNI_MES};
    g_tables[0][static_cast<uint32_t>(FwId::GC_RLC)] =
        FwBlob{fw_gc_12_0_1_rlc, fw_gc_12_0_1_rlc_size, "gc_12_0_1_rlc", FwId::GC_RLC};
    g_tables[0][static_cast<uint32_t>(FwId::GC_TOC)] =
        FwBlob{nullptr, 0, "gc_12_0_1_toc", FwId::GC_TOC};
    g_tables[0][static_cast<uint32_t>(FwId::SMU)] =
        FwBlob{fw_smu_14_0_3, fw_smu_14_0_3_size, "smu_14_0_3", FwId::SMU};
    g_tables[0][static_cast<uint32_t>(FwId::SDMA)] =
        FwBlob{fw_sdma_7_0_1, fw_sdma_7_0_1_size, "sdma_7_0_1", FwId::SDMA};
    // Navi44: UNI_MES follows the current ladder's packaging.
    g_tables[1][static_cast<uint32_t>(FwId::PSP_SOS)] =
        FwBlob{fw_psp_14_0_2_sos, fw_psp_14_0_2_sos_size, "psp_14_0_2_sos", FwId::PSP_SOS};
    g_tables[1][static_cast<uint32_t>(FwId::PSP_TA)] =
        FwBlob{fw_psp_14_0_2_ta, fw_psp_14_0_2_ta_size, "psp_14_0_2_ta", FwId::PSP_TA};
    g_tables[1][static_cast<uint32_t>(FwId::GC_IMU)] =
        FwBlob{fw_gc_12_0_0_imu, fw_gc_12_0_0_imu_size, "gc_12_0_0_imu", FwId::GC_IMU};
    g_tables[1][static_cast<uint32_t>(FwId::GC_PFP)] =
        FwBlob{fw_gc_12_0_0_pfp, fw_gc_12_0_0_pfp_size, "gc_12_0_0_pfp", FwId::GC_PFP};
    g_tables[1][static_cast<uint32_t>(FwId::GC_ME)] =
        FwBlob{fw_gc_12_0_0_me, fw_gc_12_0_0_me_size, "gc_12_0_0_me", FwId::GC_ME};
    g_tables[1][static_cast<uint32_t>(FwId::GC_MEC)] =
        FwBlob{fw_gc_12_0_0_mec, fw_gc_12_0_0_mec_size, "gc_12_0_0_mec", FwId::GC_MEC};
    g_tables[1][static_cast<uint32_t>(FwId::GC_MES)] =
        FwBlob{nullptr, 0, "gc_12_0_0_mes", FwId::GC_MES};
    g_tables[1][static_cast<uint32_t>(FwId::GC_MES1)] =
        FwBlob{nullptr, 0, "gc_12_0_0_mes1", FwId::GC_MES1};
    g_tables[1][static_cast<uint32_t>(FwId::GC_UNI_MES)] =
        FwBlob{fw_gc_12_0_0_uni_mes, fw_gc_12_0_0_uni_mes_size, "gc_12_0_0_uni_mes", FwId::GC_UNI_MES};
    g_tables[1][static_cast<uint32_t>(FwId::GC_RLC)] =
        FwBlob{fw_gc_12_0_0_rlc, fw_gc_12_0_0_rlc_size, "gc_12_0_0_rlc", FwId::GC_RLC};
    g_tables[1][static_cast<uint32_t>(FwId::GC_TOC)] =
        FwBlob{nullptr, 0, "gc_12_0_0_toc", FwId::GC_TOC};
    g_tables[1][static_cast<uint32_t>(FwId::SMU)] =
        FwBlob{fw_smu_14_0_2, fw_smu_14_0_2_size, "smu_14_0_2", FwId::SMU};
    g_tables[1][static_cast<uint32_t>(FwId::SDMA)] =
        FwBlob{fw_sdma_7_0_0, fw_sdma_7_0_0_size, "sdma_7_0_0", FwId::SDMA};
    g_built = true;
}
int family_index(cobalt::Family family) {
    switch (family) {
        case cobalt::Family::Navi48: return 0;
        case cobalt::Family::Navi44: return 1;
        default: return -1;
    }
}
bool str_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a++ != *b++) return false;
    }
    return *a == *b;
}
}
const FwBlob *fw_get(cobalt::Family family, FwId id) {
    const int table = family_index(family);
    const uint32_t index = static_cast<uint32_t>(id);
    if (table < 0 || index >= kCount) return nullptr;
    build_tables();
    return &g_tables[table][index];
}
const FwBlob *fw_find_by_name(const char *name) {
    if (!name) return nullptr;
    build_tables();
    for (uint32_t family = 0; family < kFamilies; ++family)
        for (uint32_t i = 0; i < kCount; ++i)
            if (str_eq(g_tables[family][i].name, name)) return &g_tables[family][i];
    return nullptr;
}
} // namespace amdgpu
