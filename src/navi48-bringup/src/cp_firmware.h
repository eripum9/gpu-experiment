#ifndef COBALT_CP_FIRMWARE_H
#define COBALT_CP_FIRMWARE_H

#include "gpu_info.h"

#define COBALT_CP_FIRMWARE_VERSION 1u
#define COBALT_CP_FIRMWARE_PROPERTY "Cobalt,CpFirmware-v1"
#define COBALT_CP_FIRMWARE_PSP_LOAD_COMPLETED 1u

struct cobalt_cp_firmware_v1 {
    uint32_t version;
    uint32_t size;
    uint32_t flags;
    uint32_t gc_version;
    uint32_t me_version;
    uint32_t me_feature;
    uint32_t pfp_version;
    uint32_t pfp_feature;
    uint32_t mec_version;
    uint32_t mec_feature;
    uint32_t reserved[6];
};

#if defined(__cplusplus)
static_assert(sizeof(struct cobalt_cp_firmware_v1) == 64, "CP firmware v1 wire size");
static_assert(offsetof(struct cobalt_cp_firmware_v1, me_version) == 16, "CP firmware version offset");
static_assert(offsetof(struct cobalt_cp_firmware_v1, reserved) == 40, "CP firmware reserved offset");
#else
_Static_assert(sizeof(struct cobalt_cp_firmware_v1) == 64, "CP firmware v1 wire size");
_Static_assert(offsetof(struct cobalt_cp_firmware_v1, me_version) == 16, "CP firmware version offset");
_Static_assert(offsetof(struct cobalt_cp_firmware_v1, reserved) == 40, "CP firmware reserved offset");
#endif

static inline int
cobalt_cp_firmware_v1_decode(const void *bytes, size_t length,
                            const struct cobalt_gpu_info_v1 *identity,
                            struct cobalt_cp_firmware_v1 *out)
{
    struct cobalt_cp_firmware_v1 record;
    struct cobalt_gpu_info_v1 checked_identity;
    unsigned i;
    if (!out) return 0;
    if (!bytes || length != sizeof(record)) goto invalid;
    memcpy(&record, bytes, sizeof(record));
    if (!cobalt_gpu_info_v1_decode(identity, sizeof(checked_identity), &checked_identity)) goto invalid;
    if (record.version != COBALT_CP_FIRMWARE_VERSION || record.size != sizeof(record) ||
        record.flags != COBALT_CP_FIRMWARE_PSP_LOAD_COMPLETED ||
        record.gc_version != ((checked_identity.gc_major << 16) |
                              (checked_identity.gc_minor << 8) | checked_identity.gc_revision)) goto invalid;
    if (!record.me_version || record.me_version == UINT32_MAX ||
        !record.pfp_version || record.pfp_version == UINT32_MAX ||
        !record.mec_version || record.mec_version == UINT32_MAX ||
        record.me_feature == UINT32_MAX || record.pfp_feature == UINT32_MAX ||
        record.mec_feature == UINT32_MAX) goto invalid;
    for (i = 0; i < 6; ++i) if (record.reserved[i]) goto invalid;
    *out = record;
    return 1;
invalid:
    memset(out, 0, sizeof(*out));
    return 0;
}

#endif
