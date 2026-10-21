#ifndef COBALT_CP_FIRMWARE_BUILDER_HPP
#define COBALT_CP_FIRMWARE_BUILDER_HPP

#include "cp_firmware.h"

namespace cobalt {

struct CpFirmwareBlob {
    const uint8_t *data;
    size_t size;
};

// The fresh path needs the completed stage-8 barrier, not merely staged bytes.
// Adoption restores an earlier record and must never call the fresh builder.
inline bool cp_firmware_fresh_load_ready(bool adoptProvisioned, bool tornDown,
                                         uint32_t reached) {
    return !adoptProvisioned && !tornDown && reached >= 8u;
}

namespace cp_firmware_detail {
inline uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}
inline bool within(uint32_t offset, uint32_t size, size_t limit) {
    return size != 0 && offset <= limit && size <= limit - offset;
}
struct Parsed {
    uint32_t version, feature, codeOffset, codeSize, dataOffset, dataSize;
};
inline bool parse(const CpFirmwareBlob &blob, Parsed &out) {
    // gfx_firmware_header_v2_0 is 60 bytes; header_size_bytes may include
    // padding. Explicit LE reads also support unaligned embedded headers.
    if (!blob.data || blob.size < 60u || blob.size > UINT32_MAX) return false;
    const uint8_t *b = blob.data;
    const uint32_t headerSize = le32(b + 4);
    const uint32_t payloadSize = le32(b + 20);
    const uint32_t payloadOffset = le32(b + 24);
    if (le32(b) != blob.size || headerSize < 60u || headerSize > blob.size ||
        le16(b + 8) != 2u || le16(b + 10) != 0u ||
        le16(b + 12) != 12u || le16(b + 14) != 0u ||
        payloadOffset < headerSize || !within(payloadOffset, payloadSize, blob.size) ||
        payloadSize != blob.size - payloadOffset) return false;
    out = {le32(b + 16), le32(b + 32), payloadOffset, le32(b + 36),
           le32(b + 48), le32(b + 44)};
    if (!out.version || out.version == UINT32_MAX || out.feature == UINT32_MAX ||
        le32(b + 40) != out.codeOffset ||
        !within(out.codeOffset, out.codeSize, blob.size) ||
        !within(out.dataOffset, out.dataSize, blob.size) ||
        out.dataOffset < payloadOffset ||
        (out.codeOffset < static_cast<uint64_t>(out.dataOffset) + out.dataSize &&
         out.dataOffset < static_cast<uint64_t>(out.codeOffset) + out.codeSize)) return false;
    return true;
}

template <typename Entry>
inline bool build(const cobalt_gpu_info_v1 &identity,
                  const CpFirmwareBlob (&blobs)[3], const Entry *entries,
                  uint32_t count, bool loadCompleted, cobalt_cp_firmware_v1 &out) {
    cobalt_gpu_info_v1 checked {};
    if (!loadCompleted || !entries || !count || count > 64u ||
        !cobalt_gpu_info_v1_decode(&identity, sizeof(identity), &checked)) return false;
    Parsed parsed[3] {};
    for (unsigned i = 0; i < 3; ++i) if (!parse(blobs[i], parsed[i])) return false;

    // GC12's actual extractor/load set: PFP+P0, ME+P0, MEC+P0+P1.
    // PSP also knows types 91/93/96/97, but this loader does not emit them.
    struct Expected { uint32_t type; unsigned blob; bool stack; };
    const Expected expected[] = {
        {87u, 1u, false}, {90u, 1u, true},
        {88u, 0u, false}, {92u, 0u, true},
        {89u, 2u, false}, {94u, 2u, true}, {95u, 2u, true}
    };
    uint32_t seen = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const Entry &entry = entries[i];
        if (entry.fw_type < 87u || entry.fw_type > 97u) continue;
        unsigned j = 0;
        for (; j < 7u && expected[j].type != entry.fw_type; ++j) {}
        if (j == 7u || (seen & (1u << j)) || !entry.staged) return false;
        const Expected &e = expected[j];
        const Parsed &p = parsed[e.blob];
        if (entry.src != blobs[e.blob].data + (e.stack ? p.dataOffset : p.codeOffset) ||
            entry.size != (e.stack ? p.dataSize : p.codeSize)) return false;
        seen |= 1u << j;
    }
    if (seen != 0x7fu) return false;
    cobalt_cp_firmware_v1 record {};
    record.version = COBALT_CP_FIRMWARE_VERSION;
    record.size = sizeof(record);
    record.flags = COBALT_CP_FIRMWARE_PSP_LOAD_COMPLETED;
    record.gc_version = (checked.gc_major << 16) | (checked.gc_minor << 8) | checked.gc_revision;
    record.me_version = parsed[0].version;
    record.me_feature = parsed[0].feature;
    record.pfp_version = parsed[1].version;
    record.pfp_feature = parsed[1].feature;
    record.mec_version = parsed[2].version;
    record.mec_feature = parsed[2].feature;
    return cobalt_cp_firmware_v1_decode(&record, sizeof(record), &checked, &out) != 0;
}
} // namespace cp_firmware_detail

// blobs are ME, PFP, MEC in that order. Entry has the same source/size/type/
// staged fields as FwLoaderState::Entry; no kernel headers or hardware needed.
template <typename Entry>
inline bool make_cp_firmware(const cobalt_gpu_info_v1 &identity,
                             const CpFirmwareBlob (&blobs)[3], const Entry *entries,
                             uint32_t count, bool loadCompleted,
                             cobalt_cp_firmware_v1 &out) {
    if (cp_firmware_detail::build(identity, blobs, entries, count, loadCompleted, out)) return true;
    memset(&out, 0, sizeof(out));
    return false;
}

} // namespace cobalt
#endif
