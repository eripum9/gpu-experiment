#pragma once
#include <stdint.h>

namespace cobalt::survey {

// Exact views in the immutable, hash-pinned PSP 14.0.2 SOS package. RAS is
// absent in this package. SOS and TOC are not part of this diagnostic batch.
struct PreSosImageSpec {
    const char *name;
    uint32_t type, command, fileOffset, bytes, version;
};
constexpr uint32_t kPreSosImageCount = 7;
constexpr uint32_t kPreSosFirmwareBytes = 421216;
constexpr PreSosImageSpec kPreSosImages[kPreSosImageCount] = {
    {"Kdb",   3,  0x00080000, 0x00100,  6816, 0x703b0001},
    {"Spl",   5,  0x10000000, 0x66a20,   832, 0x01003b00},
    {"Sys",   2,  0x00010000, 0x01ba0, 78272, 0x003b0f0d},
    {"Soc",   7,  0x000b0000, 0x33780,103792, 0x003b0f0d},
    {"Intf",  8,  0x000d0000, 0x4ccf0, 37280, 0x003b0f0d},
    {"Dbg",   9,  0x000c0000, 0x55e90, 53344, 0x003b0f0d},
    {"Ipkey",11,  0x000f0000, 0x637f0, 12848, 0x003b0f0d},
};

} // namespace cobalt::survey
