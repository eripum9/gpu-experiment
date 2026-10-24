#pragma once
#include "presos_manifest.hpp"

namespace cobalt::survey {

// The unchanged seven pre-SOS views, followed by SOS from the same immutable
// pinned package. TOC is never a bootloader command; RAS is absent here.
constexpr uint32_t kSosImageCount = kPreSosImageCount + 1;
constexpr uint32_t kSosFirmwareBytes = kPreSosFirmwareBytes;
constexpr PreSosImageSpec kSosImages[kSosImageCount] = {
    kPreSosImages[0], kPreSosImages[1], kPreSosImages[2], kPreSosImages[3],
    kPreSosImages[4], kPreSosImages[5], kPreSosImages[6],
    {"Sos", 1, 0x00020000, 0x14d60, 125472, 0x003b0f0d},
};

} // namespace cobalt::survey
