#pragma once

#include <stdint.h>

namespace cobalt::survey::pspMemory {

constexpr uint64_t pageBytes = 4096;
constexpr uint64_t addressLimit = 1ULL << 48;

struct Layout {
    uint64_t tableBase;
    uint64_t leaf;
    uint64_t gpuAddress;
};

// The inputs are device DMA segments from the same provider. The table and
// data pages remain owned by the caller. This builds a candidate, since Linux
// v6.19 normally places the GFX12 GART table in VRAM. The hardware must prove
// it can walk this system-memory table before the address goes to the PSP.
inline bool makeLayout(uint64_t tableDma, uint64_t dataDma, uint32_t fbBase,
                       uint32_t fbTop, Layout &out) {
    out = {};
    const auto pageAddress = [](uint64_t address) {
        return address != 0 && address <= addressLimit - pageBytes &&
            (address & (pageBytes - 1)) == 0;
    };
    if (!pageAddress(tableDma) || !pageAddress(dataDma) || tableDma == dataDma ||
        fbBase == 0 || fbTop < fbBase || fbTop > 0xffffffu) return false;

    // FB location is expressed in 16 MiB units. Use a page beyond that range,
    // aligned to a 4 GiB boundary as in Linux's GART placement.
    constexpr uint64_t granularity = 1ULL << 32;
    const uint64_t fbEnd = (uint64_t(fbTop) + 1) << 24;
    const uint64_t gpuAddress = (fbEnd + granularity - 1) & ~(granularity - 1);
    if (!pageAddress(gpuAddress) || gpuAddress == tableDma || gpuAddress == dataDma) return false;

    // Linux v6.19 amdgpu_vm.h and gmc_v12_0.c describe the root PDE and
    // flat GART leaf. Keep execute permission out of this data-only page.
    constexpr uint64_t valid = 1, system = 2, snooped = 4;
    constexpr uint64_t readable = 1ULL << 5, writable = 1ULL << 6;
    constexpr uint64_t uncached = 2ULL << 54, isPte = 1ULL << 63;
    out = {tableDma | valid | system | snooped,
           dataDma | valid | system | snooped | readable | writable | uncached | isPte,
           gpuAddress};
    return true;
}

} // namespace cobalt::survey::pspMemory
