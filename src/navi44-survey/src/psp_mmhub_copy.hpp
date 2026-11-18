#pragma once

#include "psp_mmhub_layout.hpp"

namespace cobalt::survey::pspMmhubCopy {

enum class Register {
    Context0Control, TableBaseLow, TableBaseHigh, TableStartLow, TableStartHigh,
    TableEndLow, TableEndHigh, L1Control, L2Control, L2Control3, L2Control4,
    PioSrcLow, PioSrcHigh, PioDstLow, PioDstHigh, PioControl,
    L2Control2, L2Control5, SystemApertureLow, SystemApertureHigh, AgpBase,
    AgpBottom, AgpTop, FbOffset, FbBase, FbTop, PioStatus, PioCommand
};

constexpr uint32_t copyBytes = 64;
constexpr unsigned pollLimit = 100;
constexpr uint32_t pollDelayUs = 10;

inline uint8_t sourceByte(unsigned i) { return static_cast<uint8_t>(i * 73 + 19); }
constexpr uint8_t guardByte = 0xa5;

// Seed the complete owned page before outbound DMA synchronization.
inline void seedCopyPage(uint8_t *page) {
    for (unsigned i = 0; i < copyBytes; ++i) {
        page[i] = sourceByte(i);
        page[copyBytes + i] = static_cast<uint8_t>(~sourceByte(i));
    }
    for (unsigned i = 2 * copyBytes; i < pspMemory::pageBytes; ++i) page[i] = guardByte;
}

// An adapter holds exclusive access throughout and latches any loss of its
// hardware guard. Each register access and invalidation must be bounded and
// guarded, with write ordering sufficient for the following register read.
struct Io {
    virtual ~Io() = default;
    virtual bool guard() = 0;
    virtual bool read(Register reg, uint32_t &value) = 0;
    // A false result can mean that the store reached hardware.
    virtual bool write(Register reg, uint32_t value) = 0;
    // Own distinct driver DMA pages on this device. Synchronize the flat table
    // with layout.leaf at index 0 and the seeded data page to the device.
    virtual bool prepare(pspMemory::Layout &layout) = 0;
    // Return true only once the VMID0 invalidation has completed and its
    // engine is released. An uncertain invalidation cannot be retried here.
    virtual bool invalidateVmid0() = 0;
    // Synchronize the owned data page from the device. On success, return a
    // CPU view of all pageBytes, valid until the next adapter call.
    virtual bool syncDataToCpu(const uint8_t *&page) = 0;
    virtual void delayUs(uint32_t microseconds) = 0;
};

struct Result {
    const char *status {"preflight-refused"};
    unsigned polls {0};
    uint32_t lastPioStatus {UINT32_MAX};
    bool commandAttempted {false}, copyProven {false}, restored {false};
    // Keep both DMA leases alive on any unresolved hardware state.
    bool retainPages {false}, rebootAllowed {true};
};

namespace detail {
constexpr unsigned index(Register reg) { return static_cast<unsigned>(reg); }
constexpr unsigned snapshotWords = index(Register::PioStatus);
constexpr uint32_t idle = 0x90000000u; // PIO_IDLE and PIO_FIFO_EMPTY
constexpr uint32_t active = 0x200000ffu; // FIFO_FULL, CMD_PROCESSING and CMD_IN_FIFO
constexpr uint32_t errors = 0x00078f00u;

struct Snapshot {
    uint32_t words[snapshotWords] {};
    uint32_t &operator[](Register reg) { return words[index(reg)]; }
    uint32_t operator[](Register reg) const { return words[index(reg)]; }
};

inline bool readStatus(Io &io, Result &result) {
    return io.read(Register::PioStatus, result.lastPioStatus) &&
        result.lastPioStatus != UINT32_MAX && !(result.lastPioStatus & errors);
}

inline bool engineIdle(const Result &result) {
    return (result.lastPioStatus & (idle | active)) == idle;
}

inline bool sample(Io &io, Snapshot &out, Result &result) {
    if (!io.guard()) return false;
    for (unsigned i = 0; i < snapshotWords; ++i) {
        if (!io.read(static_cast<Register>(i), out.words[i]) || out.words[i] == UINT32_MAX)
            return false;
    }
    return readStatus(io, result) && engineIdle(result) && io.guard();
}

inline bool matches(Io &io, const Snapshot &expected, Result &result) {
    Snapshot observed {};
    if (!sample(io, observed, result)) return false;
    for (unsigned i = 0; i < snapshotWords; ++i)
        if (observed.words[i] != expected.words[i]) return false;
    return true;
}

inline bool capturedBaseline(const Snapshot &state) {
    return state[Register::Context0Control] == 0x03fffc00u &&
        state[Register::TableBaseLow] == 0 && state[Register::TableBaseHigh] == 0 &&
        state[Register::TableStartLow] == 0 && state[Register::TableStartHigh] == 0 &&
        state[Register::TableEndLow] == 0 && state[Register::TableEndHigh] == 0 &&
        state[Register::L1Control] == 0x501u && state[Register::L2Control] == 0x80602u &&
        state[Register::L2Control2] == 0 && state[Register::L2Control3] == 0x80100007u &&
        state[Register::L2Control4] == 0xc1u && state[Register::L2Control5] == 0x3fe0u &&
        state[Register::SystemApertureLow] == 0x200000u &&
        state[Register::SystemApertureHigh] == 0x20feffu &&
        state[Register::AgpBase] == 0 && state[Register::AgpBottom] == 0 &&
        state[Register::AgpTop] == 0 && state[Register::FbOffset] == 0 &&
        state[Register::FbBase] == 0x8000u && state[Register::FbTop] == 0x83fbu;
}

inline bool validLayout(const pspMemory::Layout &layout, const Snapshot &state) {
    constexpr uint64_t dmaMask = (pspMemory::addressLimit - 1) & ~(pspMemory::pageBytes - 1);
    pspMemory::Layout expected {};
    return pspMemory::makeLayout(layout.tableBase & dmaMask, layout.leaf & dmaMask,
        state[Register::FbBase], state[Register::FbTop], expected) &&
        layout.tableBase == expected.tableBase && layout.leaf == expected.leaf &&
        layout.gpuAddress == expected.gpuAddress;
}

inline bool pageMatches(const uint8_t *page, bool copied) {
    for (unsigned i = 0; i < copyBytes; ++i) {
        const uint8_t expected = sourceByte(i);
        const uint8_t destination = copied ? expected : static_cast<uint8_t>(~expected);
        if (page[i] != expected || page[copyBytes + i] != destination) return false;
    }
    for (unsigned i = 2 * copyBytes; i < pspMemory::pageBytes; ++i)
        if (page[i] != guardByte) return false;
    return true;
}

inline Snapshot candidate(const Snapshot &initial, const pspMemory::Layout &layout) {
    Snapshot state = initial;
    state[Register::Context0Control] = 0;
    const uint64_t pfn = layout.gpuAddress >> 12;
    const uint64_t destination = layout.gpuAddress + copyBytes;
    state[Register::TableBaseLow] = static_cast<uint32_t>(layout.tableBase);
    state[Register::TableBaseHigh] = static_cast<uint32_t>(layout.tableBase >> 32);
    state[Register::TableStartLow] = state[Register::TableEndLow] = static_cast<uint32_t>(pfn);
    state[Register::TableStartHigh] = state[Register::TableEndHigh] = static_cast<uint32_t>(pfn >> 32);

    // Linux v6.19 mmhub_v4_1_0.c and mmhub_4_1_0_sh_mask.h supply the L1/L2
    // fields. For this flat probe, leave default-page redirection off and
    // retain the existing L2_CNTL5 small-page settings.
    constexpr uint32_t l1Mask = 0x1ff9u; // Enable, system mode, aperture, advanced, ECO, MTYPE.
    constexpr uint32_t l1Settings = 1u | (3u << 3) | (1u << 6) | (3u << 11);
    constexpr uint32_t l2Mask = 0x03fc0903u; // Cache, fragments, PDE tags/faults, defaults, identity.
    constexpr uint32_t l2Settings = 1u | (1u << 19);
    constexpr uint32_t l2BankAndFragment = 0x000f803fu;
    state[Register::L1Control] = (initial[Register::L1Control] & ~l1Mask) | l1Settings;
    state[Register::L2Control] = (initial[Register::L2Control] & ~l2Mask) | l2Settings;
    state[Register::L2Control3] = (initial[Register::L2Control3] & ~l2BankAndFragment) | 9u | (6u << 15);
    state[Register::L2Control4] = initial[Register::L2Control4] & ~0xc0u;
    state[Register::PioSrcLow] = static_cast<uint32_t>(layout.gpuAddress);
    state[Register::PioSrcHigh] = static_cast<uint32_t>(layout.gpuAddress >> 32);
    state[Register::PioDstLow] = static_cast<uint32_t>(destination);
    state[Register::PioDstHigh] = static_cast<uint32_t>(destination >> 32);
    state[Register::PioControl] = 0;
    return state;
}

inline bool writeRange(Io &io, const Snapshot &state, Register first, Register last) {
    for (unsigned i = index(first); i <= index(last); ++i)
        if (!io.write(static_cast<Register>(i), state.words[i])) return false;
    return true;
}

inline bool readContext(Io &io, uint32_t expected) {
    uint32_t value = UINT32_MAX;
    return io.read(Register::Context0Control, value) && value == expected;
}

inline Result restore(Io &io, const Snapshot &initial, Result result, bool pioSetupAttempted) {
    if (!io.guard() || !readStatus(io, result) || !engineIdle(result) ||
        !io.write(Register::Context0Control, 0) || !readContext(io, 0) ||
        !io.invalidateVmid0() ||
        !writeRange(io, initial, Register::TableBaseLow, Register::L2Control4) ||
        !io.write(Register::Context0Control, initial[Register::Context0Control]) ||
        (pioSetupAttempted && !writeRange(io, initial, Register::PioSrcLow, Register::PioControl)) ||
        !matches(io, initial, result)) {
        result.status = "restore-uncertain";
        return result;
    }
    result.restored = true;
    result.retainPages = false;
    result.rebootAllowed = true;
    return result;
}
} // namespace detail

inline Result run(Io &io) {
    using namespace detail;
    Result result {};
    Snapshot initial {};
    if (!sample(io, initial, result) || !capturedBaseline(initial)) return result;

    pspMemory::Layout layout {};
    result.status = "lease-refused";
    if (!io.prepare(layout) || !validLayout(layout, initial)) return result;
    const uint8_t *page = nullptr;
    result.status = "seed-refused";
    if (!io.syncDataToCpu(page) || !page || !pageMatches(page, false)) return result;
    result.status = "preflight-changed";
    if (!matches(io, initial, result)) return result;

    Snapshot mapping = candidate(initial, layout);
    result.retainPages = true;
    result.rebootAllowed = false;
    result.status = "mapping-setup-failed";
    if (!io.write(Register::Context0Control, 0) || !readContext(io, 0) ||
        !writeRange(io, mapping, Register::TableBaseLow, Register::L2Control4))
        return restore(io, initial, result, false);

    result.status = "copy-setup-failed";
    if (!writeRange(io, mapping, Register::PioSrcLow, Register::PioControl) ||
        !matches(io, mapping, result))
        return restore(io, initial, result, true);

    // Depth zero, one inclusive page, with fault redirects, interrupts and
    // retries disabled. The system/AGP apertures remain as captured.
    mapping[Register::Context0Control] = 1;
    result.status = "mapping-enable-failed";
    if (!io.write(Register::Context0Control, 1) || !readContext(io, 1))
        return restore(io, initial, result, true);
    result.status = "mapping-invalidate-uncertain";
    if (!io.invalidateVmid0()) return result;
    result.status = "launch-preflight-refused";
    if (!matches(io, mapping, result)) return restore(io, initial, result, true);

    // LSDMA 7.0 PIO copies through the GPU address space with all command
    // fields zero except BYTE_COUNT. Writing PIO_COMMAND launches the copy.
    result.status = "copy-command-uncertain";
    result.commandAttempted = true;
    if (!io.write(Register::PioCommand, copyBytes)) return result;
    for (unsigned i = 0; i < pollLimit; ++i) {
        io.delayUs(pollDelayUs);
        ++result.polls;
        result.status = "copy-status-unavailable";
        if (!readStatus(io, result)) return result;
        if (!engineIdle(result)) continue;

        page = nullptr;
        result.status = "copy-data-unavailable";
        if (!io.syncDataToCpu(page) || !page) return result;
        if (!pageMatches(page, true)) continue;
        result.status = "copy-status-unavailable";
        if (!readStatus(io, result)) return result;
        if (!engineIdle(result)) continue;

        result.copyProven = true;
        result.status = "copy-proven";
        return restore(io, initial, result, true);
    }
    result.status = "copy-timeout";
    return result;
}

} // namespace cobalt::survey::pspMmhubCopy
