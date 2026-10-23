#pragma once

#include <stdint.h>

namespace cobalt::survey {

struct Inputs {
    uint64_t bar0Physical;
    uint64_t bar0ConfigPhysical;
    uint64_t bar0Bytes;
    uint64_t usableVramBytes;
    uint64_t mcBase;
    uint64_t mcEnd;
    uint64_t consolePhysical;
    uint64_t consoleBytes;
    uint64_t firmwareReserveBytes;
};

struct Plan {
    bool ok;
    const char *reason;
    uint64_t windowOffset;
    uint64_t windowBytes;
    uint64_t mcAddress;
};

struct FirmwarePairPlan {
    bool ok;
    const char *reason;
    Plan kdb;
    Plan spl;
};

// Conservative experimental policy, not a guarantee that GPU firmware or
// another client leaves this region unused. The caller must establish
// ownership before any access to the planned aperture.
constexpr uint64_t kApertureWindowBytes = 1ULL << 20;
constexpr uint64_t kApertureGuardBytes = 16ULL << 20;
constexpr uint64_t kAperturePrefixBytes = 64ULL << 20;
constexpr uint64_t kExpectedBar0Bytes = 256ULL << 20;
constexpr uint64_t kMaximumUsableVramBytes = 16ULL << 30;
constexpr uint64_t kConsolePageBytes = 4096;

inline Plan planAperture(const Inputs &in) {
    Plan result{false, "invalid inputs", 0, 0, 0};
    const auto fail = [&result](const char *reason) {
        result = Plan{false, reason, 0, 0, 0};
        return result;
    };
    constexpr uint64_t max = UINT64_MAX;

    if (in.bar0Physical == 0 || in.bar0ConfigPhysical != in.bar0Physical)
        return fail("BAR0 physical address is missing or disagrees with config space");
    if (in.bar0Bytes != kExpectedBar0Bytes)
        return fail("BAR0 size is not exactly 256 MiB");
    if ((in.bar0Physical & (kExpectedBar0Bytes - 1)) != 0)
        return fail("BAR0 physical address is not 256 MiB aligned");
    if (in.bar0Physical > max - in.bar0Bytes)
        return fail("BAR0 physical range overflows");
    const uint64_t bar0End = in.bar0Physical + in.bar0Bytes;

    if (in.usableVramBytes == 0 || in.usableVramBytes > kMaximumUsableVramBytes)
        return fail("usable VRAM is zero or exceeds 16 GiB");
    if (in.firmwareReserveBytes == 0 || in.usableVramBytes <= in.firmwareReserveBytes)
        return fail("firmware reserve is zero or leaves no usable VRAM");
    const uint64_t safeVramBytes = in.usableVramBytes - in.firmwareReserveBytes;

    if (in.mcBase == 0 || (in.mcBase & (kApertureWindowBytes - 1)) != 0 || in.mcEnd <= in.mcBase)
        return fail("MC base is missing or not 1 MiB aligned, or range is reversed");
    const uint64_t mcBytes = in.mcEnd - in.mcBase;
    if (mcBytes < in.usableVramBytes)
        return fail("MC range is smaller than usable VRAM");

    if (in.consolePhysical == 0 || in.consoleBytes == 0 ||
        (in.consolePhysical & (kConsolePageBytes - 1)) != 0)
        return fail("console range is unknown, empty, or not page aligned");
    if (in.consolePhysical < in.bar0Physical || in.consolePhysical >= bar0End)
        return fail("console range begins outside BAR0");
    if (in.consolePhysical > max - in.consoleBytes)
        return fail("console range overflows");
    const uint64_t consoleEnd = in.consolePhysical + in.consoleBytes;
    if (consoleEnd > bar0End)
        return fail("console range extends beyond BAR0");
    const uint64_t consoleOffset = in.consolePhysical - in.bar0Physical;
    if (consoleOffset > safeVramBytes || in.consoleBytes > safeVramBytes - consoleOffset)
        return fail("console range extends beyond unreserved usable VRAM");

    if (consoleOffset > max - in.consoleBytes)
        return fail("console offset range overflows");
    const uint64_t consoleOffsetEnd = consoleOffset + in.consoleBytes;
    if (consoleOffsetEnd > max - kApertureGuardBytes)
        return fail("console guard range overflows");
    const uint64_t guardedEnd = consoleOffsetEnd + kApertureGuardBytes;
    if (guardedEnd > max - (kApertureWindowBytes - 1))
        return fail("window alignment overflows");
    const uint64_t alignedEnd = (guardedEnd + kApertureWindowBytes - 1) & ~(kApertureWindowBytes - 1);
    const uint64_t offset = alignedEnd > kAperturePrefixBytes ? alignedEnd : kAperturePrefixBytes;

    if (offset > in.bar0Bytes || kApertureWindowBytes > in.bar0Bytes - offset)
        return fail("planned window does not fit BAR0");
    if (offset > safeVramBytes || kApertureWindowBytes > safeVramBytes - offset)
        return fail("planned window reaches reserved or unavailable VRAM");
    if (offset > mcBytes || kApertureWindowBytes > mcBytes - offset)
        return fail("planned window does not fit the MC range");
    if (in.mcBase > max - offset)
        return fail("planned MC address overflows");
    const uint64_t mcAddress = in.mcBase + offset;
    if (mcAddress > max - kApertureWindowBytes || mcAddress + kApertureWindowBytes > in.mcEnd)
        return fail("planned MC address range overflows or exceeds MC end");
    if ((mcAddress >> 20) > UINT32_MAX)
        return fail("MC address cannot be represented in the hardware register");

    result = Plan{true, "ok", offset, kApertureWindowBytes, mcAddress};
    return result;
}

// Plan adjacent KDB and SPL apertures. The first aperture retains the
// existing conservative selection policy; the second must fit every bound
// independently as part of the same 2 MiB region.
inline FirmwarePairPlan planFirmwarePair(const Inputs &in) {
    constexpr uint64_t max = UINT64_MAX;
    const Plan first = planAperture(in);
    const auto fail = [](const char *reason) {
        const Plan cleared{false, reason, 0, 0, 0};
        return FirmwarePairPlan{false, reason, cleared, cleared};
    };
    if (!first.ok) return fail(first.reason);
    if (first.windowOffset > max - kApertureWindowBytes)
        return fail("second window offset overflows");

    const uint64_t secondOffset = first.windowOffset + kApertureWindowBytes;
    constexpr uint64_t pairBytes = 2 * kApertureWindowBytes;
    if (first.windowOffset > in.bar0Bytes || pairBytes > in.bar0Bytes - first.windowOffset)
        return fail("firmware pair does not fit BAR0");
    const uint64_t safeVramBytes = in.usableVramBytes - in.firmwareReserveBytes;
    if (first.windowOffset > safeVramBytes || pairBytes > safeVramBytes - first.windowOffset)
        return fail("firmware pair reaches reserved or unavailable VRAM");
    const uint64_t mcBytes = in.mcEnd - in.mcBase;
    if (first.windowOffset > mcBytes || pairBytes > mcBytes - first.windowOffset)
        return fail("firmware pair does not fit the MC range");
    if (in.mcBase > max - secondOffset)
        return fail("second MC address overflows");
    const uint64_t secondMcAddress = in.mcBase + secondOffset;
    if (secondMcAddress > max - kApertureWindowBytes ||
        secondMcAddress + kApertureWindowBytes > in.mcEnd)
        return fail("second MC address range overflows or exceeds MC end");
    if ((secondMcAddress >> 20) > UINT32_MAX)
        return fail("SPL MC address cannot be represented in the hardware register");

    const Plan second{true, "ok", secondOffset, kApertureWindowBytes, secondMcAddress};
    return FirmwarePairPlan{true, "ok", first, second};
}

} // namespace cobalt::survey
