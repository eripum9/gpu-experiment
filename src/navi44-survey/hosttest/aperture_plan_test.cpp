#include "aperture_plan.hpp"

#include <cstdint>
#include <cstdio>
#include <limits>

namespace {

using cobalt::survey::Inputs;
using cobalt::survey::Plan;
constexpr std::uint64_t MiB = 1ULL << 20;
constexpr std::uint64_t GiB = 1ULL << 30;
constexpr std::uint64_t kReserve = 516ULL * MiB;
constexpr std::uint64_t kBar0 = 0x80000000ULL;

Inputs validInputs() {
    return Inputs{kBar0, kBar0, 256 * MiB, GiB, 1 * GiB, 2 * GiB,
                  kBar0, 13824ULL * 1440, kReserve};
}

int checks = 0;

bool expect(bool condition, const char *label) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", label);
        return false;
    }
    return true;
}

bool rejectedAndCleared(const Inputs &input, const char *label) {
    const Plan result = cobalt::survey::planAperture(input);
    return expect(!result.ok, label) &&
           expect(result.reason != nullptr, "failure reason is present") &&
           expect(result.windowOffset == 0 && result.windowBytes == 0 && result.mcAddress == 0,
                  "failure outputs are cleared");
}

} // namespace

int main() {
    bool ok = true;
    const Inputs base = validInputs();
    const Plan expected = cobalt::survey::planAperture(base);
    ok &= expect(expected.ok, "valid sample plans successfully");
    ok &= expect(expected.windowOffset == 64 * MiB, "known 3440x1440 console selects 64 MiB offset");
    ok &= expect(expected.windowBytes == MiB, "window is exactly 1 MiB");
    ok &= expect(expected.mcAddress == base.mcBase + 64 * MiB, "MC address adds planned offset");
    ok &= expect(expected.windowOffset + expected.windowBytes <= base.bar0Bytes,
                 "sample window fits BAR0");

    Inputs movedConsole = base;
    movedConsole.consolePhysical += 80 * MiB;
    const Plan moved = cobalt::survey::planAperture(movedConsole);
    ok &= expect(moved.ok && moved.windowOffset > 80 * MiB,
                 "nonzero console offset moves the window past console plus guard");
    Inputs largeConsole = base;
    largeConsole.consoleBytes = 60 * MiB;
    const Plan large = cobalt::survey::planAperture(largeConsole);
    ok &= expect(large.ok && large.windowOffset == 76 * MiB,
                 "large console moves the window beyond the guard");

    const Plan repeated = cobalt::survey::planAperture(base);
    ok &= expect(repeated.ok == expected.ok && repeated.windowOffset == expected.windowOffset &&
                 repeated.windowBytes == expected.windowBytes && repeated.mcAddress == expected.mcAddress,
                 "planning is deterministic");

    Inputs input = base; input.consolePhysical = 0;
    ok &= rejectedAndCleared(input, "unknown console is refused");
    input = base; input.consolePhysical = kBar0 - 4096; input.consoleBytes = 8192;
    ok &= rejectedAndCleared(input, "console extending past BAR0 is refused");
    input = base; input.consolePhysical = kBar0 + 4096;
    input.consoleBytes = std::numeric_limits<std::uint64_t>::max() - input.consolePhysical + 1;
    ok &= rejectedAndCleared(input, "wrapping console range is refused");
    input = base; input.consolePhysical += 1;
    ok &= rejectedAndCleared(input, "unaligned console base is refused");
    input = base; input.usableVramBytes = 600 * MiB; input.firmwareReserveBytes = 535 * MiB;
    input.mcEnd = input.mcBase + input.usableVramBytes;
    input.consolePhysical = kBar0 + 64 * MiB; input.consoleBytes = 2 * MiB;
    ok &= rejectedAndCleared(input, "console in firmware-reserved VRAM is refused");

    input = base; input.bar0ConfigPhysical += 256 * MiB;
    ok &= rejectedAndCleared(input, "BAR0 config mismatch is refused");
    input = base; input.bar0Physical = 0;
    ok &= rejectedAndCleared(input, "zero BAR0 address is refused");
    input = base; input.bar0Bytes = 0;
    ok &= rejectedAndCleared(input, "zero BAR0 size is refused");
    input = base; input.bar0Bytes = 128 * MiB;
    ok &= rejectedAndCleared(input, "unexpected BAR0 size is refused");
    input = base; input.bar0Bytes = 255 * MiB;
    ok &= rejectedAndCleared(input, "non-power-of-two BAR0 size is refused");
    input = base; input.bar0Physical += 1; input.bar0ConfigPhysical += 1;
    ok &= rejectedAndCleared(input, "misaligned BAR0 address is refused");
    input = base; input.bar0Physical = 0xFFFFFFFFF0000000ULL; input.bar0ConfigPhysical = input.bar0Physical;
    ok &= rejectedAndCleared(input, "wrapping BAR0 range is refused");

    input = base; input.usableVramBytes = 0;
    ok &= rejectedAndCleared(input, "zero usable VRAM is refused");
    input = base; input.usableVramBytes = 16 * GiB + 1;
    ok &= rejectedAndCleared(input, "VRAM over 16 GiB is refused");
    input = base; input.firmwareReserveBytes = 0;
    ok &= rejectedAndCleared(input, "zero firmware reserve is refused");
    input = base; input.firmwareReserveBytes = input.usableVramBytes;
    ok &= rejectedAndCleared(input, "reserve consuming all VRAM is refused");
    input = base; input.usableVramBytes = kReserve;
    ok &= rejectedAndCleared(input, "VRAM equal to reserve is refused");

    input = base; input.mcBase = 0;
    ok &= rejectedAndCleared(input, "zero MC base is refused");
    input = base; input.mcBase += 4096; input.mcEnd += 4096;
    ok &= rejectedAndCleared(input, "unaligned MC base is refused");
    input = base; input.mcEnd = input.mcBase;
    ok &= rejectedAndCleared(input, "empty MC range is refused");
    input = base; input.mcEnd = input.mcBase + input.usableVramBytes - 1;
    ok &= rejectedAndCleared(input, "short MC range is refused");
    input = base; input.mcBase = 0x1000000000000000ULL; input.mcEnd = input.mcBase + input.usableVramBytes;
    ok &= rejectedAndCleared(input, "unrepresentable MC register address is refused");

    // The usable region ends exactly at the final byte of the one-MiB window.
    input = base;
    input.usableVramBytes = 600 * MiB;
    input.firmwareReserveBytes = 535 * MiB;
    input.mcEnd = input.mcBase + input.usableVramBytes;
    const Plan exactFit = cobalt::survey::planAperture(input);
    ok &= expect(exactFit.ok && exactFit.windowOffset == 64 * MiB &&
                 exactFit.windowOffset + exactFit.windowBytes ==
                     input.usableVramBytes - input.firmwareReserveBytes,
                 "window exactly fits before firmware reserve");
    input.firmwareReserveBytes = 536 * MiB;
    ok &= rejectedAndCleared(input, "window crossing firmware reserve is refused");

    if (!ok) return 1;
    std::printf("aperture_plan_test: %d checks passed\n", checks);
    return 0;
}
