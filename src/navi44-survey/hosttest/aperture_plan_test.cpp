#include "aperture_plan.hpp"

#include <cstdint>
#include <cstdio>
#include <limits>

namespace {

using cobalt::survey::Inputs;
using cobalt::survey::Plan;
using cobalt::survey::FirmwarePairPlan;
using cobalt::survey::FirmwareBatchPlan;
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

bool pairRejectedAndCleared(const Inputs &input, const char *label) {
    const FirmwarePairPlan result = cobalt::survey::planFirmwarePair(input);
    return expect(!result.ok, label) && expect(result.reason != nullptr, "pair failure reason is present") &&
           expect(!result.kdb.ok && result.kdb.windowOffset == 0 && result.kdb.windowBytes == 0 &&
                  result.kdb.mcAddress == 0 && !result.spl.ok && result.spl.windowOffset == 0 &&
                  result.spl.windowBytes == 0 && result.spl.mcAddress == 0,
                  "pair failure clears both plans");
}

bool batchRejectedAndCleared(const Inputs &input, std::uint32_t count, const char *label) {
    const FirmwareBatchPlan result = cobalt::survey::planFirmwareBatch(input, count);
    bool ok = expect(!result.ok, label) &&
              expect(result.reason != nullptr && result.count == 0,
                     "batch failure has a reason and clears count");
    for (const Plan &window : result.windows) {
        ok &= expect(!window.ok && window.windowOffset == 0 && window.windowBytes == 0 &&
                     window.mcAddress == 0, "batch failure clears every window");
    }
    return ok;
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

    Inputs hardwareInputs = base;
    hardwareInputs.mcBase = 0x8000000000ULL;
    hardwareInputs.mcEnd = hardwareInputs.mcBase + hardwareInputs.usableVramBytes;
    const FirmwarePairPlan pair = cobalt::survey::planFirmwarePair(hardwareInputs);
    ok &= expect(pair.ok && pair.kdb.windowOffset == 64 * MiB && pair.spl.windowOffset == 65 * MiB,
                 "hardware sample selects adjacent 64 MiB and 65 MiB windows");
    ok &= expect(pair.kdb.mcAddress == 0x8004000000ULL && pair.spl.mcAddress == 0x8004100000ULL,
                 "hardware sample computes the expected KDB and SPL MC addresses");
    ok &= expect(pair.kdb.windowBytes == MiB && pair.spl.windowBytes == MiB,
                 "each pair window remains exactly 1 MiB");

    const FirmwareBatchPlan hardwareBatch = cobalt::survey::planFirmwareBatch(hardwareInputs, 7);
    ok &= expect(hardwareBatch.ok && hardwareBatch.count == 7 &&
                 hardwareBatch.windows[0].windowOffset == expected.windowOffset,
                 "seven-window hardware batch retains the legacy first window");
    ok &= expect(hardwareBatch.windows[0].mcAddress == 0x8004000000ULL &&
                 hardwareBatch.windows[6].windowOffset == 70 * MiB &&
                 hardwareBatch.windows[6].mcAddress == 0x8004600000ULL,
                 "seven-window hardware batch reaches the expected final MC address");
    bool contiguousBatch = hardwareBatch.ok;
    for (std::uint32_t i = 0; i < hardwareBatch.count; ++i) {
        const Plan &window = hardwareBatch.windows[i];
        contiguousBatch &= window.ok && window.windowBytes == MiB &&
                           window.windowOffset == 64 * MiB + i * MiB &&
                           window.mcAddress == hardwareInputs.mcBase + window.windowOffset;
    }
    ok &= expect(contiguousBatch && !hardwareBatch.windows[7].ok &&
                 hardwareBatch.windows[7].windowOffset == 0,
                 "batch windows are adjacent and unused slots stay empty");

    Inputs batchBoundary = hardwareInputs;
    batchBoundary.usableVramBytes = 73 * MiB;
    batchBoundary.firmwareReserveBytes = MiB;
    batchBoundary.mcEnd = batchBoundary.mcBase + batchBoundary.usableVramBytes;
    const FirmwareBatchPlan exactEight = cobalt::survey::planFirmwareBatch(batchBoundary, 8);
    ok &= expect(exactEight.ok && exactEight.windows[7].windowOffset == 71 * MiB &&
                 exactEight.windows[7].windowOffset + exactEight.windows[7].windowBytes ==
                     batchBoundary.usableVramBytes - batchBoundary.firmwareReserveBytes,
                 "eight windows exactly fit the unreserved VRAM end");

    batchBoundary = hardwareInputs;
    batchBoundary.consolePhysical = kBar0 + 232 * MiB;
    batchBoundary.consoleBytes = MiB;
    const FirmwareBatchPlan exactBar = cobalt::survey::planFirmwareBatch(batchBoundary, 7);
    ok &= expect(exactBar.ok && exactBar.windows[0].windowOffset == 249 * MiB &&
                 exactBar.windows[6].windowOffset + exactBar.windows[6].windowBytes ==
                     batchBoundary.bar0Bytes,
                 "seven windows exactly fit the BAR0 end");

    batchBoundary = hardwareInputs;
    batchBoundary.consolePhysical = kBar0 + 233 * MiB;
    batchBoundary.consoleBytes = MiB;
    const Plan lastBarStart = cobalt::survey::planAperture(batchBoundary);
    ok &= expect(lastBarStart.ok && lastBarStart.windowOffset + MiB <= batchBoundary.bar0Bytes,
                 "BAR boundary fixture leaves the first window valid");
    ok &= batchRejectedAndCleared(batchBoundary, 7,
                                  "last batch window crossing BAR0 clears the complete batch");

    batchBoundary = hardwareInputs;
    batchBoundary.mcBase += 4096;
    batchBoundary.mcEnd += 4096;
    ok &= batchRejectedAndCleared(batchBoundary, 7,
                                  "misaligned MC base rejects and clears the complete batch");

    batchBoundary = hardwareInputs;
    batchBoundary.bar0Physical = 0xFFFFFFFFF0000000ULL;
    batchBoundary.bar0ConfigPhysical = batchBoundary.bar0Physical;
    ok &= batchRejectedAndCleared(batchBoundary, 7,
                                  "BAR0 end overflow rejects and clears the complete batch");

    batchBoundary = hardwareInputs;
    batchBoundary.usableVramBytes = 73 * MiB;
    batchBoundary.firmwareReserveBytes = 2 * MiB;
    batchBoundary.mcEnd = batchBoundary.mcBase + batchBoundary.usableVramBytes;
    const Plan lastSafeStart = cobalt::survey::planAperture(batchBoundary);
    ok &= expect(lastSafeStart.ok && lastSafeStart.windowOffset == 64 * MiB,
                 "reserve boundary fixture leaves the first window valid");
    ok &= batchRejectedAndCleared(batchBoundary, 8,
                                  "last batch window crossing firmware reserve clears the complete batch");

    batchBoundary = hardwareInputs;
    batchBoundary.mcBase =
        (static_cast<std::uint64_t>(UINT32_MAX) - 69) * MiB;
    batchBoundary.mcEnd = batchBoundary.mcBase + batchBoundary.usableVramBytes;
    const Plan fieldFirst = cobalt::survey::planAperture(batchBoundary);
    const FirmwareBatchPlan fieldBoundary = cobalt::survey::planFirmwareBatch(batchBoundary, 7);
    ok &= expect(fieldFirst.ok && (fieldFirst.mcAddress >> 20) <= UINT32_MAX &&
                 !fieldBoundary.ok && fieldBoundary.count == 0,
                 "last window crossing mailbox field range is refused after a valid first window");
    ok &= batchRejectedAndCleared(batchBoundary, 7,
                                  "unrepresentable final mailbox address clears the complete batch");

    Inputs movedBatchInputs = hardwareInputs;
    movedBatchInputs.consolePhysical += 80 * MiB;
    const Plan movedBatchFirst = cobalt::survey::planAperture(movedBatchInputs);
    const FirmwareBatchPlan movedBatch = cobalt::survey::planFirmwareBatch(movedBatchInputs, 7);
    ok &= expect(movedBatch.ok && movedBatch.windows[0].windowOffset == movedBatchFirst.windowOffset &&
                 movedBatch.windows[0].windowOffset > 80 * MiB,
                 "batch follows the console plus guard when the console moves");
    ok &= batchRejectedAndCleared(base, 0, "zero-window batch is rejected");
    ok &= batchRejectedAndCleared(base, 1, "one-window batch is rejected");
    ok &= batchRejectedAndCleared(base, 2, "two-window batch is rejected");
    ok &= batchRejectedAndCleared(base, 9, "nine-window batch is rejected");
    ok &= batchRejectedAndCleared(base, std::numeric_limits<std::uint32_t>::max(),
                                  "maximum uint32 batch count is rejected");

    Inputs movedConsole = base;
    movedConsole.consolePhysical += 80 * MiB;
    const Plan moved = cobalt::survey::planAperture(movedConsole);
    ok &= expect(moved.ok && moved.windowOffset > 80 * MiB,
                 "nonzero console offset moves the window past console plus guard");
    const FirmwarePairPlan movedPair = cobalt::survey::planFirmwarePair(movedConsole);
    ok &= expect(movedPair.ok && movedPair.kdb.windowOffset == moved.windowOffset &&
                 movedPair.spl.windowOffset == moved.windowOffset + MiB,
                 "pair follows a moved console and remains adjacent");
    Inputs largeConsole = base;
    largeConsole.consoleBytes = 60 * MiB;
    const Plan large = cobalt::survey::planAperture(largeConsole);
    ok &= expect(large.ok && large.windowOffset == 76 * MiB,
                 "large console moves the window beyond the guard");

    const Plan repeated = cobalt::survey::planAperture(base);
    ok &= expect(repeated.ok == expected.ok && repeated.windowOffset == expected.windowOffset &&
                 repeated.windowBytes == expected.windowBytes && repeated.mcAddress == expected.mcAddress,
                 "planning is deterministic");
    const FirmwarePairPlan repeatedPair = cobalt::survey::planFirmwarePair(hardwareInputs);
    ok &= expect(repeatedPair.ok && repeatedPair.kdb.windowOffset == pair.kdb.windowOffset &&
                 repeatedPair.kdb.mcAddress == pair.kdb.mcAddress &&
                 repeatedPair.spl.windowOffset == pair.spl.windowOffset &&
                 repeatedPair.spl.mcAddress == pair.spl.mcAddress,
                 "pair planning is deterministic");

    // The first window can fit at 255 MiB while its adjacent partner cannot.
    Inputs pairBoundary = base;
    pairBoundary.consolePhysical = kBar0 + 238 * MiB;
    pairBoundary.consoleBytes = MiB;
    const Plan lastBarWindow = cobalt::survey::planAperture(pairBoundary);
    ok &= expect(lastBarWindow.ok && lastBarWindow.windowOffset == 255 * MiB,
                 "boundary fixture leaves the first window inside BAR0");
    ok &= pairRejectedAndCleared(pairBoundary, "second window crossing BAR0 is refused");

    pairBoundary = base;
    pairBoundary.usableVramBytes = 66 * MiB;
    pairBoundary.firmwareReserveBytes = MiB;
    pairBoundary.mcEnd = pairBoundary.mcBase + pairBoundary.usableVramBytes;
    pairBoundary.consolePhysical = kBar0;
    pairBoundary.consoleBytes = MiB;
    const Plan lastSafeWindow = cobalt::survey::planAperture(pairBoundary);
    ok &= expect(lastSafeWindow.ok && lastSafeWindow.windowOffset == 64 * MiB,
                 "boundary fixture leaves the first window before the reserve");
    ok &= pairRejectedAndCleared(pairBoundary, "second window crossing firmware reserve is refused");

    pairBoundary = base;
    pairBoundary.mcBase = 0xFFFFFFFF00000ULL - 64 * MiB;
    pairBoundary.mcEnd = pairBoundary.mcBase + pairBoundary.usableVramBytes;
    ok &= pairRejectedAndCleared(pairBoundary, "second mailbox address beyond 32-bit MiB field is refused");

    pairBoundary = base;
    pairBoundary.bar0Physical = 0xFFFFFFFFF0000000ULL;
    pairBoundary.bar0ConfigPhysical = pairBoundary.bar0Physical;
    ok &= pairRejectedAndCleared(pairBoundary, "BAR0 end arithmetic overflow clears both pair plans");

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
