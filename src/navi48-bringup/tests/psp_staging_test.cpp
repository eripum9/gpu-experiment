// Host-only contract tests for the bounded PSP staging helper and the actual
// PSP loader. The fake backend models posted CPU writes that become visible to
// the GPU only after its flush callback; it has no hardware interfaces.
#include "psp_staging.hpp"
#include "psp.hpp"
#include "psp_container.hpp"
#include "ipdiscovery.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

using cobalt::psp::StagingBus;
using cobalt::psp::StagingError;
using cobalt::psp::StagingWindow;
using Bytes = std::vector<uint8_t>;
static constexpr uint64_t kBase = 32ULL << 20;
static constexpr uint32_t kReady = 0x80000000u;
static constexpr uint32_t kSosCommand = 0x20000u;
static constexpr uint32_t kAddressReg = 0x64, kCommandReg = 0x63, kSosReg = 0x91;
static unsigned checks = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) throw std::runtime_error(std::string("line ") + std::to_string(__LINE__) + ": " #expr); } while (0)

static_assert(!std::is_copy_constructible<StagingWindow>::value, "staging authorization cannot be copied");
static_assert(!std::is_copy_assignable<StagingWindow>::value, "staging authorization cannot be copy assigned");
static_assert(!std::is_move_constructible<StagingWindow>::value, "staging authorization cannot be moved");
static_assert(!std::is_move_assignable<StagingWindow>::value, "staging authorization cannot be move assigned");

struct BusEvent { char op; uint64_t offset; size_t length; const uint8_t *source; };

struct MemoryBus : StagingBus {
    Bytes cpu = Bytes(StagingWindow::kBytes, 0xa5);
    Bytes gpu = Bytes(StagingWindow::kBytes, 0x5a);
    std::vector<BusEvent> events;
    unsigned contextCalls = 0, zeroCalls = 0, copyCalls = 0, flushCalls = 0;
    unsigned failContextAt = 0, failZeroAt = 0, failCopyAt = 0, failFlushAt = 0;
    bool contextEnabled = true;
    uint64_t base = kBase;
    std::function<void()> onContext, onZero, onCopy, onFlush;

    bool inRange(uint64_t offset, size_t length) const {
        return offset >= base && offset - base <= StagingWindow::kBytes &&
            length <= StagingWindow::kBytes - static_cast<size_t>(offset - base);
    }
    bool contextValid() override {
        ++contextCalls;
        const auto callback = onContext;
        if (callback) callback();
        return contextEnabled && contextCalls != failContextAt;
    }
    bool zeroChunk(uint64_t offset, size_t length) override {
        ++zeroCalls; events.push_back({'Z', offset, length, nullptr});
        const auto callback = onZero;
        if (callback) callback();
        if (!inRange(offset, length) || length == 0 || length > StagingWindow::kChunkBytes || zeroCalls == failZeroAt)
            return false;
        std::fill(cpu.begin() + static_cast<std::ptrdiff_t>(offset - base),
                  cpu.begin() + static_cast<std::ptrdiff_t>(offset - base + length), uint8_t(0));
        return true;
    }
    bool copyChunk(uint64_t offset, const uint8_t *source, size_t length) override {
        ++copyCalls; events.push_back({'C', offset, length, source});
        const auto callback = onCopy;
        if (callback) callback();
        if (!inRange(offset, length) || !source || length == 0 || length > StagingWindow::kChunkBytes ||
            copyCalls == failCopyAt) return false;
        std::memcpy(cpu.data() + static_cast<size_t>(offset - base), source, length);
        return true;
    }
    bool flushWrites() override {
        ++flushCalls; events.push_back({'F', base, 0, nullptr});
        const auto callback = onFlush;
        if (callback) callback();
        if (!contextEnabled || flushCalls == failFlushAt) return false;
        gpu = cpu;
        return true;
    }
};

static Bytes pattern(size_t length) {
    Bytes bytes(length);
    for (size_t n = 0; n < length; ++n) bytes[n] = static_cast<uint8_t>((n * 37 + 11) & 0xff);
    return bytes;
}

static void assertError(const StagingWindow &window, StagingError error) {
    CHECK(window.failed()); CHECK(window.error() == error);
    CHECK(!window.cleared()); CHECK(!window.payloadVisible());
}

static void assertLatchedErrorRejectsRetries(StagingWindow &window, MemoryBus &bus,
                                             StagingError original, const Bytes &source) {
    const auto eventCount = bus.events.size();
    const auto contextCalls = bus.contextCalls, zeroCalls = bus.zeroCalls;
    const auto copyCalls = bus.copyCalls, flushCalls = bus.flushCalls;
    const auto stats = window.stats();
    CHECK(!window.zero(kBase, StagingWindow::kBytes));
    CHECK(window.error() == original);
    CHECK(!window.copy(kBase, source.data(), source.size()));
    CHECK(window.error() == original);
    CHECK(bus.events.size() == eventCount && bus.contextCalls == contextCalls);
    CHECK(bus.zeroCalls == zeroCalls && bus.copyCalls == copyCalls && bus.flushCalls == flushCalls);
    CHECK(window.stats().zeroBytesIssued == stats.zeroBytesIssued);
    CHECK(window.stats().copyBytesIssued == stats.copyBytesIssued);
    CHECK(window.stats().zeroChunksIssued == stats.zeroChunksIssued);
    CHECK(window.stats().copyChunksIssued == stats.copyChunksIssued);
    CHECK(window.stats().flushesIssued == stats.flushesIssued);
    assertError(window, original);
}

static void happyPathTests() {
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        CHECK(window.cleared()); CHECK(!window.payloadVisible());
        CHECK(bus.zeroCalls == 256 && bus.flushCalls == 1);
        CHECK(window.stats().zeroBytesIssued == StagingWindow::kBytes);
        CHECK(window.stats().zeroChunksIssued == 256 && window.stats().flushesIssued == 1);
        CHECK(std::all_of(bus.gpu.begin(), bus.gpu.end(), [](uint8_t value) { return value == 0; }));
        for (unsigned n = 0; n < bus.events.size() - 1; ++n) {
            CHECK(bus.events[n].op == 'Z');
            CHECK(bus.events[n].offset == kBase + uint64_t(n) * StagingWindow::kChunkBytes);
            CHECK(bus.events[n].length == StagingWindow::kChunkBytes);
        }
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        const Bytes source = pattern(8193);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        CHECK(window.copy(kBase, source.data(), source.size()));
        CHECK(window.payloadVisible()); CHECK(!window.cleared());
        CHECK(window.stats().copyBytesIssued == source.size());
        CHECK(window.stats().copyChunksIssued == 3);
        CHECK(bus.events[257].op == 'C' && bus.events[257].offset == kBase &&
              bus.events[257].source == source.data() && bus.events[257].length == 4096);
        CHECK(bus.events[258].source == source.data() + 4096 && bus.events[258].length == 4096);
        CHECK(bus.events[259].source == source.data() + 8192 && bus.events[259].length == 1);
        CHECK(std::equal(source.begin(), source.end(), bus.gpu.begin()));
        CHECK(std::all_of(bus.gpu.begin() + static_cast<std::ptrdiff_t>(source.size()), bus.gpu.end(),
                          [](uint8_t value) { return value == 0; }));
        CHECK(bus.gpu != bus.cpu || window.payloadVisible());
    }
    {
        MemoryBus bus; bus.base = 0; StagingWindow window(bus, 0);
        const Bytes source = pattern(StagingWindow::kBytes);
        CHECK(window.zero(0, StagingWindow::kBytes));
        CHECK(window.copy(0, source.data(), source.size()));
        CHECK(bus.gpu == source);
        CHECK(window.stats().copyBytesIssued == StagingWindow::kBytes);
        CHECK(window.stats().copyChunksIssued == 256);
        CHECK(window.stats().flushesIssued == 2);
        CHECK(bus.events[bus.events.size() - 2].op == 'C');
        CHECK(bus.events.back().op == 'F');
        CHECK(bus.events[bus.events.size() - 2].offset + bus.events[bus.events.size() - 2].length ==
              StagingWindow::kBytes);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        const Bytes source = pattern(32);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        CHECK(window.copy(kBase, source.data(), source.size()));
        CHECK(window.payloadVisible());
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        CHECK(window.cleared()); CHECK(!window.payloadVisible());
        CHECK(std::all_of(bus.cpu.begin(), bus.cpu.end(), [](uint8_t value) { return value == 0; }));
        CHECK(std::all_of(bus.gpu.begin(), bus.gpu.end(), [](uint8_t value) { return value == 0; }));
        CHECK(window.copy(kBase, source.data(), source.size()));
        CHECK(window.payloadVisible());
    }
}

static void invalidRequestTests() {
    {
        MemoryBus bus; StagingWindow window(bus, 1);
        assertError(window, StagingError::InvalidWindow);
        CHECK(!window.zero(1, StagingWindow::kBytes)); CHECK(bus.events.empty());
    }
    {
        MemoryBus bus; const uint64_t base = UINT64_MAX & ~(StagingWindow::kBytes - 1);
        StagingWindow window(bus, base);
        assertError(window, StagingError::InvalidWindow);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(!window.zero(kBase + StagingWindow::kBytes, StagingWindow::kBytes));
        assertError(window, StagingError::InvalidRequest); CHECK(bus.events.empty());
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase); const Bytes source = pattern(8);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        const auto oldCalls = bus.events.size();
        CHECK(!window.copy(kBase + StagingWindow::kBytes, source.data(), source.size()));
        assertError(window, StagingError::InvalidRequest); CHECK(bus.events.size() == oldCalls);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(!window.zero(kBase, StagingWindow::kBytes - 1));
        assertError(window, StagingError::InvalidRequest); CHECK(bus.events.empty());
    }
    for (const size_t length : {size_t(0), size_t(StagingWindow::kBytes + 1)}) {
        MemoryBus bus; StagingWindow window(bus, kBase); const Bytes source = pattern(8);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        const auto oldCalls = bus.events.size();
        CHECK(!window.copy(kBase, source.data(), length));
        assertError(window, StagingError::InvalidRequest); CHECK(bus.events.size() == oldCalls);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase); const Bytes source = pattern(8);
        CHECK(!window.copy(kBase, source.data(), source.size()));
        assertError(window, StagingError::BadSequence); CHECK(bus.events.empty());
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        CHECK(!window.copy(kBase, nullptr, 1));
        assertError(window, StagingError::InvalidSource);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        const void *wrapping = reinterpret_cast<const void *>(UINTPTR_MAX - 3);
        CHECK(!window.copy(kBase, wrapping, 8));
        assertError(window, StagingError::InvalidSource);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase); const Bytes source = pattern(8);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        CHECK(window.copy(kBase, source.data(), source.size()));
        CHECK(!window.copy(kBase, source.data(), source.size()));
        assertError(window, StagingError::BadSequence);
    }
}

static void backendFailureTests() {
    const Bytes full = pattern(StagingWindow::kBytes);
    for (unsigned chunk = 1; chunk <= 256; ++chunk) {
        MemoryBus bus; bus.failZeroAt = chunk; StagingWindow window(bus, kBase);
        CHECK(!window.zero(kBase, StagingWindow::kBytes));
        assertError(window, StagingError::ZeroFailed);
        CHECK(bus.zeroCalls == chunk && window.stats().zeroChunksIssued == chunk);
        CHECK(window.stats().zeroBytesIssued == uint64_t(chunk) * StagingWindow::kChunkBytes);
        CHECK(bus.flushCalls == 0);
        if (chunk == 1) assertLatchedErrorRejectsRetries(window, bus, StagingError::ZeroFailed, full);
    }
    for (unsigned chunk = 1; chunk <= 256; ++chunk) {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        bus.failCopyAt = chunk;
        CHECK(!window.copy(kBase, full.data(), full.size()));
        assertError(window, StagingError::CopyFailed);
        CHECK(bus.copyCalls == chunk && window.stats().copyChunksIssued == chunk);
        CHECK(window.stats().copyBytesIssued == uint64_t(chunk) * StagingWindow::kChunkBytes);
        CHECK(bus.flushCalls == 1);
        if (chunk == 1) assertLatchedErrorRejectsRetries(window, bus, StagingError::CopyFailed, full);
    }
    {
        MemoryBus bus; bus.failFlushAt = 1; StagingWindow window(bus, kBase);
        CHECK(!window.zero(kBase, StagingWindow::kBytes));
        assertError(window, StagingError::FlushFailed);
        CHECK(bus.zeroCalls == 256 && bus.flushCalls == 1);
        CHECK(window.stats().flushesIssued == 1);
        assertLatchedErrorRejectsRetries(window, bus, StagingError::FlushFailed, full);
    }
    {
        MemoryBus bus; StagingWindow window(bus, kBase); CHECK(window.zero(kBase, StagingWindow::kBytes));
        bus.failFlushAt = 2;
        CHECK(!window.copy(kBase, full.data(), full.size()));
        assertError(window, StagingError::FlushFailed);
        CHECK(bus.copyCalls == 256 && bus.flushCalls == 2);
        CHECK(window.stats().flushesIssued == 2);
        assertLatchedErrorRejectsRetries(window, bus, StagingError::FlushFailed, full);
    }
}

static unsigned successfulZeroGuardCalls() {
    MemoryBus bus; StagingWindow window(bus, kBase);
    CHECK(window.zero(kBase, StagingWindow::kBytes));
    return bus.contextCalls;
}

static unsigned successfulCopyGuardCalls() {
    MemoryBus bus; StagingWindow window(bus, kBase); const Bytes source = pattern(StagingWindow::kBytes);
    CHECK(window.zero(kBase, StagingWindow::kBytes));
    const unsigned beforeCopy = bus.contextCalls;
    CHECK(window.copy(kBase, source.data(), source.size()));
    return bus.contextCalls - beforeCopy;
}

static void guardFailureTests() {
    const Bytes source = pattern(StagingWindow::kBytes);
    const unsigned zeroGuards = successfulZeroGuardCalls();
    CHECK(zeroGuards == 514); // 256 pre/post chunk pairs plus flush pre/post checks
    for (unsigned guard = 1; guard <= zeroGuards; ++guard) {
        MemoryBus bus; bus.failContextAt = guard; StagingWindow window(bus, kBase);
        CHECK(!window.zero(kBase, StagingWindow::kBytes));
        assertError(window, StagingError::ContextLost);
        CHECK(bus.contextCalls == guard);
        CHECK(bus.zeroCalls <= guard / 2);
        CHECK(bus.events.empty() || bus.events.back().op != 'F' || guard == zeroGuards);
        if (guard == 1) assertLatchedErrorRejectsRetries(window, bus, StagingError::ContextLost, source);
    }
    const unsigned copyGuards = successfulCopyGuardCalls();
    CHECK(copyGuards == 514);
    for (unsigned guard = 1; guard <= copyGuards; ++guard) {
        MemoryBus bus; StagingWindow window(bus, kBase);
        CHECK(window.zero(kBase, StagingWindow::kBytes));
        const unsigned baseline = bus.contextCalls;
        bus.failContextAt = baseline + guard;
        CHECK(!window.copy(kBase, source.data(), source.size()));
        assertError(window, StagingError::ContextLost);
        CHECK(bus.contextCalls == baseline + guard);
        CHECK(window.stats().copyChunksIssued <= guard / 2);
    }
    {
        MemoryBus bus; bus.failContextAt = 1; StagingWindow window(bus, kBase);
        CHECK(!window.zero(kBase, StagingWindow::kBytes));
        CHECK(bus.contextCalls == 1 && bus.zeroCalls == 0 && bus.flushCalls == 0);
        assertError(window, StagingError::ContextLost);
    }
}

static void reentryTests() {
    const Bytes source = pattern(16);
    for (unsigned kind = 0; kind < 4; ++kind) {
        MemoryBus bus; StagingWindow window(bus, kBase);
        if (kind == 0) bus.onContext = [&] { bus.onContext = {}; CHECK(!window.zero(kBase, StagingWindow::kBytes)); };
        if (kind == 1) bus.onZero = [&] { bus.onZero = {}; CHECK(!window.zero(kBase, StagingWindow::kBytes)); };
        if (kind == 2) {
            CHECK(window.zero(kBase, StagingWindow::kBytes));
            bus.onCopy = [&] { bus.onCopy = {}; CHECK(!window.copy(kBase, source.data(), source.size())); };
            CHECK(!window.copy(kBase, source.data(), source.size()));
        } else if (kind == 3) {
            bus.onFlush = [&] { bus.onFlush = {}; CHECK(!window.zero(kBase, StagingWindow::kBytes)); };
            CHECK(!window.zero(kBase, StagingWindow::kBytes));
        } else {
            CHECK(!window.zero(kBase, StagingWindow::kBytes));
        }
        assertError(window, StagingError::ContextLost);
        const auto eventCount = bus.events.size();
        const auto contextCount = bus.contextCalls;
        CHECK(!window.zero(kBase, StagingWindow::kBytes));
        CHECK(bus.events.size() == eventCount && bus.contextCalls == contextCount);
    }
}

static void put32(Bytes &bytes, size_t offset, uint32_t value) {
    for (unsigned n = 0; n < 4; ++n) bytes[offset + n] = static_cast<uint8_t>(value >> (n * 8));
}

static Bytes syntheticPackage() {
    const uint32_t payload = 256;
    const uint32_t types[] = {3,5,2,7,8,9,10,11,1,4,6};
    Bytes bytes(payload + sizeof(types) / sizeof(types[0]) * 16 + 11 * 16, 0);
    const uint32_t length = static_cast<uint32_t>(bytes.size());
    put32(bytes, 0, length); put32(bytes, 4, 36); put32(bytes, 8, 2);
    put32(bytes, 20, length - payload); put32(bytes, 24, payload);
    put32(bytes, 32, static_cast<uint32_t>(sizeof(types) / sizeof(types[0])));
    uint32_t dataOffset = 0;
    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        const size_t record = 36 + i * 16;
        put32(bytes, record, types[i]); put32(bytes, record + 4, 0x100 + types[i]);
        put32(bytes, record + 8, dataOffset); put32(bytes, record + 12, 16);
        std::fill(bytes.begin() + payload + dataOffset, bytes.begin() + payload + dataOffset + 16,
                  static_cast<uint8_t>(types[i]));
        dataOffset += 16;
    }
    return bytes;
}

struct LoaderBus final : n48::HwAccess, MemoryBus {
    StagingWindow staging;
    uint32_t bootStatus = kReady, fbBase = 0x8000, fbTop = 0x83fb;
    unsigned mailboxWrites = 0, solReads = 0;
    bool sosIssued = false;
    Bytes expected;
    std::vector<Bytes> expectedStages;
    size_t nextStage = 0;
    LoaderBus() : staging(*this, kBase) { base = kBase; }

    uint32_t regReadIp(uint16_t hw, uint8_t instance, uint8_t segment, uint32_t reg) override {
        CHECK(instance == 0);
        if (hw == IpDiscovery::HwMp0) {
            CHECK(segment == 0);
            if (reg == kCommandReg) return bootStatus;
            if (reg == kSosReg) { ++solReads; return sosIssued ? 0x3b0f0du : 0; }
            throw std::runtime_error("unexpected MP0 register");
        }
        if (hw == IpDiscovery::HwMmhub) {
            CHECK(segment == 0);
            if (reg == 0x554 || reg == 0x4c7) return fbBase;
            if (reg == 0x555) return fbTop;
            throw std::runtime_error("unexpected MMHUB register");
        }
        if (hw == IpDiscovery::HwDmu) { CHECK(segment == 2 && reg == 0x475); return fbBase; }
        throw std::runtime_error("unexpected IP read");
    }
    bool regWriteIp(uint16_t hw, uint8_t instance, uint8_t segment, uint32_t reg, uint32_t value) override {
        CHECK(hw == IpDiscovery::HwMp0 && instance == 0 && segment == 0);
        CHECK(reg == kAddressReg || reg == kCommandReg);
        CHECK(staging.payloadVisible());
        CHECK(std::equal(expected.begin(), expected.end(), gpu.begin()));
        CHECK(std::all_of(gpu.begin() + static_cast<std::ptrdiff_t>(expected.size()), gpu.end(),
                          [](uint8_t byte) { return byte == 0; }));
        ++mailboxWrites;
        events.push_back({'W', reg, 4, nullptr});
        if (reg == kCommandReg && value == kSosCommand) sosIssued = true;
        return true;
    }
    bool vramWrite(uint64_t offset, const void *source, size_t length) override {
        CHECK(offset == kBase && source && length && length <= StagingWindow::kBytes);
        CHECK(nextStage < expectedStages.size());
        CHECK(expectedStages[nextStage].size() == length);
        CHECK(std::equal(expectedStages[nextStage].begin(), expectedStages[nextStage].end(),
                         static_cast<const uint8_t *>(source)));
        expected.assign(static_cast<const uint8_t *>(source), static_cast<const uint8_t *>(source) + length);
        const bool result = staging.copy(offset, source, length);
        if (result) ++nextStage;
        return result;
    }
    bool vramMemset(uint64_t offset, uint8_t value, size_t length) override {
        CHECK(value == 0);
        return staging.zero(offset, length);
    }
};

static void configureExpectedStages(LoaderBus &bus, const Bytes &firmware) {
    cobalt::psp::Package parsed{};
    CHECK(cobalt::psp::parse(firmware.data(), firmware.size(), parsed));
    const cobalt::psp::Part order[] = {cobalt::psp::Kdb, cobalt::psp::Spl, cobalt::psp::SysDrv,
        cobalt::psp::SocDrv, cobalt::psp::IntfDrv, cobalt::psp::DbgDrv, cobalt::psp::RasDrv,
        cobalt::psp::IpKeyMgrDrv, cobalt::psp::Sos};
    for (const auto part : order) if (parsed.part[part].data)
        bus.expectedStages.emplace_back(parsed.part[part].data, parsed.part[part].data + parsed.part[part].size);
}

static void runLoader(const Bytes &firmware) {
    LoaderBus bus; n48::PspLoader loader(bus);
    CHECK(loader.parseContainer(firmware.data(), firmware.size()));
    configureExpectedStages(bus, firmware);
    CHECK(loader.setFwPriOffset(kBase)); CHECK(loader.preflight());
    const n48::SubBin *stages[] = {&loader.kdb, &loader.spl, &loader.sys, &loader.soc,
        &loader.intf, &loader.dbg, &loader.ras, &loader.ipkey, &loader.sos};
    unsigned stageCount = 0; uint64_t bytesExpected = 0;
    for (const auto *stage : stages) if (stage->present()) { ++stageCount; bytesExpected += stage->size; }
    CHECK(loader.runChain());
    CHECK(loader.sosAlive()); CHECK(bus.staging.payloadVisible());
    CHECK(bus.mailboxWrites == stageCount * 2);
    CHECK(bus.staging.stats().zeroChunksIssued == stageCount * 256);
    CHECK(bus.staging.stats().copyBytesIssued == bytesExpected);
    CHECK(bus.staging.stats().flushesIssued == stageCount * 2);
    CHECK(bus.nextStage == stageCount);
    CHECK(std::equal(loader.sos.data, loader.sos.data + loader.sos.size, bus.gpu.begin()));
    CHECK(std::all_of(bus.gpu.begin() + loader.sos.size, bus.gpu.end(), [](uint8_t byte) { return byte == 0; }));
}

static void loaderFailureTests() {
    const Bytes firmware = syntheticPackage();
    for (unsigned failure = 0; failure < 3; ++failure) {
        LoaderBus bus;
        if (failure == 0) bus.failZeroAt = 1;
        if (failure == 1) bus.failCopyAt = 1;
        if (failure == 2) bus.failFlushAt = 2; // zero flush succeeds, copy flush fails
        configureExpectedStages(bus, firmware);
        n48::PspLoader loader(bus);
        CHECK(loader.parseContainer(firmware.data(), firmware.size()));
        CHECK(loader.setFwPriOffset(kBase)); CHECK(loader.preflight());
        CHECK(!loader.runChain()); CHECK(bus.mailboxWrites == 0);
        CHECK(bus.staging.failed()); CHECK(!bus.staging.cleared()); CHECK(!bus.staging.payloadVisible());
        const unsigned mailboxWrites = bus.mailboxWrites;
        const size_t events = bus.events.size();
        CHECK(!loader.runChain());
        CHECK(bus.mailboxWrites == mailboxWrites && bus.events.size() == events);
    }
}

int main(int argc, char **argv) {
    try {
        happyPathTests(); invalidRequestTests(); backendFailureTests(); guardFailureTests(); reentryTests();
        const Bytes synthetic = syntheticPackage();
        runLoader(synthetic);
        loaderFailureTests();
        for (int n = 1; n < argc; ++n) {
            std::ifstream file(argv[n], std::ios::binary);
            CHECK(file.good());
            const Bytes firmware((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            runLoader(firmware);
            std::printf("PSP staging/loader roundtrip passed: %s\n", argv[n]);
        }
        std::printf("PSP staging tests passed: %u\n", checks);
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
    return 0;
}
