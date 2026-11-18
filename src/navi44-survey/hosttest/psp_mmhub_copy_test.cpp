#include "../src/psp_mmhub_copy.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace copy = cobalt::survey::pspMmhubCopy;
namespace memory = cobalt::survey::pspMemory;
using Register = copy::Register;
using Store = std::pair<Register, uint32_t>;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error( \
    "line " + std::to_string(__LINE__) + ": " #expr); } while (0)

constexpr uint32_t idle = 0x90000000u;
constexpr uint64_t tableDma = 0x1012345000ULL;
constexpr uint64_t dataDma = 0x202468b000ULL;

constexpr unsigned regIndex(Register reg) { return static_cast<unsigned>(reg); }

struct Bus final : copy::Io {
    enum class Reply { Immediate, BusyThenDone, StaleIdle, BadGuardByte, GuardLost, PioError };

    std::array<uint32_t, regIndex(Register::PioCommand) + 1> words {};
    std::array<uint8_t, memory::pageBytes> page {};
    std::vector<Store> writes;
    std::vector<std::pair<unsigned, uint32_t>> invalidations;
    Reply reply {Reply::Immediate};
    unsigned pioReadsBeforeFirstStore {0}, delays {0}, syncs {0};
    unsigned prepareCalls {0}, failStore {0}, failInvalidate {0};
    bool launched {false}, ambiguousCommand {false}, live {true}, corruptSeed {false};
    bool invalidLayout {false}, changePreflight {false};

    Bus() {
        word(Register::Context0Control) = 0x03fffc00;
        word(Register::L1Control) = 0x501;
        word(Register::L2Control) = 0x80602;
        word(Register::L2Control3) = 0x80100007;
        word(Register::L2Control4) = 0xc1;
        word(Register::L2Control5) = 0x3fe0;
        word(Register::SystemApertureLow) = 0x200000;
        word(Register::SystemApertureHigh) = 0x20feff;
        word(Register::FbBase) = 0x8000;
        word(Register::FbTop) = 0x83fb;
        word(Register::PioStatus) = idle;
        word(Register::PioSrcLow) = 0x11;
        word(Register::PioSrcHigh) = 0x22;
        word(Register::PioDstLow) = 0x33;
        word(Register::PioDstHigh) = 0x44;
        word(Register::PioControl) = 0x55;
        word(Register::PioCommand) = 0x66;
    }

    uint32_t &word(Register reg) { return words[regIndex(reg)]; }

    bool guard() override { return live; }

    bool read(Register reg, uint32_t &value) override {
        if (!live) return false;
        if (reg == Register::PioStatus && writes.empty()) ++pioReadsBeforeFirstStore;
        value = word(reg);
        return true;
    }

    bool write(Register reg, uint32_t value) override {
        CHECK(live);
        if (writes.empty()) CHECK(pioReadsBeforeFirstStore == 2);
        writes.emplace_back(reg, value);
        if (writes.size() == failStore) return false;
        word(reg) = value;
        if (reg == Register::PioCommand) {
            CHECK(!launched && value == 64);
            CHECK(word(Register::Context0Control) == 1);
            CHECK(invalidations.size() == 1 && invalidations[0].second == 1);
            launched = true;
            if (ambiguousCommand) return false;
        }
        return true;
    }

    bool prepare(memory::Layout &layout) override {
        ++prepareCalls;
        CHECK(live && writes.empty());
        CHECK(memory::makeLayout(tableDma, dataDma, word(Register::FbBase), word(Register::FbTop), layout));
        if (invalidLayout) layout.leaf ^= 1;
        copy::seedCopyPage(page.data());
        if (corruptSeed) page.back() ^= 1;
        if (changePreflight) word(Register::PioSrcLow) ^= 1;
        return true;
    }

    bool invalidateVmid0() override {
        CHECK(live);
        invalidations.emplace_back(static_cast<unsigned>(writes.size()), word(Register::Context0Control));
        return invalidations.size() != failInvalidate;
    }

    bool syncDataToCpu(const uint8_t *&bytes) override {
        if (!live) return false;
        ++syncs;
        CHECK(word(Register::PioStatus) == idle);
        bytes = page.data();
        return true;
    }

    void delayUs(uint32_t microseconds) override {
        CHECK(launched && microseconds == copy::pollDelayUs);
        ++delays;
        switch (reply) {
        case Reply::BusyThenDone:
            if (delays == 1) {
                word(Register::PioStatus) = 1u << 3;
                break;
            }
            [[fallthrough]];
        case Reply::Immediate:
        case Reply::BadGuardByte:
            std::memcpy(page.data() + 64, page.data(), 64);
            if (reply == Reply::BadGuardByte) page.back() = 0;
            word(Register::PioStatus) = idle;
            break;
        case Reply::GuardLost: live = false; break;
        case Reply::PioError: word(Register::PioStatus) = idle | (1u << 16); break;
        case Reply::StaleIdle: break;
        }
    }
};

const std::vector<Store> launchStores {
    {Register::Context0Control, 0},
    {Register::TableBaseLow, 0x12345007}, {Register::TableBaseHigh, 0x10},
    {Register::TableStartLow, 0x08400000}, {Register::TableStartHigh, 0},
    {Register::TableEndLow, 0x08400000}, {Register::TableEndHigh, 0},
    {Register::L1Control, 0x1859}, {Register::L2Control, 0x80601},
    {Register::L2Control3, 0x80130009}, {Register::L2Control4, 1},
    {Register::PioSrcLow, 0}, {Register::PioSrcHigh, 0x84},
    {Register::PioDstLow, 64}, {Register::PioDstHigh, 0x84},
    {Register::PioControl, 0}, {Register::Context0Control, 1}, {Register::PioCommand, 64},
};

const std::vector<Store> restoreStores {
    {Register::Context0Control, 0},
    {Register::TableBaseLow, 0}, {Register::TableBaseHigh, 0},
    {Register::TableStartLow, 0}, {Register::TableStartHigh, 0},
    {Register::TableEndLow, 0}, {Register::TableEndHigh, 0},
    {Register::L1Control, 0x501}, {Register::L2Control, 0x80602},
    {Register::L2Control3, 0x80100007}, {Register::L2Control4, 0xc1},
    {Register::Context0Control, 0x03fffc00},
    {Register::PioSrcLow, 0x11}, {Register::PioSrcHigh, 0x22},
    {Register::PioDstLow, 0x33}, {Register::PioDstHigh, 0x44},
    {Register::PioControl, 0x55},
};

int main() try {
    for (auto reply : {Bus::Reply::Immediate, Bus::Reply::BusyThenDone}) {
        Bus bus;
        bus.reply = reply;
        const auto result = copy::run(bus);
        CHECK(std::strcmp(result.status, "copy-proven") == 0);
        CHECK(result.copyProven && result.restored && result.commandAttempted);
        CHECK(!result.retainPages && result.rebootAllowed);
        CHECK(bus.syncs == 2 && result.polls == bus.delays);
        CHECK(result.polls == (reply == Bus::Reply::Immediate ? 1u : 2u));
        CHECK(std::memcmp(bus.page.data(), bus.page.data() + 64, 64) == 0);
        CHECK(bus.page.front() == 19 && bus.page.back() == 0xa5);
        std::vector<Store> expected = launchStores;
        expected.insert(expected.end(), restoreStores.begin(), restoreStores.end());
        CHECK(bus.writes == expected);
        CHECK((bus.invalidations == std::vector<std::pair<unsigned, uint32_t>>{{17, 1}, {19, 0}}));
    }
    for (auto reply : {Bus::Reply::StaleIdle, Bus::Reply::BadGuardByte, Bus::Reply::GuardLost,
                       Bus::Reply::PioError}) {
        Bus bus;
        bus.reply = reply;
        const auto result = copy::run(bus);
        CHECK(result.commandAttempted && !result.copyProven && !result.restored);
        CHECK(result.retainPages && !result.rebootAllowed);
        CHECK(bus.writes == launchStores && bus.invalidations.size() == 1);
        if (reply == Bus::Reply::StaleIdle || reply == Bus::Reply::BadGuardByte) {
            CHECK(std::strcmp(result.status, "copy-timeout") == 0);
            CHECK(result.polls == copy::pollLimit);
        } else {
            CHECK(std::strcmp(result.status, "copy-status-unavailable") == 0);
            CHECK(result.polls == 1);
        }
    }
    {
        Bus bus;
        bus.ambiguousCommand = true;
        const auto result = copy::run(bus);
        CHECK(std::strcmp(result.status, "copy-command-uncertain") == 0);
        CHECK(result.commandAttempted && !result.restored && !result.copyProven && bus.launched);
        CHECK(result.retainPages && !result.rebootAllowed && bus.writes == launchStores);
        CHECK(result.polls == 0);
    }
    {
        Bus bus;
        bus.failStore = 4; // Setup stops before enable or command.
        const auto result = copy::run(bus);
        CHECK(std::strcmp(result.status, "mapping-setup-failed") == 0);
        CHECK(!result.commandAttempted && result.restored && !result.retainPages && result.rebootAllowed);
        CHECK((bus.invalidations == std::vector<std::pair<unsigned, uint32_t>>{{5, 0}}));
        CHECK(bus.word(Register::Context0Control) == 0x03fffc00);
        CHECK(bus.word(Register::TableBaseLow) == 0 && bus.word(Register::TableBaseHigh) == 0);
        CHECK(bus.word(Register::PioCommand) == 0x66);
    }
    {
        Bus bus;
        bus.failInvalidate = 1;
        const auto result = copy::run(bus);
        CHECK(std::strcmp(result.status, "mapping-invalidate-uncertain") == 0);
        CHECK(result.retainPages && !result.rebootAllowed && !result.commandAttempted && !result.restored);
        CHECK(bus.writes == std::vector<Store>(launchStores.begin(), launchStores.end() - 1));
        CHECK(bus.invalidations.size() == 1);
    }
    for (bool disableFails : {false, true}) {
        Bus bus;
        if (disableFails) bus.failStore = 19;
        else bus.failInvalidate = 2;
        const auto result = copy::run(bus);
        CHECK(std::strcmp(result.status, "restore-uncertain") == 0);
        CHECK(result.copyProven && result.retainPages && !result.restored && !result.rebootAllowed);
        CHECK(bus.word(Register::TableBaseLow) == 0x12345007);
        CHECK(bus.writes.size() == launchStores.size() + 1);
        CHECK(bus.invalidations.size() == (disableFails ? 1u : 2u));
    }
    for (const auto &change : {Store{Register::Context0Control, 0x03fffc01},
                               Store{Register::TableBaseLow, 0x1007},
                               Store{Register::PioStatus, 1u << 3},
                               Store{Register::PioStatus, idle | (1u << 8)},
                               Store{Register::PioStatus, UINT32_MAX}}) {
        Bus bus;
        bus.word(change.first) = change.second;
        const auto result = copy::run(bus);
        CHECK(bus.writes.empty() && bus.prepareCalls == 0);
        CHECK(!result.retainPages && result.rebootAllowed);
    }
    for (unsigned refuse : {0u, 1u, 2u}) {
        Bus bus;
        bus.invalidLayout = refuse == 0;
        bus.corruptSeed = refuse == 1;
        bus.changePreflight = refuse == 2;
        const auto result = copy::run(bus);
        CHECK(bus.prepareCalls == 1 && bus.writes.empty() && bus.invalidations.empty());
        CHECK(!result.retainPages && result.rebootAllowed);
    }
    std::puts("PSP MMHUB copy tests passed");
    return 0;
} catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
