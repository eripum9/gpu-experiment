#include "../src/psp_ring_checkpoint.hpp"
#include "../src/psp_mmhub_layout.hpp"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ring = cobalt::survey::pspRing;
namespace memory = cobalt::survey::pspMemory;
using Register = ring::Register;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error( \
    "line " + std::to_string(__LINE__) + ": " #expr); } while (0)

constexpr uint32_t kSos = 0x0835a4a1;
constexpr uint32_t kIdle = 0x80c00000u;
constexpr uint64_t kAddress = 0x0000008004800000ULL;

struct Bus final : ring::Io {
    enum class Reply { PendingThenReady, Echo, Stale, Error, LostSos, PointerMoved };
    ring::Mailbox state {kIdle, 0, 0, 0, 0, kSos};
    Reply createReply {Reply::PendingThenReady}, stopReply {Reply::Echo};
    bool leaseAvailable {true}, clearOnStop {true};
    unsigned leaseRequests {0}, refuseStore {0};
    uint64_t leaseAddress {kAddress};
    uint32_t command {0}, elapsed {0};
    std::vector<std::pair<Register, uint32_t>> writes;
    std::vector<uint32_t> delays;

    bool read(ring::Mailbox &sample) override {
        sample = state;
        if (!command) return true;
        CHECK(elapsed >= 20);
        const bool stopping = command == 0x00030000u;
        switch (stopping ? stopReply : createReply) {
        case Reply::PendingThenReady:
            sample.control = elapsed == 20 ? command : kIdle;
            break;
        case Reply::Echo: sample.control = 0x80000000u | command; break;
        case Reply::Stale: sample.control = state.control; break;
        case Reply::Error: sample.control = 0x80000001u; break;
        case Reply::LostSos: sample.sos = 0; break;
        case Reply::PointerMoved: sample.writePointer = 16; break;
        }
        if (stopping && clearOnStop && sample.control == 0x80030000u) {
            sample.addressLow = sample.addressHigh = sample.size = 0;
        }
        return true;
    }

    bool prepareEmptyLease(uint64_t &address) override {
        ++leaseRequests;
        address = leaseAddress;
        return leaseAvailable;
    }

    bool write(Register reg, uint32_t value) override {
        writes.emplace_back(reg, value);
        if (writes.size() == refuseStore) return false;
        switch (reg) {
        case Register::AddressLow: state.addressLow = value; break;
        case Register::AddressHigh: state.addressHigh = value; break;
        case Register::Size: state.size = value; break;
        case Register::Control:
            if (command && createReply == Reply::Echo) state.control = 0x80000000u | command;
            command = value;
            elapsed = 0;
            break;
        }
        return true;
    }

    void delayMs(uint32_t ms) override {
        delays.push_back(ms);
        elapsed += ms;
    }
};

int main() try {
    {
        constexpr uint64_t table = 0x12345000, data = 0x2468b000;
        memory::Layout layout {};
        CHECK(memory::makeLayout(table, data, 0x8000, 0x83fb, layout));
        CHECK(layout.tableBase == 0x12345007ULL);
        CHECK(layout.leaf == 0x808000002468b067ULL);
        CHECK(layout.gpuAddress == 0x8400000000ULL);

        // Refuse aliasing, truncation and overflow before a root or leaf
        // encoding can become available to a future register transaction.
        CHECK(!memory::makeLayout(table, table, 0x8000, 0x83fb, layout));
        CHECK(layout.tableBase == 0 && layout.leaf == 0 && layout.gpuAddress == 0);
        CHECK(!memory::makeLayout(table + 1, data, 0x8000, 0x83fb, layout));
        CHECK(!memory::makeLayout(table, 1ULL << 48, 0x8000, 0x83fb, layout));
        CHECK(!memory::makeLayout(table, data, 0x8000, 0xffffff, layout));
        CHECK(!memory::makeLayout(table, 0x8400000000ULL, 0x8000, 0x83fb, layout));
        CHECK(!memory::makeLayout(table, data, 0x83fb, 0x8000, layout));
    }
    {
        Bus bus;
        const auto result = ring::run(bus, kSos);
        const std::vector<std::pair<Register, uint32_t>> expected {
            {Register::AddressLow, 0x04800000}, {Register::AddressHigh, 0x80},
            {Register::Size, 4096}, {Register::Control, 0x00020000},
            {Register::Control, 0x00030000},
        };
        CHECK(bus.writes == expected);
        CHECK((bus.delays == std::vector<uint32_t>{20, 1, 1, 20, 1}));
        CHECK(result.createAcknowledged && result.stopAcknowledged && result.preserveLease);
        CHECK(result.storesAttempted == 5 && result.createPolls == 3 && result.stopPolls == 2);
    }
    for (bool staleRing : {false, true}) {
        Bus bus;
        if (staleRing) bus.state.size = 4096;
        else bus.leaseAvailable = false;
        const auto result = ring::run(bus, kSos);
        CHECK(bus.writes.empty() && !result.preserveLease);
        CHECK(bus.leaseRequests == (staleRing ? 0u : 1u));
    }
    {
        Bus bus;
        bus.leaseAddress = kAddress + 4;
        CHECK(!ring::run(bus, kSos).preserveLease && bus.writes.empty());
    }
    for (unsigned refused : {1u, 2u, 3u, 4u, 5u}) {
        Bus bus;
        bus.refuseStore = refused;
        const auto result = ring::run(bus, kSos);
        CHECK(bus.writes.size() == refused && result.storesAttempted == refused);
        CHECK(result.preserveLease && !result.stopAcknowledged);
    }
    for (auto reply : {Bus::Reply::Stale, Bus::Reply::Error, Bus::Reply::LostSos, Bus::Reply::PointerMoved}) {
        Bus bus;
        bus.createReply = reply;
        const auto result = ring::run(bus, kSos);
        CHECK(!result.createAcknowledged && result.preserveLease && bus.writes.size() == 4);
        CHECK(result.createPolls == (reply == Bus::Reply::Stale ? 4981u : 1u));
    }
    {
        Bus bus;
        bus.createReply = Bus::Reply::Echo;
        bus.stopReply = Bus::Reply::Stale;
        const auto result = ring::run(bus, kSos);
        CHECK(result.createAcknowledged && !result.stopAcknowledged);
        CHECK(result.preserveLease && result.stopPolls == 4981 && bus.writes.size() == 5);
    }
    std::puts("PSP ring checkpoint host tests passed");
    return 0;
} catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
