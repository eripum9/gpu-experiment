#pragma once

#include <stdint.h>

namespace cobalt::survey::pspRing {

constexpr uint32_t kPageBytes = 4096;
constexpr uint32_t kResponseBit = 0x80000000u;
constexpr uint32_t kStatusMask = 0x0000ffffu;
constexpr uint32_t kCreateKmRing = 0x00020000u;
constexpr uint32_t kDestroyRings = 0x00030000u;
constexpr uint32_t kSettleMs = 20;
constexpr unsigned kPolls = 4981;

struct Mailbox {
    uint32_t control, writePointer, addressLow, addressHigh, size, sos;
};

enum class Register { AddressLow, AddressHigh, Size, Control };

// The adapter must hold exclusive hardware access for the whole transaction.
// It must guard each read and write against a lost device or changed owner.
// A lease means the adapter owns a dedicated, verified zero page, visible to
// the PSP at its framebuffer aperture address. A planned BAR range alone
// cannot satisfy this contract. No SOS staging page may be leased here.
struct Io {
    virtual ~Io() = default;
    virtual bool read(Mailbox &sample) = 0;
    virtual bool prepareEmptyLease(uint64_t &address) = 0;
    virtual bool write(Register reg, uint32_t value) = 0;
    virtual void delayMs(uint32_t milliseconds) = 0;
};

struct Result {
    const char *status {"initial-state-refused"};
    Mailbox initial {}, last {};
    uint64_t address {0};
    unsigned storesAttempted {0}, createPolls {0}, stopPolls {0};
    bool createAcknowledged {false}, stopAcknowledged {false};
    // Once published to the PSP, retain the page for this boot. A stop
    // acknowledgement alone is insufficient proof that the page is free.
    bool preserveLease {false};
};

inline bool ready(uint32_t control) {
    return (control & (kResponseBit | kStatusMask)) == kResponseBit;
}

inline bool empty(const Mailbox &sample) {
    return sample.addressLow == 0 && sample.addressHigh == 0 && sample.size == 0;
}

inline bool matchesLease(const Mailbox &sample, uint64_t address) {
    return sample.addressLow == static_cast<uint32_t>(address) &&
           sample.addressHigh == static_cast<uint32_t>(address >> 32) &&
           sample.size == kPageBytes;
}

inline bool readLive(Io &io, uint32_t expectedSos, Result &result) {
    Mailbox sample {};
    if (!io.read(sample)) return false;
    result.last = sample;
    return sample.sos == expectedSos && sample.writePointer == 0 &&
           sample.control != UINT32_MAX && sample.addressLow != UINT32_MAX &&
           sample.addressHigh != UINT32_MAX && sample.size != UINT32_MAX;
}

inline bool store(Io &io, Result &result, Register reg, uint32_t value) {
    result.preserveLease = true;
    ++result.storesAttempted;
    return io.write(reg, value);
}

inline bool waitForReply(Io &io, uint32_t expectedSos, uint32_t command,
                         uint32_t priorControl, bool stopping, Result &result) {
    io.delayMs(kSettleMs);
    bool sawCommandPending = false;
    unsigned consecutive = 0;
    Mailbox candidate {};
    for (unsigned poll = 0; poll < kPolls; ++poll) {
        ++(stopping ? result.stopPolls : result.createPolls);
        if (!readLive(io, expectedSos, result)) return false;
        const auto &sample = result.last;
        const bool matchingLease = matchesLease(sample, result.address);
        if (!matchingLease && !(stopping && empty(sample))) return false;
        if (sample.control == command) sawCommandPending = true;
        if ((sample.control & kResponseBit) && !ready(sample.control)) return false;

        // A ready value carried over from before the store is not evidence
        // of completion. Require a witnessed pending command or a fresh
        // ready response that echoes this command.
        const bool freshEcho = sample.control != priorControl &&
                               sample.control == (kResponseBit | command);
        if (ready(sample.control) && (sawCommandPending || freshEcho)) {
            const bool sameReply = candidate.control == sample.control &&
                candidate.addressLow == sample.addressLow &&
                candidate.addressHigh == sample.addressHigh &&
                candidate.size == sample.size;
            consecutive = sameReply ? consecutive + 1 : 1;
            candidate = sample;
            if (consecutive == 2) return true;
        } else {
            consecutive = 0;
        }
        if (poll + 1 < kPolls) io.delayMs(1);
    }
    return false;
}

// Only create an empty kernel-mode ring and stop it. No doorbell, ring
// packet, firmware upload, recovery command or retry is part of this test.
inline Result run(Io &io, uint32_t expectedSos) {
    Result result;
    if (expectedSos == 0 || expectedSos == UINT32_MAX ||
        !readLive(io, expectedSos, result) || !ready(result.last.control) || !empty(result.last)) return result;
    result.initial = result.last;
    if (!readLive(io, expectedSos, result) || result.last.control != result.initial.control ||
        !empty(result.last)) return result;

    result.status = "lease-refused";
    if (!io.prepareEmptyLease(result.address) || !result.address ||
        (result.address & (kPageBytes - 1)) ||
        static_cast<uint32_t>(result.address >> 32) == UINT32_MAX) return result;
    result.status = "pre-store-state-changed";
    if (!readLive(io, expectedSos, result) || result.last.control != result.initial.control ||
        !empty(result.last)) return result;

    result.status = "ring-programming-unconfirmed";
    if (!store(io, result, Register::AddressLow, static_cast<uint32_t>(result.address)) ||
        !store(io, result, Register::AddressHigh, static_cast<uint32_t>(result.address >> 32)) ||
        !store(io, result, Register::Size, kPageBytes) ||
        !readLive(io, expectedSos, result) || result.last.control != result.initial.control ||
        !matchesLease(result.last, result.address)) return result;

    result.status = "create-unconfirmed";
    if (!store(io, result, Register::Control, kCreateKmRing) ||
        !waitForReply(io, expectedSos, kCreateKmRing, result.initial.control, false, result)) return result;
    result.createAcknowledged = true;

    const uint32_t createReply = result.last.control;
    result.status = "stop-unconfirmed";
    if (!store(io, result, Register::Control, kDestroyRings) ||
        !waitForReply(io, expectedSos, kDestroyRings, createReply, true, result)) return result;
    result.stopAcknowledged = true;
    result.status = "created-and-stopped";
    return result;
}

} // namespace cobalt::survey::pspRing
