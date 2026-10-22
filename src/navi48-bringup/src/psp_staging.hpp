#pragma once

#include <stdint.h>
#include <stddef.h>

namespace cobalt::psp {

// Bounds/ordering helper only. A hardware caller must separately establish
// device ownership, live mappings, the free VRAM window and its MC translation,
// and one-attempt authorization. The caller must serialize all use and keep
// source buffers valid for copy(). Backend callbacks may not start a new
// operation on this helper; an attempted reentry permanently fails it.
// Backend callbacks must not throw (the kernel target disables exceptions).
// This interface does not authorize GPU access or program any register.
struct StagingBus {
    virtual bool contextValid() = 0;
    // Each operation receives an absolute VRAM byte offset and at most 4 KiB.
    // The backend must implement bounded mapped I/O, including its own checks
    // if device lifetime can change during an operation. False may mean that
    // a partial write occurred; the helper never retries or restores on failure.
    virtual bool zeroChunk(uint64_t offset, size_t length) = 0;
    virtual bool copyChunk(uint64_t offset, const uint8_t *source, size_t length) = 0;
    // Success must mean CPU stores were fenced, the validated HDP endpoint was
    // flushed, and the posted completion read succeeded in the same context.
    virtual bool flushWrites() = 0;
protected:
    ~StagingBus() = default;
};

enum class StagingError : uint8_t {
    None, InvalidWindow, InvalidRequest, InvalidSource, BadSequence,
    ContextLost, ZeroFailed, CopyFailed, FlushFailed
};

struct StagingStats {
    // Issued counts include a failing backend call; they do not claim that
    // every requested byte reached the GPU after a partial/failing operation.
    uint64_t zeroBytesIssued {0}, copyBytesIssued {0};
    uint32_t zeroChunksIssued {0}, copyChunksIssued {0}, flushesIssued {0};
};

class StagingWindow {
public:
    static constexpr uint64_t kBytes = 1ULL << 20;
    static constexpr size_t kChunkBytes = 4096;

    // An explicit zero offset is structurally valid. Whether that region is
    // available is a caller policy decision, not a default/fallback here.
    StagingWindow(StagingBus &backend, uint64_t offset) : bus(backend), base(offset) {
        if ((offset & (kBytes - 1)) || offset > UINT64_MAX - kBytes)
            fail(StagingError::InvalidWindow);
    }
    StagingWindow(const StagingWindow &) = delete;
    StagingWindow &operator=(const StagingWindow &) = delete;
    StagingWindow(StagingWindow &&) = delete;
    StagingWindow &operator=(StagingWindow &&) = delete;

    bool zero(uint64_t offset, size_t length) {
        if (!enter()) return false;
        Operation operation {*this};
        clearReady = visible = false;
        if (offset != base || length != kBytes) return fail(StagingError::InvalidRequest);
        for (uint64_t done = 0; done < kBytes; done += kChunkBytes) {
            if (!guard()) return false;
            if (!issue(counts.zeroChunksIssued, counts.zeroBytesIssued, kChunkBytes)) return false;
            if (!bus.zeroChunk(base + done, kChunkBytes)) return fail(StagingError::ZeroFailed);
            if (!guard()) return false;
        }
        if (!flush()) return false;
        clearReady = true;
        return true;
    }

    bool copy(uint64_t offset, const void *source, size_t length) {
        if (!enter()) return false;
        Operation operation {*this};
        const bool hadClear = clearReady;
        clearReady = visible = false;
        if (offset != base || length == 0 || length > kBytes)
            return fail(StagingError::InvalidRequest);
        const uintptr_t address = reinterpret_cast<uintptr_t>(source);
        if (!source || address > UINTPTR_MAX - length) return fail(StagingError::InvalidSource);
        if (!hadClear) return fail(StagingError::BadSequence);
        const auto *bytes = static_cast<const uint8_t *>(source);
        size_t done = 0;
        while (done < length) {
            const size_t chunk = length - done < kChunkBytes ? length - done : kChunkBytes;
            if (!guard()) return false;
            if (!issue(counts.copyChunksIssued, counts.copyBytesIssued, chunk)) return false;
            if (!bus.copyChunk(base + done, bytes + done, chunk)) return fail(StagingError::CopyFailed);
            if (!guard()) return false;
            done += chunk;
        }
        if (!flush()) return false;
        visible = true;
        return true;
    }

    bool failed() const { return failure != StagingError::None; }
    StagingError error() const { return failure; }
    bool cleared() const { return clearReady && !failed(); }
    // A completed local transfer, not a live device-ownership check or mailbox
    // authorization. The eventual register backend must guard its own accesses.
    bool payloadVisible() const { return visible && !failed(); }
    const StagingStats &stats() const { return counts; }

private:
    StagingBus &bus;
    const uint64_t base;
    StagingError failure {StagingError::None};
    bool clearReady {false}, visible {false}, active {false};
    StagingStats counts {};
    struct Operation {
        StagingWindow &owner;
        ~Operation() { owner.active = false; }
    };
    bool enter() {
        if (failed()) return false;
        if (active) return fail(StagingError::ContextLost);
        active = true;
        return true;
    }
    // Saturating rejection keeps cumulative telemetry truthful even if an
    // authorized owner uses the helper far beyond one finite firmware chain.
    bool issue(uint32_t &chunks, uint64_t &bytes, size_t length) {
        if (chunks == UINT32_MAX || bytes > UINT64_MAX - length)
            return fail(StagingError::InvalidRequest);
        ++chunks;
        bytes += length;
        return true;
    }
    bool fail(StagingError error) {
        if (!failed()) failure = error;
        clearReady = visible = false;
        return false;
    }
    bool guard() {
        if (failed()) return false;
        const bool valid = bus.contextValid();
        if (failed()) return false;
        return valid || fail(StagingError::ContextLost);
    }
    bool flush() {
        if (!guard()) return false;
        if (counts.flushesIssued == UINT32_MAX) return fail(StagingError::InvalidRequest);
        ++counts.flushesIssued;
        if (!bus.flushWrites()) return fail(StagingError::FlushFailed);
        return guard();
    }
};

} // namespace cobalt::psp
