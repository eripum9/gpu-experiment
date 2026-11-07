#pragma once

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOMapper.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/libkern.h>

namespace cobalt {

// Owns one device-visible page. This is a DMA/bus address, not a CPU physical
// address or a GPU virtual address. All methods require external serialization
// and a sleepable client context (IOKit preparation may block).
class PspDmaPage final {
public:
    static constexpr UInt64 kSize = 4096;
    struct DeviceAddress { UInt64 value; };

    PspDmaPage() = default;
    PspDmaPage(const PspDmaPage &) = delete;
    PspDmaPage &operator=(const PspDmaPage &) = delete;
    ~PspDmaPage() { reset(); }

    // As in XNU's device DMA creation, absence of iommu-parent permits the
    // command's default mapper, or direct DMA if no system mapper exists.
    bool allocate(IOPCIDevice *device) {
        if (!device || memory_) return false;
        OSObject *parent = device->copyProperty("iommu-parent");
        mapper_ = IOMapper::copyMapperForDevice(device);
        const bool unresolved = parent && !mapper_;
        if (parent) parent->release();
        if (unresolved) return false;
        memory_ = IOBufferMemoryDescriptor::withOptions(
            kIODirectionInOut, kSize, kSize);
        if (!memory_ || memory_->getLength() != kSize || !memory_->getBytesNoCopy()) {
            reset(); return false;
        }
        bzero(memory_->getBytesNoCopy(), kSize);
        if (memory_->prepare(kIODirectionInOut) != kIOReturnSuccess) {
            reset(); return false;
        }
        memoryPrepared_ = true;
        command_ = IODMACommand::withSpecification(
            kIODMACommandOutputHost64, 48, kSize, IODMACommand::kMapped,
            0, kSize, mapper_);
        if (!command_ || command_->setMemoryDescriptor(memory_, false) != kIOReturnSuccess) {
            reset(); return false;
        }
        attached_ = true;
        // prepare synchronizes the zero-filled descriptor to any bounce buffer.
        if (command_->prepare(0, kSize) != kIOReturnSuccess) {
            reset(); return false;
        }
        commandPrepared_ = true;
        IODMACommand::Segment64 segment {};
        UInt64 offset = 0;
        UInt32 count = 1;
        if (command_->gen64IOVMSegments(&offset, &segment, &count) != kIOReturnSuccess ||
            count != 1 || offset != kSize || segment.fLength != kSize || !segment.fIOVMAddr ||
            (segment.fIOVMAddr & (kSize - 1)) != 0 ||
            segment.fIOVMAddr > ((1ULL << 48) - kSize)) {
            reset(); return false;
        }
        address_.value = segment.fIOVMAddr;
        return true;
    }

    DeviceAddress deviceAddress() const { return address_; }
    bool ready() const { return commandPrepared_; }

    // Prepare a flat page table with a single valid entry at index zero.
    bool initializeTable(uint64_t entry) {
        if (!ready() || !entry) return false;
        auto *words = static_cast<uint64_t *>(memory_->getBytesNoCopy());
        bzero(words, kSize);
        words[0] = entry;
        return command_->synchronize(kIODirectionOut) == kIOReturnSuccess;
    }

    // This preparation checkpoint never publishes an address to the GPU.
    // A future transfer must keep the lease alive until hardware is quiescent.
    void reset() {
        if (commandPrepared_) { command_->complete(); commandPrepared_ = false; }
        if (attached_) { command_->clearMemoryDescriptor(false); attached_ = false; }
        if (command_) { command_->release(); command_ = nullptr; }
        if (memoryPrepared_) { memory_->complete(kIODirectionInOut); memoryPrepared_ = false; }
        if (memory_) { memory_->release(); memory_ = nullptr; }
        if (mapper_) { mapper_->release(); mapper_ = nullptr; }
        address_.value = 0;
    }

private:
    IOBufferMemoryDescriptor *memory_ = nullptr;
    IODMACommand *command_ = nullptr;
    IOMapper *mapper_ = nullptr;
    DeviceAddress address_ {0};
    bool memoryPrepared_ = false;
    bool attached_ = false;
    bool commandPrepared_ = false;
};

} // namespace cobalt
