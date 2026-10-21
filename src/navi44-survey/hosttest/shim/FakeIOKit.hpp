#pragma once
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <utility>

using SInt32 = int32_t;
using UInt8 = uint8_t;
using IOOptionBits = uint32_t;
using IOByteCount = uint64_t;
using task_t = void *;
inline task_t kernel_task = reinterpret_cast<void *>(1);
constexpr IOOptionBits kIOMapAnywhere = 1, kIOMapUnique = 0x04000000;
constexpr IOOptionBits kIOMapReadOnly = 0x1000, kIOMapInhibitCache = 0x100;
constexpr IOOptionBits kIOMapCacheMask = 0xf00, kIOMemoryMapperNone = 0x800;

struct TestState {
    std::string boot = "1";
    bool bootPresent = true, superStart = true, allocFail = false, dataFail = false;
    bool publicationFail = false;
    unsigned allocations = 0, mapsLive = 0, mapRequests = 0, mapReleases = 0;
    unsigned memsizeReads = 0, backingDescriptorsLive = 0, backingDescriptorReleases = 0;
    std::vector<uint32_t> memsizeValues;
    std::function<void(unsigned)> onMemsize;
};
inline TestState testState;

#define OSDeclareDefaultStructors(T) public: T() = default; ~T() override = default;
#define OSDefineMetaClassAndStructors(T, B)
#define OSDynamicCast(T, value) dynamic_cast<T *>(value)

class OSObject {
    unsigned refs = 1;
public:
    virtual ~OSObject() = default;
    void retain() { ++refs; }
    void release() { if (--refs == 0) delete this; }
};
class OSData : public OSObject {
public:
    std::vector<uint8_t> bytes;
    static OSData *withBytes(const void *p, unsigned n) {
        if (testState.dataFail) return nullptr;
        auto *data = new OSData;
        const auto *start = static_cast<const uint8_t *>(p);
        data->bytes.assign(start, start + n);
        return data;
    }
};

class IOService : public OSObject {
public:
    bool registered = false;
    unsigned stopCalls = 0, startCalls = 0;
    std::map<std::string, std::string> strings;
    std::map<std::string, uint64_t> numbers;
    std::map<std::string, std::vector<uint8_t>> blobs;
    virtual IOService *probe(IOService *, SInt32 *) { return this; }
    virtual bool start(IOService *) { ++startCalls; return testState.superStart; }
    virtual void stop(IOService *) { ++stopCalls; }
    bool setProperty(const char *key, const char *value) { strings[key] = value; return true; }
    bool setProperty(const char *key, uint64_t value, unsigned) { numbers[key] = value; return true; }
    bool setProperty(const char *key, bool value) { numbers[key] = value ? 1 : 0; return true; }
    bool setProperty(const char *key, OSObject *object) {
        if (testState.mapsLive || testState.backingDescriptorsLive)
            throw std::runtime_error("GPU resources retained at snapshot publication");
        if (testState.publicationFail) return false;
        auto *value = dynamic_cast<OSData *>(object);
        if (!value) throw std::runtime_error("non OSData publication");
        blobs[key] = value->bytes; return true;
    }
    void removeProperty(const char *key) { strings.erase(key); numbers.erase(key); blobs.erase(key); }
    void registerService() {
        if (testState.mapsLive || testState.backingDescriptorsLive || testState.allocations)
            throw std::runtime_error("GPU resources retained at registerService");
        registered = true;
    }
};

class IOMemoryDescriptor;
class IOMemoryMap : public OSObject {
public:
    uint64_t physical = 0, length = 0;
    uintptr_t address = 0;
    IOOptionBits options = 0;
    IOMemoryDescriptor *descriptor = nullptr;
    bool ownsDescriptor = false;
    IOByteCount descriptorOffset = 0;
    bool fragmented = false, wrongSegment = false;
    std::function<void()> onAddress;
    IOMemoryMap() { ++testState.mapsLive; }
    ~IOMemoryMap() override;
    uint64_t getPhysicalAddress() { return physical; }
    IOByteCount getLength() { return length; }
    uintptr_t getVirtualAddress() { if (onAddress) onAddress(); return address; }
    IOOptionBits getMapOptions() { return options; }
    IOMemoryDescriptor *getMemoryDescriptor() { return descriptor; }
    uint64_t getPhysicalSegment(IOByteCount offset, IOByteCount *n, IOOptionBits segmentOptions);
};

class IOMemoryDescriptor : public OSObject {
public:
    uint64_t physical = 0, length = 0, contiguous = 0;
    std::vector<uint32_t> storage; // aligned backing for the mapped test window only
    bool mapFail = false, mapTruncated = false, mapWrongPhysical = false;
    bool mapWritable = false, mapCached = false, mapNullAddress = false;
    bool mapWrongDescriptor = false, mapFragmented = false;
    bool mapOriginalDescriptor = false, mapDescriptorWrongLength = false;
    bool mapDescriptorWrongPhysical = false, mapDescriptorFragmented = false;
    bool mapDescriptorWrongSegment = false, mapSegmentWrongPhysical = false;
    bool sourceWrongSegment = false, sourceFragmented = false;
    bool physicalSegmentWrong = false;
    bool uniqueBacking = false;
    uint64_t expectedOffset = 0, expectedLength = 0;
    unsigned requests = 0;
    std::function<void()> onMap, onAddress;
    ~IOMemoryDescriptor() override {
        if (uniqueBacking) { --testState.backingDescriptorsLive; ++testState.backingDescriptorReleases; }
    }
    uint64_t getPhysicalAddress() { return physical; }
    IOByteCount getLength() { return length; }
    uint64_t getPhysicalSegment(IOByteCount offset, IOByteCount *n, IOOptionBits options) {
        if (options != kIOMemoryMapperNone) throw std::runtime_error("translated physical descriptor");
        if (offset >= length || offset >= contiguous) { *n = 0; return 0; }
        *n = contiguous - offset;
        if (sourceFragmented && offset) *n = expectedLength - 1;
        return physical + offset + ((sourceWrongSegment && offset) || physicalSegmentWrong ? 4 : 0);
    }
    IOMemoryMap *createMappingInTask(task_t task, uint64_t address, IOOptionBits options,
                                   uint64_t offset, uint64_t n) {
        ++testState.mapRequests; ++requests;
        if (task != kernel_task || address != 0 || offset != expectedOffset || n != expectedLength ||
            options != (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache))
            throw std::runtime_error("unexpected mapping request");
        if (onMap) onMap();
        if (mapFail) return nullptr;
        auto *map = new IOMemoryMap;
        map->physical = physical + offset + (mapWrongPhysical ? 4 : 0);
        map->length = n - (mapTruncated ? 1 : 0);
        map->fragmented = mapFragmented;
        map->wrongSegment = mapSegmentWrongPhysical;
        map->options = options & ~(mapWritable ? kIOMapReadOnly : 0u);
        if (mapCached) map->options &= ~kIOMapCacheMask;
        // Reproduce XNU makeMapping's unique-physical branch: withAddressRange
        // creates a separate exact-length descriptor; the map offset is zero.
        if (!mapWrongDescriptor) {
            if (mapOriginalDescriptor) {
                map->descriptor = this;
                map->descriptorOffset = offset;
            } else {
                auto *backing = new IOMemoryDescriptor;
                backing->uniqueBacking = true;
                ++testState.backingDescriptorsLive;
                backing->physical = physical + offset + (mapDescriptorWrongPhysical ? 4 : 0);
                backing->length = n + (mapDescriptorWrongLength ? 1 : 0);
                backing->contiguous = n - (mapDescriptorFragmented ? 1 : 0);
                // A deliberately inconsistent descriptor must fail independently
                // of the map's reported start/length.
                backing->physicalSegmentWrong = mapDescriptorWrongSegment;
                map->descriptor = backing;
                map->ownsDescriptor = true;
            }
        }
        map->address = mapNullAddress ? 0 : reinterpret_cast<uintptr_t>(storage.data());
        map->onAddress = onAddress;
        return map;
    }
};
inline IOMemoryMap::~IOMemoryMap() {
    if (ownsDescriptor) descriptor->release();
    --testState.mapsLive; ++testState.mapReleases;
}
inline uint64_t IOMemoryMap::getPhysicalSegment(IOByteCount offset, IOByteCount *n, IOOptionBits segmentOptions) {
    if (!descriptor) throw std::runtime_error("null mapping descriptor");
    const uint64_t result = descriptor->getPhysicalSegment(descriptorOffset + offset, n, segmentOptions);
    if (fragmented) *n = length - 1;
    return result + (wrongSegment ? 4 : 0);
}
using IODeviceMemory = IOMemoryDescriptor;

class IOPCIDevice : public IOService {
public:
    uint32_t identity = 0x75901002, classRevision = 0x030000c0, subsystem = 0x12341002;
    uint16_t command = 2;
    uint8_t header = 0;
    uint32_t bars[6] = {0x0c, 0x10, 0, 0, 0, 0xc0000000};
    IODeviceMemory *memories[6] = {};
    unsigned identityReads = 0, otherReads = 0, descriptorReads = 0;
    std::function<void(uint8_t)> onRead;
    uint32_t configRead32(uint8_t offset) {
        if (onRead) onRead(offset);
        if (offset == 0) { ++identityReads; return identity; }
        ++otherReads;
        if (offset == 8) return classRevision;
        if (offset == 0x2c) return subsystem;
        if (offset >= 0x10 && offset <= 0x24 && offset % 4 == 0) return bars[(offset - 0x10) / 4];
        throw std::runtime_error("unexpected config32 read");
    }
    uint16_t configRead16(uint8_t offset) {
        ++otherReads;
        if (onRead) onRead(offset);
        if (offset == 4) return command;
        throw std::runtime_error("unexpected config16 read");
    }
    uint8_t configRead8(uint8_t offset) {
        ++otherReads;
        if (onRead) onRead(offset);
        if (offset == 0x0e) return header;
        throw std::runtime_error("unexpected config8 read");
    }
    IODeviceMemory *getDeviceMemoryWithRegister(uint8_t offset) {
        ++descriptorReads;
        if (offset < 0x10 || offset > 0x24 || offset % 4) throw std::runtime_error("unexpected descriptor");
        return memories[(offset - 0x10) / 4];
    }
    // Deliberately no config-write, enable, DMA, IRQ, or provider-open methods.
};

inline bool PE_parse_boot_argn(const char *key, void *out, int n) {
    if (std::string(key) != "cobalt-survey") throw std::runtime_error("unexpected boot argument");
    if (!testState.bootPresent) return false;
    // Reproduce XNU's integer conversion first, including decimal/hex/octal.
    // The real API does not choose string versus integer from buffer size.
    // Space and tab terminate the value in the actual boot-argument string.
    const std::string token = testState.boot.substr(0, testState.boot.find_first_of(" \t"));
    char *end = nullptr;
    const auto numeric = std::strtoll(token.c_str(), &end, 0);
    if (!token.empty() && end && *end == '\0') {
        const uint32_t integer = static_cast<uint32_t>(numeric);
        std::memcpy(out, &integer, static_cast<size_t>(n) < sizeof(integer) ? static_cast<size_t>(n) : sizeof(integer));
    } else {
        std::memset(out, 0, static_cast<size_t>(n));
        std::memcpy(out, token.data(), token.size() < static_cast<size_t>(n) ? token.size() : static_cast<size_t>(n));
    }
    return true;
}
inline void *IOMalloc(uint64_t n) {
    if (n != 10240) throw std::runtime_error("unbounded allocation");
    if (testState.allocFail) return nullptr;
    ++testState.allocations; return std::malloc(static_cast<size_t>(n));
}
inline void IOFree(void *p, uint64_t n) {
    if (!p || n != 10240) throw std::runtime_error("invalid IOFree");
    --testState.allocations; std::free(p);
}
inline void IOLog(const char *, ...) {}
inline uint32_t OSSwapLittleToHostInt32(uint32_t value) {
    const unsigned index = testState.memsizeReads++;
    if (testState.onMemsize) testState.onMemsize(index);
    return index < testState.memsizeValues.size() ? testState.memsizeValues[index] : value;
}
