#include "CobaltNavi44Survey.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/OSByteOrder.h>
#include <pexpert/pexpert.h>
#include "ipdiscovery.hpp"
#include "gpu_profile.hpp"
#include "gfx_topology.hpp"
#include "aperture_plan.hpp"
#include "psp_staging.hpp"
#include "psp.hpp"
#include "psp_container.hpp"
#include "psp_firmware.hpp"

#define super IOService
OSDefineMetaClassAndStructors(CobaltNavi44Survey, IOService)

namespace {
constexpr uint32_t kIdentity = 0x75901002;
constexpr uint64_t kGiB = 1ULL << 30;
constexpr uint64_t kDiscoveryTail = 64 * 1024;
constexpr uint64_t kDiscoverySize = 10 * 1024;
// Linux v6.19 amdgpu_discovery.c: RCC_CONFIG_MEMSIZE is dword 0xde3,
// containing the VRAM size in MiB. Only this direct register is read.
constexpr uint64_t kMemsizePage = 0x3000;
constexpr uint64_t kMemsizePageSize = 0x1000;
constexpr uint64_t kMemsizeInPage = 0x378c - kMemsizePage;
constexpr IOOptionBits kMapOptions = kIOMapAnywhere | kIOMapUnique |
    kIOMapReadOnly | kIOMapInhibitCache;

bool armed() {
    // XNU returns recognized numeric boot arguments as an integer, regardless
    // of buffer size. Require value 1, rather than accepting arbitrary nonzero.
    uint32_t value = 0;
    return PE_parse_boot_argn("cobalt-survey", &value, sizeof(value)) && value == 1u;
}

bool indexedArmed() {
    uint32_t value = 0;
    return PE_parse_boot_argn("cobalt-survey-indexed", &value, sizeof(value)) && value == 1u;
}

bool stateArmed() {
    uint32_t value = 0;
    return PE_parse_boot_argn("cobalt-survey-state", &value, sizeof(value)) && value == 1u;
}

bool apertureArmed() {
    uint32_t value = 0;
    return PE_parse_boot_argn("cobalt-survey-aperture", &value, sizeof(value)) && value == 1u;
}

bool stagingArmed() {
    uint32_t value = 0;
    return PE_parse_boot_argn("cobalt-survey-staging", &value, sizeof(value)) && value == 1u;
}

bool kdbArmed() {
    uint32_t value = 0;
    return PE_parse_boot_argn("cobalt-survey-kdb", &value, sizeof(value)) && value == 1u;
}

struct PciState {
    uint32_t identity, classRevision, subsystem;
    uint16_t command;
    uint8_t header;
    uint32_t bars[6];
};

bool capture(IOPCIDevice *pci, PciState &s) {
    s.identity = pci->configRead32(static_cast<UInt8>(0));
    if (s.identity != kIdentity) return false;
    s.command = pci->configRead16(static_cast<UInt8>(4));
    s.classRevision = pci->configRead32(static_cast<UInt8>(8));
    s.header = pci->configRead8(static_cast<UInt8>(0x0e));
    s.subsystem = pci->configRead32(static_cast<UInt8>(0x2c));
    for (unsigned i = 0; i < 6; ++i)
        s.bars[i] = pci->configRead32(static_cast<UInt8>(0x10 + 4 * i));
    return true;
}

bool validHeaderClass(const PciState &s) {
    // Type-0 PCI endpoint, display/VGA or display/other, programming IF 0.
    const uint32_t cls = s.classRevision >> 8;
    return (s.header & 0x7f) == 0 && (cls == 0x030000 || cls == 0x038000);
}

bool unchanged(IOPCIDevice *pci, const PciState &s) {
    PciState now {};
    if (!capture(pci, now) || now.identity != s.identity ||
        now.command != s.command || now.classRevision != s.classRevision ||
        now.header != s.header || now.subsystem != s.subsystem) return false;
    for (unsigned i = 0; i < 6; ++i)
        if (now.bars[i] != s.bars[i]) return false;
    return true;
}

bool range(uint64_t base, uint64_t length) {
    return base != 0 && length != 0 && length - 1 <= UINT64_MAX - base;
}

struct Aperture {
    IODeviceMemory *memory;
    uint64_t physical, length;
};

// Descriptor references are borrowed from the PCI provider, which remains the
// provider throughout synchronous start. No descriptor or map escapes survey().
Aperture aperture(IOPCIDevice *pci, unsigned index) {
    Aperture a {};
    a.memory = pci->getDeviceMemoryWithRegister(static_cast<UInt8>(0x10 + index * 4));
    if (a.memory) {
        a.physical = a.memory->getPhysicalAddress();
        a.length = a.memory->getLength();
    }
    return a;
}

bool apertureValid(const Aperture &a, uint64_t base) {
    if (!a.memory || a.physical != base || !range(base, a.length)) return false;
    IOByteCount contiguous = 0;
    const uint64_t physical = a.memory->getPhysicalSegment(0, &contiguous, kIOMemoryMapperNone);
    return physical == base && contiguous >= a.length;
}

bool apertureUnchanged(IOPCIDevice *pci, unsigned index, const Aperture &a) {
    const Aperture now = aperture(pci, index);
    return now.memory == a.memory && now.physical == a.physical &&
        now.length == a.length && apertureValid(now, a.physical);
}

// Fixed-purpose routing proof. The native offset is resolved from the validated
// NBIF record, never accepted from a boot argument or a raw remap alone.
struct HdpFlushTarget {
    uint32_t byteOffset {0}, nativeOffset {0};
    bool native {false};
    bool valid() const {
        const uint32_t page = nativeOffset & ~0xfffu;
        return !(nativeOffset & 3) && page != 0 && page != 0x7f000 &&
            nativeOffset < 0x80000 && byteOffset == (native ? nativeOffset : 0x7f000);
    }
    uint32_t pageOffset() const { return byteOffset & ~0xfffu; }
};

struct KdbMailboxTarget {
    uint32_t commandOffset {0}, addressOffset {0}, sosOffset {0};
    uint32_t page() const { return commandOffset & ~0xfffu; }
    bool valid() const {
        return page() && page() != 0x7f000 && page() < 0x80000 &&
            !(commandOffset & 3u) && !(addressOffset & 3u) && !(sosOffset & 3u) &&
            (addressOffset & ~0xfffu) == page() && (sosOffset & ~0xfffu) == page() &&
            commandOffset != addressOffset && commandOffset != sosOffset && addressOffset != sosOffset;
    }
};

// Only two fixed mailbox endpoints are writable. The guard and one-attempt
// policy live in KdbTransaction; this type never exposes a writable pointer.
class KdbMailboxMapping {
    volatile uint8_t *bytes {nullptr};
    KdbMailboxTarget target {};
    friend class Map;
    KdbMailboxMapping(volatile uint8_t *p, KdbMailboxTarget t) : bytes(p), target(t) {}
    void store(uint32_t offset, uint32_t value) const {
        auto *word = reinterpret_cast<volatile uint32_t *>(bytes + (offset & 0xfff));
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestKdbWrite32(word, value, offset);
#else
        *word = value;
#endif
    }
public:
    KdbMailboxMapping() = default;
    bool valid() const { return bytes && !(reinterpret_cast<uintptr_t>(bytes) & 3u) && target.valid(); }
    const volatile uint8_t *readBytes() const { return valid() ? bytes : nullptr; }
    void address(uint32_t value) const { store(target.addressOffset, value); }
    void command() const { store(target.commandOffset, 0x00080000u); }
};

// The only full-window writable endpoint. No caller receives its raw pointer;
// all accesses are aligned dwords within this exact 1 MiB mapping.
class StagingMapping {
    volatile uint32_t *words {nullptr};
    friend class Map;
    explicit StagingMapping(volatile uint32_t *address) : words(address) {}
public:
    StagingMapping() = default;
    bool valid() const { return words && !(reinterpret_cast<uintptr_t>(words) & 3u); }
    bool read(size_t index, uint32_t &value) const {
        if (!valid() || index >= cobalt::psp::StagingWindow::kBytes / 4) return false;
#if defined(COBALT_SURVEY_HOSTTEST)
        value = cobaltSurveyTestApertureCpuRead(words + index);
#else
        value = words[index];
#endif
        return true;
    }
    bool write(size_t index, uint32_t value) const {
        if (!valid() || index >= cobalt::psp::StagingWindow::kBytes / 4) return false;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureCpuWrite(words + index, value);
#else
        words[index] = value;
#endif
        return true;
    }
};

class Map {
    IOMemoryMap *value {nullptr};
    const char *failure {"none"};
    const char *descriptorIdentity {"none"};
    uint64_t requestedOffset {0}, requestedLength {0};
    uint64_t sourcePhysical {0}, sourceContiguous {0};
    uint64_t mapPhysical {0}, mapLength {0}, mapSegmentPhysical {0}, mapContiguous {0};
    uint64_t descriptorPhysical {0}, descriptorLength {0};
    uint64_t descriptorSegmentPhysical {0}, descriptorContiguous {0};
    IOOptionBits mapOptions {0};
    IOOptionBits requestedOptions {kMapOptions};
    bool fail(const char *reason) {
        failure = reason;
        reset();
        return false;
    }
public:
    ~Map() { reset(); }
    void reset() { if (value) { value->release(); value = nullptr; } }
    Map() = default;
    Map(const Map &) = delete;
    Map &operator=(const Map &) = delete;
    static void clearFailure(IOService *service) {
        const char *keys[] = {"MapStage", "MapFailure", "MapDescriptorIdentity",
            "MapRequestedOffset", "MapRequestedLength", "MapRequestedOptions",
            "MapSourcePhysical", "MapSourceContiguous", "MapObservedPhysical",
            "MapObservedLength", "MapObservedOptions", "MapObservedSegmentPhysical",
            "MapObservedContiguous", "MapDescriptorPhysical", "MapDescriptorLength",
            "MapDescriptorSegmentPhysical", "MapDescriptorContiguous"};
        for (const char *key : keys) {
            char property[64];
            snprintf(property, sizeof(property), "CobaltSurvey,%s", key);
            service->removeProperty(property);
        }
    }
    bool create(const Aperture &a, uint64_t offset, uint64_t length) {
        return createPolicy(a, offset, length, false);
    }
    // Writable mappings remain fixed-purpose and page-bounded.
    bool createIndexedPage(const Aperture &a) { return createPolicy(a, 0, 4096, true); }
    bool createProbePage(const Aperture &a, const cobalt::survey::Plan &plan) {
        return plan.ok && plan.windowBytes == (1ULL << 20) &&
            !(plan.windowOffset & ((1ULL << 20) - 1)) &&
            createPolicy(a, plan.windowOffset, 4096, true);
    }
    bool createStagingWindow(const Aperture &a, const cobalt::survey::Plan &plan) {
        return plan.ok && plan.windowBytes == cobalt::psp::StagingWindow::kBytes &&
            !(plan.windowOffset & (cobalt::psp::StagingWindow::kBytes - 1)) &&
            createPolicy(a, plan.windowOffset, cobalt::psp::StagingWindow::kBytes, true);
    }
    bool createFlushPage(const Aperture &a, const HdpFlushTarget &target) {
        return target.valid() && createPolicy(a, target.pageOffset(), 4096, true);
    }
    bool createKdbMailboxPage(const Aperture &a, const KdbMailboxTarget &target) {
        return target.valid() && createPolicy(a, target.page(), 4096, true);
    }
private:
    bool createPolicy(const Aperture &a, uint64_t offset, uint64_t length, bool indexed) {
        requestedOptions = indexed ? (kMapOptions & ~kIOMapReadOnly) : kMapOptions;
        requestedOffset = offset;
        requestedLength = length;
        if (!a.memory || !range(a.physical, a.length) ||
            offset > a.length || length > a.length - offset ||
            !range(a.physical + offset, length)) return fail("request-range");
        const uint64_t expectedPhysical = a.physical + offset;
        IOByteCount contiguous = 0;
        sourcePhysical = a.memory->getPhysicalSegment(offset, &contiguous, kIOMemoryMapperNone);
        sourceContiguous = contiguous;
        if (sourcePhysical != expectedPhysical || contiguous < length)
            return fail("source-segment");
        value = a.memory->createMappingInTask(kernel_task, 0, requestedOptions, offset, length);
        if (!value) return fail("map-null");
        mapLength = value->getLength();
        mapPhysical = value->getPhysicalAddress();
        mapOptions = value->getMapOptions();
        IOMemoryDescriptor *descriptor = value->getMemoryDescriptor();
        if (descriptor) {
            const bool original = descriptor == a.memory;
            descriptorIdentity = original ? "original" : "replacement";
            descriptorLength = descriptor->getLength();
            descriptorPhysical = descriptor->getPhysicalAddress();
            descriptorSegmentPhysical = descriptor->getPhysicalSegment(
                original ? offset : 0, &contiguous, kIOMemoryMapperNone);
            descriptorContiguous = contiguous;
            mapSegmentPhysical = value->getPhysicalSegment(0, &contiguous, kIOMemoryMapperNone);
            mapContiguous = contiguous;
        }
        if (mapLength != length) return fail("map-length");
        if (mapPhysical != expectedPhysical) return fail("map-physical");
        if (!descriptor) return fail("descriptor-null");
        // XNU IOMemoryDescriptor::makeMapping (xnu-12377.1.9) creates a new
        // physical descriptor for kIOMapUnique and resets the map offset to 0.
        // Pointer identity with the provider is therefore not an API invariant.
        // Accept that replacement only when its entire physical interval is
        // exactly the requested interval of the still-validated PCI descriptor.
        const bool original = descriptor == a.memory;
        if (descriptorLength != (original ? a.length : length))
            return fail("descriptor-length");
        if (descriptorPhysical != (original ? a.physical : expectedPhysical))
            return fail("descriptor-physical");
        if (descriptorSegmentPhysical != expectedPhysical || descriptorContiguous < length)
            return fail("descriptor-segment");
        if (bool(mapOptions & kIOMapReadOnly) == indexed)
            return fail(indexed ? "map-not-writable" : "map-readonly");
        if ((mapOptions & kIOMapCacheMask) != kIOMapInhibitCache)
            return fail("map-cache");
        if (mapSegmentPhysical != expectedPhysical || mapContiguous < length)
            return fail("map-segment");
        return true;
    }
public:
    void publishFailure(IOService *service, const char *stage, const char *reason = nullptr) {
        if (reason) fail(reason);
        // Bounded metadata only: never publish kernel pointers or mapped bytes.
        service->setProperty("CobaltSurvey,MapStage", stage);
        service->setProperty("CobaltSurvey,MapFailure", failure);
        service->setProperty("CobaltSurvey,MapDescriptorIdentity", descriptorIdentity);
        service->setProperty("CobaltSurvey,MapRequestedOffset", requestedOffset, 64);
        service->setProperty("CobaltSurvey,MapRequestedLength", requestedLength, 64);
        service->setProperty("CobaltSurvey,MapRequestedOptions", requestedOptions, 32);
        service->setProperty("CobaltSurvey,MapSourcePhysical", sourcePhysical, 64);
        service->setProperty("CobaltSurvey,MapSourceContiguous", sourceContiguous, 64);
        service->setProperty("CobaltSurvey,MapObservedPhysical", mapPhysical, 64);
        service->setProperty("CobaltSurvey,MapObservedLength", mapLength, 64);
        service->setProperty("CobaltSurvey,MapObservedOptions", mapOptions, 32);
        service->setProperty("CobaltSurvey,MapObservedSegmentPhysical", mapSegmentPhysical, 64);
        service->setProperty("CobaltSurvey,MapObservedContiguous", mapContiguous, 64);
        service->setProperty("CobaltSurvey,MapDescriptorPhysical", descriptorPhysical, 64);
        service->setProperty("CobaltSurvey,MapDescriptorLength", descriptorLength, 64);
        service->setProperty("CobaltSurvey,MapDescriptorSegmentPhysical", descriptorSegmentPhysical, 64);
        service->setProperty("CobaltSurvey,MapDescriptorContiguous", descriptorContiguous, 64);
    }
    const volatile uint8_t *bytes() const {
        const uintptr_t address = value->getVirtualAddress();
        if (!range(address, value->getLength())) return nullptr;
        return reinterpret_cast<const volatile uint8_t *>(address);
    }
    volatile uint32_t *selectorPage() const {
        if (requestedOffset != 0 || requestedLength != 4096 ||
            requestedOptions != (kMapOptions & ~kIOMapReadOnly)) return nullptr;
        return reinterpret_cast<volatile uint32_t *>(const_cast<volatile uint8_t *>(bytes()));
    }
    volatile uint32_t *probePage(const cobalt::survey::Plan &plan) const {
        if (!plan.ok || requestedOffset != plan.windowOffset || requestedLength != 4096 ||
            requestedOptions != (kMapOptions & ~kIOMapReadOnly)) return nullptr;
        return reinterpret_cast<volatile uint32_t *>(const_cast<volatile uint8_t *>(bytes()));
    }
    volatile uint32_t *flushWord(const HdpFlushTarget &target) const {
        if (!target.valid() || requestedOffset != target.pageOffset() || requestedLength != 4096 ||
            requestedOptions != (kMapOptions & ~kIOMapReadOnly)) return nullptr;
        const volatile uint8_t *base = bytes();
        if (!base) return nullptr;
        return reinterpret_cast<volatile uint32_t *>(
            const_cast<volatile uint8_t *>(base + (target.byteOffset & 0xfff)));
    }
    StagingMapping stagingWindow(const cobalt::survey::Plan &plan) const {
        if (!value || !plan.ok || plan.windowBytes != cobalt::psp::StagingWindow::kBytes ||
            (plan.windowOffset & (cobalt::psp::StagingWindow::kBytes - 1)) ||
            requestedOffset != plan.windowOffset || requestedLength != plan.windowBytes ||
            requestedOptions != (kMapOptions & ~kIOMapReadOnly)) return {};
        return StagingMapping(reinterpret_cast<volatile uint32_t *>(
            const_cast<volatile uint8_t *>(bytes())));
    }
    KdbMailboxMapping kdbMailbox(const KdbMailboxTarget &target) const {
        if (!value || !target.valid() || requestedOffset != target.page() || requestedLength != 4096 ||
            requestedOptions != (kMapOptions & ~kIOMapReadOnly)) return {};
        return KdbMailboxMapping(const_cast<volatile uint8_t *>(bytes()), target);
    }
};

struct StateObservation {
    uint32_t values[8] {};
    uint32_t offsets[4] {};
};

void clearStateProperties(IOService *service) {
    const char *keys[] = {"StateStatus", "StatePspBootloaderRaw", "StatePspSosRaw",
        "StateFbBaseRaw", "StateFbTopRaw", "StatePspBootloaderByteOffset",
        "StatePspSosByteOffset", "StateFbBaseByteOffset", "StateFbTopByteOffset",
        "StateReadCount", "StateReadOnly"};
    for (const char *key : keys) {
        char property[64];
        snprintf(property, sizeof(property), "CobaltSurvey,%s", key);
        service->removeProperty(property);
    }
}

const char *passiveState(IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, const IpDiscovery &discovery,
    StateObservation &result) {
    constexpr uint16_t kMp0 = IpDiscovery::HwMp0;
    constexpr uint16_t kMmhub = IpDiscovery::HwMmhub;
    const uint16_t ids[] = {kMp0, kMmhub};
    const cobalt::Version versions[] = {{14, 0, 2}, {4, 1, 0}};
    for (unsigned i = 0; i < 2; ++i) {
        unsigned matches = 0;
        for (uint16_t n = 0; n < discovery.ipCount(); ++n) {
            IpDiscovery::IpEntry entry {};
            if (!discovery.ipAt(n, entry)) return "ip-record-invalid";
            if (entry.hwId == ids[i]) {
                ++matches;
                if (entry.instance != 0 || !entry.numBases ||
                    !cobalt::version_matches(versions[i], {entry.major, entry.minor, entry.revision}))
                    return "ip-version-or-instance-mismatch";
            }
        }
        if (matches != 1) return "ip-record-missing-or-duplicate";
    }
    const uint32_t dwords[] = {0x63, 0x91, 0x554, 0x555};
    for (unsigned i = 0; i < 4; ++i) {
        if (!discovery.regByteOffset(i < 2 ? kMp0 : kMmhub, 0, 0, dwords[i], result.offsets[i]))
            return "register-offset-unavailable";
        if ((result.offsets[i] & 3u) || result.offsets[i] > mmio.length ||
            sizeof(uint32_t) > mmio.length - result.offsets[i]) return "register-offset-out-of-range";
    }
    const uint64_t pages[2] = {result.offsets[0] & ~uint64_t(0xfff), result.offsets[2] & ~uint64_t(0xfff)};
    const uint64_t within[4] = {result.offsets[0] - pages[0], result.offsets[1] - pages[0],
        result.offsets[2] - pages[1], result.offsets[3] - pages[1]};
    for (unsigned i = 0; i < 4; ++i)
        if ((within[i] & 3u) || within[i] > 4092) return "register-offset-out-of-range";
    if (pci->isInactive() || !unchanged(pci, state) || !apertureUnchanged(pci, 5, mmio) ||
        !apertureUnchanged(pci, 0, vram)) return "pci-state-changed";
    Map maps[2];
    for (unsigned i = 0; i < 2; ++i) {
        if (!maps[i].create(mmio, pages[i], 4096)) return "state-map-failed";
        const volatile uint8_t *bytes = maps[i].bytes();
        if (!bytes || (reinterpret_cast<uintptr_t>(bytes) & 3u)) return "state-map-invalid";
    }
    const volatile uint8_t *mapped[2] = {maps[0].bytes(), maps[1].bytes()};
    for (unsigned pass = 0; pass < 2; ++pass) {
        for (unsigned reg = 0; reg < 4; ++reg) {
            if (pci->isInactive() || !unchanged(pci, state) ||
                !apertureUnchanged(pci, 5, mmio) || !apertureUnchanged(pci, 0, vram))
                return "pci-state-changed";
            const unsigned mapIndex = reg < 2 ? 0 : 1;
            const uintptr_t address = reinterpret_cast<uintptr_t>(mapped[mapIndex] + within[reg]);
            if (address & 3u) return "state-map-invalid";
#if defined(COBALT_SURVEY_HOSTTEST)
            result.values[pass * 4 + reg] = cobaltSurveyTestReadState32(
                reinterpret_cast<volatile uint32_t *>(address), result.offsets[reg]);
#else
            result.values[pass * 4 + reg] = *reinterpret_cast<const volatile uint32_t *>(address);
#endif
            if (pci->isInactive() || !unchanged(pci, state) ||
                !apertureUnchanged(pci, 5, mmio) || !apertureUnchanged(pci, 0, vram))
                return "pci-state-changed";
            if (result.values[pass * 4 + reg] == UINT32_MAX) return "register-unreadable";
            if (pass == 1 && result.values[4 + reg] != result.values[reg]) return "state-unstable";
        }
    }
    for (auto &map : maps) map.reset();
    if (pci->isInactive() || !unchanged(pci, state) ||
        !apertureUnchanged(pci, 5, mmio) || !apertureUnchanged(pci, 0, vram))
        return "pci-state-changed";
    return nullptr;
}

bool publishState(IOService *service, const StateObservation &state) {
    const char *names[] = {"StatePspBootloaderRaw", "StatePspSosRaw", "StateFbBaseRaw", "StateFbTopRaw"};
    const char *offsetNames[] = {"StatePspBootloaderByteOffset", "StatePspSosByteOffset",
        "StateFbBaseByteOffset", "StateFbTopByteOffset"};
    for (unsigned i = 0; i < 4; ++i) {
        char key[64];
        snprintf(key, sizeof(key), "CobaltSurvey,%s", names[i]);
        if (!service->setProperty(key, state.values[i], 32)) return false;
        snprintf(key, sizeof(key), "CobaltSurvey,%s", offsetNames[i]);
        if (!service->setProperty(key, state.offsets[i], 32)) return false;
    }
    return service->setProperty("CobaltSurvey,StateReadCount", 8ULL, 32) &&
        service->setProperty("CobaltSurvey,StateReadOnly", true) &&
        service->setProperty("CobaltSurvey,StateStatus", "observed-stable") &&
        service->setProperty("CobaltSurvey,Schema", 3ULL, 32);
}

void publishStateFailure(IOService *service, const char *reason) {
    clearStateProperties(service);
    if (!service->setProperty("CobaltSurvey,StateStatus", reason))
        clearStateProperties(service);
}

// OS console metadata only. These observations do not reserve GPU memory or
// establish that any address outside the current console is safe to write.
constexpr unsigned kConsoleScalarCount = 10;
const char *const kConsoleNames[kConsoleScalarCount] = {"ConsoleBaseRaw", "ConsoleRowBytes",
    "ConsoleWidth", "ConsoleHeight", "ConsoleDepth", "ConsoleDisplay", "ConsoleOffsetRaw",
    "ConsoleLengthRaw", "ConsoleRotate", "ConsoleScale"};
struct ConsoleObservation {
    uint64_t values[kConsoleScalarCount] {};
    uint64_t offset {0}, span {0};
    const char *rangeStatus {"unavailable"};
};

void clearConsoleProperties(IOService *service) {
    for (const char *name : kConsoleNames) {
        char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,%s", name);
        service->removeProperty(key);
    }
    const char *extra[] = {"ConsoleStatus", "ConsoleRangeStatus", "ConsoleReadCount",
        "ConsoleReadOnly", "ConsoleVramOffset", "ConsoleSpanBytes"};
    for (const char *name : extra) {
        char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,%s", name);
        service->removeProperty(key);
    }
}

void consoleScalars(const PE_Video &video, uint64_t (&values)[kConsoleScalarCount]) {
    values[0] = static_cast<uint64_t>(video.v_baseAddr);
    values[1] = static_cast<uint64_t>(video.v_rowBytes);
    values[2] = static_cast<uint64_t>(video.v_width);
    values[3] = static_cast<uint64_t>(video.v_height);
    values[4] = static_cast<uint64_t>(video.v_depth);
    values[5] = static_cast<uint64_t>(video.v_display);
    values[6] = static_cast<uint64_t>(video.v_offset);
    values[7] = static_cast<uint64_t>(video.v_length);
    values[8] = static_cast<uint64_t>(video.v_rotate);
    values[9] = static_cast<uint64_t>(video.v_scale);
}

const char *consoleRange(ConsoleObservation &result, const Aperture &vram) {
    const uint64_t *v = result.values;
    // XNU xnu-12377.1.9 osfmk/console/video_console.c:2678-2686:
    // with VM running, bit0 marks a physical address; otherwise it is virtual.
    // XNU obtains the physical address by clearing the low TWO bits. Keep the
    // original scalar intact and refuse any remaining non-page-aligned bits.
    if (!v[0]) return "base-unaligned-or-zero";
    if (!(v[0] & 1ULL)) return "base-not-tagged-physical";
    const uint64_t physical = v[0] & ~3ULL;
    if (!physical || (physical & 0xfff)) return "base-unaligned-or-zero";
    if (v[6] != 0) return "offset-unsupported";
    if (v[8] != 0) return "rotation-unsupported";
    // x86 pexpert/i386/boot.h: GRAPHICS_MODE=1, FB_TEXT_MODE=2.
    if (v[5] != 1) return "display-mode-unsupported";
    if (!v[1] || !v[2] || !v[3] || !v[4] || v[4] > 64) return "geometry-invalid";
    if (v[1] > UINT64_MAX / 8 || v[2] > UINT64_MAX / v[4] ||
        v[2] * v[4] > v[1] * 8) return "geometry-invalid";
    if (v[1] > UINT64_MAX / v[3]) return "span-overflow";
    const uint64_t visible = v[1] * v[3];
    const uint64_t span = v[7] ? v[7] : visible;
    if (span < visible) return "length-too-small";
    if (span > UINT64_MAX - physical) return "span-overflow";
    if (physical < vram.physical) return "outside-bar0";
    const uint64_t offset = physical - vram.physical;
    if (offset >= vram.length || span > vram.length - offset) return "outside-bar0";
    result.offset = offset; result.span = span;
    return "inside-bar0-observed";
}

bool consoleGuard(IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram) {
    return !pci->isInactive() && unchanged(pci, state) &&
        apertureUnchanged(pci, 5, mmio) && apertureUnchanged(pci, 0, vram);
}

const char *passiveConsole(IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, ConsoleObservation &result) {
    if (!consoleGuard(pci, state, mmio, vram)) return "pci-state-changed";
    // getPlatform returns a borrowed singleton. Do not release it.
    IOPlatformExpert *platform = IOService::getPlatform();
    if (!platform) return "platform-unavailable";
    for (unsigned pass = 0; pass < 2; ++pass) {
        if (!consoleGuard(pci, state, mmio, vram)) return "pci-state-changed";
        PE_Video video {};
        const IOReturn rc = platform->getConsoleInfo(&video);
        if (!consoleGuard(pci, state, mmio, vram)) return "pci-state-changed";
        if (rc != kIOReturnSuccess) return "console-api-failed";
        uint64_t values[kConsoleScalarCount] {};
        consoleScalars(video, values);
        for (unsigned i = 0; i < kConsoleScalarCount; ++i) {
            if (pass == 0) result.values[i] = values[i];
            else if (values[i] != result.values[i]) return "console-unstable";
        }
    }
    result.rangeStatus = consoleRange(result, vram);
    return nullptr;
}

bool publishConsole(IOService *service, const ConsoleObservation &result) {
    for (unsigned i = 0; i < kConsoleScalarCount; ++i) {
        char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,%s", kConsoleNames[i]);
        if (!service->setProperty(key, result.values[i], 64)) return false;
    }
    if (result.span && (!service->setProperty("CobaltSurvey,ConsoleVramOffset", result.offset, 64) ||
        !service->setProperty("CobaltSurvey,ConsoleSpanBytes", result.span, 64))) return false;
    return service->setProperty("CobaltSurvey,ConsoleRangeStatus", result.rangeStatus) &&
        service->setProperty("CobaltSurvey,ConsoleReadCount", 2ULL, 32) &&
        service->setProperty("CobaltSurvey,ConsoleReadOnly", true) &&
        service->setProperty("CobaltSurvey,ConsoleStatus", "observed-stable") &&
        service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
}

void publishConsoleFailure(IOService *service, const char *reason) {
    clearConsoleProperties(service);
    // State was already published successfully before console collection.
    service->setProperty("CobaltSurvey,Schema", 3ULL, 32);
    if (!service->setProperty("CobaltSurvey,ConsoleStatus", reason)) clearConsoleProperties(service);
}

uint32_t readMemsize(const volatile uint8_t *bytes) {
    return OSSwapLittleToHostInt32(*reinterpret_cast<const volatile uint32_t *>(bytes + kMemsizeInPage));
}

bool plausibleMemsize(uint32_t mib) {
    return mib >= 1024 && mib <= 64 * 1024;
}

// Cooperative ownership only: this does not exclude firmware, forced removal,
// or clients which ignore provider open. Never seize an existing owner.
class ProviderSession {
    IOPCIDevice *pci;
    IOService *owner;
    bool opened {false};
public:
    ProviderSession(IOPCIDevice *device, IOService *service) : pci(device), owner(service) {}
    ~ProviderSession() { close(); }
    bool open() { opened = pci->open(owner, 0); return opened; }
    bool owns() const { return opened && !pci->isInactive() && pci->isOpen(owner); }
    void close() { if (opened) { pci->close(owner, 0); opened = false; } }
};

bool onlyClient(IOPCIDevice *pci, IOService *service) {
    OSIterator *iterator = pci->getClientIterator();
    if (!iterator) {
        service->setProperty("CobaltSurvey,IndexedPeers", "iterator-failed");
        return false;
    }
    unsigned count = 0, unexpected = 0, self = 0;
    OSObject *entry = nullptr;
    while (count < 64 && (entry = iterator->getNextObject())) {
        ++count;
        if (entry == service) ++self;
        else {
            if (!unexpected) service->setProperty("CobaltSurvey,IndexedFirstPeerClass",
                entry->getMetaClass()->getClassName());
            ++unexpected;
        }
    }
    const bool valid = iterator->isValid() && count < 64;
    iterator->release();
    service->setProperty("CobaltSurvey,IndexedClientCount", count, 32);
    service->setProperty("CobaltSurvey,IndexedUnexpectedClientCount", unexpected, 32);
    const bool alone = valid && count == 1 && self == 1 && unexpected == 0;
    service->setProperty("CobaltSurvey,IndexedPeers", alone ? "self-only" : "refused");
    return alone;
}

// Deliberately no generic register-write or MM_DATA-write operation. Production
// builds are x86_64: aligned volatile dword accesses to the uncached page retain
// order. The host build substitutes an event-recording MMIO device, not RAM.
class SelectorIO {
    volatile uint32_t *page;
    static uint32_t read(volatile uint32_t *address) {
#if defined(COBALT_SURVEY_HOSTTEST)
        return cobaltSurveyTestRead32(address);
#else
        return *address;
#endif
    }
    static void write(volatile uint32_t *address, uint32_t value) {
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestWriteSelector32(address, value);
#else
        *address = value;
#endif
    }
public:
    explicit SelectorIO(volatile uint32_t *bytes) : page(bytes) {}
    uint32_t low() const { return read(page); }
    uint32_t high() const { return read(page + 6); }
    uint32_t data() const { return read(page + 1); }
    void low(uint32_t value) { write(page, value); }
    void high(uint32_t value) { write(page + 6, value); }
};

class IndexedTransaction {
    IOService *service;
    IOPCIDevice *pci;
    const PciState &state;
    const Aperture &mmio, &vram;
    ProviderSession &session;
    SelectorIO io;
    uint32_t savedLow {0}, savedHigh {0}, writes {0}, reads {0};
    bool dirty {false};
public:
    IndexedTransaction(IOService *s, IOPCIDevice *p, const PciState &st,
        const Aperture &m, const Aperture &v, ProviderSession &owner, volatile uint32_t *page)
        : service(s), pci(p), state(st), mmio(m), vram(v), session(owner), io(page) {}
    bool guard() const {
        return session.owns() && unchanged(pci, state) &&
            apertureUnchanged(pci, 5, mmio) && apertureUnchanged(pci, 0, vram);
    }
    bool selectors(uint32_t &low, uint32_t &high) const {
        if (!guard()) return false;
        low = io.low();
        if (!guard()) return false;
        high = io.high();
        return guard();
    }
    const char *save() {
        uint32_t low = 0, high = 0;
        if (!selectors(savedLow, savedHigh) || !selectors(low, high)) return "pci-state-changed";
        if (savedLow == UINT32_MAX || savedHigh == UINT32_MAX ||
            low != savedLow || high != savedHigh) return "indexed-selectors-unreadable-or-unstable";
        return nullptr;
    }
    bool low(uint32_t value) {
        if (!guard()) return false;
        dirty = true; ++writes; io.low(value); return true;
    }
    bool high(uint32_t value) {
        if (!guard()) return false;
        dirty = true; ++writes; io.high(value); return true;
    }
    const char *copy(uint64_t vramBytes, uint8_t *snapshot) {
        // No caller-supplied address or size: only the validated discovery tail.
        if (vramBytes < kGiB || vramBytes > 64 * kGiB) return "indexed-range-invalid";
        const uint64_t begin = vramBytes - kDiscoveryTail;
        const uint64_t end = begin + kDiscoverySize;
        if ((begin & 3) || end > vramBytes) return "indexed-range-invalid";
        auto *words = reinterpret_cast<uint32_t *>(snapshot);
        for (unsigned pass = 0; pass < 2; ++pass) {
            if (!guard()) return "pci-state-changed";
            if (!onlyClient(pci, service)) return "indexed-peer-refused";
            uint32_t lastHigh = UINT32_MAX;
            for (uint64_t pos = begin; pos < end; pos += 4) {
                const uint32_t targetLow = static_cast<uint32_t>(pos) | 0x80000000u;
                const uint32_t targetHigh = static_cast<uint32_t>(pos >> 31);
                if (!low(targetLow)) return "pci-state-changed";
                if (targetHigh != lastHigh) {
                    if (!high(targetHigh)) return "pci-state-changed";
                    lastHigh = targetHigh;
                }
                uint32_t observedLow = 0, observedHigh = 0;
                if (!selectors(observedLow, observedHigh)) return "pci-state-changed";
                if (observedLow != targetLow || observedHigh != targetHigh)
                    return "indexed-selector-readback-mismatch";
                if (!guard()) return "pci-state-changed";
                words[pass * (kDiscoverySize / 4) + (pos - begin) / 4] = io.data();
                ++reads;
            }
            if (!guard()) return "pci-state-changed";
            if (!onlyClient(pci, service)) return "indexed-peer-refused";
        }
        for (uint64_t i = 0; i < kDiscoverySize; ++i)
            if (snapshot[i] != snapshot[kDiscoverySize + i]) return "discovery-snapshot-unstable";
        return nullptr;
    }
    bool cleanup() {
        const char *result = "not-needed";
        bool restored = !dirty;
        if (dirty) {
            // One bounded attempt. Never restore through a stale BAR mapping.
            if (!low(savedLow) || !high(savedHigh)) result = "restore-skipped-device-changed";
            else {
                uint32_t observedLow = 0, observedHigh = 0;
                if (!selectors(observedLow, observedHigh)) result = "restore-skipped-device-changed";
                else if (observedLow != savedLow || observedHigh != savedHigh)
                    result = "restore-readback-mismatch";
                else { result = "restored-observed"; restored = true; }
            }
        }
        const bool reported = service->setProperty("CobaltSurvey,IndexedCleanup", result) &&
            service->setProperty("CobaltSurvey,IndexedSelectorWritesIssued", writes, 32) &&
            service->setProperty("CobaltSurvey,IndexedDataReads", reads, 32);
        return restored && reported;
    }
};

const char *indexedSnapshot(IOService *service, IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, Map &registers,
    const volatile uint8_t *regBytes, uint32_t mib, uint8_t *snapshot) {
    if (!service->setProperty("CobaltSurvey,VRAMBytes", static_cast<uint64_t>(mib) << 20, 64) ||
        !service->setProperty("CobaltSurvey,DiscoveryOffset", (static_cast<uint64_t>(mib) << 20) - kDiscoveryTail, 64) ||
        !service->setProperty("CobaltSurvey,DiscoverySize", kDiscoverySize, 64) ||
        !service->setProperty("CobaltSurvey,Ready", false) ||
        !service->setProperty("CobaltSurvey,IndexedOwnership", "not-acquired") ||
        !service->setProperty("CobaltSurvey,IndexedCleanup", "not-needed") ||
        !service->setProperty("CobaltSurvey,IndexedAttempted", false) ||
        !service->setProperty("CobaltSurvey,IndexedSelectorWritesIssued", 0ULL, 32) ||
        !service->setProperty("CobaltSurvey,IndexedDataReads", 0ULL, 32))
        return "indexed-metadata-publication-failed";
    if (pci->isInactive()) return "indexed-provider-inactive";
    if (!onlyClient(pci, service)) return "indexed-peer-refused";
    ProviderSession session(pci, service);
    if (!session.open()) return "indexed-provider-busy";
    if (!service->setProperty("CobaltSurvey,IndexedOwnership", "exclusive-cooperative"))
        return "indexed-metadata-publication-failed";
    if (!onlyClient(pci, service)) return "indexed-peer-refused";
    if (!session.owns() || !unchanged(pci, state) ||
        !apertureUnchanged(pci, 0, vram) || !apertureUnchanged(pci, 5, mmio))
        return "pci-state-changed";
    if (readMemsize(regBytes) != mib) return "memsize-changed";
    if (pci->getProperty("CobaltSurvey,IndexedAttempt-v1")) return "indexed-already-attempted";
    Map page;
    if (!page.createIndexedPage(mmio)) {
        page.publishFailure(service, "indexed"); return "indexed-map-failed";
    }
    volatile uint32_t *bytes = page.selectorPage();
    if (!bytes || (reinterpret_cast<uintptr_t>(bytes) & 3)) return "indexed-map-invalid";
    IndexedTransaction transaction(service, pci, state, mmio, vram, session, bytes);
    const char *failure = transaction.save();
    if (failure) return failure;
    if (!transaction.guard()) return "pci-state-changed";
    // Ownership serializes this claim among cooperative instances. Keep the
    // provider property after stop/unload; it is never cleared by this driver.
    if (pci->getProperty("CobaltSurvey,IndexedAttempt-v1")) return "indexed-already-attempted";
    if (!pci->setProperty("CobaltSurvey,IndexedAttempt-v1", true)) return "indexed-claim-failed";
    if (!service->setProperty("CobaltSurvey,Schema", 2ULL, 32) ||
        !service->setProperty("CobaltSurvey,ReadOnly", false) ||
        !service->setProperty("CobaltSurvey,AccessMode", "indexed-selector-writes") ||
        !service->setProperty("CobaltSurvey,IndexedAttempted", true))
        return "indexed-metadata-publication-failed";
    failure = transaction.copy(static_cast<uint64_t>(mib) << 20, snapshot);
    // Last MMIO outside cleanup. If the device changed, do not dereference even
    // the read-only memsize mapping. After cleanup there is no further MMIO.
    if (transaction.guard()) {
        if (readMemsize(regBytes) != mib && !failure) failure = "memsize-changed";
    } else if (!failure) failure = "pci-state-changed";
    const bool restored = transaction.cleanup();
    page.reset();
    registers.reset();
    session.close();
    if (!restored) return "indexed-cleanup-unverified";
    if (pci->isInactive() || !unchanged(pci, state) || !apertureUnchanged(pci, 0, vram) ||
        !apertureUnchanged(pci, 5, mmio)) return "pci-state-changed";
    return failure;
}

// Everything retained here is a value. IpDiscovery points into temporary
// snapshot storage and must never be consulted by the aperture transaction.
struct ApertureProof {
    const char *failure {"aperture-ip-proof-unavailable"};
    uint32_t remapOffset {0}, memsizeOffset {0}, nativeFlushOffset {0}, stateOffsets[4] {};
};

ApertureProof apertureProof(const IpDiscovery &d, const StateObservation &observed,
    const Aperture &mmio) {
    ApertureProof proof;
    const uint16_t ids[] = {IpDiscovery::HwNbif, IpDiscovery::HwHdp};
    const cobalt::Version versions[] = {{6, 3, 1}, {7, 0, 0}};
    for (unsigned i = 0; i < 2; ++i) {
        unsigned count = 0;
        for (uint16_t n = 0; n < d.ipCount(); ++n) {
            IpDiscovery::IpEntry entry {};
            if (!d.ipAt(n, entry)) return proof;
            if (entry.hwId != ids[i]) continue;
            ++count;
            if (entry.instance != 0 || entry.numBases < (i == 0 ? 3 : 1) ||
                !cobalt::version_matches(versions[i], {entry.major, entry.minor, entry.revision}))
                return proof;
        }
        if (count != 1) return proof;
    }
    if (!d.regByteOffset(IpDiscovery::HwNbif, 0, 2, 0x12d, proof.remapOffset) ||
        !d.regByteOffset(IpDiscovery::HwNbif, 0, 2, 0xc3, proof.memsizeOffset) ||
        !d.regByteOffset(IpDiscovery::HwNbif, 0, 2, 0xf7, proof.nativeFlushOffset)) return proof;
    if ((proof.remapOffset & 3) || (proof.memsizeOffset & 3) || (proof.nativeFlushOffset & 3) ||
        (proof.remapOffset & ~0xfffu) != (proof.memsizeOffset & ~0xfffu) ||
        (proof.remapOffset & ~0xfffu) != (proof.nativeFlushOffset & ~0xfffu) ||
        (proof.nativeFlushOffset & ~0xfffu) == 0 ||
        (proof.nativeFlushOffset & ~0xfffu) == 0x7f000 ||
        proof.nativeFlushOffset == proof.memsizeOffset || proof.nativeFlushOffset == proof.remapOffset ||
        proof.remapOffset > mmio.length || 4 > mmio.length - proof.remapOffset ||
        proof.nativeFlushOffset > mmio.length || 4 > mmio.length - proof.nativeFlushOffset ||
        proof.memsizeOffset > mmio.length || 4 > mmio.length - proof.memsizeOffset) return proof;
    for (unsigned i = 0; i < 4; ++i) proof.stateOffsets[i] = observed.offsets[i];
    proof.failure = nullptr;
    return proof;
}

// Resolve while discovery's backing snapshot is alive. All later access uses
// these checked values, never the parser or caller-provided register addresses.
struct KdbProof {
    const char *failure {"kdb-ip-proof-unavailable"};
    KdbMailboxTarget mailbox {};
    uint32_t offsets[6] {}; // boot, SOS, FB base/top, FB offset, DCN FB base
};

KdbProof kdbProof(const IpDiscovery &d, const ApertureProof &ap, const Aperture &mmio) {
    KdbProof p;
    if (ap.failure) return p;
    const uint16_t ids[] = {IpDiscovery::HwMp0, IpDiscovery::HwMmhub, IpDiscovery::HwDmu};
    const cobalt::Version versions[] = {{14, 0, 2}, {4, 1, 0}, {4, 1, 0}};
    for (unsigned i = 0; i < 3; ++i) {
        unsigned matches = 0;
        for (uint16_t n = 0; n < d.ipCount(); ++n) {
            IpDiscovery::IpEntry ip {};
            if (!d.ipAt(n, ip)) return p;
            if (ip.hwId != ids[i]) continue;
            ++matches;
            if (ip.instance || ip.numBases < (i == 2 ? 3 : 1) ||
                !cobalt::version_matches(versions[i], {ip.major, ip.minor, ip.revision})) return p;
        }
        if (matches != 1) return p;
    }
    const uint16_t hw[] = {ids[0], ids[0], ids[1], ids[1], ids[1], ids[2]};
    const uint32_t words[] = {0x63, 0x91, 0x554, 0x555, 0x4c7, 0x475};
    for (unsigned n = 0; n < 6; ++n) {
        if (!d.regByteOffset(hw[n], 0, n == 5 ? 2 : 0, words[n], p.offsets[n]) ||
            (p.offsets[n] & 3u) || p.offsets[n] > mmio.length || 4 > mmio.length - p.offsets[n]) return p;
    }
    if (!d.regByteOffset(ids[0], 0, 0, 0x64, p.mailbox.addressOffset)) return p;
    p.mailbox.commandOffset = p.offsets[0]; p.mailbox.sosOffset = p.offsets[1];
    if (!p.mailbox.valid()) return p;
    const uint32_t pages[] = {p.mailbox.page(), p.offsets[2] & ~0xfffu, p.offsets[5] & ~0xfffu,
        ap.remapOffset & ~0xfffu, 0x7f000};
    for (unsigned i = 0; i < 5; ++i) {
        if (!pages[i] || pages[i] > mmio.length || 4096 > mmio.length - pages[i]) return p;
        for (unsigned j = 0; j < i; ++j) if (pages[i] == pages[j]) return p;
    }
    for (unsigned n = 2; n < 5; ++n) if ((p.offsets[n] & ~0xfffu) != pages[1]) return p;
    if (p.mailbox.addressOffset > mmio.length || 4 > mmio.length - p.mailbox.addressOffset) return p;
    for (unsigned i = 0; i < 6; ++i)
        for (unsigned j = 0; j < i; ++j) if (p.offsets[i] == p.offsets[j]) return p;
    p.failure = nullptr;
    return p;
}

// No registry writes during access guards: diagnostics are published after
// closing this independent provider session, without altering Indexed* fields.
bool apertureOnlyClient(IOPCIDevice *pci, IOService *service) {
    OSIterator *iterator = pci->getClientIterator();
    if (!iterator) return false;
    unsigned count = 0, self = 0;
    while (count < 64) {
        OSObject *entry = iterator->getNextObject();
        if (!entry) break;
        ++count;
        if (entry == service) ++self;
    }
    const bool valid = iterator->isValid() && count == 1 && self == 1;
    iterator->release();
    return valid;
}

struct ApertureResult {
    const char *status {"prerequisites-unavailable"};
    const char *cleanup {"not-needed"};
    const char *vramCleanup {"not-needed"}, *selectorCleanup {"not-needed"};
    const char *flushRoute {"not-selected"}, *guardMapping {"not-selected"};
    uint32_t nativeFlushOffset {0}, flushOffset {0};
    cobalt::survey::Plan plan {false, "not-planned", 0, 0, 0};
    uint32_t remap[2] {}, selectorWrites {0}, dataReads {0}, vramWrites {0}, flushWrites {0};
    bool attempted {false}, success {false};
};

struct StagingResult : ApertureResult {
    static constexpr size_t payloadBytes = 125472;
    static_assert(payloadBytes % sizeof(uint32_t) == 0, "staging payload must contain whole dwords");
    static_assert(payloadBytes <= cobalt::psp::StagingWindow::kBytes, "staging payload exceeds window");
    static_assert(cobalt::psp::StagingWindow::kBytes % cobalt::psp::StagingWindow::kChunkBytes == 0,
        "staging window must contain whole chunks");
    cobalt::psp::StagingStats helperStats {};
    uint64_t cpuReadBytes {0}, restoreBytes {0};
    uint32_t cpuReadChunks {0}, restoreChunks {0};
    bool originalStable {false}, zeroVerified {false}, copyVerified {false};
    bool restoreVerified {false}, contextLost {false};
};

struct KdbResult : StagingResult {
    static constexpr size_t kPayloadBytes = 6816;
    static_assert(kPayloadBytes % sizeof(uint32_t) == 0, "KDB must contain whole dwords");
    uint32_t raw[6] {}, offsets[6] {}, lastStatus {0};
    uint32_t addressWrites {0}, commandWrites {0}, registerReads {0};
    const char *lastStep {"none"};
    bool addressAttempted {false}, commandAttempted {false}, readyObserved {false};
    bool resetRequired {false}, stagingPreserved {false};
};

void clearStagingProperties(IOService *service) {
    const char *names[] = {"Status", "Cleanup", "VramCleanup", "SelectorCleanup", "PlanReason",
        "WindowOffset", "WindowBytes", "McAddress", "RemapFirstRaw", "RemapSecondRaw", "Attempted",
        "SelectorWritesIssued", "DataReads", "VramWritesIssued", "FlushWritesIssued", "ReadOnly",
        "FlushRoute", "GuardMapping", "FlushByteOffset", "NativeFlushByteOffset", "PayloadBytes",
        "ZeroBytesIssued", "CopyBytesIssued", "ZeroChunksIssued", "CopyChunksIssued", "HelperFlushesIssued",
        "RestoreBytesIssued", "RestoreChunksIssued", "CpuReadBytes", "CpuReadChunks", "OriginalStable",
        "ZeroVerified", "CopyVerified", "RestoreVerified", "ContextLost"};
    for (const char *name : names) {
        char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,Staging%s", name);
        service->removeProperty(key);
    }
}

void clearApertureProperties(IOService *service) {
    const char *names[] = {"ApertureStatus", "ApertureCleanup", "ApertureVramCleanup", "ApertureSelectorCleanup", "AperturePlanReason",
        "ApertureWindowOffset", "ApertureWindowBytes", "ApertureMcAddress",
        "ApertureRemapFirstRaw", "ApertureRemapSecondRaw", "ApertureAttempted",
        "ApertureSelectorWritesIssued", "ApertureDataReads", "ApertureVramWritesIssued",
        "ApertureFlushWritesIssued", "ApertureReadOnly", "ApertureFlushRoute",
        "ApertureGuardMapping", "ApertureFlushByteOffset", "ApertureNativeFlushByteOffset"};
    for (const char *name : names) {
        char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,%s", name);
        service->removeProperty(key);
    }
}

uint32_t apertureRegisterRead(const volatile uint32_t *address, uint32_t offset) {
#if defined(COBALT_SURVEY_HOSTTEST)
    return cobaltSurveyTestApertureRegisterRead(address, offset);
#else
    (void)offset;
    return *address;
#endif
}

// Fixed 16-byte reader/writer. There is intentionally no public address, count,
// arbitrary MMIO write, MM_DATA write, or firmware-loader operation.
class ApertureTransaction {
    IOService *service;
    IOPCIDevice *pci;
    const PciState &state;
    const Aperture &mmio, &vram;
    ProviderSession &session;
    const ApertureProof &proof;
    const HdpFlushTarget target;
    ApertureResult &result;
    uint32_t mib;
    const volatile uint8_t *nbif;
    volatile uint32_t *cpu, *flush;
    SelectorIO io;
    uint32_t savedLow {0}, savedHigh {0}, original[4] {};
    bool selectorDirty {false}, vramDirty {false};
    mutable bool contextLost {false};
    bool baseGuard() const {
        if (contextLost) return false;
        const bool current = session.owns() && consoleGuard(pci, state, mmio, vram) &&
            apertureOnlyClient(pci, service) && session.owns() &&
            consoleGuard(pci, state, mmio, vram);
        if (!current) contextLost = true;
        return current;
    }
    bool registerRead(uint32_t offset, uint32_t &value) const {
        if (!baseGuard()) return false;
        value = apertureRegisterRead(reinterpret_cast<const volatile uint32_t *>(
            nbif + (offset & 0xfff)), offset);
        return baseGuard();
    }
    bool selectorRead(uint32_t &low, uint32_t &high) const {
        if (!guard()) return false;
        low = io.low();
        if (!guard()) return false;
        high = io.high();
        return guard();
    }
    bool selectorWrite(bool high, uint32_t value) {
        if (!guard()) return false;
        selectorDirty = true; ++result.selectorWrites;
        if (high) io.high(value); else io.low(value);
        return guard();
    }
    bool cpuRead(uint32_t (&words)[4]) const {
        for (unsigned i = 0; i < 4; ++i) {
            if (!guard()) return false;
#if defined(COBALT_SURVEY_HOSTTEST)
            words[i] = cobaltSurveyTestApertureCpuRead(cpu + i);
#else
            words[i] = cpu[i];
#endif
            if (!guard()) return false;
        }
        return true;
    }
    bool cpuWrite(const uint32_t (&words)[4]) {
        for (unsigned i = 0; i < 4; ++i) {
            if (!guard()) return false;
            vramDirty = true; ++result.vramWrites;
#if defined(COBALT_SURVEY_HOSTTEST)
            cobaltSurveyTestApertureCpuWrite(cpu + i, words[i]);
#else
            cpu[i] = words[i];
#endif
            if (!guard()) return false;
        }
        return true;
    }
    bool indexedRead(uint32_t (&words)[4]) {
        for (unsigned i = 0; i < 4; ++i) {
            const uint64_t pos = result.plan.windowOffset + 4 * i;
            const uint32_t low = static_cast<uint32_t>(pos) | 0x80000000u;
            const uint32_t high = static_cast<uint32_t>(pos >> 31);
            if (!selectorWrite(false, low) || !selectorWrite(true, high)) return false;
            uint32_t actualLow = 0, actualHigh = 0;
            if (!selectorRead(actualLow, actualHigh) || actualLow != low || actualHigh != high)
                return false;
            if (!guard()) return false;
            words[i] = io.data(); ++result.dataReads;
            if (!guard()) return false;
        }
        return true;
    }
    static bool equal(const uint32_t (&a)[4], const uint32_t (&b)[4]) {
        for (unsigned i = 0; i < 4; ++i) if (a[i] != b[i]) return false;
        return true;
    }
    bool visible() {
        if (!guard()) return false;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureFence();
#else
        __asm__ volatile("mfence" ::: "memory");
#endif
        if (!guard()) return false;
        ++result.flushWrites;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureFlush(flush);
#else
        *flush = 0;
#endif
        // Linux NBIO 6.3.1's CPU-write flush posts via MEMSIZE after the
        // remapped HDP write. Only the selected fixed-purpose word is written.
        uint32_t posted = 0;
        if (!registerRead(proof.memsizeOffset, posted) || posted != mib) {
            contextLost = true;
            return false;
        }
        return guard();
    }
public:
    ApertureTransaction(IOService *s, IOPCIDevice *p, const PciState &st,
        const Aperture &m, const Aperture &v, ProviderSession &owner,
        const ApertureProof &ip, const HdpFlushTarget &selected, ApertureResult &r, uint32_t size,
        const volatile uint8_t *registers, volatile uint32_t *probe,
        volatile uint32_t *flushWord, volatile uint32_t *selectors)
        : service(s), pci(p), state(st), mmio(m), vram(v), session(owner), proof(ip), target(selected),
          result(r), mib(size), nbif(registers), cpu(probe), flush(flushWord), io(selectors) {}
    bool guard() const {
        if (contextLost) return false;
        uint32_t remap = 0, memsize = 0;
        const bool current = target.valid() && registerRead(proof.remapOffset, remap) &&
            remap == target.byteOffset &&
            registerRead(proof.memsizeOffset, memsize) && memsize == mib;
        if (!current) contextLost = true;
        return current;
    }
    const char *saveSelectors() {
        uint32_t low = 0, high = 0;
        if (!selectorRead(savedLow, savedHigh) || !selectorRead(low, high)) return "device-context-changed";
        if (savedLow == UINT32_MAX || savedHigh == UINT32_MAX ||
            savedLow != low || savedHigh != high) return "selectors-unreadable-or-unstable";
        return nullptr;
    }
    const char *exercise() {
        uint32_t cpuWords[4] {}, indexedWords[4] {};
        for (unsigned pass = 0; pass < 2; ++pass) {
            if (!cpuRead(cpuWords) || !indexedRead(indexedWords)) return "original-read-failed";
            if (!equal(cpuWords, indexedWords) || (pass && !equal(original, cpuWords)))
                return "original-read-mismatch";
            if (!pass) for (unsigned i = 0; i < 4; ++i) original[i] = cpuWords[i];
        }
        uint32_t pattern[4] {};
        const uint32_t masks[] = {0xc0ba1744u, 0x59a63ce1u, 0x138bf025u, 0xe72d460bu};
        for (unsigned i = 0; i < 4; ++i) pattern[i] = original[i] ^ masks[i];
        if (!cpuWrite(pattern) || !visible()) return "pattern-write-or-flush-failed";
        if (!cpuRead(cpuWords) || !indexedRead(indexedWords)) return "pattern-read-failed";
        if (!equal(pattern, cpuWords) || !equal(pattern, indexedWords)) return "pattern-read-mismatch";
        return nullptr;
    }
    bool cleanup() {
        bool restored = true;
        if (vramDirty) {
            uint32_t cpuWords[4] {}, indexedWords[4] {};
            restored = cpuWrite(original) && visible() && cpuRead(cpuWords) &&
                indexedRead(indexedWords) && equal(original, cpuWords) && equal(original, indexedWords);
            result.cleanup = restored ? "vram-and-selectors-restored-observed" : "vram-restore-unverified";
            result.vramCleanup = restored ? "restored-observed" : "restore-skipped-or-unverified";
        }
        if (selectorDirty) {
            uint32_t low = 0, high = 0;
            const bool selectorsRestored = selectorWrite(false, savedLow) && selectorWrite(true, savedHigh) &&
                selectorRead(low, high) && low == savedLow && high == savedHigh;
            result.selectorCleanup = selectorsRestored ? "restored-observed" : "restore-skipped-or-unverified";
            if (!selectorsRestored) {
                result.cleanup = "restore-skipped-or-unverified-device-context";
                restored = false;
            } else if (!vramDirty) result.cleanup = "selectors-restored-observed";
        }
        return restored;
    }
};

class StagingStorage {
public:
    uint32_t *original {nullptr};
    uint8_t *payload {nullptr};
    StagingStorage() = default;
    StagingStorage(const StagingStorage &) = delete;
    StagingStorage &operator=(const StagingStorage &) = delete;
    ~StagingStorage() { reset(); }
    void reset() {
        if (payload) { IOFree(payload, StagingResult::payloadBytes); payload = nullptr; }
        if (original) { IOFree(original, cobalt::psp::StagingWindow::kBytes); original = nullptr; }
    }
    bool allocate() {
        original = static_cast<uint32_t *>(IOMalloc(cobalt::psp::StagingWindow::kBytes));
        if (!original) return false;
        payload = static_cast<uint8_t *>(IOMalloc(StagingResult::payloadBytes));
        if (!payload) return false;
        for (size_t offset = 0; offset < StagingResult::payloadBytes; ++offset)
            payload[offset] = static_cast<uint8_t>((offset * 37u) ^ (offset >> 8) ^
                (offset >> 16) ^ 0xa7u);
        return true;
    }
};

// One synthetic transfer only. The helper never restores or retries: recovery
// uses the separately saved original and only the still-valid device context.
class StagingTransaction final : public cobalt::psp::StagingBus {
    IOService *service;
    IOPCIDevice *pci;
    const PciState &state;
    const Aperture &mmio, &vram;
    ProviderSession &session;
    const ApertureProof &proof;
    const HdpFlushTarget target;
    StagingResult &result;
    StagingStorage &storage;
    uint32_t mib;
    const volatile uint8_t *nbif;
    StagingMapping cpu;
    const StateObservation &prior;
    const volatile uint8_t *liveState[2];
    volatile uint32_t *flush;
    SelectorIO io;
    uint32_t savedLow {0}, savedHigh {0};
    bool selectorDirty {false}, vramDirty {false};
    static constexpr size_t kBytes = cobalt::psp::StagingWindow::kBytes;
    static constexpr size_t kChunk = cobalt::psp::StagingWindow::kChunkBytes;
    bool baseGuard() {
        if (result.contextLost) return false;
        const bool current = session.owns() && consoleGuard(pci, state, mmio, vram) &&
            apertureOnlyClient(pci, service) && session.owns() && consoleGuard(pci, state, mmio, vram);
        if (!current) result.contextLost = true;
        return current;
    }
    bool registerRead(uint32_t offset, uint32_t &value) {
        if (!baseGuard()) return false;
        value = apertureRegisterRead(reinterpret_cast<const volatile uint32_t *>(
            nbif + (offset & 0xfff)), offset);
        return baseGuard();
    }
    bool selectorRead(uint32_t &low, uint32_t &high) {
        if (!guard()) return false;
        low = io.low();
        if (!guard()) return false;
        high = io.high();
        return guard();
    }
    bool selectorWrite(bool high, uint32_t value) {
        if (!guard()) return false;
        selectorDirty = true; ++result.selectorWrites;
        if (high) io.high(value); else io.low(value);
        return guard();
    }
    static uint32_t sourceWord(const uint8_t *source) {
        // Source buffers need not be dword-aligned.
        return static_cast<uint32_t>(source[0]) | (static_cast<uint32_t>(source[1]) << 8) |
            (static_cast<uint32_t>(source[2]) << 16) | (static_cast<uint32_t>(source[3]) << 24);
    }
    uint32_t expectedWord(size_t index, unsigned mode) const {
        if (mode == 1) return storage.original[index];
        if (mode == 3 && index * 4 < StagingResult::payloadBytes)
            return sourceWord(storage.payload + index * 4);
        return 0;
    }
    bool readWindow(unsigned mode) {
        for (size_t offset = 0; offset < kBytes; offset += kChunk) {
            if (!guard()) return false;
            ++result.cpuReadChunks;
            bool matches = true;
            for (size_t local = 0; local < kChunk; local += 4) {
                const size_t index = (offset + local) / 4;
                uint32_t value = 0;
                if (!cpu.read(index, value)) return false;
                result.cpuReadBytes += 4;
                if (mode == 0) storage.original[index] = value;
                else if (value != expectedWord(index, mode)) matches = false;
            }
            if (!guard() || !matches) return false;
        }
        return true;
    }
    bool indexedSamples(unsigned mode) {
        for (size_t page = 0; page < kBytes; page += kChunk) {
            for (unsigned edge = 0; edge < 2; ++edge) {
                const size_t offset = page + (edge ? kChunk - 4 : 0);
                const uint64_t address = result.plan.windowOffset + offset;
                const uint32_t low = static_cast<uint32_t>(address) | 0x80000000u;
                const uint32_t high = static_cast<uint32_t>(address >> 31);
                if (!selectorWrite(false, low) || !selectorWrite(true, high)) return false;
                uint32_t observedLow = 0, observedHigh = 0;
                if (!selectorRead(observedLow, observedHigh) || observedLow != low || observedHigh != high)
                    return false;
                if (!guard()) return false;
                const uint32_t value = io.data(); ++result.dataReads;
                if (!guard() || value != expectedWord(offset / 4, mode)) return false;
            }
        }
        return true;
    }
    bool writeChunk(uint64_t offset, const uint8_t *source, size_t length) {
        // This experiment only submits word-aligned zero, 125472-byte copy,
        // and original restoration. Reject any tail instead of widening I/O.
        if (!cpu.valid() || !length || length > kChunk || (offset & 3) || (length & 3) ||
            offset < result.plan.windowOffset || offset - result.plan.windowOffset > kBytes ||
            length > kBytes - (offset - result.plan.windowOffset)) return false;
        if (!guard()) return false;
        const size_t index = static_cast<size_t>((offset - result.plan.windowOffset) / 4);
        for (size_t local = 0; local < length; local += 4) {
            const uint32_t value = source ? sourceWord(source + local) : 0;
            vramDirty = true;
            if (!cpu.write(index + local / 4, value)) return false;
            ++result.vramWrites;
        }
        return guard();
    }
public:
    StagingTransaction(IOService *s, IOPCIDevice *p, const PciState &st,
        const Aperture &m, const Aperture &v, ProviderSession &owner,
        const ApertureProof &ip, const HdpFlushTarget &selected, StagingResult &r,
        StagingStorage &buffers, uint32_t size, const volatile uint8_t *registers,
        StagingMapping mapping, volatile uint32_t *flushWord, volatile uint32_t *selectors,
        const StateObservation &observed, const volatile uint8_t *stateFirst,
        const volatile uint8_t *stateSecond)
        : service(s), pci(p), state(st), mmio(m), vram(v), session(owner), proof(ip), target(selected),
          result(r), storage(buffers), mib(size), nbif(registers), cpu(mapping), prior(observed),
          liveState {stateFirst, stateSecond}, flush(flushWord), io(selectors) {}
    bool guard() {
        if (result.contextLost) return false;
        uint32_t remap = 0, memsize = 0;
        bool current = target.valid() && registerRead(proof.remapOffset, remap) &&
            remap == target.byteOffset && registerRead(proof.memsizeOffset, memsize) && memsize == mib;
        for (unsigned n = 0; current && n < 4; ++n) {
            if (!baseGuard()) { current = false; break; }
            const uint32_t offset = proof.stateOffsets[n];
            const auto *address = reinterpret_cast<const volatile uint32_t *>(liveState[n / 2] + (offset & 0xfff));
#if defined(COBALT_SURVEY_HOSTTEST)
            const uint32_t value = cobaltSurveyTestReadState32(const_cast<volatile uint32_t *>(address), offset);
#else
            const uint32_t value = *address;
#endif
            current = baseGuard() && value != UINT32_MAX && value == prior.values[n];
        }
        if (!current) result.contextLost = true;
        return current;
    }
    bool contextValid() override { return guard(); }
    bool zeroChunk(uint64_t offset, size_t length) override { return writeChunk(offset, nullptr, length); }
    bool copyChunk(uint64_t offset, const uint8_t *source, size_t length) override {
        return source && writeChunk(offset, source, length);
    }
    bool flushWrites() override {
        if (!guard()) return false;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureFence();
#else
        __asm__ volatile("mfence" ::: "memory");
#endif
        if (!guard()) return false;
        ++result.flushWrites;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureFlush(flush);
#else
        *flush = 0;
#endif
        uint32_t posted = 0;
        if (!registerRead(proof.memsizeOffset, posted) || posted != mib) {
            result.contextLost = true; return false;
        }
        return guard();
    }
    const char *prepare() {
        uint32_t low = 0, high = 0;
        if (!selectorRead(savedLow, savedHigh) || !selectorRead(low, high)) return "device-context-changed";
        if (savedLow == UINT32_MAX || savedHigh == UINT32_MAX || savedLow != low || savedHigh != high)
            return "selectors-unreadable-or-unstable";
        if (!readWindow(0)) return "original-read-failed";
        if (!readWindow(1)) return "original-read-mismatch";
        result.originalStable = true;
        return nullptr;
    }
    const char *exercise() {
        if (!indexedSamples(1)) return "original-indexed-mismatch";
        cobalt::psp::StagingWindow window(*this, result.plan.windowOffset);
        const bool zeroed = window.zero(result.plan.windowOffset, kBytes);
        result.helperStats = window.stats();
        if (!zeroed || !window.cleared()) return "zero-or-flush-failed";
        if (!readWindow(2) || !indexedSamples(2)) return "zero-read-mismatch";
        result.zeroVerified = true;
        const bool copied = window.copy(result.plan.windowOffset, storage.payload, StagingResult::payloadBytes);
        result.helperStats = window.stats();
        if (!copied || !window.payloadVisible()) return "copy-or-flush-failed";
        if (!readWindow(3) || !indexedSamples(3)) return "copy-read-mismatch";
        result.copyVerified = true;
        return nullptr;
    }
    bool cleanup() {
        bool restored = true;
        if (vramDirty) {
            restored = guard();
            for (size_t offset = 0; restored && offset < kBytes; offset += kChunk) {
                if (!guard()) { restored = false; break; }
                ++result.restoreChunks; result.restoreBytes += kChunk;
                restored = writeChunk(result.plan.windowOffset + offset,
                    reinterpret_cast<const uint8_t *>(storage.original) + offset, kChunk);
            }
            restored = restored && flushWrites() && readWindow(1) && indexedSamples(1);
            result.restoreVerified = restored;
            result.vramCleanup = restored ? "restored-observed" : "restore-skipped-or-unverified";
            result.cleanup = restored ? "vram-and-selectors-restored-observed" : "vram-restore-unverified";
        }
        if (selectorDirty) {
            uint32_t low = 0, high = 0;
            const bool selectorsRestored = selectorWrite(false, savedLow) && selectorWrite(true, savedHigh) &&
                selectorRead(low, high) && low == savedLow && high == savedHigh;
            result.selectorCleanup = selectorsRestored ? "restored-observed" : "restore-skipped-or-unverified";
            if (!selectorsRestored) {
                result.cleanup = "restore-skipped-or-unverified-device-context"; restored = false;
            } else if (!vramDirty) result.cleanup = "selectors-restored-observed";
        }
        return restored;
    }
};

// The PSP protocol is supplied by PspLoader. This adapter supplies only the
// fixed six reads, two one-shot mailbox endpoints and one bounded staging view.
class KdbTransaction final : public n48::HwAccess, public cobalt::psp::StagingBus {
    IOService *service;
    IOPCIDevice *pci;
    const PciState &state;
    const Aperture &mmio, &vram;
    ProviderSession &session;
    const ApertureProof &ap;
    const KdbProof &proof;
    const ConsoleObservation &console;
    HdpFlushTarget target;
    KdbResult &result;
    uint32_t mib;
    const volatile uint8_t *nbif, *mmhub, *dmu;
    KdbMailboxMapping mp0;
    StagingMapping cpu;
    volatile uint32_t *flush;
    SelectorIO io;
    uint32_t *original;
    const uint8_t *payload;
    cobalt::psp::StagingWindow window;
    uint32_t savedLow {0}, savedHigh {0};
    bool pinned {false}, selectorDirty {false}, vramDirty {false};
    bool zeroRequested {false}, copyRequested {false}, originalIndexed {false};
    static constexpr size_t kBytes = cobalt::psp::StagingWindow::kBytes;
    static constexpr size_t kChunk = cobalt::psp::StagingWindow::kChunkBytes;
    bool lose() { result.contextLost = true; return false; }
    bool baseGuard() {
        if (result.contextLost) return false;
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
            !apertureOnlyClient(pci, service)) return lose();
        IOPlatformExpert *platform = IOService::getPlatform();
        PE_Video video {};
        if (!platform || platform->getConsoleInfo(&video) != kIOReturnSuccess) return lose();
        uint64_t values[kConsoleScalarCount] {};
        consoleScalars(video, values);
        for (unsigned n = 0; n < kConsoleScalarCount; ++n)
            if (values[n] != console.values[n]) return lose();
        return (session.owns() && consoleGuard(pci, state, mmio, vram) &&
            apertureOnlyClient(pci, service)) || lose();
    }
    bool rawState(unsigned n, uint32_t &value) {
        if (n >= 6 || !baseGuard()) return false;
        const volatile uint8_t *page = n < 2 ? mp0.readBytes() : (n < 5 ? mmhub : dmu);
        if (!page) return lose();
        const auto *word = reinterpret_cast<const volatile uint32_t *>(page + (proof.offsets[n] & 0xfff));
#if defined(COBALT_SURVEY_HOSTTEST)
        value = cobaltSurveyTestReadState32(const_cast<volatile uint32_t *>(word), proof.offsets[n]);
#else
        value = *word;
#endif
        ++result.registerReads;
        if (value == UINT32_MAX) return lose();
        return baseGuard();
    }
    bool nbifRead(uint32_t offset, uint32_t &value) {
        if (!baseGuard()) return false;
        value = apertureRegisterRead(reinterpret_cast<const volatile uint32_t *>(nbif + (offset & 0xfff)), offset);
        if (value == UINT32_MAX) return lose();
        return baseGuard();
    }
    bool selectorRead(uint32_t &low, uint32_t &high) {
        if (!guard()) return false;
        low = io.low();
        if (low == UINT32_MAX) return lose();
        if (!guard()) return false;
        high = io.high();
        if (high == UINT32_MAX) return lose();
        return guard();
    }
    bool selectorWrite(bool high, uint32_t value) {
        if (!guard()) return false;
        selectorDirty = true; ++result.selectorWrites;
        if (high) io.high(value); else io.low(value);
        return guard();
    }
    static uint32_t sourceWord(const uint8_t *source) {
        return static_cast<uint32_t>(source[0]) | (static_cast<uint32_t>(source[1]) << 8) |
            (static_cast<uint32_t>(source[2]) << 16) | (static_cast<uint32_t>(source[3]) << 24);
    }
    uint32_t expected(size_t index, unsigned mode) const {
        if (mode == 1) return original[index];
        if (mode == 3 && index * 4 < KdbResult::kPayloadBytes) return sourceWord(payload + index * 4);
        return 0;
    }
    bool readWindow(unsigned mode) {
        for (size_t offset = 0; offset < kBytes; offset += kChunk) {
            if (!guard()) return false;
            ++result.cpuReadChunks;
            bool matches = true;
            for (size_t local = 0; local < kChunk; local += 4) {
                const size_t index = (offset + local) / 4;
                uint32_t value = 0;
                if (!cpu.read(index, value)) return lose();
                result.cpuReadBytes += 4;
                if (!mode) original[index] = value;
                else if (value != expected(index, mode)) matches = false;
            }
            if (!guard() || !matches) return false;
        }
        return true;
    }
    bool indexedSamples(unsigned mode) {
        for (size_t page = 0; page < kBytes; page += kChunk) for (unsigned edge = 0; edge < 2; ++edge) {
            const size_t offset = page + (edge ? kChunk - 4 : 0);
            const uint64_t address = result.plan.windowOffset + offset;
            const uint32_t low = static_cast<uint32_t>(address) | 0x80000000u;
            const uint32_t high = static_cast<uint32_t>(address >> 31);
            if (!selectorWrite(false, low) || !selectorWrite(true, high)) return false;
            uint32_t observedLow = 0, observedHigh = 0;
            if (!selectorRead(observedLow, observedHigh)) return false;
            if (observedLow != low || observedHigh != high) return lose();
            if (!guard()) return false;
            const uint32_t value = io.data(); ++result.dataReads;
            // An all-ones VRAM word is valid data; only registers use the
            // unreadable sentinel. Edges are compared to the CPU image.
            if (!guard() || value != expected(offset / 4, mode)) return false;
        }
        return true;
    }
    bool writeChunk(uint64_t offset, const uint8_t *source, size_t length) {
        if (result.commandAttempted || !cpu.valid() || !length || length > kChunk ||
            (offset & 3) || (length & 3) || offset < result.plan.windowOffset ||
            offset - result.plan.windowOffset > kBytes || length > kBytes - (offset - result.plan.windowOffset)) return false;
        if (!guard()) return false;
        const size_t index = static_cast<size_t>((offset - result.plan.windowOffset) / 4);
        for (size_t local = 0; local < length; local += 4) {
            vramDirty = true;
            if (!cpu.write(index + local / 4, source ? sourceWord(source + local) : 0)) return lose();
            ++result.vramWrites;
        }
        return guard();
    }
public:
    KdbTransaction(IOService *s, IOPCIDevice *p, const PciState &st, const Aperture &m, const Aperture &v,
        ProviderSession &owner, const ApertureProof &a, const KdbProof &ip, const ConsoleObservation &co,
        HdpFlushTarget selected, KdbResult &r, uint32_t size, const volatile uint8_t *registers,
        KdbMailboxMapping mailbox, const volatile uint8_t *hub, const volatile uint8_t *display,
        StagingMapping mapping, volatile uint32_t *flushWord, volatile uint32_t *selectors,
        uint32_t *backup, const uint8_t *kdb)
        : service(s), pci(p), state(st), mmio(m), vram(v), session(owner), ap(a), proof(ip), console(co),
          target(selected), result(r), mib(size), nbif(registers), mmhub(hub), dmu(display), mp0(mailbox),
          cpu(mapping), flush(flushWord), io(selectors), original(backup), payload(kdb),
          window(*this, r.plan.windowOffset) {}
    bool guard() {
        if (result.contextLost) return false;
        uint32_t remap = 0, memsize = 0;
        if (!target.valid() || !nbifRead(ap.remapOffset, remap) || remap != target.byteOffset ||
            !nbifRead(ap.memsizeOffset, memsize) || memsize != mib) return lose();
        for (unsigned n = 0; n < 6; ++n) {
            uint32_t value = 0;
            if (!rawState(n, value)) return false;
            if (n == 0) {
                // C2PMSG35 intentionally changes when the command is issued.
                if (!result.commandAttempted && value != 0x80000000u) return lose();
            } else if ((n == 1 && value != 0) || (n >= 2 && pinned && value != result.raw[n])) return lose();
        }
        return true;
    }
    const char *prepare(const StateObservation &prior) {
        for (unsigned pass = 0; pass < 2; ++pass) for (unsigned n = 0; n < 6; ++n) {
            uint32_t value = 0;
            if (!rawState(n, value)) return "fresh-state-unreadable-or-context-changed";
            if (!pass) result.raw[n] = value;
            else if (result.raw[n] != value) return "fresh-state-unstable";
        }
        if (result.raw[0] != 0x80000000u || result.raw[1] != 0 || result.raw[2] != prior.values[2] ||
            result.raw[3] != prior.values[3] || result.raw[2] > 0xffffff || result.raw[3] > 0xffffff ||
            result.raw[4] > 0xffffff || (result.raw[5] & 0xffffff) != result.raw[2]) return "fresh-state-policy-refused";
        // FB_OFFSET is separately recorded and pinned. Its relationship to
        // FB_LOCATION_BASE is not an established MC-translation proof.
        pinned = true;
        if (!guard()) return "device-context-changed";
        uint32_t low = 0, high = 0;
        if (!selectorRead(savedLow, savedHigh) || !selectorRead(low, high)) return "selectors-unreadable-or-context-changed";
        if (low != savedLow || high != savedHigh) return "selectors-unstable";
        if (!readWindow(0) || !readWindow(1)) return "original-read-mismatch";
        result.originalStable = true;
        return nullptr;
    }
    bool verifyOriginalIndexed() {
        originalIndexed = result.attempted && result.originalStable && indexedSamples(1);
        return originalIndexed;
    }
    bool contextValid() override { return guard(); }
    bool zeroChunk(uint64_t offset, size_t length) override { return zeroRequested && !copyRequested && writeChunk(offset, nullptr, length); }
    bool copyChunk(uint64_t offset, const uint8_t *source, size_t length) override {
        if (!copyRequested || !source || offset < result.plan.windowOffset) return false;
        const uint64_t relative = offset - result.plan.windowOffset;
        if (relative >= KdbResult::kPayloadBytes || length > KdbResult::kPayloadBytes - relative ||
            source != payload + relative) return false;
        return writeChunk(offset, source, length);
    }
    bool flushWrites() override {
        if (result.commandAttempted || !guard()) return false;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureFence();
#else
        __asm__ volatile("mfence" ::: "memory");
#endif
        if (!guard()) return false;
        ++result.flushWrites;
#if defined(COBALT_SURVEY_HOSTTEST)
        cobaltSurveyTestApertureFlush(flush);
#else
        *flush = 0;
#endif
        uint32_t posted = 0;
        if (!nbifRead(ap.memsizeOffset, posted) || posted != mib) return lose();
        return guard();
    }
    uint32_t regReadIp(uint16_t hw, uint8_t instance, uint8_t segment, uint32_t word) override {
        unsigned n = 6;
        if (!instance && !segment && hw == IpDiscovery::HwMp0) {
            if (word == 0x63) n = 0;
            else if (word == 0x91) n = 1;
        } else if (!instance && !segment && hw == IpDiscovery::HwMmhub) {
            if (word == 0x554) n = 2;
            else if (word == 0x555) n = 3;
            else if (word == 0x4c7) n = 4;
        } else if (!instance && segment == 2 && hw == IpDiscovery::HwDmu && word == 0x475) n = 5;
        if (n == 6 || !guard()) { lose(); return UINT32_MAX; }
        uint32_t value = 0;
        if (!rawState(n, value)) return UINT32_MAX;
        if ((n == 0 && !result.commandAttempted && value != 0x80000000u) ||
            (n == 1 && value != 0) || (n >= 2 && value != result.raw[n])) {
            lose(); return UINT32_MAX;
        }
        if (!guard()) return UINT32_MAX;
        return value;
    }
    bool regWriteIp(uint16_t hw, uint8_t instance, uint8_t segment, uint32_t word, uint32_t value) override {
        if (!result.attempted || hw != IpDiscovery::HwMp0 || instance || segment ||
            !window.payloadVisible() || !result.copyVerified || !guard()) return false;
        if (word == 0x64 && value == static_cast<uint32_t>(result.plan.mcAddress >> 20) &&
            !result.addressAttempted && !result.commandAttempted) {
            // Mark before the volatile store; a failed postguard cannot erase
            // the fact that a mailbox operation may have reached hardware.
            result.addressAttempted = result.resetRequired = true; ++result.addressWrites;
            mp0.address(value);
            return guard();
        }
        if (word == 0x63 && value == 0x00080000u && result.addressAttempted && !result.commandAttempted) {
            result.commandAttempted = result.resetRequired = result.stagingPreserved = true;
            ++result.commandWrites;
            mp0.command();
            return guard();
        }
        return false;
    }
    bool vramMemset(uint64_t offset, uint8_t value, size_t length) override {
        if (!result.attempted || !result.originalStable || !originalIndexed || zeroRequested || copyRequested || value ||
            offset != result.plan.windowOffset || length != kBytes || !guard()) return false;
        zeroRequested = true;
        const bool zeroed = window.zero(offset, length);
        result.helperStats = window.stats();
        if (!zeroed || !window.cleared() || !readWindow(2) || !indexedSamples(2)) return false;
        result.zeroVerified = true;
        return true;
    }
    bool vramWrite(uint64_t offset, const void *source, size_t length) override {
        if (!result.attempted || !result.zeroVerified || copyRequested || source != payload ||
            length != KdbResult::kPayloadBytes || offset != result.plan.windowOffset || !guard()) return false;
        copyRequested = true;
        const bool copied = window.copy(offset, source, length);
        result.helperStats = window.stats();
        if (!copied || !window.payloadVisible() || !readWindow(3) || !indexedSamples(3)) return false;
        result.copyVerified = true;
        return true;
    }
    bool cleanup() {
        bool restored = true;
        if (result.commandAttempted) {
            result.stagingPreserved = true;
            result.vramCleanup = "preserved-until-cold-reset";
            result.cleanup = "staging-preserved-reset-required";
        } else if (vramDirty) {
            restored = guard();
            for (size_t offset = 0; restored && offset < kBytes; offset += kChunk) {
                ++result.restoreChunks; result.restoreBytes += kChunk;
                restored = writeChunk(result.plan.windowOffset + offset,
                    reinterpret_cast<const uint8_t *>(original) + offset, kChunk);
            }
            restored = restored && flushWrites() && readWindow(1) && indexedSamples(1);
            result.restoreVerified = restored;
            result.vramCleanup = restored ? "restored-observed" : "restore-skipped-or-unverified";
            result.cleanup = restored ? "vram-and-selectors-restored-observed" : "vram-restore-unverified";
        }
        if (selectorDirty) {
            uint32_t low = 0, high = 0;
            const bool ok = selectorWrite(false, savedLow) && selectorWrite(true, savedHigh) &&
                selectorRead(low, high) && low == savedLow && high == savedHigh;
            result.selectorCleanup = ok ? "restored-observed" : "restore-skipped-or-unverified";
            if (!ok) { restored = false; result.cleanup = "selector-restore-skipped-or-unverified"; }
        }
        return restored;
    }
};

const char *freshApertureState(IOService *service, IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, ProviderSession &session,
    const ApertureProof &proof, const StateObservation &prior) {
    Map maps[2];
    const uint32_t pages[] = {proof.stateOffsets[0] & ~0xfffu, proof.stateOffsets[2] & ~0xfffu};
    for (unsigned n = 0; n < 2; ++n)
        if (!maps[n].create(mmio, pages[n], 4096)) return "fresh-state-map-failed";
    const volatile uint8_t *bytes[] = {maps[0].bytes(), maps[1].bytes()};
    if (!bytes[0] || !bytes[1] || (reinterpret_cast<uintptr_t>(bytes[0]) & 3) ||
        (reinterpret_cast<uintptr_t>(bytes[1]) & 3)) return "fresh-state-map-invalid";
    for (unsigned pass = 0; pass < 2; ++pass) for (unsigned n = 0; n < 4; ++n) {
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
            !apertureOnlyClient(pci, service)) return "device-context-changed";
        const uint32_t offset = proof.stateOffsets[n];
        const auto *address = reinterpret_cast<const volatile uint32_t *>(bytes[n / 2] + (offset & 0xfff));
#if defined(COBALT_SURVEY_HOSTTEST)
        const uint32_t value = cobaltSurveyTestReadState32(const_cast<volatile uint32_t *>(address), offset);
#else
        const uint32_t value = *address;
#endif
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
            !apertureOnlyClient(pci, service)) return "device-context-changed";
        if (value == UINT32_MAX || value != prior.values[n]) return "fresh-state-changed";
    }
    return nullptr;
}

void runApertureExperiment(IOService *service, IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, uint32_t mib,
    const ApertureProof &proof, const StateObservation &prior, const ConsoleObservation &console,
    ApertureResult &result, StagingResult *staging) {
    if (!indexedArmed() || !stateArmed() || (staging && !apertureArmed())) return;
    if ((state.classRevision & 0xff) != 0xc0 || state.subsystem != 0x86011eae ||
        vram.length != (256ULL << 20) || mmio.length != 0x80000) {
        result.status = "board-policy-refused"; return;
    }
    if (proof.failure) { result.status = proof.failure; return; }
    result.nativeFlushOffset = proof.nativeFlushOffset;
    if (!console.span || !prior.offsets[0] || prior.values[0] != 0x80000000 || prior.values[1] != 0 ||
        prior.values[2] > 0xffffff || prior.values[3] > 0xffffff) {
        result.status = "state-or-console-policy-refused"; return;
    }
    result.plan = cobalt::survey::planAperture({vram.physical,
        (static_cast<uint64_t>(state.bars[1]) << 32) | (state.bars[0] & ~0xfu), vram.length,
        static_cast<uint64_t>(mib) << 20, static_cast<uint64_t>(prior.values[2]) << 24,
        (static_cast<uint64_t>(prior.values[3]) + 1) << 24,
        console.values[0] & ~3ULL, console.span, 516ULL << 20});
    if (!result.plan.ok) { result.status = "window-plan-refused"; return; }
    if (!apertureOnlyClient(pci, service)) { result.status = "peer-refused"; return; }
    ProviderSession session(pci, service);
    if (!session.open()) { result.status = "provider-busy"; return; }
    if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
        !apertureOnlyClient(pci, service)) { result.status = "device-context-changed"; return; }
    const char *attemptKey = staging ? "CobaltSurvey,StagingAttempt-v1" : "CobaltSurvey,ApertureAttempt-v1";
    if (pci->getProperty(attemptKey)) { result.status = "already-attempted"; return; }
    ConsoleObservation freshConsole {};
    result.status = passiveConsole(pci, state, mmio, vram, freshConsole);
    if (result.status) return;
    for (unsigned n = 0; n < kConsoleScalarCount; ++n)
        if (freshConsole.values[n] != console.values[n]) { result.status = "fresh-console-changed"; return; }
    result.status = freshApertureState(service, pci, state, mmio, vram, session, proof, prior);
    if (result.status) return;
    Map nbif, selectors, probe, flush;
    if (!nbif.create(mmio, proof.remapOffset & ~0xfffu, 4096)) {
        result.status = "nbif-map-failed"; return;
    }
    const volatile uint8_t *registers = nbif.bytes();
    if (!registers || (reinterpret_cast<uintptr_t>(registers) & 3)) {
        result.status = "nbif-map-invalid"; return;
    }
    for (unsigned pass = 0; pass < 2; ++pass) {
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
            !apertureOnlyClient(pci, service)) { result.status = "device-context-changed"; return; }
        result.remap[pass] = apertureRegisterRead(reinterpret_cast<const volatile uint32_t *>(
            registers + (proof.remapOffset & 0xfff)), proof.remapOffset);
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
            !apertureOnlyClient(pci, service)) { result.status = "device-context-changed"; return; }
        if (result.remap[pass] != 0x7f000 && result.remap[pass] != proof.nativeFlushOffset) {
            result.status = "hdp-remap-not-whitelisted"; return;
        }
    }
    if (result.remap[0] != result.remap[1]) { result.status = "hdp-remap-unstable"; return; }
    const HdpFlushTarget target {result.remap[0], proof.nativeFlushOffset,
        result.remap[0] == proof.nativeFlushOffset};
    if (!target.valid()) { result.status = "hdp-flush-target-invalid"; return; }
    result.flushOffset = target.byteOffset;
    result.flushRoute = target.native ? "native-nbif" : "isolated-remap";
    result.guardMapping = target.native ? "shared-native-rw" : "read-only-nbif";
    if (target.native) {
        // The native flush word shares the NBIF guard page. Drop the RO
        // preflight view before creating its single RW replacement: no RO/RW
        // aliases, and only flushWord() exposes a writable register endpoint.
        registers = nullptr;
        nbif.reset();
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) ||
            !apertureOnlyClient(pci, service) || !session.owns() ||
            !consoleGuard(pci, state, mmio, vram)) {
            result.status = "device-context-changed"; return;
        }
    }
    if (!selectors.createIndexedPage(mmio) ||
        !(staging ? probe.createStagingWindow(vram, result.plan) : probe.createProbePage(vram, result.plan)) ||
        !flush.createFlushPage(mmio, target)) { result.status = "writable-map-failed"; return; }
    if (target.native) registers = flush.bytes();
    volatile uint32_t *selectorWords = selectors.selectorPage(),
        *cpuWords = staging ? nullptr : probe.probePage(result.plan),
        *flushWord = flush.flushWord(target);
    const StagingMapping stagingMapping = staging ? probe.stagingWindow(result.plan) : StagingMapping {};
    if (!registers || !selectorWords || (!staging && !cpuWords) || (staging && !stagingMapping.valid()) || !flushWord ||
        ((reinterpret_cast<uintptr_t>(selectorWords) | reinterpret_cast<uintptr_t>(cpuWords) |
          reinterpret_cast<uintptr_t>(flushWord) | reinterpret_cast<uintptr_t>(registers)) & 3)) {
        result.status = "writable-map-invalid"; return;
    }
    if (staging) {
        Map liveState[2];
        const uint32_t pages[] = {proof.stateOffsets[0] & ~0xfffu, proof.stateOffsets[2] & ~0xfffu};
        if (pages[0] == pages[1]) { result.status = "live-state-map-invalid"; return; }
        for (unsigned n = 0; n < 4; ++n) {
            if ((proof.stateOffsets[n] & 3) ||
                (proof.stateOffsets[n] & ~0xfffu) != pages[n / 2]) {
                result.status = "live-state-map-invalid"; return;
            }
        }
        for (unsigned n = 0; n < 2; ++n) {
            if (!pages[n] || pages[n] == target.pageOffset() || pages[n] == (proof.remapOffset & ~0xfffu) ||
                !liveState[n].create(mmio, pages[n], 4096)) {
                result.status = "live-state-map-failed"; return;
            }
            const auto *address = liveState[n].bytes();
            if (!address || (reinterpret_cast<uintptr_t>(address) & 3)) {
                result.status = "live-state-map-invalid"; return;
            }
        }
        StagingStorage storage;
        if (!storage.allocate()) { result.status = "staging-allocation-failed"; return; }
        StagingTransaction transaction(service, pci, state, mmio, vram, session, proof, target,
            *staging, storage, mib, registers, stagingMapping, flushWord, selectorWords,
            prior, liveState[0].bytes(), liveState[1].bytes());
        result.status = transaction.prepare();
        if (result.status) return;
        if (!transaction.guard()) { result.status = "device-context-changed"; return; }
        if (pci->getProperty(attemptKey)) { result.status = "already-attempted"; return; }
        // Publish required authorization metadata before claiming or issuing
        // selectors/VRAM writes. Missing metadata never starts the experiment.
        if (!service->setProperty("CobaltSurvey,Ready", false) ||
            !service->setProperty("CobaltSurvey,ReadOnly", false) ||
            !service->setProperty("CobaltSurvey,AccessMode", "indexed-and-synthetic-staging-writes")) {
            result.status = "metadata-publication-failed"; return;
        }
        if (!transaction.guard()) { result.status = "device-context-changed"; return; }
        if (!pci->setProperty(attemptKey, true)) { result.status = "attempt-claim-failed"; return; }
        result.attempted = true;
        result.status = transaction.exercise();
        const bool cleaned = transaction.cleanup();
        storage.reset();
        liveState[0].reset(); liveState[1].reset();
        flush.reset(); probe.reset(); selectors.reset(); nbif.reset(); session.close();
        if (!cleaned) result.status = "cleanup-unverified";
        else if (!consoleGuard(pci, state, mmio, vram)) result.status = "device-context-changed";
        result.success = !result.status;
        if (result.success) result.status = "synthetic-zero-copy-and-restore-verified";
        return;
    }
    ApertureTransaction transaction(service, pci, state, mmio, vram, session, proof, target, result,
        mib, registers, cpuWords, flushWord, selectorWords);
    result.status = transaction.saveSelectors();
    if (result.status) return;
    if (!transaction.guard()) { result.status = "device-context-changed"; return; }
    if (pci->getProperty("CobaltSurvey,ApertureAttempt-v1")) { result.status = "already-attempted"; return; }
    if (!pci->setProperty("CobaltSurvey,ApertureAttempt-v1", true)) {
        result.status = "attempt-claim-failed"; return;
    }
    result.attempted = true;
    if (!service->setProperty("CobaltSurvey,ReadOnly", false) ||
        !service->setProperty("CobaltSurvey,AccessMode", "indexed-and-bounded-aperture-writes")) {
        result.status = "metadata-publication-failed"; return;
    }
    result.status = transaction.exercise();
    const bool cleaned = transaction.cleanup();
    // Destructor order releases mappings before provider close on every exit.
    flush.reset(); probe.reset(); selectors.reset(); nbif.reset(); session.close();
    if (!cleaned) result.status = "cleanup-unverified";
    else if (!consoleGuard(pci, state, mmio, vram)) result.status = "device-context-changed";
    result.success = !result.status;
    if (result.success) result.status = "pattern-and-restore-verified";
}

class KdbStorage {
public:
    uint32_t *original {nullptr};
    ~KdbStorage() { reset(); }
    KdbStorage() = default;
    KdbStorage(const KdbStorage &) = delete;
    KdbStorage &operator=(const KdbStorage &) = delete;
    bool allocate() {
        original = static_cast<uint32_t *>(IOMalloc(cobalt::psp::StagingWindow::kBytes));
        return original != nullptr;
    }
    void reset() {
        if (original) { IOFree(original, cobalt::psp::StagingWindow::kBytes); original = nullptr; }
    }
};

void runKdb(IOService *service, IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, uint32_t mib, const ApertureProof &ap,
    const KdbProof &proof, const StateObservation &prior, const ConsoleObservation &console, KdbResult &result) {
    if (!kdbArmed() || !armed() || !indexedArmed() || !stateArmed() || !apertureArmed() || !stagingArmed()) {
        result.status = "all-six-flags-required"; return;
    }
    if ((state.classRevision & 0xff) != 0xc0 || state.subsystem != 0x86011eae ||
        vram.length != (256ULL << 20) || mmio.length != 0x80000) {
        result.status = "board-policy-refused"; return;
    }
    if (ap.failure || proof.failure) { result.status = ap.failure ? ap.failure : proof.failure; return; }
    for (unsigned n = 0; n < 6; ++n) result.offsets[n] = proof.offsets[n];
    result.nativeFlushOffset = ap.nativeFlushOffset;
    if (!console.span || prior.values[0] != 0x80000000u || prior.values[1] != 0 ||
        prior.values[2] > 0xffffff || prior.values[3] > 0xffffff) {
        result.status = "state-or-console-policy-refused"; return;
    }
    // This is the existing conservative exclusion plan, not proof that
    // firmware or another owner has reserved this region for the diagnostic.
    result.plan = cobalt::survey::planAperture({vram.physical,
        (static_cast<uint64_t>(state.bars[1]) << 32) | (state.bars[0] & ~0xfu), vram.length,
        static_cast<uint64_t>(mib) << 20, static_cast<uint64_t>(prior.values[2]) << 24,
        (static_cast<uint64_t>(prior.values[3]) + 1) << 24,
        console.values[0] & ~3ULL, console.span, 516ULL << 20});
    if (!result.plan.ok) { result.status = "window-plan-refused"; return; }
    const cobalt::survey::FirmwareView firmware = cobalt::survey::psp1402Firmware();
    cobalt::psp::Package package {};
    if (!cobalt::psp::parse(firmware.data, firmware.size, package) || firmware.size < 256 + KdbResult::kPayloadBytes ||
        package.part[cobalt::psp::Kdb].data != firmware.data + 256 ||
        package.part[cobalt::psp::Kdb].size != KdbResult::kPayloadBytes ||
        package.part[cobalt::psp::Kdb].version != 0x703b0001u) {
        result.status = "firmware-package-invalid"; return;
    }
    if (!apertureOnlyClient(pci, service)) { result.status = "peer-refused"; return; }
    ProviderSession session(pci, service);
    if (!session.open()) { result.status = "provider-busy"; return; }
    if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
        result.status = "device-context-changed"; return;
    }
    constexpr const char *attemptKey = "CobaltSurvey,KdbAttempt-v1";
    if (pci->getProperty(attemptKey)) { result.status = "already-attempted"; return; }
    Map nbif, selectors, staging, flush, mp0, mmhub, dmu;
    if (!nbif.create(mmio, ap.remapOffset & ~0xfffu, 4096)) { result.status = "nbif-map-failed"; return; }
    const volatile uint8_t *registers = nbif.bytes();
    if (!registers || (reinterpret_cast<uintptr_t>(registers) & 3)) { result.status = "nbif-map-invalid"; return; }
    for (unsigned pass = 0; pass < 2; ++pass) {
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
            result.status = "device-context-changed"; return;
        }
        result.remap[pass] = apertureRegisterRead(reinterpret_cast<const volatile uint32_t *>(
            registers + (ap.remapOffset & 0xfff)), ap.remapOffset);
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
            result.status = "device-context-changed"; return;
        }
        if (result.remap[pass] != 0x7f000 && result.remap[pass] != ap.nativeFlushOffset) {
            result.status = "hdp-remap-not-whitelisted"; return;
        }
    }
    if (result.remap[0] != result.remap[1]) { result.status = "hdp-remap-unstable"; return; }
    const HdpFlushTarget target {result.remap[0], ap.nativeFlushOffset, result.remap[0] == ap.nativeFlushOffset};
    if (!target.valid()) { result.status = "hdp-flush-target-invalid"; return; }
    result.flushOffset = target.byteOffset;
    result.flushRoute = target.native ? "native-nbif" : "isolated-remap";
    result.guardMapping = target.native ? "shared-native-rw" : "read-only-nbif";
    if (target.native) { registers = nullptr; nbif.reset(); }
    if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
        result.status = "device-context-changed"; return;
    }
    if (!selectors.createIndexedPage(mmio) || !staging.createStagingWindow(vram, result.plan) ||
        !flush.createFlushPage(mmio, target) || !mp0.createKdbMailboxPage(mmio, proof.mailbox) ||
        !mmhub.create(mmio, proof.offsets[2] & ~0xfffu, 4096) ||
        !dmu.create(mmio, proof.offsets[5] & ~0xfffu, 4096)) {
        result.status = "kdb-map-failed"; return;
    }
    if (target.native) registers = flush.bytes();
    const KdbMailboxMapping mailbox = mp0.kdbMailbox(proof.mailbox);
    const StagingMapping mapping = staging.stagingWindow(result.plan);
    volatile uint32_t *selectorWords = selectors.selectorPage(), *flushWord = flush.flushWord(target);
    if (!registers || !mailbox.valid() || !mapping.valid() || !selectorWords || !flushWord ||
        !mmhub.bytes() || !dmu.bytes() ||
        ((reinterpret_cast<uintptr_t>(registers) | reinterpret_cast<uintptr_t>(selectorWords) |
          reinterpret_cast<uintptr_t>(flushWord) | reinterpret_cast<uintptr_t>(mmhub.bytes()) |
          reinterpret_cast<uintptr_t>(dmu.bytes())) & 3u)) {
        result.status = "kdb-map-invalid"; return;
    }
    KdbStorage storage;
    if (!storage.allocate()) { result.status = "kdb-allocation-failed"; return; }
    KdbTransaction transaction(service, pci, state, mmio, vram, session, ap, proof, console, target,
        result, mib, registers, mailbox, mmhub.bytes(), dmu.bytes(), mapping, flushWord, selectorWords,
        storage.original, package.part[cobalt::psp::Kdb].data);
    result.status = transaction.prepare(prior);
    if (result.status) return;
    n48::PspLoader loader(transaction);
    if (!loader.parseContainer(firmware.data, firmware.size) || !loader.setFwPriOffset(result.plan.windowOffset) ||
        !loader.preflight() || !transaction.guard()) {
        result.lastStatus = loader.lastBootloaderStatus(); result.lastStep = loader.lastStep();
        result.status = "psp-preflight-refused"; return;
    }
    if (pci->getProperty(attemptKey)) { result.status = "already-attempted"; return; }
    if (!service->setProperty("CobaltSurvey,Ready", false) ||
        !service->setProperty("CobaltSurvey,ReadOnly", false) ||
        !service->setProperty("CobaltSurvey,AccessMode", "indexed-and-one-kdb-command")) {
        result.status = "metadata-publication-failed"; return;
    }
    if (!transaction.guard()) { result.status = "device-context-changed"; return; }
    if (!pci->setProperty(attemptKey, true)) { result.status = "attempt-claim-failed"; return; }
    result.attempted = true;
    if (!transaction.verifyOriginalIndexed()) result.status = "original-indexed-mismatch";
    else {
        const bool ready = loader.runKeyDatabase(); // Never runChain, retry, reset or continue.
        result.lastStatus = loader.lastBootloaderStatus(); result.lastStep = loader.lastStep();
        result.readyObserved = ready && result.commandAttempted;
        result.status = result.readyObserved ? "kdb-ready-observed-reset-required" : "kdb-protocol-failed";
    }
    const bool cleaned = transaction.cleanup();
    result.success = result.readyObserved && cleaned && !result.contextLost;
    if (!cleaned) {
        result.resetRequired = true;
        result.status = "cleanup-unverified";
    }
    storage.reset();
    dmu.reset(); mmhub.reset(); mp0.reset(); flush.reset(); staging.reset(); selectors.reset(); nbif.reset();
    session.close();
}

void runAperture(IOService *service, IOPCIDevice *pci, const PciState &state,
    const Aperture &mmio, const Aperture &vram, uint32_t mib,
    const ApertureProof &proof, const StateObservation &prior, const ConsoleObservation &console,
    ApertureResult &result, StagingResult *staging = nullptr) {
    if (stagingArmed()) {
        if (!staging) { result.status = "staging-result-unavailable"; return; }
        runApertureExperiment(service, pci, state, mmio, vram, mib, proof, prior, console, *staging, staging);
    } else {
        runApertureExperiment(service, pci, state, mmio, vram, mib, proof, prior, console, result, nullptr);
    }
}

void publishAperture(IOService *service, ApertureResult &result) {
    bool counts = service->setProperty("CobaltSurvey,ApertureAttempted", result.attempted);
    counts = service->setProperty("CobaltSurvey,ApertureSelectorWritesIssued", result.selectorWrites, 32) && counts;
    counts = service->setProperty("CobaltSurvey,ApertureDataReads", result.dataReads, 32) && counts;
    counts = service->setProperty("CobaltSurvey,ApertureVramWritesIssued", result.vramWrites, 32) && counts;
    counts = service->setProperty("CobaltSurvey,ApertureFlushWritesIssued", result.flushWrites, 32) && counts;
    counts = service->setProperty("CobaltSurvey,ApertureCleanup", result.cleanup) && counts;
    counts = service->setProperty("CobaltSurvey,ApertureVramCleanup", result.vramCleanup) && counts;
    counts = service->setProperty("CobaltSurvey,ApertureSelectorCleanup", result.selectorCleanup) && counts;
    const bool published = counts &&
        service->setProperty("CobaltSurvey,ApertureRemapFirstRaw", result.remap[0], 32) &&
        service->setProperty("CobaltSurvey,ApertureRemapSecondRaw", result.remap[1], 32) &&
        service->setProperty("CobaltSurvey,ApertureFlushRoute", result.flushRoute) &&
        service->setProperty("CobaltSurvey,ApertureGuardMapping", result.guardMapping) &&
        service->setProperty("CobaltSurvey,ApertureFlushByteOffset", result.flushOffset, 32) &&
        service->setProperty("CobaltSurvey,ApertureNativeFlushByteOffset", result.nativeFlushOffset, 32) &&
        service->setProperty("CobaltSurvey,AperturePlanReason", result.plan.reason) &&
        service->setProperty("CobaltSurvey,ApertureWindowOffset", result.plan.windowOffset, 64) &&
        service->setProperty("CobaltSurvey,ApertureWindowBytes", result.plan.windowBytes, 64) &&
        service->setProperty("CobaltSurvey,ApertureMcAddress", result.plan.mcAddress, 64) &&
        service->setProperty("CobaltSurvey,ApertureReadOnly", !result.attempted) &&
        service->setProperty("CobaltSurvey,ApertureStatus", result.status) &&
        service->setProperty("CobaltSurvey,Schema", result.success ? 5ULL : 4ULL, 32);
    if (!published) {
        const char *partial[] = {"ApertureWindowOffset", "ApertureWindowBytes", "ApertureMcAddress",
            "ApertureRemapFirstRaw", "ApertureRemapSecondRaw", "AperturePlanReason", "ApertureReadOnly",
            "ApertureFlushRoute", "ApertureGuardMapping", "ApertureFlushByteOffset", "ApertureNativeFlushByteOffset"};
        for (const char *name : partial) {
            char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,%s", name); service->removeProperty(key);
        }
        service->removeProperty("CobaltSurvey,ApertureStatus");
        service->setProperty("CobaltSurvey,ApertureStatus", "metadata-publication-failed");
        service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
        result.success = false;
    }
}

void publishStaging(IOService *service, StagingResult &result) {
    bool published = true;
    // Evaluate every publication even after one fails, so issued counts remain
    // available independently of success metadata. Schema 6 is committed last.
#define STAGING_PROPERTY(name, value) \
    published = service->setProperty("CobaltSurvey,Staging" name, value) && published
#define STAGING_NUMBER(name, value, bits) \
    published = service->setProperty("CobaltSurvey,Staging" name, value, bits) && published
    STAGING_PROPERTY("Attempted", result.attempted);
    STAGING_NUMBER("SelectorWritesIssued", result.selectorWrites, 32);
    STAGING_NUMBER("DataReads", result.dataReads, 32);
    STAGING_NUMBER("VramWritesIssued", result.vramWrites, 32);
    STAGING_NUMBER("FlushWritesIssued", result.flushWrites, 32);
    STAGING_NUMBER("ZeroBytesIssued", result.helperStats.zeroBytesIssued, 64);
    STAGING_NUMBER("CopyBytesIssued", result.helperStats.copyBytesIssued, 64);
    STAGING_NUMBER("ZeroChunksIssued", result.helperStats.zeroChunksIssued, 32);
    STAGING_NUMBER("CopyChunksIssued", result.helperStats.copyChunksIssued, 32);
    STAGING_NUMBER("HelperFlushesIssued", result.helperStats.flushesIssued, 32);
    STAGING_NUMBER("RestoreBytesIssued", result.restoreBytes, 64);
    STAGING_NUMBER("RestoreChunksIssued", result.restoreChunks, 32);
    STAGING_NUMBER("CpuReadBytes", result.cpuReadBytes, 64);
    STAGING_NUMBER("CpuReadChunks", result.cpuReadChunks, 32);
    STAGING_PROPERTY("Cleanup", result.cleanup);
    STAGING_PROPERTY("VramCleanup", result.vramCleanup);
    STAGING_PROPERTY("SelectorCleanup", result.selectorCleanup);
    STAGING_NUMBER("RemapFirstRaw", result.remap[0], 32);
    STAGING_NUMBER("RemapSecondRaw", result.remap[1], 32);
    STAGING_PROPERTY("FlushRoute", result.flushRoute);
    STAGING_PROPERTY("GuardMapping", result.guardMapping);
    STAGING_NUMBER("FlushByteOffset", result.flushOffset, 32);
    STAGING_NUMBER("NativeFlushByteOffset", result.nativeFlushOffset, 32);
    STAGING_PROPERTY("PlanReason", result.plan.reason);
    STAGING_NUMBER("WindowOffset", result.plan.windowOffset, 64);
    STAGING_NUMBER("WindowBytes", result.plan.windowBytes, 64);
    STAGING_NUMBER("McAddress", result.plan.mcAddress, 64);
    STAGING_NUMBER("PayloadBytes", StagingResult::payloadBytes, 64);
    STAGING_PROPERTY("ReadOnly", !result.attempted);
    STAGING_PROPERTY("OriginalStable", result.originalStable);
    STAGING_PROPERTY("ZeroVerified", result.zeroVerified);
    STAGING_PROPERTY("CopyVerified", result.copyVerified);
    STAGING_PROPERTY("RestoreVerified", result.restoreVerified);
    STAGING_PROPERTY("ContextLost", result.contextLost);
    STAGING_PROPERTY("Status", result.status);
#undef STAGING_PROPERTY
#undef STAGING_NUMBER
    published = published && service->setProperty("CobaltSurvey,Schema", result.success ? 6ULL : 4ULL, 32);
    if (!published) {
        const char *partial[] = {"WindowOffset", "WindowBytes", "McAddress", "RemapFirstRaw", "RemapSecondRaw",
            "PlanReason", "ReadOnly", "FlushRoute", "GuardMapping", "FlushByteOffset", "NativeFlushByteOffset",
            "PayloadBytes", "OriginalStable", "ZeroVerified", "CopyVerified", "RestoreVerified"};
        for (const char *name : partial) {
            char key[64]; snprintf(key, sizeof(key), "CobaltSurvey,Staging%s", name); service->removeProperty(key);
        }
        result.success = false;
        result.status = "metadata-publication-failed";
        service->removeProperty("CobaltSurvey,StagingStatus");
        service->setProperty("CobaltSurvey,StagingStatus", result.status);
        // Revoke any earlier schema 6 before the fallible fallback update.
        service->removeProperty("CobaltSurvey,Schema");
        service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
    }
}

void clearKdbProperties(IOService *service) {
    const char *names[] = {"Status", "Cleanup", "VramCleanup", "SelectorCleanup", "PlanReason", "WindowOffset",
        "WindowBytes", "McAddress", "RemapFirstRaw", "RemapSecondRaw", "Attempted", "ReadOnly", "FlushRoute",
        "GuardMapping", "FlushByteOffset", "NativeFlushByteOffset", "PayloadBytes", "SelectorWritesIssued",
        "DataReads", "VramWritesIssued", "FlushWritesIssued", "ZeroBytesIssued", "CopyBytesIssued",
        "ZeroChunksIssued", "CopyChunksIssued", "HelperFlushesIssued", "RestoreBytesIssued", "RestoreChunksIssued",
        "CpuReadBytes", "CpuReadChunks", "OriginalStable", "ZeroVerified", "CopyVerified", "RestoreVerified",
        "ContextLost", "AddressAttempted", "CommandAttempted", "AddressWritesIssued", "CommandWritesIssued",
        "ReadyObserved", "ResetRequired", "StagingPreserved", "LastStatus", "LastStep", "RegisterReads",
        "PspBootloaderRaw", "PspSosRaw", "FbBaseRaw", "FbTopRaw", "FbOffsetRaw", "DcnFbBaseRaw",
        "PspBootloaderByteOffset", "PspSosByteOffset", "FbBaseByteOffset", "FbTopByteOffset", "FbOffsetByteOffset",
        "DcnFbBaseByteOffset"};
    for (const char *name : names) {
        char key[80]; snprintf(key, sizeof(key), "CobaltSurvey,Kdb%s", name); service->removeProperty(key);
    }
}

void publishKdb(IOService *service, KdbResult &result) {
    bool published = true;
#define KDB_PROPERTY(name, value) \
    published = service->setProperty("CobaltSurvey,Kdb" name, value) && published
#define KDB_NUMBER(name, value, bits) \
    published = service->setProperty("CobaltSurvey,Kdb" name, value, bits) && published
    KDB_PROPERTY("Attempted", result.attempted);
    KDB_PROPERTY("AddressAttempted", result.addressAttempted);
    KDB_PROPERTY("CommandAttempted", result.commandAttempted);
    KDB_PROPERTY("ReadyObserved", result.readyObserved);
    KDB_PROPERTY("ResetRequired", result.resetRequired);
    KDB_PROPERTY("StagingPreserved", result.stagingPreserved);
    KDB_PROPERTY("ContextLost", result.contextLost);
    KDB_NUMBER("AddressWritesIssued", result.addressWrites, 32);
    KDB_NUMBER("CommandWritesIssued", result.commandWrites, 32);
    KDB_NUMBER("SelectorWritesIssued", result.selectorWrites, 32);
    KDB_NUMBER("DataReads", result.dataReads, 32);
    KDB_NUMBER("VramWritesIssued", result.vramWrites, 32);
    KDB_NUMBER("FlushWritesIssued", result.flushWrites, 32);
    KDB_NUMBER("ZeroBytesIssued", result.helperStats.zeroBytesIssued, 64);
    KDB_NUMBER("CopyBytesIssued", result.helperStats.copyBytesIssued, 64);
    KDB_NUMBER("ZeroChunksIssued", result.helperStats.zeroChunksIssued, 32);
    KDB_NUMBER("CopyChunksIssued", result.helperStats.copyChunksIssued, 32);
    KDB_NUMBER("HelperFlushesIssued", result.helperStats.flushesIssued, 32);
    KDB_NUMBER("RestoreBytesIssued", result.restoreBytes, 64);
    KDB_NUMBER("RestoreChunksIssued", result.restoreChunks, 32);
    KDB_NUMBER("CpuReadBytes", result.cpuReadBytes, 64);
    KDB_NUMBER("CpuReadChunks", result.cpuReadChunks, 32);
    KDB_PROPERTY("Cleanup", result.cleanup);
    KDB_PROPERTY("VramCleanup", result.vramCleanup);
    KDB_PROPERTY("SelectorCleanup", result.selectorCleanup);
    KDB_NUMBER("RemapFirstRaw", result.remap[0], 32);
    KDB_NUMBER("RemapSecondRaw", result.remap[1], 32);
    KDB_PROPERTY("FlushRoute", result.flushRoute);
    KDB_PROPERTY("GuardMapping", result.guardMapping);
    KDB_NUMBER("FlushByteOffset", result.flushOffset, 32);
    KDB_NUMBER("NativeFlushByteOffset", result.nativeFlushOffset, 32);
    KDB_PROPERTY("PlanReason", result.plan.reason);
    KDB_NUMBER("WindowOffset", result.plan.windowOffset, 64);
    KDB_NUMBER("WindowBytes", result.plan.windowBytes, 64);
    KDB_NUMBER("McAddress", result.plan.mcAddress, 64);
    KDB_NUMBER("PayloadBytes", KdbResult::kPayloadBytes, 64);
    KDB_PROPERTY("ReadOnly", !result.attempted);
    KDB_PROPERTY("OriginalStable", result.originalStable);
    KDB_PROPERTY("ZeroVerified", result.zeroVerified);
    KDB_PROPERTY("CopyVerified", result.copyVerified);
    KDB_PROPERTY("RestoreVerified", result.restoreVerified);
    KDB_NUMBER("LastStatus", result.lastStatus, 32);
    KDB_PROPERTY("LastStep", result.lastStep);
    KDB_NUMBER("RegisterReads", result.registerReads, 32);
    KDB_PROPERTY("Status", result.status);
    const char *names[] = {"PspBootloader", "PspSos", "FbBase", "FbTop", "FbOffset", "DcnFbBase"};
    for (unsigned n = 0; n < 6; ++n) {
        char key[80];
        snprintf(key, sizeof(key), "CobaltSurvey,Kdb%sRaw", names[n]);
        published = service->setProperty(key, result.raw[n], 32) && published;
        snprintf(key, sizeof(key), "CobaltSurvey,Kdb%sByteOffset", names[n]);
        published = service->setProperty(key, result.offsets[n], 32) && published;
    }
#undef KDB_PROPERTY
#undef KDB_NUMBER
    published = service->setProperty("CobaltSurvey,Ready", false) && published;
    // Schema 7 commits only a complete, published ready-observed result. It
    // makes no statement about MC mapping, authentication or GPU execution.
    published = published && service->setProperty("CobaltSurvey,Schema", result.success ? 7ULL : 4ULL, 32);
    if (!published) {
        result.success = false; result.status = "metadata-publication-failed";
        service->removeProperty("CobaltSurvey,KdbStatus");
        service->setProperty("CobaltSurvey,KdbStatus", result.status);
        service->removeProperty("CobaltSurvey,Schema");
        service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
    }
}

bool criticalIps(const IpDiscovery &d) {
    const uint16_t ids[] = {IpDiscovery::HwGc, IpDiscovery::HwMp0,
        IpDiscovery::HwMp1, IpDiscovery::HwSdma0, IpDiscovery::HwDmu};
    const cobalt::Version versions[] = {cobalt::kNavi44Profile.gc,
        cobalt::kNavi44Profile.psp, cobalt::kNavi44Profile.smu,
        cobalt::kNavi44Profile.sdma, cobalt::kNavi44Profile.dcn};
    for (unsigned i = 0; i < 5; ++i) {
        IpDiscovery::IpEntry ip {};
        if (!d.findIp(ids[i], 0, ip) || !ip.numBases ||
            !cobalt::version_matches(versions[i], {ip.major, ip.minor, ip.revision})) return false;
        // Do not silently accept a conflicting duplicate critical block.
        unsigned instanceZeroCount = 0;
        for (uint16_t n = 0; n < d.ipCount(); ++n) {
            if (!d.ipAt(n, ip)) return false;
            if (ip.hwId == ids[i]) {
                if (!cobalt::version_matches(versions[i], {ip.major, ip.minor, ip.revision})) return false;
                if (ip.instance == 0) ++instanceZeroCount;
            }
        }
        if (instanceZeroCount != 1) return false;
    }
    return true;
}
} // namespace

IOService *CobaltNavi44Survey::probe(IOService *provider, SInt32 *score) {
    if (!armed()) return nullptr;
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci || pci->configRead32(static_cast<UInt8>(0)) != kIdentity) return nullptr;
    return super::probe(provider, score);
}

void CobaltNavi44Survey::status(const char *value) {
    setProperty("CobaltSurvey,Status", value);
    IOLog("CobaltNavi44Survey: %s\n", value);
}

bool CobaltNavi44Survey::start(IOService *provider) {
    // Repeat the entire gate: start must be safe without a preceding probe.
    if (!armed()) return false;
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci || pci->configRead32(static_cast<UInt8>(0)) != kIdentity) return false;
    if (!super::start(provider)) return false;
    removeProperty("CobaltSurvey,DiscoverySnapshot");
    const char *indexedProperties[] = {"AccessMode", "DiscoverySize", "IndexedOwnership", "IndexedCleanup",
        "IndexedAttempted", "IndexedSelectorWritesIssued", "IndexedDataReads", "IndexedPeers",
        "IndexedFirstPeerClass", "IndexedClientCount", "IndexedUnexpectedClientCount"};
    for (const char *name : indexedProperties) {
        char key[64];
        snprintf(key, sizeof(key), "CobaltSurvey,%s", name);
        removeProperty(key);
    }
    clearStateProperties(this);
    clearConsoleProperties(this);
    clearApertureProperties(this);
    clearStagingProperties(this);
    clearKdbProperties(this);
    Map::clearFailure(this);
    setProperty("CobaltSurvey,Protocol", "CobaltNavi44Survey");
    setProperty("CobaltSurvey,Schema", 1ULL, 32);
    setProperty("CobaltSurvey,ReadOnly", true);
    setProperty("CobaltSurvey,Ready", false);
    survey(pci);
    registerService(); // Partial observations are useful; this never means ready.
    return true;
}

void CobaltNavi44Survey::survey(IOPCIDevice *pci) {
    PciState s {};
    if (!capture(pci, s)) { status("identity-changed"); return; }
    setProperty("CobaltSurvey,VendorID", s.identity & 0xffffu, 32);
    setProperty("CobaltSurvey,DeviceID", s.identity >> 16, 32);
    setProperty("CobaltSurvey,Revision", s.classRevision & 0xffu, 32);
    setProperty("CobaltSurvey,Class", s.classRevision >> 8, 32);
    setProperty("CobaltSurvey,SubsystemVendorID", s.subsystem & 0xffffu, 32);
    setProperty("CobaltSurvey,SubsystemDeviceID", s.subsystem >> 16, 32);
    setProperty("CobaltSurvey,Command", s.command, 32);
    setProperty("CobaltSurvey,HeaderType", s.header, 32);
    for (unsigned i = 0; i < 6; ++i) {
        char key[64];
        snprintf(key, sizeof(key), "CobaltSurvey,BAR%uRaw", i);
        setProperty(key, s.bars[i], 32);
        const Aperture a = aperture(pci, i);
        snprintf(key, sizeof(key), "CobaltSurvey,BAR%uDescriptorPresent", i);
        setProperty(key, a.memory != nullptr);
        if (a.memory) {
            snprintf(key, sizeof(key), "CobaltSurvey,BAR%uPhysical", i);
            setProperty(key, a.physical, 64);
            snprintf(key, sizeof(key), "CobaltSurvey,BAR%uLength", i);
            setProperty(key, a.length, 64);
        }
    }
    if (!validHeaderClass(s)) { status("pci-header-class-invalid"); return; }
    if (!(s.command & 2)) { status("memory-decoding-disabled"); return; }
    // BAR5 must be a non-prefetchable 32-bit memory BAR.
    const uint64_t mmioBase = s.bars[5] & ~0xfu;
    const Aperture mmio = aperture(pci, 5);
    if ((s.bars[5] & 0xf) != 0 || (s.bars[4] & 7) == 4 ||
        !apertureValid(mmio, mmioBase) || mmio.length > (1ULL << 32) - mmioBase ||
        mmio.length < kMemsizePage + kMemsizePageSize) {
        status("bar5-invalid"); return;
    }
    Map registers;
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 5, mmio)) {
        status("pci-state-changed"); return;
    }
    if (!registers.create(mmio, kMemsizePage, kMemsizePageSize)) {
        registers.publishFailure(this, "memsize");
        status("memsize-map-failed"); return;
    }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 5, mmio)) {
        status("pci-state-changed"); return;
    }
    const volatile uint8_t *regBytes = registers.bytes();
    if (!regBytes || (reinterpret_cast<uintptr_t>(regBytes) & 3)) {
        registers.publishFailure(this, "memsize", "map-address");
        status("memsize-map-invalid"); return;
    }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 5, mmio)) {
        status("pci-state-changed"); return;
    }
    const uint32_t first = readMemsize(regBytes);
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 5, mmio)) {
        status("pci-state-changed"); return;
    }
    const uint32_t second = readMemsize(regBytes);
    setProperty("CobaltSurvey,MemsizeFirstMiB", first, 32);
    setProperty("CobaltSurvey,MemsizeSecondMiB", second, 32);
    if (first != second || !plausibleMemsize(first)) {
        status("memsize-invalid-or-unstable"); return;
    }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 5, mmio)) {
        status("pci-state-changed"); return;
    }
    const uint64_t vramBytes = static_cast<uint64_t>(first) * (kGiB / 1024);
    setProperty("CobaltSurvey,VRAMBytes", vramBytes, 64);
    const uint64_t vramBase = (static_cast<uint64_t>(s.bars[1]) << 32) | (s.bars[0] & ~0xfu);
    const Aperture vram = aperture(pci, 0);
    // Permit the prefetchable flag, require MEM64. No aperture size probing.
    if ((s.bars[0] & 7) != 4 || !apertureValid(vram, vramBase) ||
        !range(vramBase, vramBytes)) { status("bar0-invalid"); return; }
    const uint64_t offset = vramBytes - kDiscoveryTail;
    // Preserve the default refusal and avoid opening the provider unless the
    // separately armed experiment is actually needed for a small aperture.
    const bool indexed = vram.length < vramBytes && indexedArmed();
    if (vram.length < vramBytes && !indexed) { status("discovery-aperture-too-small"); return; }
    setProperty("CobaltSurvey,DiscoveryOffset", offset, 64);
    if (indexed) setProperty("CobaltSurvey,DiscoverySize", kDiscoverySize, 64);
    const uint64_t allocationSize = indexed ? 2 * kDiscoverySize : kDiscoverySize;
    Map discovery;
    uint8_t *snapshot = nullptr;
    if (indexed) {
        snapshot = static_cast<uint8_t *>(IOMalloc(allocationSize));
        if (!snapshot) { status("snapshot-allocation-failed"); return; }
        const char *failure = indexedSnapshot(this, pci, s, mmio, vram, registers,
            regBytes, first, snapshot);
        if (failure) { IOFree(snapshot, allocationSize); status(failure); return; }
    } else {
        if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
            !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
        if (!discovery.create(vram, offset, kDiscoverySize)) {
            discovery.publishFailure(this, "discovery"); status("discovery-map-failed"); return;
        }
        if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
            !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
        const volatile uint8_t *source = discovery.bytes();
        if (!source) {
            discovery.publishFailure(this, "discovery", "map-address"); status("discovery-map-invalid"); return;
        }
        if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
            !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
        if (readMemsize(regBytes) != first) { status("memsize-changed"); return; }
        if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
            !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
        snapshot = static_cast<uint8_t *>(IOMalloc(kDiscoverySize));
        if (!snapshot) { status("snapshot-allocation-failed"); return; }
        for (size_t i = 0; i < kDiscoverySize; ++i) snapshot[i] = source[i];
        if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
            !apertureUnchanged(pci, 5, mmio)) {
            IOFree(snapshot, kDiscoverySize); status("pci-state-changed"); return;
        }
        bool stable = true;
        for (size_t i = 0; i < kDiscoverySize; ++i)
            if (snapshot[i] != source[i]) { stable = false; break; }
        const bool current = unchanged(pci, s) && apertureUnchanged(pci, 0, vram) &&
            apertureUnchanged(pci, 5, mmio);
        if (!current || !stable || readMemsize(regBytes) != first) {
            IOFree(snapshot, kDiscoverySize);
            status(current ? "discovery-snapshot-unstable" : "pci-state-changed"); return;
        }
        if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
            !apertureUnchanged(pci, 5, mmio)) {
            IOFree(snapshot, kDiscoverySize); status("pci-state-changed"); return;
        }
    }
    IpDiscovery parser;
    IpDiscovery::GcTopology topology {};
    const char *failure = nullptr;
    if (!parser.init(snapshot, kDiscoverySize)) failure = "discovery-parser-invalid";
    else if (!criticalIps(parser)) failure = "discovery-profile-mismatch";
    else if (!parser.gcTopology(topology) || !cobalt::gfx_topology_compatible(
        cobalt::Family::Navi44, cobalt::kNavi44Profile.gc, topology)) failure = "discovery-topology-invalid";
    if (failure) { IOFree(snapshot, allocationSize); status(failure); return; }
    const bool collectState = stateArmed();
    StateObservation stateResult {};
    const char *stateFailure = nullptr;
    if (collectState) {
        stateFailure = passiveState(pci, s, mmio, vram, parser, stateResult);
    }
    const bool collectAperture = apertureArmed() || kdbArmed();
    const ApertureProof proof = collectAperture ? apertureProof(parser, stateResult, mmio) : ApertureProof {};
    const KdbProof kdbIp = kdbArmed() ? kdbProof(parser, proof, mmio) : KdbProof {};
    ApertureResult apertureResult;
    StagingResult stagingResult;
    KdbResult kdbResult;
    const uint64_t binaryOffset = parser.binaryOffset();
    const uint32_t ipCount = parser.ipCount();
    discovery.reset();
    registers.reset();
    OSData *data = OSData::withBytes(snapshot, static_cast<unsigned>(kDiscoverySize));
    IOFree(snapshot, allocationSize);
    if (!data) { status("snapshot-publication-allocation-failed"); return; }
    const bool published = setProperty("CobaltSurvey,DiscoverySnapshot", data);
    data->release();
    if (!published) { status("snapshot-publication-failed"); return; }
    setProperty("CobaltSurvey,DiscoveryBinaryOffset", binaryOffset, 64);
    setProperty("CobaltSurvey,DiscoveryIPCount", ipCount, 32);
    setProperty("CobaltSurvey,ShaderEngineCapacity", topology.shaderEngines, 32);
    setProperty("CobaltSurvey,ArraysPerEngineCapacity", topology.shaderArraysPerEngine, 32);
    setProperty("CobaltSurvey,WGPPerArrayCapacity", topology.wgpPerArray, 32);
    setProperty("CobaltSurvey,ComputeUnitCapacity", topology.maxComputeUnits, 32);
    setProperty("CobaltSurvey,RenderBackendsPerEngineCapacity", topology.renderBackendsPerEngine, 32);
    setProperty("CobaltSurvey,MaxWavesPerSIMD", topology.maxWavesPerSimd, 32);
    if (collectState && !stateFailure && (pci->isInactive() || !unchanged(pci, s) ||
        !apertureUnchanged(pci, 5, mmio) || !apertureUnchanged(pci, 0, vram)))
        stateFailure = "pci-state-changed";
    if (collectState) {
        if (stateFailure) {
            publishStateFailure(this, stateFailure);
        } else if (!publishState(this, stateResult)) {
            publishStateFailure(this, "metadata-publication-failed");
        } else {
            // All GPU mappings and temporary snapshot storage were released
            // before these OS calls. The existing state read set is unchanged.
            ConsoleObservation consoleResult {};
            const char *consoleFailure = passiveConsole(pci, s, mmio, vram, consoleResult);
            if (!consoleFailure && !consoleGuard(pci, s, mmio, vram)) consoleFailure = "pci-state-changed";
            if (consoleFailure) publishConsoleFailure(this, consoleFailure);
            else if (!publishConsole(this, consoleResult)) publishConsoleFailure(this, "metadata-publication-failed");
            else if (!consoleGuard(pci, s, mmio, vram)) publishConsoleFailure(this, "pci-state-changed");
            else if (collectAperture) {
                if (kdbArmed()) {
                    runKdb(this, pci, s, mmio, vram, first, proof, kdbIp, stateResult, consoleResult, kdbResult);
                    if (!consoleGuard(pci, s, mmio, vram)) {
                        kdbResult.success = false; kdbResult.contextLost = true;
                        kdbResult.status = "device-context-changed";
                    }
                    publishKdb(this, kdbResult);
                    if (!consoleGuard(pci, s, mmio, vram)) {
                        kdbResult.success = false; kdbResult.contextLost = true;
                        kdbResult.status = "device-context-changed";
                        publishKdb(this, kdbResult);
                    }
                } else {
                    runAperture(this, pci, s, mmio, vram, first, proof, stateResult, consoleResult,
                        apertureResult, &stagingResult);
                    // runAperture owns every aperture resource synchronously. No
                    // mapped byte or provider ownership escapes into publication.
                    ApertureResult &experiment = stagingArmed() ? stagingResult : apertureResult;
                    if (!consoleGuard(pci, s, mmio, vram)) {
                        experiment.success = false;
                        experiment.status = "device-context-changed";
                    }
                    if (stagingArmed()) publishStaging(this, stagingResult);
                    else publishAperture(this, apertureResult);
                    if (!consoleGuard(pci, s, mmio, vram)) {
                        experiment.success = false;
                        experiment.status = "device-context-changed";
                        if (stagingArmed()) publishStaging(this, stagingResult);
                        else publishAperture(this, apertureResult);
                    }
                }
            }
        }
    }
    status("discovery-snapshot-validated");
}

void CobaltNavi44Survey::stop(IOService *provider) {
    removeProperty("CobaltSurvey,DiscoverySnapshot");
    clearStateProperties(this);
    clearConsoleProperties(this);
    clearApertureProperties(this);
    clearStagingProperties(this);
    clearKdbProperties(this);
    status("stopped");
    super::stop(provider);
}
