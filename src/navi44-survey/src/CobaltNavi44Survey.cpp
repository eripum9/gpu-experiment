#include "CobaltNavi44Survey.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/OSByteOrder.h>
#include <pexpert/pexpert.h>
#include "ipdiscovery.hpp"
#include "gpu_profile.hpp"
#include "gfx_topology.hpp"

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
    // The only writable mapping policy is this fixed BAR5 selector page.
    bool createIndexedPage(const Aperture &a) { return createPolicy(a, 0, 4096, true); }
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
        }
    }
    status("discovery-snapshot-validated");
}

void CobaltNavi44Survey::stop(IOService *provider) {
    removeProperty("CobaltSurvey,DiscoverySnapshot");
    clearStateProperties(this);
    status("stopped");
    super::stop(provider);
}
