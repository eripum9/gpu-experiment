#include "CobaltNavi44Survey.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSData.h>
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
public:
    IOMemoryMap *value {nullptr};
    ~Map() { if (value) value->release(); }
    bool create(const Aperture &a, uint64_t offset, uint64_t length) {
        if (offset > a.length || length > a.length - offset ||
            !range(a.physical + offset, length)) return false;
        value = a.memory->createMappingInTask(kernel_task, 0, kMapOptions, offset, length);
        if (!value || value->getLength() != length ||
            value->getPhysicalAddress() != a.physical + offset ||
            value->getMemoryDescriptor() != a.memory) return false;
        const IOOptionBits options = value->getMapOptions();
        if (!(options & kIOMapReadOnly) ||
            (options & kIOMapCacheMask) != kIOMapInhibitCache) return false;
        IOByteCount contiguous = 0;
        return value->getPhysicalSegment(0, &contiguous, kIOMemoryMapperNone) ==
            a.physical + offset && contiguous >= length;
    }
    const volatile uint8_t *bytes() const {
        const uintptr_t address = value->getVirtualAddress();
        if (!range(address, value->getLength())) return nullptr;
        return reinterpret_cast<const volatile uint8_t *>(address);
    }
};

uint32_t readMemsize(const volatile uint8_t *bytes) {
    return OSSwapLittleToHostInt32(*reinterpret_cast<const volatile uint32_t *>(bytes + kMemsizeInPage));
}

bool plausibleMemsize(uint32_t mib) {
    return mib >= 1024 && mib <= 64 * 1024 && (mib & (mib - 1)) == 0;
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
        status("memsize-map-failed"); return;
    }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 5, mmio)) {
        status("pci-state-changed"); return;
    }
    const volatile uint8_t *regBytes = registers.bytes();
    if (!regBytes || (reinterpret_cast<uintptr_t>(regBytes) & 3)) {
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
    if (vram.length < vramBytes) { status("discovery-aperture-too-small"); return; }
    const uint64_t offset = vramBytes - kDiscoveryTail;
    setProperty("CobaltSurvey,DiscoveryOffset", offset, 64);
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
        !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
    Map discovery;
    if (!discovery.create(vram, offset, kDiscoverySize)) { status("discovery-map-failed"); return; }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
        !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
    const volatile uint8_t *source = discovery.bytes();
    if (!source) { status("discovery-map-invalid"); return; }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
        !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
    if (readMemsize(regBytes) != first) { status("memsize-changed"); return; }
    if (!unchanged(pci, s) || !apertureUnchanged(pci, 0, vram) ||
        !apertureUnchanged(pci, 5, mmio)) { status("pci-state-changed"); return; }
    uint8_t *snapshot = static_cast<uint8_t *>(IOMalloc(kDiscoverySize));
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
    IpDiscovery parser;
    IpDiscovery::GcTopology topology {};
    const char *failure = nullptr;
    if (!parser.init(snapshot, kDiscoverySize)) failure = "discovery-parser-invalid";
    else if (!criticalIps(parser)) failure = "discovery-profile-mismatch";
    else if (!parser.gcTopology(topology) || !cobalt::gfx_topology_compatible(
        cobalt::Family::Navi44, cobalt::kNavi44Profile.gc, topology)) failure = "discovery-topology-invalid";
    if (failure) { IOFree(snapshot, kDiscoverySize); status(failure); return; }
    const uint64_t binaryOffset = parser.binaryOffset();
    const uint32_t ipCount = parser.ipCount();
    OSData *data = OSData::withBytes(snapshot, static_cast<unsigned>(kDiscoverySize));
    IOFree(snapshot, kDiscoverySize);
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
    status("discovery-snapshot-validated");
}

void CobaltNavi44Survey::stop(IOService *provider) {
    removeProperty("CobaltSurvey,DiscoverySnapshot");
    status("stopped");
    super::stop(provider);
}
