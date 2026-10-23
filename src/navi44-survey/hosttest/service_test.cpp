#include "CobaltNavi44Survey.hpp"
#include <FakeIOKit.hpp>
#include "ipdiscovery.hpp"
#include "psp_container.hpp"
#include "psp_firmware.hpp"
#include "presos_manifest.hpp"
#include <iostream>

static unsigned checks = 0;
static const char *activeTestPhase = "startup";
#define CHECK(expression) do { ++checks; if (!(expression)) throw std::runtime_error( \
    std::string("line ") + std::to_string(__LINE__) + ": " #expression); } while (0)
using Bytes = std::vector<uint8_t>;
static void put16(Bytes &b, size_t p, uint16_t v) { b[p] = uint8_t(v); b[p+1] = uint8_t(v >> 8); }
static void put32(Bytes &b, size_t p, uint32_t v) { for (unsigned i=0; i<4; ++i) b[p+i] = uint8_t(v >> (8*i)); }
static cobalt::survey::FirmwareView firmwareOverride {};
static const Bytes &syntheticPspFirmware() {
    static const Bytes firmware = [] {
        const uint32_t payloadOffset = 256;
        const uint32_t kdbBytes = 6816;
        const uint32_t types[] = {3,5,2,7,8,9,10,11,1,4,6};
        // Keep the pinned container file layout: SPL begins at file offset
        // 0x66a20 (payload-relative 0x66920), with deterministic synthetic
        // padding and no real firmware bytes.
        const uint32_t splPayloadOffset = 0x66920;
        const uint32_t splBytes = 832;
        const uint32_t payloadBytes = splPayloadOffset + splBytes + 10 * 16;
        Bytes result(payloadOffset + payloadBytes);
        put32(result, 0, static_cast<uint32_t>(result.size()));
        put32(result, 4, 36); put32(result, 8, 2);
        put32(result, 20, payloadBytes); put32(result, 24, payloadOffset);
        put32(result, 32, static_cast<uint32_t>(sizeof(types) / sizeof(types[0])));
        uint32_t cursor = 0;
        for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
            const uint32_t length = i == 0 ? kdbBytes : types[i] == 5 ? splBytes : 16;
            if (types[i] == 5) cursor = splPayloadOffset;
            const size_t descriptor = 36 + i * 16;
            put32(result, descriptor, types[i]);
            put32(result, descriptor + 4, types[i] == 3 ? 0x703b0001u : types[i] == 5 ? 0x01003b00u : 0x140200 + types[i]);
            put32(result, descriptor + 8, cursor); put32(result, descriptor + 12, length);
            for (uint32_t n = 0; n < length; ++n)
                result[payloadOffset + cursor + n] = static_cast<uint8_t>((n * 29u + types[i] * 17u) & 0xffu);
            cursor += length;
        }
        return result;
    }();
    return firmware;
}
static const Bytes &syntheticPreSosPspFirmware() {
    static const Bytes firmware = [] {
        struct Descriptor { uint32_t type, version, fileOffset, bytes; };
        // Metadata mirrors the complete pinned package table. Every byte is
        // deterministic test data; no bytes are copied from real firmware.
        constexpr Descriptor descriptors[] = {
            {3,  0x703b0001u, 0x00100,  6816},
            {2,  0x003b0f0du, 0x01ba0, 78272},
            {1,  0x003b0f0du, 0x14d60,125472},
            {7,  0x003b0f0du, 0x33780,103792},
            {8,  0x003b0f0du, 0x4ccf0, 37280},
            {9,  0x003b0f0du, 0x55e90, 53344},
            {4,  0x00000000u, 0x62ef0,  2304},
            {11, 0x003b0f0du, 0x637f0, 12848},
            {5,  0x01003b00u, 0x66a20,   832},
        };
        Bytes result(cobalt::survey::kPreSosFirmwareBytes);
        for (size_t i = 0; i < result.size(); ++i)
            result[i] = static_cast<uint8_t>((i * 37u + (i >> 7) * 11u + 0x5du) & 0xffu);
        put32(result, 0, static_cast<uint32_t>(result.size()));
        put32(result, 4, 36); put32(result, 8, 2);
        put32(result, 20, 420960); put32(result, 24, 256);
        put32(result, 32, static_cast<uint32_t>(sizeof(descriptors) / sizeof(descriptors[0])));
        for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) {
            const auto &entry = descriptors[i];
            const size_t table = 36 + i * 16;
            put32(result, table, entry.type);
            put32(result, table + 4, entry.version);
            put32(result, table + 8, entry.fileOffset - 256);
            put32(result, table + 12, entry.bytes);
            for (uint32_t n = 0; n < entry.bytes; ++n)
                result[entry.fileOffset + n] = static_cast<uint8_t>((entry.type * 41u + n * 19u + (n >> 5)) & 0xffu);
        }
        return result;
    }();
    return firmware;
}
class FirmwareOverrideScope {
    cobalt::survey::FirmwareView previous_;
public:
    explicit FirmwareOverrideScope(const Bytes &bytes) : previous_(firmwareOverride) {
        firmwareOverride = {bytes.data(), bytes.size()};
    }
    ~FirmwareOverrideScope() { firmwareOverride = previous_; }
    FirmwareOverrideScope(const FirmwareOverrideScope &) = delete;
    FirmwareOverrideScope &operator=(const FirmwareOverrideScope &) = delete;
};
cobalt::survey::FirmwareView cobalt::survey::psp1402Firmware() {
    if (firmwareOverride.data || firmwareOverride.size) return firmwareOverride;
    const auto &firmware = syntheticPspFirmware();
    return {firmware.data(), firmware.size()};
}
static uint16_t sum(const Bytes &b, size_t begin, size_t end) {
    uint16_t n=0; for (size_t i=begin; i<end; ++i) n=uint16_t(n+b[i]); return n;
}
static constexpr size_t prefix=256, ipds=prefix+60, die=ipds+80;
static constexpr size_t ipdsSize=80+4+5*12, gc=ipds+ipdsSize, gcSize=164;
static void repair(Bytes &b) {
    put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize));
    put16(b,prefix+22,sum(b,gc,gc+gcSize));
    put16(b,prefix+8,sum(b,prefix+10,gc+gcSize));
}
static Bytes fixture() {
    Bytes b(10240);
    put32(b,prefix,0x28211407); put16(b,prefix+4,1); put16(b,prefix+6,3);
    put16(b,prefix+10,uint16_t(gc+gcSize-prefix));
    put16(b,prefix+12,60); put16(b,prefix+16,uint16_t(ipdsSize));
    put16(b,prefix+20,uint16_t(gc-prefix)); put16(b,prefix+24,uint16_t(gcSize));
    put32(b,ipds,0x53445049); put16(b,ipds+4,3); put16(b,ipds+6,uint16_t(ipdsSize));
    put16(b,ipds+12,1); put16(b,ipds+16,uint16_t(die-prefix)); put16(b,die+2,5);
    const uint16_t ids[] = {11,255,1,42,271};
    const uint8_t major[] = {12,14,14,7,4}, minor[] = {0,0,0,0,1}, rev[] = {0,2,2,0,0};
    for (unsigned i=0; i<5; ++i) {
        const size_t p=die+4+i*12; put16(b,p,ids[i]); b[p+3]=1;
        b[p+4]=major[i]; b[p+5]=minor[i]; b[p+6]=rev[i]; put32(b,p+8,0x1000+i*0x100);
    }
    put32(b,gc,0x4347); put16(b,gc+4,1); put16(b,gc+6,3); put32(b,gc+8,uint32_t(gcSize));
    put32(b,gc+12,2); put32(b,gc+16,4); put32(b,gc+24,4);
    put32(b,gc+60,16); put32(b,gc+76,2); repair(b); return b;
}
static Bytes stateFixture(uint32_t mmhubBase=0x2500) {
    Bytes b=fixture();
    b.insert(b.begin()+static_cast<std::ptrdiff_t>(gc),12,0);
    put16(b,prefix+10,uint16_t(gc+gcSize+12-prefix));
    put16(b,prefix+16,uint16_t(ipdsSize+12));
    put16(b,prefix+20,uint16_t(gc+12-prefix));
    put16(b,ipds+6,uint16_t(ipdsSize+12));
    put16(b,die+2,6);
    const size_t mmhub=die+4+5*12;
    put16(b,mmhub,34); b[mmhub+3]=1; b[mmhub+4]=4; b[mmhub+5]=1; b[mmhub+6]=0;
    put32(b,mmhub+8,mmhubBase);
    const size_t shiftedGc=gc+12;
    put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12));
    put16(b,prefix+22,sum(b,shiftedGc,shiftedGc+gcSize));
    put16(b,prefix+8,sum(b,prefix+10,shiftedGc+gcSize));
    b.resize(10240);
    return b;
}
static Bytes duplicateStateFixture() {
    Bytes b=stateFixture();
    const size_t oldGc=gc+12;
    b.insert(b.begin()+static_cast<std::ptrdiff_t>(oldGc),12,0);
    const size_t source=die+4+5*12, duplicate=die+4+6*12;
    std::memcpy(b.data()+duplicate,b.data()+source,12);
    put16(b,prefix+10,uint16_t(gc+gcSize+24-prefix));
    put16(b,prefix+16,uint16_t(ipdsSize+24));
    put16(b,prefix+20,uint16_t(gc+24-prefix));
    put16(b,ipds+6,uint16_t(ipdsSize+24));
    put16(b,die+2,7);
    const size_t shiftedGc=gc+24;
    put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+24));
    put16(b,prefix+22,sum(b,shiftedGc,shiftedGc+gcSize));
    put16(b,prefix+8,sum(b,prefix+10,shiftedGc+gcSize));
    b.resize(10240);
    return b;
}

struct Device {
    IOPCIDevice pci;
    IODeviceMemory mmio, vram;
    CobaltNavi44Survey service;
    Device() {
        testState = {};
        mmio.physical=0xc0000000; mmio.length=mmio.contiguous=0x100000;
        mmio.expectedOffset=0x3000; mmio.expectedLength=0x1000;
        mmio.storage.resize(0x1000/4); mmio.storage[0x78c/4]=16384;
        vram.physical=0x1000000000ULL; vram.length=vram.contiguous=16ULL<<30;
        vram.expectedOffset=(16ULL<<30)-65536; vram.expectedLength=10240;
        vram.storage.resize(10240/4);
        load(fixture()); pci.memories[0]=&vram; pci.memories[5]=&mmio;
        pci.clients.push_back(&service);
    }
    void load(const Bytes &b) {
        std::memcpy(vram.storage.data(),b.data(),b.size()); testState.discovery=b;
    }
    void indexed(uint32_t mib=16304) {
        testState.indexedBootPresent=true;
        mmio.storage[0x78c/4]=mib;
        vram.length=vram.contiguous=256ULL<<20;
        testState.discoveryOffset=(uint64_t(mib)<<20)-65536;
        mmio.selectorStorage[0]=0x12345678; mmio.selectorStorage[6]=2;
    }
    void run(const char *expected) {
        CHECK(service.start(&pci)); CHECK(service.registered);
        if (service.strings.at("CobaltSurvey,Status")!=expected)
            throw std::runtime_error(std::string("expected status ")+expected+" got "+service.strings.at("CobaltSurvey,Status"));
        CHECK(service.numbers.at("CobaltSurvey,Ready")==0);
        CHECK(testState.mapsLive==0); CHECK(testState.allocations==0);
        CHECK(testState.backingDescriptorsLive==0);
        CHECK(testState.openLive==0); CHECK(testState.iteratorsLive==0);
        if (std::string(expected)!="discovery-snapshot-validated")
            CHECK(service.blobs.count("CobaltSurvey,DiscoverySnapshot")==0);
    }
};

static void gates() {
    for (const auto *argument : {"", "0", "2", "49", "-1", "1x", "true", "11111111111111111"}) {
        Device d; testState.boot=argument;
        SInt32 score=0;
        CHECK(d.service.probe(&d.pci,&score)==nullptr);
        CHECK(!d.service.start(&d.pci));
        CHECK(d.pci.identityReads==0); CHECK(d.pci.otherReads==0);
        CHECK(d.pci.descriptorReads==0); CHECK(testState.mapRequests==0);
    }
    for (const auto *argument : {"1", "01", "0x1", "1 ", "1\t"}) {
        Device d; testState.boot=argument;
        CHECK(d.service.probe(&d.pci,nullptr)==&d.service);
        d.run("discovery-snapshot-validated");
    }
    {
        Device d; testState.bootPresent=false;
        CHECK(d.service.probe(&d.pci,nullptr)==nullptr); CHECK(!d.service.start(&d.pci));
        CHECK(d.pci.identityReads==0);
    }
    for (const uint32_t identity : {0x75501002u,0x75901003u,0xffffffffu,0u}) {
        Device d; d.pci.identity=identity;
        CHECK(d.service.probe(&d.pci,nullptr)==nullptr); CHECK(!d.service.start(&d.pci));
        CHECK(d.pci.identityReads==2); CHECK(d.pci.otherReads==0);
        CHECK(d.pci.descriptorReads==0); CHECK(testState.mapRequests==0);
    }
    {
        Device d; IOService other;
        CHECK(d.service.probe(&other,nullptr)==nullptr); CHECK(!d.service.start(&other));
        CHECK(testState.mapRequests==0);
    }
    {
        Device d; CHECK(d.service.probe(&d.pci,nullptr)==&d.service);
        testState.boot="0"; CHECK(!d.service.start(&d.pci));
        CHECK(d.pci.identityReads==1); CHECK(testState.mapRequests==0);
    }
    {
        Device d; CHECK(d.service.probe(&d.pci,nullptr)==&d.service);
        d.pci.identity=0x75501002; CHECK(!d.service.start(&d.pci));
        CHECK(d.pci.otherReads==0); CHECK(testState.mapRequests==0);
    }
    {
        Device d; testState.superStart=false; CHECK(!d.service.start(&d.pci));
        CHECK(!d.service.registered); CHECK(d.pci.otherReads==0);
    }
}

static void noIndexedWrites() {
    CHECK(testState.selectorWrites==0); CHECK(testState.indexedDataReads==0);
}
static void restored(Device &d) {
    CHECK(d.mmio.selectorStorage[0]==0x12345678); CHECK(d.mmio.selectorStorage[6]==2);
    CHECK(d.service.strings.at("CobaltSurvey,IndexedCleanup")=="restored-observed");
    CHECK(d.service.numbers.at("CobaltSurvey,IndexedSelectorWritesIssued")==testState.selectorWrites);
    CHECK(d.service.numbers.at("CobaltSurvey,IndexedDataReads")==testState.indexedDataReads);
    CHECK(d.service.numbers.at("CobaltSurvey,ReadOnly")==0);
    CHECK(d.service.numbers.at("CobaltSurvey,Ready")==0);
}
static void indexedGatesAndPreflight() {
    for (const auto *argument : {"", "0", "2", "-1", "1x", "true"}) {
        Device d; d.indexed(); testState.indexedBoot=argument;
        d.run("discovery-aperture-too-small"); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    {
        Device d; d.indexed(); testState.indexedBootPresent=false;
        d.run("discovery-aperture-too-small"); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    {
        Device d; d.indexed(); testState.boot="0";
        CHECK(!d.service.start(&d.pci)); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    {
        Device d; d.indexed(); d.pci.identity=0x75501002;
        CHECK(!d.service.start(&d.pci)); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    {
        Device d; testState.indexedBootPresent=true;
        d.run("discovery-snapshot-validated"); noIndexedWrites(); CHECK(testState.openCalls==0);
        CHECK(d.service.numbers.at("CobaltSurvey,ReadOnly")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==1);
    }
    {
        Device d; d.indexed(); IOService other; other.meta.name="UnexpectedGpuHelper";
        d.pci.clients.push_back(&other); d.run("indexed-peer-refused"); noIndexedWrites();
        CHECK(testState.openCalls==0); CHECK(d.service.numbers.at("CobaltSurvey,IndexedClientCount")==2);
        CHECK(d.service.strings.at("CobaltSurvey,IndexedFirstPeerClass")=="UnexpectedGpuHelper");
    }
    for (unsigned condition : {0u,1u,2u}) {
        Device d; d.indexed();
        if (condition==0) d.pci.iteratorFail=true;
        if (condition==1) d.pci.iteratorInvalid=true;
        if (condition==2) d.pci.clients.clear();
        d.run("indexed-peer-refused"); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    {
        Device d; d.indexed(); d.pci.openBusy=true;
        d.run("indexed-provider-busy"); noIndexedWrites(); CHECK(testState.openCalls==1);
        CHECK(testState.closeCalls==0);
    }
    {
        Device d; d.indexed(); d.pci.inactive=true;
        d.run("indexed-provider-inactive"); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    {
        Device d; d.indexed(); IOService other;
        d.pci.onOpen=[&d,&other]() { d.pci.clients.push_back(&other); };
        d.run("indexed-peer-refused"); noIndexedWrites(); CHECK(testState.closeCalls==1);
    }
    for (unsigned condition : {0u,1u,2u,3u}) {
        Device d; d.indexed();
        d.pci.onOpen=[&d,condition]() {
            if (condition==0) d.pci.bars[5]+=4096;
            if (condition==1) d.mmio.length-=4096;
            if (condition==2) d.pci.inactive=true;
            if (condition==3) d.vram.physical+=4096;
        };
        d.run("pci-state-changed"); noIndexedWrites(); CHECK(testState.closeCalls==1);
    }
    {
        Device d; d.indexed(); testState.memsizeValues={16304,16304,8192};
        d.run("memsize-changed"); noIndexedWrites(); CHECK(testState.closeCalls==1);
    }
    {
        Device d; d.indexed(); testState.allocFail=true;
        d.run("snapshot-allocation-failed"); noIndexedWrites(); CHECK(testState.openCalls==0);
    }
    for (unsigned condition : {0u,1u,2u}) {
        Device d; d.indexed();
        if (condition==0) d.mmio.indexedMapFail=true;
        if (condition==1) d.mmio.indexedMapReadOnly=true;
        if (condition==2) d.mmio.onMap=[&d]() { if(d.mmio.requests==2) d.mmio.mapNullAddress=true; };
        d.run(condition==2 ? "indexed-map-invalid" : "indexed-map-failed");
        noIndexedWrites(); CHECK(testState.closeCalls==1);
    }
    {
        Device d; d.indexed(); testState.claimFail=true;
        d.run("indexed-claim-failed"); noIndexedWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,IndexedAttempt-v1"));
    }
    for (const auto *key : {"VRAMBytes", "DiscoveryOffset", "DiscoverySize", "Ready", "IndexedOwnership",
        "IndexedCleanup", "IndexedAttempted", "IndexedSelectorWritesIssued", "IndexedDataReads",
        "Schema", "ReadOnly", "AccessMode"}) {
        Device d; d.indexed(); testState.propertyFailKey=std::string("CobaltSurvey,")+key;
        // Ready's initial publication also fails: do not use Device::run's Ready assertion.
        CHECK(d.service.start(&d.pci)); CHECK(d.service.registered);
        CHECK(d.service.strings.at("CobaltSurvey,Status")=="indexed-metadata-publication-failed");
        noIndexedWrites(); CHECK(testState.mapsLive==0); CHECK(testState.openLive==0);
        CHECK(testState.allocations==0); CHECK(testState.backingDescriptorsLive==0);
    }
    for (unsigned condition : {0u,1u,2u}) {
        Device d; d.indexed();
        if (condition==0) d.mmio.selectorStorage[0]=UINT32_MAX;
        if (condition==1) d.mmio.selectorStorage[6]=UINT32_MAX;
        unsigned lowReads=0;
        if (condition==2) testState.selectorRead=[&lowReads](uint32_t off,uint32_t val) {
            return off==0 && ++lowReads==2 ? val^4u : val;
        };
        d.run("indexed-selectors-unreadable-or-unstable"); noIndexedWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,IndexedAttempt-v1"));
    }
}

static void indexedExactTransfer() {
    Device d; d.indexed();
    d.run("discovery-snapshot-validated"); restored(d);
    CHECK(testState.openCalls==1); CHECK(testState.closeCalls==1);
    CHECK(testState.indexedDataReads==5120); CHECK(testState.selectorWrites==5124);
    CHECK(d.service.numbers.at("CobaltSurvey,Schema")==2);
    CHECK(d.service.strings.at("CobaltSurvey,AccessMode")=="indexed-selector-writes");
    CHECK(d.service.numbers.at("CobaltSurvey,IndexedAttempted")==1);
    CHECK(d.service.numbers.at("CobaltSurvey,DiscoveryOffset")==0x3faff0000ULL);
    CHECK(d.service.numbers.at("CobaltSurvey,DiscoverySize")==10240);
    CHECK(d.service.blobs.at("CobaltSurvey,DiscoverySnapshot")==fixture());
    size_t at=0;
    const auto event=[&at](char op,uint32_t off,uint32_t value) {
        CHECK(at<testState.mmioEvents.size()); const auto &e=testState.mmioEvents[at++];
        CHECK(e.operation==op); CHECK(e.offset==off); CHECK(e.value==value);
    };
    for (unsigned n=0;n<2;++n) { event('r',0,0x12345678); event('r',0x18,2); }
    const auto expected=fixture();
    for (unsigned pass=0;pass<2;++pass) for(unsigned word=0;word<2560;++word) {
        const uint32_t low=0xfaff0000u+4*word;
        event('w',0,low); if(!word) event('w',0x18,7);
        event('r',0,low); event('r',0x18,7);
        uint32_t data=0; std::memcpy(&data,expected.data()+word*4,4); event('r',4,data);
    }
    event('w',0,0x12345678); event('w',0x18,2);
    event('r',0,0x12345678); event('r',0x18,2);
    CHECK(at==testState.mmioEvents.size());
    d.service.stop(&d.pci);
    CobaltNavi44Survey reloaded; d.pci.clients={&reloaded};
    CHECK(reloaded.start(&d.pci)); CHECK(reloaded.registered);
    CHECK(reloaded.strings.at("CobaltSurvey,Status")=="indexed-already-attempted");
    CHECK(testState.selectorWrites==5124); CHECK(testState.openLive==0);
    CHECK(reloaded.blobs.empty());
    // Same-instance restart in default mode clears stale indexed scope fields.
    testState.indexedBootPresent=false; d.pci.clients={&d.service};
    d.run("discovery-aperture-too-small");
    CHECK(d.service.numbers.at("CobaltSurvey,ReadOnly")==1);
    CHECK(d.service.numbers.at("CobaltSurvey,Schema")==1);
    CHECK(!d.service.numbers.count("CobaltSurvey,IndexedAttempted"));
    CHECK(!d.service.strings.count("CobaltSurvey,AccessMode"));
    CHECK(d.pci.getProperty("CobaltSurvey,IndexedAttempt-v1"));
}

static void indexedFaults() {
    for (uint32_t offset : {0u,0x18u}) {
        Device d; d.indexed(); bool mismatched=false;
        testState.selectorRead=[offset,&mismatched](uint32_t off,uint32_t value) {
            if (testState.selectorWrites && off==offset && !mismatched) { mismatched=true; return value^4u; }
            return value;
        };
        d.run("indexed-selector-readback-mismatch"); restored(d);
        CHECK(testState.indexedDataReads==0); CHECK(testState.selectorWrites==4);
    }
    for (uint32_t offset : {0u,0x18u}) {
        Device d; d.indexed(); bool restoring=false;
        testState.onMmio=[&restoring](const MmioEvent &e) {
            if(e.operation=='w' && e.offset==0 && e.value==0x12345678) restoring=true;
        };
        testState.selectorRead=[offset,&restoring](uint32_t off,uint32_t value) {
            return restoring && off==offset ? value^4u : value;
        };
        d.run("indexed-cleanup-unverified"); CHECK(testState.indexedDataReads==5120);
        CHECK(testState.selectorWrites==5124);
        CHECK(d.service.strings.at("CobaltSurvey,IndexedCleanup")=="restore-readback-mismatch");
    }
    {
        Device d; d.indexed();
        testState.dataRead=[](unsigned n,uint32_t value) { return n==2560 ? value^1u : value; };
        d.run("discovery-snapshot-unstable"); restored(d); CHECK(testState.indexedDataReads==5120);
    }
    {
        Device d; d.indexed(); testState.memsizeValues={16304,16304,16304,8192};
        d.run("memsize-changed"); restored(d); CHECK(testState.indexedDataReads==5120);
    }
    for (unsigned condition : {0u,1u,2u,3u,4u}) {
        Device d; d.indexed();
        testState.onMmio=[&d,condition](const MmioEvent &e) {
            if (e.operation!='r' || e.offset!=4 || testState.indexedDataReads!=17) return;
            if(condition==0) d.pci.identity=UINT32_MAX;
            if(condition==1) d.pci.bars[5]+=4096;
            if(condition==2) d.mmio.length-=4096;
            if(condition==3) d.pci.inactive=true;
            if(condition==4) d.vram.length-=4096;
        };
        d.run("indexed-cleanup-unverified"); CHECK(testState.indexedDataReads==17);
        CHECK(testState.selectorWrites==18);
        CHECK(d.service.strings.at("CobaltSurvey,IndexedCleanup")=="restore-skipped-device-changed");
    }
    {
        Device d; d.indexed(); testState.onMmio=[&d](const MmioEvent &e) {
            if(e.operation=='w' && testState.selectorWrites==1) d.pci.command=0;
        };
        d.run("indexed-cleanup-unverified"); CHECK(testState.selectorWrites==1);
        CHECK(testState.indexedDataReads==0);
    }
    {
        Device d; d.indexed(); testState.onMmio=[&d](const MmioEvent &e) {
            if(e.operation=='w' && e.offset==0 && e.value==0x12345678) d.pci.bars[5]+=4096;
        };
        d.run("indexed-cleanup-unverified"); CHECK(testState.selectorWrites==5123);
        CHECK(d.service.strings.at("CobaltSurvey,IndexedCleanup")=="restore-skipped-device-changed");
    }
    {
        Device d; d.indexed(); d.pci.onClose=[&d]() { d.pci.command=0; };
        d.run("pci-state-changed"); restored(d); CHECK(testState.indexedDataReads==5120);
    }
    {
        Device d; d.indexed(); IOService latePeer;
        testState.onMmio=[&d,&latePeer](const MmioEvent &e) {
            if(e.operation=='r' && e.offset==4 && testState.indexedDataReads==2560)
                d.pci.clients.push_back(&latePeer);
        };
        d.run("indexed-peer-refused"); restored(d); CHECK(testState.indexedDataReads==2560);
    }
    for (unsigned condition : {0u,1u,2u,3u,4u}) {
        Device d; d.indexed(); Bytes data=fixture();
        if(condition==0) data[prefix+8]^=1;
        if(condition==1) { data[die+4+6]^=1; repair(data); }
        if(condition==2) { put32(data,gc+12,8); repair(data); }
        if(condition==3) testState.dataFail=true;
        if(condition==4) testState.publicationFail=true;
        d.load(data);
        const char *statuses[]={"discovery-parser-invalid", "discovery-profile-mismatch",
            "discovery-topology-invalid", "snapshot-publication-allocation-failed", "snapshot-publication-failed"};
        d.run(statuses[condition]); restored(d); CHECK(testState.indexedDataReads==5120);
    }
    for (const auto *argument : {"1", "01", "0x1", "1 ", "1\t"}) {
        Device d; d.indexed(); testState.indexedBoot=argument;
        d.run("discovery-snapshot-validated"); restored(d);
    }
    for (uint32_t mib : {1024u,1025u,8192u,65536u}) {
        Device d; d.indexed(mib); d.run("discovery-snapshot-validated"); restored(d);
        CHECK(testState.indexedDataReads==5120);
        CHECK(d.service.numbers.at("CobaltSurvey,DiscoveryOffset")==testState.discoveryOffset);
    }
}

static void pciGuards() {
    {
        Device d; d.pci.command=0; d.run("memory-decoding-disabled"); CHECK(testState.mapRequests==0);
    }
    for (uint8_t header : {uint8_t(1),uint8_t(2),uint8_t(0xff)}) {
        Device d; d.pci.header=header; d.run("pci-header-class-invalid"); CHECK(testState.mapRequests==0);
    }
    for (uint32_t cls : {0x020000c0u,0x030100c0u,0x030001c0u,0xffffffc0u}) {
        Device d; d.pci.classRevision=cls; d.run("pci-header-class-invalid"); CHECK(testState.mapRequests==0);
    }
    for (uint32_t low : {0xc0000001u,0xc0000004u,0u,0xffffffffu}) {
        Device d; d.pci.bars[5]=low; d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.pci.memories[5]=nullptr; d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.mmio.physical+=4096; d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.mmio.length=0x3fff; d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.mmio.contiguous=4096; d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.pci.bars[4]=4; d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.pci.bars[5]=0xfffff000; d.mmio.physical=0xfffff000;
        d.run("bar5-invalid"); CHECK(testState.mapRequests==0);
    }
    {
        Device d; d.pci.header=0x80; d.pci.classRevision=0x038000c0;
        d.run("discovery-snapshot-validated");
    }
}

static void mappingFailures() {
    using Flag = bool IOMemoryDescriptor::*;
    struct Failure { Flag flag; const char *reason; };
    const Failure failures[] = {
        {&IOMemoryDescriptor::mapFail,"map-null"},
        {&IOMemoryDescriptor::mapTruncated,"map-length"},
        {&IOMemoryDescriptor::mapWrongPhysical,"map-physical"},
        {&IOMemoryDescriptor::mapWritable,"map-readonly"},
        {&IOMemoryDescriptor::mapCached,"map-cache"},
        {&IOMemoryDescriptor::mapWrongDescriptor,"descriptor-null"},
        {&IOMemoryDescriptor::mapFragmented,"map-segment"},
        {&IOMemoryDescriptor::mapDescriptorWrongLength,"descriptor-length"},
        {&IOMemoryDescriptor::mapDescriptorWrongPhysical,"descriptor-physical"},
        {&IOMemoryDescriptor::mapDescriptorFragmented,"descriptor-segment"},
        {&IOMemoryDescriptor::mapDescriptorWrongSegment,"descriptor-segment"},
        {&IOMemoryDescriptor::mapSegmentWrongPhysical,"map-segment"},
        {&IOMemoryDescriptor::sourceWrongSegment,"source-segment"},
        {&IOMemoryDescriptor::sourceFragmented,"source-segment"}
    };
    for (unsigned stage : {0u,1u}) {
        for (const auto &failure : failures) {
            Device d;
            auto &memory = stage==0 ? d.mmio : d.vram;
            memory.*failure.flag=true;
            d.run(stage==0 ? "memsize-map-failed" : "discovery-map-failed");
            CHECK(testState.memsizeReads==(stage==0 ? 0u : 2u));
            CHECK(d.service.strings.at("CobaltSurvey,MapStage")== (stage==0 ? "memsize" : "discovery"));
            CHECK(d.service.strings.at("CobaltSurvey,MapFailure")==failure.reason);
            CHECK(d.service.numbers.at("CobaltSurvey,MapRequestedOffset")==memory.expectedOffset);
            CHECK(d.service.numbers.at("CobaltSurvey,MapRequestedLength")==memory.expectedLength);
            CHECK(d.service.numbers.at("CobaltSurvey,MapRequestedOptions")==
                (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache));
            if (failure.flag==&IOMemoryDescriptor::mapFail) {
                CHECK(d.service.strings.at("CobaltSurvey,MapDescriptorIdentity")=="none");
                CHECK(d.service.numbers.at("CobaltSurvey,MapObservedLength")==0);
            } else if (failure.flag==&IOMemoryDescriptor::mapDescriptorWrongLength) {
                CHECK(d.service.strings.at("CobaltSurvey,MapDescriptorIdentity")=="replacement");
                CHECK(d.service.numbers.at("CobaltSurvey,MapDescriptorLength")==memory.expectedLength+1);
                CHECK(d.service.numbers.at("CobaltSurvey,MapDescriptorPhysical")==memory.physical+memory.expectedOffset);
            }
            if (stage==0) CHECK(d.vram.requests==0);
        }
    }
    {
        Device d; d.mmio.mapNullAddress=true; d.run("memsize-map-invalid"); CHECK(testState.memsizeReads==0);
        CHECK(d.service.strings.at("CobaltSurvey,MapFailure")=="map-address");
    }
    {
        Device d; d.vram.mapNullAddress=true; d.run("discovery-map-invalid"); CHECK(testState.memsizeReads==2);
        CHECK(d.service.strings.at("CobaltSurvey,MapFailure")=="map-address");
    }
    {
        Device d; d.mmio.mapOriginalDescriptor=d.vram.mapOriginalDescriptor=true;
        d.run("discovery-snapshot-validated"); CHECK(testState.backingDescriptorReleases==0);
    }
    {
        // The default fake follows XNU's unique physical clone, so this test
        // rejects the old map-descriptor == provider-descriptor assumption.
        Device d; d.run("discovery-snapshot-validated");
        CHECK(testState.backingDescriptorReleases==2);
        CHECK(d.service.strings.count("CobaltSurvey,MapFailure")==0);
    }
    {
        Device d; d.mmio.mapFail=true; d.run("memsize-map-failed");
        d.service.stop(&d.pci); d.mmio.mapFail=false;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.count("CobaltSurvey,MapFailure")==0);
        CHECK(d.service.strings.count("CobaltSurvey,MapStage")==0);
        CHECK(d.service.strings.count("CobaltSurvey,MapDescriptorIdentity")==0);
        CHECK(d.service.numbers.count("CobaltSurvey,MapRequestedLength")==0);
        CHECK(d.service.numbers.count("CobaltSurvey,MapObservedLength")==0);
        CHECK(d.service.numbers.count("CobaltSurvey,MapDescriptorLength")==0);
    }
}

static void memsizeGuards() {
    for (uint32_t value : {0u,0xffffffffu,512u,1023u,65537u,131072u}) {
        Device d; testState.memsizeValues={value,value};
        d.run("memsize-invalid-or-unstable"); CHECK(d.vram.requests==0);
    }
    {
        Device d; testState.memsizeValues={16384,8192};
        d.run("memsize-invalid-or-unstable"); CHECK(d.vram.requests==0);
    }
    for (uint32_t value : {1024u,1025u,1536u,2048u,4096u,8192u,12288u,16384u,32768u,65536u}) {
        Device d; testState.memsizeValues={value,value,value,value};
        d.vram.length=d.vram.contiguous=uint64_t(value)<<20;
        d.vram.expectedOffset=d.vram.length-65536;
        d.run("discovery-snapshot-validated"); CHECK(testState.memsizeReads==4);
        CHECK(d.service.numbers.at("CobaltSurvey,VRAMBytes")==uint64_t(value)<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,DiscoveryOffset")==d.vram.expectedOffset);
    }
    {
        // The device reports 16,304 MiB while its BAR exposes the nominal 16 GiB window.
        Device d; testState.memsizeValues={16304,16304,16304,16304};
        d.vram.expectedOffset=(uint64_t(16304)<<20)-65536;
        d.run("discovery-snapshot-validated"); CHECK(testState.memsizeReads==4);
        CHECK(d.service.numbers.at("CobaltSurvey,VRAMBytes")==uint64_t(16304)<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,DiscoveryOffset")==d.vram.expectedOffset);
    }
    {
        Device d; testState.memsizeValues={16384,16384,8192}; d.run("memsize-changed");
    }
    {
        Device d; testState.memsizeValues={16384,16384,16384,8192}; d.run("discovery-snapshot-unstable");
    }
}

static void apertureGuards() {
    {
        Device d; testState.memsizeValues={16304,16304};
        d.vram.length=d.vram.contiguous=256ULL<<20;
        d.run("discovery-aperture-too-small"); CHECK(d.vram.requests==0);
        CHECK(testState.memsizeReads==2); CHECK(testState.mapReleases==1);
        CHECK(d.service.numbers.at("CobaltSurvey,VRAMBytes")==uint64_t(16304)<<20);
    }
    for (uint32_t low : {0u,1u,8u,0xffffffffu}) {
        Device d; d.pci.bars[0]=low; d.run("bar0-invalid"); CHECK(d.vram.requests==0);
    }
    {
        Device d; d.vram.physical+=4096; d.run("bar0-invalid"); CHECK(d.vram.requests==0);
    }
    {
        Device d; d.pci.memories[0]=nullptr; d.run("bar0-invalid"); CHECK(d.vram.requests==0);
    }
    {
        Device d; d.vram.contiguous-=1; d.run("bar0-invalid"); CHECK(d.vram.requests==0);
    }
    {
        Device d; d.pci.bars[0]=0xffff000c; d.pci.bars[1]=0xffffffff;
        d.vram.physical=0xffffffffffff0000ULL;
        d.run("bar0-invalid"); CHECK(d.vram.requests==0);
    }
}

static void revalidation() {
    for (unsigned stage : {0u,1u}) {
        Device d;
        (stage==0 ? d.mmio : d.vram).onMap=[&d]() { d.pci.command=0; };
        d.run("pci-state-changed"); CHECK(testState.memsizeReads==(stage==0 ? 0u : 2u));
    }
    for (unsigned stage : {0u,1u,2u,3u}) {
        Device d;
        testState.onMemsize=[&d,stage](unsigned index) { if(index==stage) d.pci.bars[5]+=4096; };
        d.run("pci-state-changed");
        CHECK(testState.memsizeReads==stage+1);
    }
    {
        Device d; d.mmio.onMap=[&d]() { d.mmio.length-=4096; };
        d.run("pci-state-changed"); CHECK(testState.memsizeReads==0);
    }
    {
        Device d; d.vram.onMap=[&d]() { d.vram.physical+=4096; };
        d.run("discovery-map-failed"); CHECK(testState.memsizeReads==2);
    }
    {
        Device d; d.mmio.onMap=[&d]() { d.pci.identity=0xffffffff; };
        d.run("pci-state-changed"); CHECK(testState.memsizeReads==0);
    }
    for (unsigned stage : {0u,1u}) {
        Device d;
        (stage==0 ? d.mmio : d.vram).onAddress=[&d]() { d.pci.command=0; };
        d.run("pci-state-changed"); CHECK(testState.memsizeReads==(stage==0 ? 0u : 2u));
    }
}

static void parserAndPublication() {
    {
        Device d; Bytes b=fixture(); b[prefix+8]^=1; d.load(b); d.run("discovery-parser-invalid");
    }
    for (unsigned i=0; i<5; ++i) {
        Device d; Bytes b=fixture(); b[die+4+i*12+6]^=1; repair(b); d.load(b);
        d.run("discovery-profile-mismatch");
    }
    {
        Device d; Bytes b=fixture(); put32(b,gc+12,8); repair(b); d.load(b);
        d.run("discovery-topology-invalid");
    }
    {
        Device d; Bytes b=fixture(); put16(b,prefix+22,0); put16(b,prefix+8,sum(b,prefix+10,gc+gcSize));
        d.load(b); d.run("discovery-topology-invalid");
    }
    {
        Device d; testState.allocFail=true; d.run("snapshot-allocation-failed");
    }
    {
        Device d; testState.dataFail=true; d.run("snapshot-publication-allocation-failed");
    }
    {
        Device d; testState.publicationFail=true; d.run("snapshot-publication-failed");
    }
    {
        Device d; const auto beforeMMIO=d.mmio.storage, beforeVRAM=d.vram.storage;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.blobs.at("CobaltSurvey,DiscoverySnapshot")==fixture());
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==1);
        CHECK(d.service.strings.at("CobaltSurvey,Protocol")=="CobaltNavi44Survey");
        CHECK(d.service.numbers.at("CobaltSurvey,Revision")==0xc0);
        CHECK(d.service.numbers.at("CobaltSurvey,ComputeUnitCapacity")==32);
        CHECK(d.service.numbers.at("CobaltSurvey,DiscoveryIPCount")==5);
        CHECK(d.service.numbers.at("CobaltSurvey,BAR0Length")==16ULL<<30);
        CHECK(d.mmio.storage==beforeMMIO); CHECK(d.vram.storage==beforeVRAM);
        CHECK(testState.mapRequests==2); CHECK(testState.mapReleases==2);
        const unsigned configReads=d.pci.identityReads+d.pci.otherReads;
        d.service.stop(&d.pci);
        CHECK(d.service.strings.at("CobaltSurvey,Status")=="stopped");
        CHECK(d.service.blobs.empty()); CHECK(d.service.stopCalls==1);
        CHECK(d.pci.identityReads+d.pci.otherReads==configReads);
        CHECK(testState.mapRequests==2); CHECK(testState.mapsLive==0);
    }
}

static void passiveState() {
    {
        const Bytes state=stateFixture(); IpDiscovery verify;
        if(!verify.init(state.data(),state.size())) throw std::runtime_error("synthetic state fixture did not parse");
        Device d; d.load(state); testState.stateBootPresent=true;
        d.run("discovery-snapshot-validated");
        CHECK(testState.stateReads==8); CHECK(testState.stateEvents.size()==8);
        const uint32_t expected[] = {0x458c,0x4644,0xa950,0xa954,0x458c,0x4644,0xa950,0xa954};
        for(unsigned i=0;i<8;++i) CHECK(testState.stateEvents[i].first==expected[i]);
        CHECK(testState.stateMapRequests.size()==2);
        CHECK(testState.stateMapRequests[0].first==0x4000);
        CHECK(testState.stateMapRequests[1].first==0xa000);
        for(const auto &request : testState.stateMapRequests)
            CHECK(request.second==(kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache));
        CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="observed-stable");
        CHECK(d.service.numbers.at("CobaltSurvey,StatePspBootloaderRaw")==0x11);
        CHECK(d.service.numbers.at("CobaltSurvey,StatePspSosRaw")==0x22);
        CHECK(d.service.numbers.at("CobaltSurvey,StateFbBaseRaw")==0x33);
        CHECK(d.service.numbers.at("CobaltSurvey,StateFbTopRaw")==0x44);
        CHECK(d.service.numbers.at("CobaltSurvey,StatePspBootloaderByteOffset")==0x458c);
        CHECK(d.service.numbers.at("CobaltSurvey,StateFbBaseByteOffset")==0xa950);
        CHECK(d.service.numbers.at("CobaltSurvey,StateReadCount")==8);
        CHECK(d.service.numbers.at("CobaltSurvey,StateReadOnly")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,ReadOnly")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready")==0);
        CHECK(testState.selectorWrites==0); CHECK(testState.openCalls==0);
        d.service.stop(&d.pci);
        CHECK(!d.service.strings.count("CobaltSurvey,StateStatus"));
        CHECK(!d.service.numbers.count("CobaltSurvey,StatePspBootloaderRaw"));
        testState.stateBootPresent=false;
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,StateStatus"));
        CHECK(!d.service.numbers.count("CobaltSurvey,StateReadCount"));
    }
    {
        Device d; d.load(stateFixture(0x2800)); testState.stateBootPresent=true;
        testState.stateAllowedOffsets={0x458c,0x4644,0xb550,0xb554};
        d.run("discovery-snapshot-validated");
        CHECK(testState.stateReads==8);
        CHECK(testState.stateMapRequests[0].first==0x4000);
        CHECK(testState.stateMapRequests[1].first==0xb000);
        CHECK(d.service.numbers.at("CobaltSurvey,StateFbBaseByteOffset")==0xb550);
    }
    for(const auto *arg : {"", "0", "2", "49", "-1", "1x", "true"}) {
        Device d; d.load(stateFixture()); testState.stateBootPresent=true; testState.stateBoot=arg;
        d.run("discovery-snapshot-validated"); CHECK(testState.stateReads==0);
        CHECK(testState.stateMapRequests.empty()); CHECK(!d.service.numbers.count("CobaltSurvey,StateReadCount"));
    }
    for(unsigned failure=0;failure<9;++failure) {
        Device d; Bytes b=failure==6 ? duplicateStateFixture() : stateFixture();
        if(failure==0) { put16(b,die+2,5); put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12)); put16(b,prefix+8,sum(b,prefix+10,gc+gcSize+12)); }
        if(failure==1) { b[die+4+5*12+4]=5; put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12)); put16(b,prefix+8,sum(b,prefix+10,gc+gcSize+12)); }
        if(failure==2) {
            put32(b,die+4+5*12+8,0xfffffff0u);
            put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12));
            put16(b,prefix+8,sum(b,prefix+10,gc+gcSize+12));
        }
        if(failure==5) { b[die+4+5*12+2]=1; put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12)); put16(b,prefix+8,sum(b,prefix+10,gc+gcSize+12)); }
        if(failure==7) { put32(b,die+4+5*12+8,0x100000u); put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12)); put16(b,prefix+8,sum(b,prefix+10,gc+gcSize+12)); }
        if(failure==8) { b[die+4+5*12+3]=0; put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+12)); put16(b,prefix+8,sum(b,prefix+10,gc+gcSize+12)); }
        d.load(b); testState.stateBootPresent=true;
        if(failure==3) testState.stateRead=[](uint32_t offset,uint32_t value) { return offset==0x458c ? UINT32_MAX : value; };
        if(failure==4) testState.stateRead=[](uint32_t offset,uint32_t value) { return offset==0xa950 && testState.stateReads==2 ? value^1u : value; };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.blobs.count("CobaltSurvey,DiscoverySnapshot")==1);
        if(failure==0 || failure==1 || failure==2 || failure==5 || failure==6 || failure==7 || failure==8)
            CHECK(testState.stateMapRequests.empty());
        CHECK(!d.service.numbers.count("CobaltSurvey,StatePspBootloaderRaw"));
        CHECK(testState.selectorWrites==0); CHECK(testState.openCalls==0);
    }
    for(unsigned releaseAt : {1u,4u}) {
        Device d; d.load(stateFixture()); testState.stateBootPresent=true;
        testState.onMapRelease=[&d,releaseAt](unsigned released) {
            if(released==releaseAt) d.pci.command=0;
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="pci-state-changed");
        CHECK(!d.service.numbers.count("CobaltSurvey,StatePspBootloaderRaw"));
        CHECK(testState.stateReads==8);
    }
    {
        Device d; d.load(stateFixture()); testState.stateBootPresent=true;
        testState.onDiscoverySnapshotPublication=[&d]() { d.pci.command=0; };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="pci-state-changed");
        CHECK(!d.service.numbers.count("CobaltSurvey,StatePspBootloaderRaw"));
        CHECK(testState.stateReads==8);
    }
    for(unsigned change : {0u,1u,2u}) {
        Device d; d.load(stateFixture()); testState.stateBootPresent=true;
        testState.stateRead=[&d,change](uint32_t, uint32_t value) {
            if(testState.stateReads==3) {
                if(change==0) d.pci.command=0;
                if(change==1) d.pci.bars[5]+=4096;
                if(change==2) d.pci.inactive=true;
            }
            return value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.stateReads==4);
        CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="pci-state-changed");
        CHECK(!d.service.numbers.count("CobaltSurvey,StatePspBootloaderRaw"));
    }
    {
        Device d; d.load(stateFixture()); d.indexed(); testState.stateBootPresent=true;
        d.run("discovery-snapshot-validated");
        CHECK(testState.stateReads==8); CHECK(testState.openCalls==1);
        CHECK(testState.selectorWrites==5124);
        CHECK(d.service.numbers.at("CobaltSurvey,ReadOnly")==0);
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==3);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready")==0);
    }
    {
        Device d; d.load(stateFixture()); testState.stateBootPresent=true;
        testState.failMapRequest=3;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="state-map-failed");
        CHECK(testState.stateReads==0); CHECK(!d.service.numbers.count("CobaltSurvey,StateReadCount"));
    }
    for(const char *key : {"StatePspBootloaderRaw", "StatePspSosRaw", "StateFbBaseRaw", "StateFbTopRaw",
        "StatePspBootloaderByteOffset", "StatePspSosByteOffset", "StateFbBaseByteOffset", "StateFbTopByteOffset",
        "StateReadCount", "StateReadOnly", "StateStatus"}) {
        Device d; d.load(stateFixture()); testState.stateBootPresent=true;
        testState.propertyFailKey=std::string("CobaltSurvey,")+key;
        d.run("discovery-snapshot-validated");
        if(std::string(key)=="StateStatus") CHECK(!d.service.strings.count("CobaltSurvey,StateStatus"));
        else CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="metadata-publication-failed");
        for(const char *raw : {"StatePspBootloaderRaw", "StatePspSosRaw", "StateFbBaseRaw", "StateFbTopRaw"})
            CHECK(!d.service.numbers.count(std::string("CobaltSurvey,")+raw));
    }
}

static void consoleFixture(Device &d) {
    d.load(stateFixture()); testState.stateBootPresent=true; testState.platformAvailable=true;
    testState.console.v_baseAddr=(d.vram.physical+(2ULL<<20))|1ULL;
    testState.console.v_rowBytes=4096; testState.console.v_width=1024;
    testState.console.v_height=768; testState.console.v_depth=32;
    testState.console.v_display=1; testState.console.v_scale=1;
}
static void noConsoleRaw(const Device &d) {
    CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleBaseRaw"));
    CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleReadCount"));
    CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleVramOffset"));
    CHECK(!d.service.strings.count("CobaltSurvey,ConsoleRangeStatus"));
    CHECK(d.service.numbers.at("CobaltSurvey,Schema")==3);
    CHECK(d.service.strings.at("CobaltSurvey,StateStatus")=="observed-stable");
}
static void passiveConsoleTests() {
    // XNU's live-console address is virtual unless its physical tag is set.
    // An address resembling BAR0 is insufficient evidence without that tag.
    for(uint64_t raw : {0x1000200000ULL,0xffff800000200000ULL,0x1000200002ULL}) {
        Device d; consoleFixture(d); testState.console.v_baseAddr=raw;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleRangeStatus")=="base-not-tagged-physical");
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleBaseRaw")==raw);
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleVramOffset"));
        CHECK(testState.stateReads==8); CHECK(testState.consoleCalls==2);
    }
    for(uint64_t tag : {1ULL,3ULL}) {
        Device d; consoleFixture(d);
        testState.console.v_baseAddr=(d.vram.physical+(2ULL<<20))|tag;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleRangeStatus")=="inside-bar0-observed");
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleVramOffset")==2ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleBaseRaw")==testState.console.v_baseAddr);
    }
    {
        // Regression for a physical-tagged boot display at the start of a
        // small BAR0; evaluates the observed geometry without touching a GPU.
        Device d; consoleFixture(d); d.indexed();
        d.vram.physical=0x830000000ULL; d.pci.bars[0]=0x3000000c; d.pci.bars[1]=8;
        auto &v=testState.console;
        v.v_baseAddr=0x830000001ULL; v.v_rowBytes=13824; v.v_width=3440;
        v.v_height=1440; v.v_depth=32; v.v_scale=2;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleBaseRaw")==0x830000001ULL);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleVramOffset")==0);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleSpanBytes")==19906560);
        CHECK(testState.stateReads==8); CHECK(testState.consoleCalls==2);
        CHECK(testState.selectorWrites==5124); CHECK(testState.mapRequests==4);
    }
    {
        Device d; consoleFixture(d); d.run("discovery-snapshot-validated");
        CHECK(testState.platformCalls==1); CHECK(testState.consoleCalls==2);
        CHECK(testState.stateReads==8); CHECK(testState.mapRequests==4);
        CHECK(testState.selectorWrites==0); CHECK(testState.openCalls==0);
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleBaseRaw")==((d.vram.physical+(2ULL<<20))|1ULL));
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleBaseRaw")>UINT32_MAX);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleRowBytes")==4096);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleWidth")==1024);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleHeight")==768);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleDepth")==32);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleDisplay")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleOffsetRaw")==0);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleLengthRaw")==0);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleRotate")==0);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleScale")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleReadCount")==2);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleReadOnly")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleVramOffset")==2ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleSpanBytes")==4096*768);
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")=="observed-stable");
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleRangeStatus")=="inside-bar0-observed");
        d.service.stop(&d.pci);
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleBaseRaw"));
        CHECK(!d.service.strings.count("CobaltSurvey,ConsoleStatus"));
        testState.stateBootPresent=false;
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleReadCount"));
        CHECK(!d.service.strings.count("CobaltSurvey,ConsoleRangeStatus"));
        CHECK(testState.consoleCalls==2);
    }
    for(const char *arg : {"0", "2", "true"}) {
        Device d; consoleFixture(d); testState.stateBoot=arg;
        d.run("discovery-snapshot-validated");
        CHECK(testState.platformCalls==0); CHECK(testState.consoleCalls==0);
    }
    {
        Device d; consoleFixture(d); testState.stateBootPresent=false;
        d.run("discovery-snapshot-validated");
        CHECK(testState.platformCalls==0); CHECK(testState.consoleCalls==0);
    }
    for(unsigned kind=0;kind<3;++kind) {
        Device d; consoleFixture(d);
        if(kind==0) testState.platformAvailable=false;
        if(kind==1) testState.consoleResult=-1;
        if(kind==2) testState.onConsole=[](unsigned call, PE_Video &) { if(call==2) testState.consoleResult=-1; };
        d.run("discovery-snapshot-validated"); noConsoleRaw(d);
        CHECK(testState.consoleCalls==(kind==0?0u:kind==1?1u:2u));
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")==
            (kind==0?"platform-unavailable":"console-api-failed"));
    }
    for(unsigned scalar=0;scalar<10;++scalar) {
        Device d; consoleFixture(d);
        testState.onConsole=[scalar](unsigned call, PE_Video &v) {
            if(call!=2) return;
            switch(scalar) {
            case 0: ++v.v_baseAddr; break; case 1: ++v.v_rowBytes; break;
            case 2: ++v.v_width; break; case 3: ++v.v_height; break;
            case 4: ++v.v_depth; break; case 5: ++v.v_display; break;
            case 6: ++v.v_offset; break; case 7: ++v.v_length; break;
            case 8: ++v.v_rotate; break; case 9: ++v.v_scale; break;
            }
        };
        d.run("discovery-snapshot-validated"); noConsoleRaw(d);
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")=="console-unstable");
        CHECK(testState.consoleCalls==2);
    }
    // Padding/non-scalar metadata cannot spuriously change the observation.
    {
        Device d; consoleFixture(d);
        testState.onConsole=[](unsigned call, PE_Video &v) { v.v_pixelFormat[0]=char(call); };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
    }
    const char *rangeFailures[] = {"base-unaligned-or-zero", "base-unaligned-or-zero",
        "offset-unsupported", "rotation-unsupported", "geometry-invalid", "geometry-invalid",
        "geometry-invalid", "geometry-invalid", "geometry-invalid", "geometry-invalid",
        "span-overflow", "span-overflow", "length-too-small", "outside-bar0", "outside-bar0", "outside-bar0"};
    for(unsigned kind=0;kind<16;++kind) {
        Device d; consoleFixture(d); auto &v=testState.console;
        if(kind==0) v.v_baseAddr|=4;
        if(kind==1) v.v_baseAddr=0;
        if(kind==2) v.v_offset=4096;
        if(kind==3) v.v_rotate=1;
        if(kind==4) v.v_width=0;
        if(kind==5) v.v_height=0;
        if(kind==6) v.v_rowBytes=0;
        if(kind==7) v.v_depth=65;
        if(kind==8) v.v_width=UINT64_MAX;
        if(kind==9) v.v_rowBytes=UINT64_MAX;
        if(kind==10) { v.v_rowBytes=1ULL<<40; v.v_width=1; v.v_height=1ULL<<40; }
        if(kind==11) v.v_baseAddr=(UINT64_MAX&~0xfffULL)|1ULL;
        if(kind==12) v.v_length=1;
        if(kind==13) v.v_baseAddr=(d.vram.physical-4096)|1ULL;
        if(kind==14) v.v_baseAddr=(d.vram.physical+d.vram.length)|1ULL;
        if(kind==15) v.v_length=d.vram.length;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleRangeStatus")==rangeFailures[kind]);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleBaseRaw")==v.v_baseAddr);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleOffsetRaw")==v.v_offset);
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleLengthRaw")==v.v_length);
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleVramOffset"));
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleSpanBytes"));
        CHECK(testState.stateReads==8); CHECK(testState.mapRequests==4);
    }
    for(uint64_t display : {0ULL,2ULL,UINT64_MAX}) {
        Device d; consoleFixture(d); testState.console.v_display=display;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleRangeStatus")=="display-mode-unsupported");
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleDisplay")==display);
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleVramOffset"));
    }
    for(unsigned extra=0;extra<2;++extra) {
        Device d; consoleFixture(d); auto &v=testState.console;
        v.v_baseAddr=(d.vram.physical+d.vram.length-4096*768)|1ULL;
        v.v_length=4096*768+extra;
        d.run("discovery-snapshot-validated");
        if(extra) CHECK(d.service.strings.at("CobaltSurvey,ConsoleRangeStatus")=="outside-bar0");
        else CHECK(d.service.numbers.at("CobaltSurvey,ConsoleSpanBytes")==v.v_length);
    }
    {
        Device d; consoleFixture(d); testState.console.v_length=4ULL<<20;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.numbers.at("CobaltSurvey,ConsoleSpanBytes")==4ULL<<20);
    }
    for(unsigned kind=0;kind<4;++kind) for(unsigned at : {1u,2u}) {
        Device d; consoleFixture(d);
        testState.onConsole=[&d,kind,at](unsigned call, PE_Video &) {
            if(call!=at) return;
            if(kind==0) d.pci.command=0;
            if(kind==1) d.pci.bars[0]+=4096;
            if(kind==2) d.vram.physical+=4096;
            if(kind==3) d.pci.inactive=true;
        };
        d.run("discovery-snapshot-validated"); noConsoleRaw(d);
        CHECK(testState.consoleCalls==at);
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")=="pci-state-changed");
    }
    for(const char *key : {"ConsoleBaseRaw", "ConsoleRowBytes", "ConsoleWidth", "ConsoleHeight",
        "ConsoleDepth", "ConsoleDisplay", "ConsoleOffsetRaw", "ConsoleLengthRaw", "ConsoleRotate", "ConsoleScale",
        "ConsoleReadCount", "ConsoleReadOnly", "ConsoleRangeStatus", "ConsoleStatus", "ConsoleVramOffset", "ConsoleSpanBytes"}) {
        Device d; consoleFixture(d); testState.propertyFailKey=std::string("CobaltSurvey,")+key;
        d.run("discovery-snapshot-validated"); noConsoleRaw(d);
        if(std::string(key)=="ConsoleStatus") CHECK(!d.service.strings.count("CobaltSurvey,ConsoleStatus"));
        else CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")=="metadata-publication-failed");
    }
    {
        Device d; consoleFixture(d); testState.failConsoleSchema=true;
        d.run("discovery-snapshot-validated"); noConsoleRaw(d);
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")=="metadata-publication-failed");
    }
    for(const char *key : {"ConsoleBaseRaw", "ConsoleStatus"}) {
        Device d; consoleFixture(d);
        testState.onConsolePublication=[&d,key](const std::string &name) {
            if(name==std::string("CobaltSurvey,")+key) d.pci.command=0;
        };
        d.run("discovery-snapshot-validated"); noConsoleRaw(d);
        CHECK(d.service.strings.at("CobaltSurvey,ConsoleStatus")=="pci-state-changed");
    }
    {
        Device d; consoleFixture(d); d.indexed(); d.run("discovery-snapshot-validated");
        CHECK(testState.consoleCalls==2); CHECK(testState.stateReads==8);
        CHECK(testState.selectorWrites==5124); CHECK(testState.mapRequests==4);
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(d.service.numbers.at("CobaltSurvey,ReadOnly")==0);
        // Restart without stop must also remove every previous console property.
        testState.stateBootPresent=false; testState.indexedBootPresent=false;
        d.vram.length=d.vram.contiguous=16ULL<<30; d.mmio.storage[0x78c/4]=16384;
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.numbers.count("CobaltSurvey,ConsoleBaseRaw"));
        CHECK(!d.service.strings.count("CobaltSurvey,ConsoleStatus"));
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==1);
    }
}

static Bytes apertureFixture(uint32_t nbifSegmentBase=0xd20) {
    Bytes b=stateFixture();
    const size_t oldGc=gc+12;
    b.insert(b.begin()+static_cast<std::ptrdiff_t>(oldGc),32,0);
    const size_t nbif=die+4+6*12, hdp=nbif+20, shiftedGc=oldGc+32;
    put16(b,nbif,108); b[nbif+3]=3; b[nbif+4]=6; b[nbif+5]=3; b[nbif+6]=1;
    put32(b,nbif+8,0x1000); put32(b,nbif+12,0x2000); put32(b,nbif+16,nbifSegmentBase);
    put16(b,hdp,41); b[hdp+3]=1; b[hdp+4]=7; put32(b,hdp+8,0x1000);
    put16(b,prefix+10,uint16_t(shiftedGc+gcSize-prefix));
    put16(b,prefix+16,uint16_t(ipdsSize+44)); put16(b,prefix+20,uint16_t(shiftedGc-prefix));
    put16(b,ipds+6,uint16_t(ipdsSize+44)); put16(b,die+2,8);
    put16(b,prefix+14,sum(b,ipds,ipds+ipdsSize+44));
    put16(b,prefix+22,sum(b,shiftedGc,shiftedGc+gcSize));
    put16(b,prefix+8,sum(b,prefix+10,shiftedGc+gcSize)); b.resize(10240);
    return b;
}
static Bytes kdbDiscoveryFixture() {
    Bytes b = apertureFixture();
    const size_t dmu = die + 4 + 4 * 12;
    // The existing synthetic DMU entry has one base. KDB proof requires the
    // real segment-2 register base, so insert two additional base dwords.
    b[dmu + 3] = 3;
    b.insert(b.begin() + static_cast<std::ptrdiff_t>(dmu + 12), 8, 0);
    put32(b, dmu + 12, 0x1600); put32(b, dmu + 16, 0x1700);
    const size_t shiftedGc = gc + 52;
    put16(b, prefix + 10, uint16_t(shiftedGc + gcSize - prefix));
    put16(b, prefix + 16, uint16_t(ipdsSize + 52));
    put16(b, prefix + 20, uint16_t(shiftedGc - prefix));
    put16(b, ipds + 6, uint16_t(ipdsSize + 52));
    put16(b, prefix + 14, sum(b, ipds, ipds + ipdsSize + 52));
    put16(b, prefix + 22, sum(b, shiftedGc, shiftedGc + gcSize));
    put16(b, prefix + 8, sum(b, prefix + 10, shiftedGc + gcSize));
    b.resize(10240);
    return b;
}
static void apertureDevice(Device &d, bool nativeRoute=false, uint32_t nbifSegmentBase=0xd20) {
    consoleFixture(d); d.load(apertureFixture(nbifSegmentBase)); d.indexed();
    d.mmio.length=d.mmio.contiguous=0x80000; d.pci.subsystem=0x86011eae;
    testState.apertureNbifSegmentBase=nbifSegmentBase;
    testState.apertureNativeRoute=nativeRoute;
    if(nativeRoute) {
        testState.apertureRemap=(nbifSegmentBase+0xf7)*4;
    }
    testState.apertureBootPresent=true;
    testState.stateRead=[](uint32_t offset,uint32_t) {
        if(offset==0x458c) return 0x80000000u;
        if(offset==0x4644) return 0u;
        if(offset==0xa950) return 0x8000u;
        if(offset==0xa954) return 0x83fbu;
        throw std::runtime_error("unexpected aperture state offset");
    };
}
static void kdbDevice(Device &d, bool nativeRoute=false) {
    apertureDevice(d, nativeRoute);
    d.load(kdbDiscoveryFixture());
    testState.kdbBootPresent = true;
    testState.kdbBoot = "1";
    testState.stagingBootPresent = true;
    testState.stagingBoot = "1";
    testState.kdbAddressByteOffset = 0x4590;
    testState.kdbCommandByteOffset = 0x458c;
    testState.kdbStateOffsets = {0x458c, 0x4644, 0xa950, 0xa954, 0xa71c, 0x6dd4};
    testState.stateRead = [](uint32_t offset, uint32_t) {
        if (offset == 0x458c) return 0x80000000u;
        if (offset == 0x4644) return 0u;
        if (offset == 0xa950 || offset == 0x6dd4) return 0x8000u;
        if (offset == 0xa954) return 0x83fbu;
        if (offset == 0xa71c) return 0x1234u;
        throw std::runtime_error("unexpected KDB state offset");
    };
}
static void preSosDevice(Device &d, bool nativeRoute) {
    kdbDevice(d, nativeRoute);
    testState.preSosCpu.assign(7, std::vector<uint32_t>(262144, 0x31415926));
    testState.preSosGpu.assign(7, std::vector<uint32_t>(262144, 0x31415926));
    testState.splBootPresent = true; testState.splBoot = "1";
    testState.preSosBootPresent = true; testState.preSosBoot = "1";
    testState.preSosClaimFail = false;
}
static void noKdbWrites() {
    CHECK(testState.kdbWrites == 0);
    CHECK(testState.apertureCpuWrites == 0);
    CHECK(testState.apertureFlushWrites == 0);
}
static void kdbTests() {
    for (bool nativeRoute : {false, true}) {
        Device d; kdbDevice(d, nativeRoute);
        bool rejectedWrongEndpoint = false;
        testState.onKdb = [&rejectedWrongEndpoint](const TestState::KdbEvent &event) {
            try {
                cobaltSurveyTestKdbWrite32(testState.apertureCpu.data(), event.value, event.offset);
            } catch (const std::runtime_error &) {
                rejectedWrongEndpoint = true;
            }
        };
        try { d.run("discovery-snapshot-validated"); }
        catch (const std::exception &e) {
            throw std::runtime_error(std::string("KDB service run failed: ") + e.what() +
                " mailbox=" + std::to_string(testState.kdbWrites) +
                " cpuWrites=" + std::to_string(testState.apertureCpuWrites) +
                " selectorWrites=" + std::to_string(testState.selectorWrites) +
                " maps=" + std::to_string(testState.mapsLive) +
                " open=" + std::to_string(testState.openLive));
        }
        if (!d.service.strings.count("CobaltSurvey,KdbStatus")) {
            std::string detail = "KDB telemetry absent; status=" + d.service.strings["CobaltSurvey,Status"] +
                " state=" + d.service.strings["CobaltSurvey,StateStatus"] + " kdbEnabled=" +
                std::to_string(testState.kdbEnabled) + " stateReads=" + std::to_string(testState.stateReads) +
                " kdbWrites=" + std::to_string(testState.kdbWrites) + " strings:";
            for (const auto &entry : d.service.strings) detail += " " + entry.first;
            throw std::runtime_error(detail);
        }
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "kdb-ready-observed-reset-required");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema") == 7);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbAddressAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbCommandAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbReadyObserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbStagingPreserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbZeroVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbCopyVerified") == 1);
        CHECK(testState.kdbEvents.size() == 2);
        CHECK(testState.kdbEvents[0].offset == testState.kdbAddressByteOffset);
        CHECK(testState.kdbEvents[0].value == d.service.numbers.at("CobaltSurvey,KdbMcAddress") >> 20);
        CHECK(testState.kdbEvents[1].offset == testState.kdbCommandByteOffset);
        CHECK(testState.kdbEvents[1].value == 0x80000);
        CHECK(rejectedWrongEndpoint);
        CHECK(testState.apertureCpuWrites == (1u << 18) + (6816u / 4));
        const auto fw = cobalt::survey::psp1402Firmware();
        CHECK(fw.data && fw.size > 256 + 6816);
        uint32_t payloadFirst = 0, payloadLast = 0;
        std::memcpy(&payloadFirst, fw.data + 256, sizeof(payloadFirst));
        std::memcpy(&payloadLast, fw.data + 256 + 6812, sizeof(payloadLast));
        CHECK(testState.apertureGpu[0] == payloadFirst);
        CHECK(testState.apertureGpu[6816 / 4 - 1] == payloadLast);
        CHECK(testState.apertureGpu[6816 / 4] == 0);
        CHECK(d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        CHECK(testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
        CHECK(testState.openLive == 0 && testState.allocations == 0);
        CHECK(testState.closeCalls == testState.openCalls);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbCommandWritesIssued") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbAddressWritesIssued") == 1);
        const auto writes = testState.apertureCpuWrites;
        d.service.stop(&d.pci);
        CobaltNavi44Survey replay; d.pci.clients = {&replay};
        CHECK(replay.start(&d.pci));
        CHECK(replay.strings.at("CobaltSurvey,Status") == "indexed-already-attempted");
        CHECK(testState.kdbWrites == 2 && testState.apertureCpuWrites == writes);
    }
    {
        Device d; kdbDevice(d); testState.boot = "0";
        CobaltNavi44Survey direct; d.pci.clients = {&direct};
        CHECK(!direct.start(&d.pci));
        noKdbWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
    }
    for (unsigned missing = 1; missing < 5; ++missing) {
        Device d; kdbDevice(d);
        if (missing == 1) testState.indexedBoot = "0";
        if (missing == 2) testState.stateBoot = "0";
        if (missing == 3) testState.apertureBoot = "0";
        if (missing == 4) testState.stagingBoot = "0";
        d.run(missing == 1 ? "discovery-aperture-too-small" : "discovery-snapshot-validated"); noKdbWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        CHECK(!d.service.numbers.count("CobaltSurvey,KdbCommandAttempted") ||
            d.service.numbers.at("CobaltSurvey,KdbCommandAttempted") == 0);
    }
    {
        Device d; kdbDevice(d); testState.kdbBoot = "0";
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,KdbStatus"));
        CHECK(d.service.strings.at("CobaltSurvey,StagingStatus") == "synthetic-zero-copy-and-restore-verified");
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        CHECK(testState.kdbWrites == 0);
    }
    {
        Device d; kdbDevice(d);
        Bytes malformed = syntheticPspFirmware();
        put32(malformed, 40, 0xdeadbeefu);
        firmwareOverride = {malformed.data(), malformed.size()};
        d.run("discovery-snapshot-validated");
        firmwareOverride = {};
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "firmware-package-invalid");
        CHECK(!d.service.numbers.at("CobaltSurvey,KdbAttempted"));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        noKdbWrites();
    }
    {
        Device d; kdbDevice(d); d.pci.numbers["CobaltSurvey,KdbAttempt-v1"] = 1;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "already-attempted");
        noKdbWrites();
    }
    for (unsigned failAt = 1; failAt <= 2; ++failAt) {
        Device d; kdbDevice(d);
        testState.onKdb = [&d, failAt](const TestState::KdbEvent &event) {
            if (testState.kdbWrites == failAt) d.pci.command = 0;
            (void)event;
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.kdbWrites == failAt);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbStagingPreserved") == (failAt == 2 ? 1u : 0u));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbRestoreBytesIssued") == 0);
        CHECK(testState.apertureCpuWrites == (1u << 18) + 6816u / 4);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbCommandWritesIssued") == (failAt == 2 ? 1u : 0u));
        CHECK(testState.openLive == 0 && testState.mapsLive == 0 && testState.allocations == 0);
    }
    {
        Device d; kdbDevice(d); bool armed = false, transientBad = false;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &armed, &transientBad](uint32_t offset, uint32_t observed) {
            const uint32_t actual = read(offset, observed);
            if (armed && !transientBad && offset == 0x4644) {
                transientBad = true; return 1u;
            }
            return actual;
        };
        testState.onAperture = [&armed](const MmioEvent &event) {
            if (!armed && event.operation == 'v' && testState.apertureCpuWrites == 1024) armed = true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(transientBad);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbContextLost") == 1);
        CHECK(testState.kdbWrites == 0);
        CHECK(testState.apertureCpuWrites == 1024);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbResetRequired") == 1);
    }
    {
        Device d; kdbDevice(d); bool commandIssued = false; unsigned postCommandReads = 0;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &commandIssued, &postCommandReads](uint32_t offset, uint32_t observed) {
            if (offset == 0x458c && commandIssued) {
                ++postCommandReads;
                return postCommandReads < 30 ? 0u : 0x80000000u;
            }
            return read(offset, observed);
        };
        testState.onKdb = [&commandIssued](const TestState::KdbEvent &event) {
            if (event.offset == testState.kdbCommandByteOffset) commandIssued = true;
        };
        d.run("discovery-snapshot-validated");
        if (postCommandReads < 3 || testState.sleepCalls < 1)
            throw std::runtime_error("KDB busy-ready transition missing reads=" + std::to_string(postCommandReads) +
                " sleeps=" + std::to_string(testState.sleepCalls) + " status=" + d.service.strings["CobaltSurvey,KdbStatus"]);
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "kdb-ready-observed-reset-required");
        CHECK(d.service.numbers.at("CobaltSurvey,KdbReadyObserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbCommandWritesIssued") == 1);
    }
    {
        Device d; kdbDevice(d); bool commandIssued = false; unsigned postCommandReads = 0;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &commandIssued, &postCommandReads](uint32_t offset, uint32_t observed) {
            if (offset == 0x458c && commandIssued) { ++postCommandReads; return 0u; }
            return read(offset, observed);
        };
        testState.onKdb = [&commandIssued](const TestState::KdbEvent &event) {
            if (event.offset == testState.kdbCommandByteOffset) commandIssued = true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(postCommandReads >= 10000 && testState.sleepCalls == 10000);
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "kdb-protocol-failed");
        CHECK(d.service.numbers.at("CobaltSurvey,KdbResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbStagingPreserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbRestoreBytesIssued") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbCommandWritesIssued") == 1);
        CHECK(testState.kdbWrites == 2);
        CHECK(testState.apertureCpuWrites == (1u << 18) + 6816u / 4);
    }
    for (const bool failFallback : {false, true}) {
        Device d; kdbDevice(d);
        testState.propertyFailKey = "CobaltSurvey,KdbFlushRoute";
        testState.onAperturePublication = [&d, failFallback](const std::string &key) {
            if (key == "CobaltSurvey,KdbFlushRoute") {
                d.service.numbers["CobaltSurvey,Schema"] = 7;
                // Arm after the prerequisite schema-4 publication. Even if
                // fallback publication now fails, stale schema 7 must vanish.
                testState.failConsoleSchema = failFallback;
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "metadata-publication-failed");
        if (failFallback) CHECK(!d.service.numbers.count("CobaltSurvey,Schema"));
        else CHECK(d.service.numbers.at("CobaltSurvey,Schema") == 4);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbResetRequired") == 1);
        CHECK(testState.mapsLive == 0 && testState.openLive == 0 && testState.allocations == 0);
    }
}

static void kdbSplDevice(Device &d, bool nativeRoute=true) {
    kdbDevice(d, nativeRoute);
    testState.splBootPresent = true;
    testState.splBoot = "1";
    testState.splAddressByteOffset = testState.kdbAddressByteOffset;
    testState.splCommandByteOffset = testState.kdbCommandByteOffset;
}
static void kdbSplTests() {
    for (bool nativeRoute : {false, true}) {
        activeTestPhase = nativeRoute ? "kdbSplTests.native-success" : "kdbSplTests.isolated-success";
        Device d; kdbSplDevice(d, nativeRoute);
        bool sawSplWindowWrite = false;
        testState.onAperture = [&sawSplWindowWrite](const MmioEvent &event) {
            if (event.operation == 'v' && event.offset >= (1u << 20)) sawSplWindowWrite = true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "kdb-spl-ready-observed-reset-required");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema") == 8);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSharedApiUsed") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplPhase") == 4);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplAddressWritesIssued") == 2);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCommandWritesIssued") == 2);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplStagingPreserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbWindowOffset") == (64ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplWindowOffset") == (65ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbMcAddress") == 0x8004000000ULL);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplMcAddress") == 0x8004100000ULL);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbZeroVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbCopyVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplZeroVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplCopyVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCpuReadBytes") == (8ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCpuReadChunks") == 2048);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplDataReads") == 3072);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSelectorWritesIssued") == 6146);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplVramWritesIssued") == 526200);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplFlushWritesIssued") == 4);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplZeroBytesIssued") == (2ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCopyBytesIssued") == 7648);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplZeroChunksIssued") == 512);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCopyChunksIssued") == 3);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
        CHECK(d.service.strings.at("CobaltSurvey,AccessMode") == "indexed-and-kdb-spl-commands");
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplFlushRoute") == (nativeRoute ? "native-nbif" : "isolated-remap"));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbPayloadBytes") == 6816);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplPayloadBytes") == 832);
        CHECK(testState.kdbWrites == 2 && testState.splWrites == 2);
        CHECK(testState.kdbEvents.size() == 2 && testState.splEvents.size() == 2);
        CHECK(testState.kdbEvents[1].value == 0x80000);
        CHECK(testState.splEvents[1].value == 0x10000000);
        CHECK(testState.apertureCpuWrites == 526200);
        CHECK(sawSplWindowWrite);
        CHECK(testState.apertureFlushWrites == 4);
        CHECK(testState.apertureCpuReads == 2097152);
        CHECK(testState.apertureDataReads == 3072);
        CHECK(testState.selectorWrites == 11270);
        uint32_t kdbFirst = 0, splFirst = 0;
        const auto firmware = cobalt::survey::psp1402Firmware();
        std::memcpy(&kdbFirst, firmware.data + 256, sizeof(kdbFirst));
        std::memcpy(&splFirst, firmware.data + 0x66a20, sizeof(splFirst));
        CHECK(testState.apertureGpu[0] == kdbFirst);
        CHECK(testState.splGpu[0] == splFirst);
        CHECK(testState.apertureGpu[6816 / 4] == 0);
        CHECK(testState.splGpu[832 / 4] == 0);
        bool kdbImageMatches = true, splImageMatches = true;
        for (size_t word = 0; word < testState.apertureCpu.size(); ++word) {
            uint32_t expectedKdb = 0, expectedSpl = 0;
            if (word * 4 < 6816) std::memcpy(&expectedKdb, firmware.data + 256 + word * 4, 4);
            if (word * 4 < 832) std::memcpy(&expectedSpl, firmware.data + 0x66a20 + word * 4, 4);
            kdbImageMatches = kdbImageMatches && testState.apertureCpu[word] == expectedKdb &&
                testState.apertureGpu[word] == expectedKdb;
            splImageMatches = splImageMatches && testState.splCpu[word] == expectedSpl &&
                testState.splGpu[word] == expectedSpl;
        }
        CHECK(kdbImageMatches && splImageMatches);
        CHECK(d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
        CHECK(testState.openLive == 0 && testState.allocations == 0);
    }
    {
        activeTestPhase = "kdbSplTests.busy-ready-success";
        Device d; kdbSplDevice(d);
        unsigned protocolStage = 0, stageSleepBaseline = 0;
        const auto armStage = [&protocolStage, &stageSleepBaseline](const TestState::KdbEvent &event, unsigned stage) {
            if (event.offset == testState.kdbCommandByteOffset) {
                protocolStage = stage;
                stageSleepBaseline = testState.sleepCalls;
            }
        };
        testState.onKdb = [&armStage](const TestState::KdbEvent &event) { armStage(event, 1); };
        testState.onSpl = [&armStage](const TestState::KdbEvent &event) { armStage(event, 2); };
        const auto read = testState.stateRead;
        testState.stateRead = [read, &protocolStage, &stageSleepBaseline](uint32_t offset, uint32_t value) {
            if (protocolStage && offset == 0x458c && testState.sleepCalls - stageSleepBaseline < 2) return 0u;
            return read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "kdb-spl-ready-observed-reset-required");
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbReadyObserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplReadyObserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplAddressWritesIssued") == 2);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCommandWritesIssued") == 2);
        CHECK(testState.sleepCalls >= stageSleepBaseline + 2);
        CHECK(testState.kdbWrites == 2 && testState.splWrites == 2);
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
    }
    for (unsigned failedStore = 1; failedStore <= 4; ++failedStore) {
        Device d; kdbSplDevice(d); unsigned stores = 0;
        const auto loseAt = [&d, failedStore, &stores](const TestState::KdbEvent &) {
            if (++stores == failedStore) d.pci.command = 0;
        };
        testState.onKdb = loseAt; testState.onSpl = loseAt;
        d.run("discovery-snapshot-validated");
        CHECK(stores == failedStore);
        CHECK(testState.kdbWrites + testState.splWrites == failedStore);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplContextLost") == 1);
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplVramCleanup") == "preserved-until-cold-reset");
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
        CHECK(testState.openLive == 0 && testState.mapsLive == 0 && testState.allocations == 0);
    }
    {
        // A single direct boot-ready read reports busy after the SPL address.
        // The next simulated sample is ready again, but context loss is sticky.
        Device d; kdbSplDevice(d); bool armed = false, injected = false; unsigned afterSplAddress = 0;
        const auto read = testState.stateRead;
        testState.onSpl = [&armed](const TestState::KdbEvent &event) {
            if (event.offset == testState.splAddressByteOffset) armed = true;
        };
        testState.stateRead = [read, &armed, &injected, &afterSplAddress](uint32_t offset, uint32_t value) {
            const uint32_t actual = read(offset, value);
            if (armed && offset == 0x458c && !injected) {
                if (++afterSplAddress == 3) { injected = true; return 0u; }
            }
            return actual;
        };
        d.run("discovery-snapshot-validated");
        CHECK(injected);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplContextLost") == 1);
        CHECK(testState.kdbWrites + testState.splWrites == 3);
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCommandWritesIssued") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
        CHECK(testState.openLive == 0 && testState.mapsLive == 0 && testState.allocations == 0);
    }
    {
        // An unreadable direct SOS sample after the SPL address also latches
        // context loss and prevents its command store.
        Device d; kdbSplDevice(d); bool armed = false, injected = false; unsigned afterSplAddress = 0;
        const auto read = testState.stateRead;
        testState.onSpl = [&armed](const TestState::KdbEvent &event) {
            if (event.offset == testState.splAddressByteOffset) armed = true;
        };
        testState.stateRead = [read, &armed, &injected, &afterSplAddress](uint32_t offset, uint32_t value) {
            const uint32_t actual = read(offset, value);
            if (armed && offset == 0x4644 && !injected && ++afterSplAddress == 5) {
                injected = true; return UINT32_MAX;
            }
            return actual;
        };
        d.run("discovery-snapshot-validated");
        CHECK(injected);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplContextLost") == 1);
        CHECK(testState.kdbWrites + testState.splWrites == 3);
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
    }
    {
        // If KDB never returns ready, SPL must not be attempted.
        activeTestPhase = "kdbSplTests.kdb-timeout";
        Device d; kdbSplDevice(d); bool commandSent = false, sawGuardReady = false, sawDirectBusy = false;
        unsigned afterCommandReads = 0;
        testState.onKdb = [&commandSent](const TestState::KdbEvent &event) {
            if (event.offset == testState.kdbCommandByteOffset) commandSent = true;
        };
        const auto read = testState.stateRead;
        testState.stateRead = [read, &commandSent, &afterCommandReads, &sawGuardReady, &sawDirectBusy](uint32_t offset, uint32_t value) {
            if (commandSent && offset == 0x458c) {
                if (++afterCommandReads % 3 == 0) { sawDirectBusy = true; return 0u; }
                sawGuardReady = true;
            }
            return read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(commandSent);
        CHECK(sawGuardReady && sawDirectBusy);
        CHECK(testState.kdbWrites == 2 && testState.splWrites == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbCommandAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplAddressAttempted") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
    }
    {
        activeTestPhase = "kdbSplTests.spl-timeout";
        Device d; kdbSplDevice(d); bool splCommandSent = false; unsigned protocolReads = 0;
        testState.onSpl = [&splCommandSent](const TestState::KdbEvent &event) {
            if (event.offset == testState.splCommandByteOffset) splCommandSent = true;
        };
        const auto read = testState.stateRead;
        testState.stateRead = [read, &splCommandSent, &protocolReads](uint32_t offset, uint32_t value) {
            if (splCommandSent && offset == 0x458c) { ++protocolReads; return 0u; }
            return read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(splCommandSent && protocolReads >= 3);
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "kdb-spl-protocol-failed");
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbReadyObserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplReadyObserved") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplAddressWritesIssued") == 2);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplCommandWritesIssued") == 2);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
        CHECK(testState.kdbWrites == 2 && testState.splWrites == 2);
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
    }
    {
        // Preparation failure after modifying KDB but before any mailbox store
        // must restore the dirty window while the guarded context is intact.
        Device d; kdbSplDevice(d);
        testState.apertureCpuRead = [](unsigned read, uint32_t value) {
            return read == 1572864 ? value ^ 1u : value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1") || d.service.numbers.at("CobaltSurvey,KdbSplAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == (2ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplKdbRestoreVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplSplRestoreVerified") == 1);
        CHECK(testState.apertureCpuWrites == 262144 + (6816 / 4) + 262144 + 524288);
        CHECK(testState.apertureFlushWrites == 5);
        CHECK(testState.apertureCpu == std::vector<uint32_t>(262144, 0xabc01234));
        CHECK(testState.splCpu == std::vector<uint32_t>(262144, 0xdef05678));
        CHECK(testState.apertureGpu == testState.apertureCpu);
        CHECK(testState.splGpu == testState.splCpu);
    }
    {
        Device d; kdbSplDevice(d); bool changed = false;
        testState.onAperture = [&d, &changed](const MmioEvent &event) {
            if (!changed && event.operation == 'v' && testState.apertureCpuWrites == 1024) {
                changed = true; d.pci.command = 0;
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed && d.service.numbers.at("CobaltSurvey,KdbSplContextLost") == 1);
        CHECK(testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,KdbSplRestoreBytesIssued") == 0);
        CHECK(testState.apertureCpuWrites == 1024 && testState.apertureFlushWrites == 0);
    }
    {
        Device d; kdbSplDevice(d); testState.boot = "0";
        CHECK(!d.service.start(&d.pci));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.kdbWrites == 0 && testState.splWrites == 0);
    }
    {
        activeTestPhase = "kdbSplTests.indexed-gate";
        Device d; kdbSplDevice(d); testState.indexedBoot = "0";
        d.run("discovery-aperture-too-small");
        CHECK(!d.service.strings.count("CobaltSurvey,KdbSplStatus"));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        CHECK(testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
    }
    for (unsigned missing = 0; missing < 4; ++missing) {
        Device d; kdbSplDevice(d);
        if (missing == 0) testState.stateBoot = "0";
        if (missing == 1) testState.apertureBoot = "0";
        if (missing == 2) testState.stagingBoot = "0";
        if (missing == 3) testState.kdbBoot = "0";
        d.run("discovery-snapshot-validated");
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
        CHECK(!d.service.strings.count("CobaltSurvey,KdbStatus"));
    }
    {
        Device d; kdbSplDevice(d);
        const auto read = testState.stateRead;
        testState.stateRead = [read](uint32_t offset, uint32_t value) {
            return offset == 0xa954 ? 0x83f0u : read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "window-plan-refused");
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
    }
    {
        Device d; kdbSplDevice(d); testState.splBoot = "0";
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,KdbSplStatus"));
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "kdb-ready-observed-reset-required");
        CHECK(d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
    }
    {
        Device d; kdbSplDevice(d); testState.failAllocationCall = 3;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "kdb-spl-allocation-failed");
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
        CHECK(testState.allocations == 0 && testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
    }
    {
        Device d; kdbSplDevice(d);
        d.vram.onMap = [&d] { if (d.vram.requests == 2) d.vram.mapFail = true; };
        d.run("discovery-snapshot-validated");
        if (d.service.strings.at("CobaltSurvey,KdbSplStatus") != "kdb-spl-map-failed")
            throw std::runtime_error("map status=" + d.service.strings.at("CobaltSurvey,KdbSplStatus") +
                " vram requests=" + std::to_string(d.vram.requests) + " all maps=" + std::to_string(testState.mapRequests));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
        CHECK(testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
    }
    {
        Device d; kdbSplDevice(d); Bytes malformed = syntheticPspFirmware();
        put32(malformed, 56, 0xdeadbeefu);
        firmwareOverride = {malformed.data(), malformed.size()};
        d.run("discovery-snapshot-validated");
        firmwareOverride = {};
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "firmware-package-invalid");
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
    }
    {
        Device d; kdbSplDevice(d); d.pci.numbers["CobaltSurvey,KdbAttempt-v1"] = 1;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "already-attempted");
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
    }
    {
        activeTestPhase = "kdbSplTests.reciprocal-marker";
        Device d; kdbSplDevice(d); testState.splBoot = "0";
        d.pci.numbers["CobaltSurvey,KdbSplAttempt-v1"] = 1;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "already-attempted");
        CHECK(!d.service.strings.count("CobaltSurvey,KdbSplStatus"));
        CHECK(!d.pci.getProperty("CobaltSurvey,KdbAttempt-v1"));
        CHECK(testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
    }
    {
        Device d; kdbSplDevice(d);
        testState.onAperturePublication = [&d](const std::string &key) {
            if (key == "CobaltSurvey,KdbSplStatus") {
                d.service.numbers["CobaltSurvey,Schema"] = 8;
                testState.propertyFailKey = "CobaltSurvey,Schema";
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.numbers.count("CobaltSurvey,Schema"));
        CHECK(d.service.numbers.at("CobaltSurvey,Ready") == 0);
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "metadata-publication-failed");
        CHECK(d.pci.getProperty("CobaltSurvey,KdbSplAttempt-v1"));
        CHECK(testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
        CHECK(testState.openLive == 0 && testState.allocations == 0);
    }
}
static void preSosTests() {
    activeTestPhase = "preSosTests.fixture";
    const Bytes &fake = syntheticPreSosPspFirmware();
    CHECK(fake.size() == cobalt::survey::kPreSosFirmwareBytes);
    cobalt::psp::Package package {};
    CHECK(cobalt::psp::parse(fake.data(), fake.size(), package));
    CHECK(package.part[cobalt::psp::RasDrv].data == nullptr);
    CHECK(package.part[cobalt::psp::Sos].data == fake.data() + 0x14d60);
    CHECK(package.part[cobalt::psp::Toc].data == fake.data() + 0x62ef0);
    for (unsigned n = 0; n < cobalt::survey::kPreSosImageCount; ++n) {
        const auto &spec = cobalt::survey::kPreSosImages[n];
        const auto &part = package.part[spec.type];
        CHECK(part.data == fake.data() + spec.fileOffset);
        CHECK(part.size == spec.bytes && part.version == spec.version);
    }

    for (bool nativeRoute : {false, true}) {
        activeTestPhase = nativeRoute ? "preSosTests.native-success" : "preSosTests.isolated-success";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, nativeRoute);
        d.run("discovery-snapshot-validated");
        activeTestPhase = nativeRoute ? "preSosTests.native-assert" : "preSosTests.isolated-assert";
        if (d.service.strings.at("CobaltSurvey,PreSosStatus") != "pre-sos-ready-observed-reset-required") {
            std::string detail = "pre-SOS status=" + d.service.strings.at("CobaltSurvey,PreSosStatus") +
                " phase=" + std::to_string(d.service.numbers["CobaltSurvey,PreSosPhase"]) +
                " writes=" + std::to_string(testState.preSosWrites) +
                " cpu=" + std::to_string(testState.apertureCpuWrites) +
                " flush=" + std::to_string(testState.apertureFlushWrites) + " props:";
            for (const auto &entry : d.service.strings)
                if (entry.first.find("PreSos") != std::string::npos) detail += " " + entry.first + "=" + entry.second;
            throw std::runtime_error(detail);
        }
        CHECK(d.service.numbers.at("CobaltSurvey,Schema") == 9);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready") == 0);
        CHECK(d.service.strings.at("CobaltSurvey,AccessMode") == "indexed-and-pre-sos-commands");
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosComponentCount") == 7);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosPhase") == 14);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosSharedApiUsed") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosAddressWritesIssued") == 7);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosCommandWritesIssued") == 7);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosAttempted") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosStagingPreserved") == 1);
        CHECK(d.service.strings.at("CobaltSurvey,PreSosFlushRoute") == (nativeRoute ? "native-nbif" : "isolated-remap"));
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosPayloadBytes") == 293184);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosZeroBytesIssued") == (7ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosCopyBytesIssued") == 293184);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosZeroChunksIssued") == 1792);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosCopyChunksIssued") == 77);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosHelperFlushesIssued") == 14);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosFlushWritesIssued") == 14);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosCpuReadBytes") == (28ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosCpuReadChunks") == 7168);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosDataReads") == 10752);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosSelectorWritesIssued") == 21506);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosVramWritesIssued") == 1908304);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == 0);
        CHECK(testState.preSosWrites == 14 && testState.preSosEvents.size() == 14);
        CHECK(testState.apertureCpuWrites == 1908304);
        CHECK(testState.apertureFlushWrites == 14);
        CHECK(testState.apertureCpuReads == (28ULL << 20) / 4);
        CHECK(testState.apertureDataReads == 10752);
        CHECK(testState.selectorWrites == 26630); // 21,506 transaction + 5,124 discovery writes.
        const uint64_t firstMc = d.service.numbers.at("CobaltSurvey,PreSosKdbMcAddress");
        for (unsigned n = 0; n < cobalt::survey::kPreSosImageCount; ++n) {
            const auto &spec = cobalt::survey::kPreSosImages[n];
            const std::string key = std::string("CobaltSurvey,PreSos") + spec.name;
            CHECK(d.service.numbers.at(key + "WindowOffset") == ((64ULL + n) << 20));
            CHECK(d.service.numbers.at(key + "McAddress") == firstMc + (uint64_t(n) << 20));
            CHECK(d.service.numbers.at(key + "PayloadBytes") == spec.bytes);
            CHECK(d.service.numbers.at(key + "Command") == spec.command);
            CHECK(d.service.numbers.at(key + "AddressAttempted") == 1);
            CHECK(d.service.numbers.at(key + "CommandAttempted") == 1);
            CHECK(d.service.numbers.at(key + "ReadyObserved") == 1);
            CHECK(d.service.numbers.at(key + "OriginalStable") == 1);
            CHECK(d.service.numbers.at(key + "ZeroVerified") == 1);
            CHECK(d.service.numbers.at(key + "CopyVerified") == 1);
            CHECK(d.service.numbers.at(key + "StagingPreserved") == 1);
            bool imageMatches = true;
            for (size_t word = 0; word < testState.preSosCpu[n].size(); ++word) {
                uint32_t expected = 0;
                if (word * 4 < spec.bytes) std::memcpy(&expected, fake.data() + spec.fileOffset + word * 4, 4);
                imageMatches = imageMatches && testState.preSosCpu[n][word] == expected &&
                    testState.preSosGpu[n][word] == expected;
            }
            CHECK(imageMatches);
        }
        for (unsigned n = 0; n < cobalt::survey::kPreSosImageCount; ++n) {
            CHECK(testState.preSosEvents[n * 2].offset == testState.kdbAddressByteOffset);
            CHECK(testState.preSosEvents[n * 2].value == static_cast<uint32_t>((firstMc + (uint64_t(n) << 20)) >> 20));
            CHECK(testState.preSosEvents[n * 2 + 1].offset == testState.kdbCommandByteOffset);
            CHECK(testState.preSosEvents[n * 2 + 1].value == cobalt::survey::kPreSosImages[n].command);
        }
        CHECK(d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
        CHECK(testState.openLive == 0 && testState.allocations == 0);
    }
    // A mailbox store permanently ends all CPU-window writes and flushes.
    // Inject an unreadable direct boot register after each of the 14 stores.
    for (unsigned lostAfterStore = 1; lostAfterStore <= 14; ++lostAfterStore) {
        activeTestPhase = "preSosTests.mailbox-loss";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        const auto read = testState.stateRead;
        testState.stateRead = [read, lostAfterStore](uint32_t offset, uint32_t value) {
            if (testState.preSosWrites >= lostAfterStore && offset == 0x458c) return UINT32_MAX;
            return read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.preSosWrites == lostAfterStore);
        CHECK(testState.apertureCpuWrites == 1908304);
        CHECK(testState.apertureFlushWrites == 14);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosContextLost") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosStagingPreserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == 0);
    }

    // A single transient bad guard read in the first address gap is sticky.
    {
        activeTestPhase = "preSosTests.early-address-gap-busy";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        bool armed = false, injected = false;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &armed, &injected](uint32_t offset, uint32_t value) {
            if (armed && !injected && offset == 0x458c) { injected = true; return 0u; }
            return read(offset, value);
        };
        testState.onPreSos = [&armed](const TestState::PreSosEvent &event) {
            if (event.offset == testState.kdbAddressByteOffset) armed = true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(injected && testState.preSosWrites == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosContextLost") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosPhase") == 1);
        CHECK(testState.apertureCpuWrites == 1908304 && testState.apertureFlushWrites == 14);
    }
    // Inject one direct bad register read after an early and a late address;
    // the shim recovers immediately afterward, but the attempt stays sticky.
    for (unsigned fault = 0; fault < 4; ++fault) {
        const unsigned addressStore = fault < 2 ? 3u : 13u;
        activeTestPhase = fault == 0 ? "preSosTests.early-direct-busy" :
            fault == 1 ? "preSosTests.early-direct-allones" :
            fault == 2 ? "preSosTests.late-direct-sos" : "preSosTests.late-direct-sos-allones";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        bool armed = false, injected = false;
        unsigned bootReads = 0, sosReads = 0;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &armed, &injected, &bootReads, &sosReads, fault](uint32_t offset, uint32_t value) {
            const bool bootFault = armed && fault < 2 && offset == 0x458c && ++bootReads == 3;
            const bool sosFault = armed && fault >= 2 && offset == 0x4644 && ++sosReads == 5;
            if (armed && !injected && (bootFault || sosFault)) {
                injected = true;
                if (fault == 0) return 0u;
                if (fault == 1 || fault == 3) return UINT32_MAX;
                return 1u;
            }
            return read(offset, value);
        };
        testState.onPreSos = [&armed, addressStore](const TestState::PreSosEvent &event) {
            if (testState.preSosEvents.size() == addressStore && event.offset == testState.kdbAddressByteOffset) armed = true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(injected && testState.preSosWrites == addressStore);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosKdbReadyObserved") == 1);
        if (addressStore == 13) CHECK(d.service.numbers.at("CobaltSurvey,PreSosDbgReadyObserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosContextLost") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosPhase") == addressStore);
        CHECK(testState.apertureCpuWrites == 1908304 && testState.apertureFlushWrites == 14);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == 0);
    }

    // A timeout on the first response cannot fall through to later commands.
    {
        activeTestPhase = "preSosTests.timeout";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        const auto read = testState.stateRead;
        testState.stateRead = [read](uint32_t offset, uint32_t value) {
            if (testState.preSosWrites >= 2 && offset == 0x458c) return 0u;
            return read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.preSosWrites == 2);
        CHECK(testState.sleepCalls >= 10000);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosReadyObserved") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosResetRequired") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosStagingPreserved") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == 0);
        CHECK(testState.apertureCpuWrites == 1908304 && testState.apertureFlushWrites == 14);
    }
    // Guard reads continue to see ready while repeated direct response reads
    // see busy; guard evidence alone must never advance to the next image.
    // After the post-command guard, each strict poll reads boot and SOS through
    // HwAccess. Its direct boot samples are reads 3, 8, 13, ...; the remaining
    // boot samples belong to guards. Keep the timeout and context assertions.
    {
        activeTestPhase = "preSosTests.guard-ready-direct-busy";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        bool commandSent = false, sawGuardReady = false, sawDirectBusy = false;
        unsigned afterCommandReads = 0;
        std::vector<uint32_t> observedBoot;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &commandSent, &afterCommandReads, &sawGuardReady, &sawDirectBusy, &observedBoot](uint32_t offset, uint32_t value) {
            if (commandSent && offset == 0x458c) {
                ++afterCommandReads;
                uint32_t result = read(offset, value);
                if (afterCommandReads % 5 == 3) { sawDirectBusy = true; result = 0u; }
                else sawGuardReady = true;
                observedBoot.push_back(result);
                return result;
            }
            return read(offset, value);
        };
        testState.onPreSos = [&commandSent](const TestState::PreSosEvent &event) {
            if (event.offset == testState.kdbCommandByteOffset) commandSent = true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(sawGuardReady && sawDirectBusy);
        CHECK(testState.preSosWrites == 2);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosKdbCommandAttempted") == 1);
        if (d.service.numbers.at("CobaltSurvey,PreSosKdbReadyObserved") != 0) {
            std::string trace;
            for (size_t n = 0; n < observedBoot.size(); ++n) trace += " " + std::to_string(n + 1) + ":" + std::to_string(observedBoot[n]);
            throw std::runtime_error("direct-busy cadence observed ready reads=" + std::to_string(afterCommandReads) +
                " sleeps=" + std::to_string(testState.sleepCalls) + " status=" + d.service.strings.at("CobaltSurvey,PreSosStatus") + " samples:" + trace);
        }
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosKdbReadyObserved") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosSplAddressAttempted") == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosContextLost") == 0);
        CHECK(testState.sleepCalls >= 10000);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == 0);
        CHECK(testState.apertureCpuWrites == 1908304 && testState.apertureFlushWrites == 14);
    }

    // A recoverable busy period must still complete all seven commands.
    {
        activeTestPhase = "preSosTests.busy-ready";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        unsigned command = 0, polls = 0, sleepStart = 0;
        std::vector<unsigned> sleepByCommand;
        const auto read = testState.stateRead;
        testState.stateRead = [read, &command, &polls](uint32_t offset, uint32_t value) {
            if (offset == 0x458c && command && polls) { --polls; return 0u; }
            return read(offset, value);
        };
        testState.onPreSos = [&command, &polls, &sleepStart, &sleepByCommand](const TestState::PreSosEvent &event) {
            if (event.offset == testState.kdbCommandByteOffset) {
                if (command) sleepByCommand.push_back(testState.sleepCalls - sleepStart);
                ++command; polls = 4; sleepStart = testState.sleepCalls;
            }
        };
        d.run("discovery-snapshot-validated");
        sleepByCommand.push_back(testState.sleepCalls - sleepStart);
        CHECK(testState.preSosWrites == 14);
        CHECK(command == 7);
        CHECK(sleepByCommand.size() == 7);
        CHECK(std::all_of(sleepByCommand.begin(), sleepByCommand.end(), [](unsigned sleeps) { return sleeps > 0; }));
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "pre-sos-ready-observed-reset-required");
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosPhase") == 14);
        CHECK(testState.sleepCalls >= 7);
    }

    // Preparation failure while context remains valid restores the dirty image;
    // an observed context loss skips every cleanup write.
    {
        activeTestPhase = "preSosTests.dirty-restore";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        const auto read = testState.apertureCpuRead;
        testState.apertureCpuRead = [read](unsigned n, uint32_t value) {
            if (n == 3670016) return value ^ 1u;
            return read ? read(n, value) : value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.preSosWrites == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == (1ULL << 20));
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreChunksIssued") == 256);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosKdbRestoreVerified") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosContextLost") == 0);
        CHECK(testState.apertureFlushWrites == 2);
        CHECK(testState.apertureCpuWrites == 2 * 262144);
    }
    {
        activeTestPhase = "preSosTests.context-loss-skips-restore";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        bool changed = false;
        testState.onAperture = [&changed](const MmioEvent &event) {
            if (!changed && event.operation == 'v') { changed = true; testState.apertureRemap ^= 4; }
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed && testState.preSosWrites == 0);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosContextLost") == 1);
        CHECK(d.service.numbers.at("CobaltSurvey,PreSosRestoreBytesIssued") == 0);
        CHECK(testState.apertureCpuWrites == 1024 && testState.apertureFlushWrites == 0);
    }

    for (int index : {0, 6}) {
        activeTestPhase = "preSosTests.window-map-failure";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); testState.preSosMapFailIndex = index;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "pre-sos-map-failed");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
        CHECK(testState.mapsLive == 0 && testState.openLive == 0 && testState.allocations == 0);
    }
    {
        activeTestPhase = "preSosTests.window-map-invalid";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); testState.preSosMapInvalidIndex = 6;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "pre-sos-map-invalid");
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
        CHECK(testState.mapsLive == 0 && testState.openLive == 0 && testState.allocations == 0);
    }

    // Failed persistent claim happens before any image or selector mutation.
    {
        activeTestPhase = "preSosTests.claim-failure";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); testState.preSosClaimFail = true;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "attempt-claim-failed");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
    }

    // Old-mode attempts and pre-SOS replay all refuse before any new map/write.
    for (const char *marker : {"CobaltSurvey,KdbAttempt-v1", "CobaltSurvey,KdbSplAttempt-v1", "CobaltSurvey,PreSosAttempt-v1"}) {
        activeTestPhase = "preSosTests.marker";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); d.pci.numbers[marker] = 1;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "already-attempted");
        CHECK(testState.preSosWrites == 0 && testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
        CHECK(testState.mapsLive == 0 && testState.openLive == 0 && testState.allocations == 0);
    }

    // A malformed full-size fake table refuses before claiming or staging.
    {
        activeTestPhase = "preSosTests.firmware-metadata";
        Bytes malformed = fake; put32(malformed, 40, 0);
        FirmwareOverrideScope firmware(malformed);
        Device d; preSosDevice(d, false);
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "firmware-package-invalid");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
    }
    {
        activeTestPhase = "preSosTests.last-image-version";
        Bytes malformed = fake; put32(malformed, 36 + 7 * 16 + 4, 0xdeadbeefu);
        FirmwareOverrideScope firmware(malformed);
        Device d; preSosDevice(d, false);
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "firmware-package-invalid");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
    }

    // Refusals caused by each required predecessor flag never fall through to
    // either older firmware mode. The primary survey flag controls service start.
    {
        activeTestPhase = "preSosTests.survey-off";
        Device d; preSosDevice(d, false); testState.boot = "0";
        CHECK(!d.service.start(&d.pci));
        CHECK(testState.preSosWrites == 0 && testState.kdbWrites == 0 && testState.splWrites == 0);
    }
    for (unsigned missing = 1; missing < 7; ++missing) {
        activeTestPhase = "preSosTests.required-flag";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        if (missing == 1) testState.indexedBoot = "0";
        if (missing == 2) testState.stateBoot = "0";
        if (missing == 3) testState.apertureBoot = "0";
        if (missing == 4) testState.stagingBoot = "0";
        if (missing == 5) testState.kdbBoot = "0";
        if (missing == 6) testState.splBoot = "0";
        CHECK(d.service.start(&d.pci));
        CHECK(d.service.registered);
        CHECK(testState.mapsLive == 0 && testState.allocations == 0 && testState.backingDescriptorsLive == 0);
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(!d.service.strings.count("CobaltSurvey,KdbStatus"));
        CHECK(!d.service.strings.count("CobaltSurvey,KdbSplStatus"));
        CHECK(testState.preSosWrites == 0 && testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
    }
    {
        activeTestPhase = "preSosTests.new-flag-off-preserves-pair";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); testState.preSosBoot = "0";
        d.run("discovery-snapshot-validated");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(!d.service.strings.count("CobaltSurvey,PreSosStatus"));
        CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "kdb-spl-ready-observed-reset-required");
        CHECK(d.service.strings.at("CobaltSurvey,AccessMode") == "indexed-and-kdb-spl-commands");
        CHECK(testState.preSosWrites == 0 && testState.kdbWrites == 2 && testState.splWrites == 2);
        CHECK(testState.apertureCpuWrites == 526200 && testState.apertureFlushWrites == 4);
    }
    for (bool pair : {false, true}) {
        activeTestPhase = pair ? "preSosTests.new-marker-blocks-pair" : "preSosTests.new-marker-blocks-kdb";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); testState.preSosBoot = "0";
        if (!pair) testState.splBoot = "0";
        d.pci.numbers["CobaltSurvey,PreSosAttempt-v1"] = 1;
        d.run("discovery-snapshot-validated");
        CHECK(testState.preSosWrites == 0 && testState.kdbWrites == 0 && testState.splWrites == 0);
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0);
        if (pair) CHECK(d.service.strings.at("CobaltSurvey,KdbSplStatus") == "already-attempted");
        else CHECK(d.service.strings.at("CobaltSurvey,KdbStatus") == "already-attempted");
    }

    // The exact seven-window planner refuses an invalid framebuffer extent.
    // First and last backup-allocation failures unwind all already-created maps.
    {
        activeTestPhase = "preSosTests.planner-refusal";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        const auto read = testState.stateRead;
        testState.stateRead = [read](uint32_t offset, uint32_t value) {
            return offset == 0xa954 ? 0x83f0u : read(offset, value);
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "window-plan-refused");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
    }
    for (unsigned failedAllocation : {2u, 8u}) {
        activeTestPhase = failedAllocation == 2 ? "preSosTests.first-allocation-failure" : "preSosTests.last-allocation-failure";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false); testState.failAllocationCall = failedAllocation;
        d.run("discovery-snapshot-validated");
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "pre-sos-allocation-failed");
        CHECK(!d.pci.getProperty("CobaltSurvey,PreSosAttempt-v1"));
        CHECK(testState.apertureCpuWrites == 0 && testState.apertureFlushWrites == 0 && testState.preSosWrites == 0);
        CHECK(testState.allocations == 0 && testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
    }

    // Commit schema 9 only after all telemetry succeeds, and revoke an injected
    // stale schema 9 before the intentionally failed schema-4 fallback.
    {
        activeTestPhase = "preSosTests.stale-schema-fallback";
        FirmwareOverrideScope firmware(fake);
        Device d; preSosDevice(d, false);
        testState.onAperturePublication = [&d](const std::string &key) {
            if (key == "CobaltSurvey,PreSosStatus") {
                d.service.numbers["CobaltSurvey,Schema"] = 9;
                testState.propertyFailKey = "CobaltSurvey,Schema";
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.numbers.count("CobaltSurvey,Schema"));
        CHECK(d.service.numbers.at("CobaltSurvey,Ready") == 0);
        CHECK(d.service.strings.at("CobaltSurvey,PreSosStatus") == "metadata-publication-failed");
        CHECK(testState.mapsLive == 0 && testState.backingDescriptorsLive == 0);
        CHECK(testState.openLive == 0 && testState.allocations == 0);
    }
}
static const std::string &apertureStatus(const Device &d) {
    return d.service.strings.at("CobaltSurvey,ApertureStatus");
}
static void noApertureWrites() {
    CHECK(testState.selectorWrites==5124); CHECK(testState.apertureCpuWrites==0);
    CHECK(testState.apertureFlushWrites==0); CHECK(testState.apertureDataReads==0);
}
static void apertureTests() {
    unsigned successfulRegisterReads=0, successfulCoreEvents=0;
    {
        Device d; apertureDevice(d);
        testState.onAperture=[](const MmioEvent &e) {
            if(e.operation=='v') {
                CHECK(e.offset<16); CHECK((e.offset&3)==0);
                // CPU writes are posted; the indexed GPU view changes only
                // when the audited HDP flush is issued after the fence.
                if(testState.apertureCpuWrites<=4)
                    for(auto word:testState.apertureGpu) CHECK(word==0xabc01234);
            }
            if(e.operation=='h') CHECK(testState.apertureCpuWrites==testState.apertureFlushWrites*4);
            if(e.operation=='d'||e.operation=='c') CHECK(e.offset<16 && !(e.offset&3));
        };
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="pattern-and-restore-verified");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==5);
        CHECK(d.service.numbers.at("CobaltSurvey,IndexedSelectorWritesIssued")==5124);
        CHECK(d.service.numbers.at("CobaltSurvey,IndexedDataReads")==5120);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureSelectorWritesIssued")==34);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureDataReads")==16);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureVramWritesIssued")==8);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureFlushWritesIssued")==2);
        CHECK(testState.apertureCpuWrites==8); CHECK(testState.apertureFlushWrites==2);
        CHECK(testState.openCalls==2); CHECK(testState.closeCalls==2);
        CHECK(testState.consoleCalls==4); CHECK(testState.stateReads==16);
        CHECK(testState.selectorWrites==5158); CHECK(testState.indexedDataReads==5120);
        CHECK(testState.apertureDataReads==16); CHECK(testState.apertureCpuReads==16);
        CHECK(d.mmio.selectorStorage[0]==0x12345678); CHECK(d.mmio.selectorStorage[6]==2);
        CHECK(d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restored-observed");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restored-observed");
        for(unsigned i=0;i<4;++i) { CHECK(testState.apertureCpu[i]==0xabc01234); CHECK(testState.apertureGpu[i]==0xabc01234); }
        for(unsigned i=4;i<1024;++i) CHECK(testState.apertureCpu[i]==0xabc01234);
        successfulRegisterReads=testState.apertureRegisterReads;
        for(const auto &e:testState.apertureEvents) if(e.operation!='n') ++successfulCoreEvents;
        d.service.stop(&d.pci); CHECK(d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(!d.service.strings.count("CobaltSurvey,ApertureStatus"));
    }
    for(const char *arg:{"", "0", "2", "-1", "true", "1x"}) {
        Device d; apertureDevice(d); testState.apertureBoot=arg; d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,ApertureStatus")); noApertureWrites();
        CHECK(testState.openCalls==1); CHECK(testState.stateReads==8); CHECK(testState.consoleCalls==2);
    }
    {
        Device d; apertureDevice(d); testState.apertureBootPresent=false; d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,ApertureStatus")); noApertureWrites();
    }
    for(unsigned kind=0;kind<6;++kind) {
        Device d; apertureDevice(d);
        if(kind==0) d.pci.subsystem^=1;
        if(kind==1) d.pci.classRevision^=1;
        if(kind==2) d.mmio.length=d.mmio.contiguous=0x100000;
        if(kind==3) d.vram.length=d.vram.contiguous=128ULL<<20;
        if(kind==4) d.load(stateFixture());
        if(kind==5) testState.console.v_length=250ULL<<20;
        d.run("discovery-snapshot-validated"); CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(apertureStatus(d)!="pattern-and-restore-verified"); noApertureWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
    }
    for(uint32_t remap:{0u,0x1000u,0x7f001u,0xffffffffu}) {
        Device d; apertureDevice(d); testState.apertureRemap=remap;
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="hdp-remap-not-whitelisted");
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureRemapFirstRaw")==remap); noApertureWrites();
    }
    {
        Device d; apertureDevice(d); unsigned reads=0;
        testState.apertureRegisterRead=[&reads](uint32_t offset,uint32_t value) {
            return offset==0x3934 && ++reads==2 ? 0u : value;
        };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="hdp-remap-not-whitelisted"); noApertureWrites();
    }
    for(unsigned kind=0;kind<8;++kind) {
        Device d; apertureDevice(d); IOService peer;
        if(kind==0) d.pci.onOpen=[&d] { if(testState.openCalls==2) d.pci.owner=nullptr; };
        if(kind==1) testState.onConsole=[&d](unsigned call,PE_Video &) { if(call==3) d.pci.command=0; };
        if(kind==2) testState.onConsole=[](unsigned call,PE_Video &v) { if(call>=3) ++v.v_scale; };
        if(kind==3) testState.onConsole=[&d,&peer](unsigned call,PE_Video &) { if(call==3) d.pci.clients.push_back(&peer); };
        if(kind==4) d.pci.numbers["CobaltSurvey,ApertureAttempt-v1"]=1;
        if(kind==5) testState.apertureClaimFail=true;
        if(kind==6) testState.onConsole=[&d](unsigned call,PE_Video &) { if(call==3) d.pci.iteratorInvalid=true; };
        if(kind==7) d.pci.onClose=[&d] { if(testState.closeCalls==1) d.pci.openBusy=true; };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)!="pattern-and-restore-verified"); noApertureWrites();
    }
    // Every new mapping failure must precede the persistent attempt and all
    // new selector, CPU and flush writes. Four baseline maps precede six new.
    for(unsigned request=5;request<=10;++request) {
        Device d; apertureDevice(d); testState.failMapRequest=request;
        d.run("discovery-snapshot-validated"); noApertureWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(apertureStatus(d)!="pattern-and-restore-verified");
    }
    for(unsigned request=5;request<=10;++request) for(unsigned fault=0;fault<13;++fault) {
        Device d; apertureDevice(d);
        auto corrupt=[&](IODeviceMemory &memory) {
            if(testState.mapRequests!=request) return;
            if(fault==0) memory.mapTruncated=true;
            if(fault==1) memory.mapWrongPhysical=true;
            if(fault==2) memory.mapCached=true;
            if(fault==3) memory.mapNullAddress=true;
            if(fault==4) memory.mapMisalignedAddress=true;
            if(fault==5) memory.mapWrongDescriptor=true;
            if(fault==6) memory.mapFragmented=true;
            if(fault==7) memory.mapDescriptorWrongLength=true;
            if(fault==8) memory.mapDescriptorWrongPhysical=true;
            if(fault==9) memory.mapDescriptorFragmented=true;
            if(fault==10) memory.mapDescriptorWrongSegment=true;
            if(fault==11) memory.mapSegmentWrongPhysical=true;
            if(fault==12) { if(request<=7) memory.mapWritable=true; else memory.mapForceReadOnly=true; }
        };
        d.mmio.onMap=[&] { corrupt(d.mmio); }; d.vram.onMap=[&] { corrupt(d.vram); };
        d.run("discovery-snapshot-validated"); noApertureWrites();
        CHECK(apertureStatus(d)!="pattern-and-restore-verified");
        CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
    }
    for(unsigned at=8;at<16;++at) {
        Device d; apertureDevice(d); const auto read=testState.stateRead;
        testState.stateRead=[read,at](uint32_t offset,uint32_t value) {
            const auto actual=read(offset,value); return testState.stateReads==at ? actual^1 : actual;
        };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="fresh-state-changed"); noApertureWrites();
    }
    for(unsigned kind=0;kind<7;++kind) {
        Device d; apertureDevice(d); auto bytes=apertureFixture();
        const size_t nbif=die+4+6*12, hdp=nbif+20, shiftedGc=gc+44;
        if(kind==0) bytes[nbif+4]=7;
        if(kind==1) bytes[nbif+5]=4;
        if(kind==2) bytes[nbif+6]=2;
        if(kind==3) bytes[nbif+2]=1;
        if(kind==4) bytes[hdp+4]=6;
        if(kind==5) bytes[hdp+2]=1;
        if(kind==6) put16(bytes,hdp,108);
        put16(bytes,prefix+14,sum(bytes,ipds,ipds+ipdsSize+44));
        put16(bytes,prefix+22,sum(bytes,shiftedGc,shiftedGc+gcSize));
        put16(bytes,prefix+8,sum(bytes,prefix+10,shiftedGc+gcSize)); d.load(bytes);
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="aperture-ip-proof-unavailable"); noApertureWrites();
    }
    for(unsigned at=0;at<8;++at) {
        Device d; apertureDevice(d);
        testState.apertureDataRead=[at](unsigned read,uint32_t value) { return read==at ? value^1 : value; };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="original-read-mismatch");
        CHECK(testState.apertureCpuWrites==0); CHECK(testState.apertureFlushWrites==0);
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restored-observed");
    }
    for(unsigned at=8;at<12;++at) {
        Device d; apertureDevice(d);
        testState.apertureDataRead=[at](unsigned read,uint32_t value) { return read==at ? value^1 : value; };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="pattern-read-mismatch");
        CHECK(testState.apertureCpuWrites==8); CHECK(testState.apertureFlushWrites==2);
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restored-observed");
    }
    for(unsigned at=0;at<12;++at) {
        Device d; apertureDevice(d);
        testState.apertureCpuRead=[at](unsigned read,uint32_t value) { return read==at ? value^1 : value; };
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)==(at<8 ? "original-read-mismatch" : "pattern-read-mismatch"));
        CHECK(testState.apertureCpuWrites==(at<8 ? 0u : 8u));
        CHECK(testState.apertureFlushWrites==(at<8 ? 0u : 2u));
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restored-observed");
    }
    for(unsigned at=0;at<4;++at) {
        Device d; apertureDevice(d); unsigned reads=0;
        testState.selectorRead=[&](uint32_t,uint32_t value) {
            return aperturePhase() && reads++==at ? UINT32_MAX : value;
        };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="selectors-unreadable-or-unstable");
        noApertureWrites(); CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
    }
    {
        Device d; apertureDevice(d);
        testState.onMmio=[&d](const MmioEvent &e) {
            if(aperturePhase() && e.operation=='w' && testState.selectorWrites==5158)
                d.mmio.selectorStorage[6]^=1;
        };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="cleanup-unverified");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restored-observed");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restore-skipped-or-unverified");
    }
    for(unsigned at=12;at<16;++at) {
        Device d; apertureDevice(d);
        testState.apertureDataRead=[at](unsigned read,uint32_t value) { return read==at ? value^1 : value; };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="cleanup-unverified");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restore-skipped-or-unverified");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restored-observed");
    }
    // At every fixed access event, make the PCI/BAR/ownership or NBIF context
    // stale. After the event no further write through the old maps is allowed.
    for(unsigned kind=0;kind<8;++kind) for(unsigned at=1;at<=successfulCoreEvents;++at) {
        Device d; apertureDevice(d); IOService peer; unsigned core=0,writesAtFault=0; bool fault=false;
        testState.onAperture=[&](const MmioEvent &e) {
            if(e.operation=='n') return;
            if(++core!=at) return;
            fault=true; writesAtFault=testState.selectorWrites+testState.apertureCpuWrites+testState.apertureFlushWrites;
            if(kind==0) d.pci.command=0;
            if(kind==1) d.pci.bars[0]+=4096;
            if(kind==2) d.pci.inactive=true;
            if(kind==3) d.pci.clients.push_back(&peer);
            if(kind==4) testState.apertureRemap=0;
            if(kind==5) testState.apertureMemsize=1;
            if(kind==6) d.pci.owner=nullptr;
            if(kind==7) d.vram.physical+=4096;
        };
        d.run("discovery-snapshot-validated"); CHECK(fault);
        CHECK(testState.selectorWrites+testState.apertureCpuWrites+testState.apertureFlushWrites==writesAtFault);
        CHECK(apertureStatus(d)!="pattern-and-restore-verified"); CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
    }
    {
        Device d; apertureDevice(d); testState.failApertureSchema=true;
        d.run("discovery-snapshot-validated"); CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(apertureStatus(d)=="metadata-publication-failed");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restored-observed");
    }
    {
        Device d; apertureDevice(d); d.run("discovery-snapshot-validated");
        const unsigned cpuWrites=testState.apertureCpuWrites, flushWrites=testState.apertureFlushWrites;
        d.service.stop(&d.pci);
        // Removing the independent discovery attempt only in this test proves
        // the aperture marker itself survives stop/restart and refuses retry.
        d.pci.removeProperty("CobaltSurvey,IndexedAttempt-v1");
        // The fixture distinguishes discovery from aperture MM_DATA by session.
        testState.openCalls=0; testState.closeCalls=0;
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="already-attempted");
        CHECK(testState.apertureCpuWrites==cpuWrites); CHECK(testState.apertureFlushWrites==flushWrites);
        CHECK(d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
    }
    // One-shot bad remap/memsize samples return to normal immediately. Once
    // observed, context loss remains latched, including cleanup's posted read.
    for(unsigned at=3;at<=successfulRegisterReads;++at) {
        Device d; apertureDevice(d); unsigned reads=0,writesAtFault=0; bool fault=false;
        testState.apertureRegisterRead=[&](uint32_t,uint32_t value) {
            if(++reads!=at) return value;
            fault=true; writesAtFault=testState.selectorWrites+testState.apertureCpuWrites+testState.apertureFlushWrites;
            return 0u;
        };
        d.run("discovery-snapshot-validated"); CHECK(fault);
        CHECK(testState.selectorWrites+testState.apertureCpuWrites+testState.apertureFlushWrites==writesAtFault);
        CHECK(apertureStatus(d)!="pattern-and-restore-verified");
    }
    for(const char *name:{"ApertureAttempted","ApertureSelectorWritesIssued","ApertureDataReads",
        "ApertureVramWritesIssued","ApertureFlushWritesIssued","ApertureCleanup","ApertureVramCleanup",
        "ApertureSelectorCleanup","ApertureStatus","ApertureWindowOffset","ApertureWindowBytes",
        "ApertureMcAddress","ApertureRemapFirstRaw","ApertureRemapSecondRaw","ApertureReadOnly","AperturePlanReason"}) {
        Device d; apertureDevice(d); testState.propertyFailKey=std::string("CobaltSurvey,")+name;
        d.run("discovery-snapshot-validated"); CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(!d.service.numbers.count("CobaltSurvey,ApertureMcAddress"));
        CHECK(d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        if(std::string(name)!="ApertureSelectorCleanup")
            CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restored-observed");
        if(std::string(name)!="ApertureStatus") CHECK(apertureStatus(d)=="metadata-publication-failed");
    }
    for(const char *name:{"ReadOnly","AccessMode"}) {
        Device d; apertureDevice(d);
        testState.onConsole=[name](unsigned call,PE_Video &) {
            if(call==4) testState.propertyFailKey=std::string("CobaltSurvey,")+name;
        };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="metadata-publication-failed");
        noApertureWrites(); CHECK(d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureAttempted")==1);
    }
    {
        Device d; apertureDevice(d); d.pci.onClose=[&d] { if(testState.closeCalls==2) d.pci.command=0; };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="device-context-changed");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
    }
    {
        Device d; apertureDevice(d); testState.onAperturePublication=[&d](const std::string &) { d.pci.command=0; };
        d.run("discovery-snapshot-validated"); CHECK(apertureStatus(d)=="device-context-changed");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
    }
    std::cout << "Aperture exhaustive register/core fault positions: " << successfulRegisterReads << "/" << successfulCoreEvents << "\n";
}

static void nativeApertureTests() {
    constexpr uint32_t nativeBase = 0xd20;
    constexpr uint32_t nativeOffset = (nativeBase + 0xf7) * 4;
    {
        Device d; apertureDevice(d, true, nativeBase);
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="pattern-and-restore-verified");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureFlushRoute")=="native-nbif");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureGuardMapping")=="shared-native-rw");
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureFlushByteOffset")==nativeOffset);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureNativeFlushByteOffset")==nativeOffset);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureRemapFirstRaw")==nativeOffset);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureRemapSecondRaw")==nativeOffset);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureSelectorWritesIssued")==34);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureDataReads")==16);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureVramWritesIssued")==8);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureFlushWritesIssued")==2);
        CHECK(testState.apertureCpuWrites==8 && testState.apertureFlushWrites==2);
        CHECK(testState.mapRequests==10);
        CHECK(!testState.apertureNbifReadLive && !testState.flushMapLive);
        CHECK(testState.backingDescriptorsLive==0 && testState.mapsLive==0);
    }
    {
        constexpr uint32_t relocatedBase = 0xd30;
        const uint32_t relocatedNative = (relocatedBase + 0xf7) * 4;
        Device d; apertureDevice(d, true, relocatedBase);
        CHECK(testState.apertureRemap==relocatedNative);
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="pattern-and-restore-verified");
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureNativeFlushByteOffset")==relocatedNative);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureFlushByteOffset")==relocatedNative);
        CHECK(d.service.numbers.at("CobaltSurvey,ApertureRemapFirstRaw")==relocatedNative);
    }
    {
        Device d; apertureDevice(d, true, nativeBase); unsigned remapSamples=0;
        testState.apertureRegisterRead=[&](uint32_t offset,uint32_t value) {
            if(offset==(nativeBase+0x12d)*4 && ++remapSamples==2) return 0x7f000u;
            return value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="hdp-remap-unstable");
        CHECK(remapSamples==2); noApertureWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
    }
    {
        Device d; apertureDevice(d, true, nativeBase); bool changed=false;
        testState.apertureRegisterRead=[&](uint32_t offset,uint32_t value) {
            if(!changed && offset==(nativeBase+0x12d)*4 && testState.apertureRegisterReads>=2) {
                changed=true; return 0x7f000u;
            }
            return value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed); CHECK(apertureStatus(d)!="pattern-and-restore-verified");
        noApertureWrites();
    }
    {
        Device d; apertureDevice(d, true, nativeBase);
        bool changed=false; unsigned writesAtChange=0;
        testState.onAperture=[&](const MmioEvent &event) {
            if(!changed && event.operation=='v') {
                changed=true;
                writesAtChange=testState.selectorWrites+testState.apertureCpuWrites+testState.apertureFlushWrites;
                // Both routes are individually supported, but a transaction
                // must never follow a changed route or resume stale cleanup.
                testState.apertureRemap=0x7f000;
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed); CHECK(apertureStatus(d)=="cleanup-unverified");
        CHECK(testState.selectorWrites+testState.apertureCpuWrites+testState.apertureFlushWrites==writesAtChange);
        CHECK(testState.apertureCpuWrites==1 && testState.apertureFlushWrites==0);
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restore-skipped-or-unverified");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restore-skipped-or-unverified");
    }
    {
        Device d; apertureDevice(d, true, nativeBase);
        testState.onApertureNbifRelease=[&d] { d.pci.command=0; };
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="device-context-changed");
        CHECK(!testState.apertureNbifReadLive && !testState.flushMapLive);
        noApertureWrites(); CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
    }
    // Native and isolated routing use the same six new fixed-purpose mappings;
    // exercise each mapping failure shape before the persistent attempt claim.
    for(unsigned request=5;request<=10;++request) {
        Device d; apertureDevice(d, true, nativeBase); testState.failMapRequest=request;
        d.run("discovery-snapshot-validated"); noApertureWrites();
        CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(apertureStatus(d)!="pattern-and-restore-verified");
    }
    for(unsigned request=5;request<=10;++request) for(unsigned fault=0;fault<13;++fault) {
        Device d; apertureDevice(d, true, nativeBase);
        auto corrupt=[&](IODeviceMemory &memory) {
            if(testState.mapRequests!=request) return;
            if(fault==0) memory.mapTruncated=true;
            if(fault==1) memory.mapWrongPhysical=true;
            if(fault==2) memory.mapCached=true;
            if(fault==3) memory.mapNullAddress=true;
            if(fault==4) memory.mapMisalignedAddress=true;
            if(fault==5) memory.mapWrongDescriptor=true;
            if(fault==6) memory.mapFragmented=true;
            if(fault==7) memory.mapDescriptorWrongLength=true;
            if(fault==8) memory.mapDescriptorWrongPhysical=true;
            if(fault==9) memory.mapDescriptorFragmented=true;
            if(fault==10) memory.mapDescriptorWrongSegment=true;
            if(fault==11) memory.mapSegmentWrongPhysical=true;
            if(fault==12) { if(request<=7) memory.mapWritable=true; else memory.mapForceReadOnly=true; }
        };
        d.mmio.onMap=[&] { corrupt(d.mmio); }; d.vram.onMap=[&] { corrupt(d.vram); };
        d.run("discovery-snapshot-validated"); noApertureWrites();
        CHECK(apertureStatus(d)!="pattern-and-restore-verified");
        CHECK(!d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(!testState.apertureNbifReadLive && !testState.flushMapLive);
    }
    {
        Device d; apertureDevice(d, true, nativeBase);
        testState.apertureDataRead=[](unsigned read,uint32_t value) { return read==8 ? value^1 : value; };
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="pattern-read-mismatch");
        CHECK(testState.apertureCpuWrites==8 && testState.apertureFlushWrites==2);
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restored-observed");
    }
    {
        Device d; apertureDevice(d, true, nativeBase);
        testState.onMmio=[&d](const MmioEvent &e) {
            if(aperturePhase() && e.operation=='w' && testState.selectorWrites==5158)
                d.mmio.selectorStorage[6]^=1;
        };
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="cleanup-unverified");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureVramCleanup")=="restored-observed");
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restore-skipped-or-unverified");
    }
    for(const char *name:{"ApertureFlushRoute","ApertureGuardMapping","ApertureFlushByteOffset",
                          "ApertureNativeFlushByteOffset"}) {
        Device d; apertureDevice(d, true, nativeBase);
        testState.propertyFailKey=std::string("CobaltSurvey,")+name;
        d.run("discovery-snapshot-validated");
        CHECK(apertureStatus(d)=="metadata-publication-failed");
        CHECK(d.pci.getProperty("CobaltSurvey,ApertureAttempt-v1"));
        CHECK(d.service.strings.at("CobaltSurvey,ApertureSelectorCleanup")=="restored-observed");
    }
}

static uint32_t stagingOriginal(size_t word) {
    return uint32_t(word * 0x9e3779b9u) ^ uint32_t(word >> 3) ^ 0x6a09e667u;
}
static uint8_t stagingPayloadByte(size_t offset) {
    return uint8_t(((offset * 37u) ^ (offset >> 8) ^ (offset >> 16) ^ 0xa7u) & 0xffu);
}
static uint32_t stagingPayloadWord(size_t word) {
    uint32_t result=0;
    for(size_t j=0;j<4;++j) result |= uint32_t(stagingPayloadByte(word*4+j)) << (8*j);
    return result;
}
static const std::string &stagingStatus(const Device &d) {
    return d.service.strings.at("CobaltSurvey,StagingStatus");
}
static void stagingDevice(Device &d, bool nativeRoute=true) {
    apertureDevice(d, nativeRoute);
    testState.stagingBootPresent = true;
    testState.stagingBoot = "1";
    for (size_t i=0; i<testState.apertureCpu.size(); ++i) {
        const uint32_t value = stagingOriginal(i);
        testState.apertureCpu[i] = value;
        testState.apertureGpu[i] = value;
    }
}
static void stagingTests() {
    {
        Device d; stagingDevice(d);
        bool firstCpuWrite = true;
        testState.onAperture=[&](const MmioEvent &event) {
            if (event.operation=='v' && firstCpuWrite) {
                firstCpuWrite=false;
                for(size_t i : {size_t(0),size_t(1),size_t(1023),size_t(65535),size_t(262143)})
                    CHECK(testState.apertureGpu[i]==stagingOriginal(i));
            }
            if(event.operation=='h') {
                CHECK(testState.apertureGpu==testState.apertureCpu);
                const unsigned flush=testState.apertureFlushWrites;
                if(flush==1) {
                    for(uint32_t word:testState.apertureGpu) CHECK(word==0);
                } else if(flush==2) {
                    for(size_t i=0;i<testState.apertureGpu.size();++i)
                        CHECK(testState.apertureGpu[i]==(i<125472/4 ? stagingPayloadWord(i) : 0));
                } else if(flush==3) {
                    for(size_t i=0;i<testState.apertureGpu.size();++i)
                        CHECK(testState.apertureGpu[i]==stagingOriginal(i));
                }
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(stagingStatus(d)=="synthetic-zero-copy-and-restore-verified");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==6);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingWindowOffset")==64ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingWindowBytes")==1ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingPayloadBytes")==125472);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingZeroBytesIssued")==1ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingCopyBytesIssued")==125472);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingZeroChunksIssued")==256);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingCopyChunksIssued")==31);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingHelperFlushesIssued")==2);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingRestoreBytesIssued")==1ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingRestoreChunksIssued")==256);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingCpuReadBytes")==5ULL<<20);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingCpuReadChunks")==1280);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingOriginalStable")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingZeroVerified")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingCopyVerified")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingRestoreVerified")==1);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingContextLost")==0);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingSelectorWritesIssued")==4098);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingDataReads")==2048);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingVramWritesIssued")==555656);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingFlushWritesIssued")==3);
        CHECK(d.service.strings.at("CobaltSurvey,StagingFlushRoute")=="native-nbif");
        CHECK(d.service.strings.at("CobaltSurvey,StagingGuardMapping")=="shared-native-rw");
        CHECK(testState.apertureCpuWrites==555656);
        CHECK(testState.apertureFlushWrites==3);
        CHECK(testState.apertureCpuReads==1310720);
        CHECK(testState.apertureDataReads==2048);
        CHECK(testState.selectorWrites==9222);
        CHECK(testState.selectorWrites-5124==4098);
        CHECK(d.mmio.selectorStorage[0]==0x12345678);
        CHECK(d.mmio.selectorStorage[6]==2);
        CHECK(d.service.strings.at("CobaltSurvey,StagingVramCleanup")=="restored-observed");
        CHECK(d.service.strings.at("CobaltSurvey,StagingSelectorCleanup")=="restored-observed");
        CHECK(testState.apertureEvents.empty());
        for(size_t i=0; i<testState.apertureCpu.size(); ++i) {
            CHECK(testState.apertureCpu[i]==stagingOriginal(i));
            CHECK(testState.apertureGpu[i]==stagingOriginal(i));
        }
        CHECK(d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.mapsLive==0 && testState.backingDescriptorsLive==0);
    }
    {
        Device d; stagingDevice(d);
        testState.propertyFailKey="CobaltSurvey,StagingZeroVerified";
        d.run("discovery-snapshot-validated");
        CHECK(d.service.numbers.at("CobaltSurvey,Schema")==4);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready")==0);
        CHECK(d.service.strings.at("CobaltSurvey,StagingStatus")=="metadata-publication-failed");
        CHECK(!d.service.numbers.count("CobaltSurvey,StagingZeroVerified"));
        CHECK(d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.apertureCpu==testState.apertureGpu);
    }
    {
        Device d; stagingDevice(d); bool changed=false; unsigned statusPublications=0;
        testState.onAperturePublication=[&](const std::string &key) {
            if (key=="CobaltSurvey,StagingStatus" && ++statusPublications==1) {
                changed=true; d.pci.command=0;
            }
            if (changed && key=="CobaltSurvey,StagingAttempted")
                testState.propertyFailKey="CobaltSurvey,Schema";
        };
        d.run("discovery-snapshot-validated");
        if (!changed || statusPublications<2)
            throw std::runtime_error("staging publication hook changed=" + std::to_string(changed) +
                " status-count=" + std::to_string(statusPublications));
        CHECK(!d.service.numbers.count("CobaltSurvey,Schema"));
        CHECK(d.service.numbers.at("CobaltSurvey,Ready")==0);
        CHECK(d.service.strings.at("CobaltSurvey,StagingStatus")=="metadata-publication-failed");
        CHECK(d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.apertureCpu==testState.apertureGpu);
    }
    {
        Device d; stagingDevice(d);
        d.pci.numbers["CobaltSurvey,StagingAttempt-v1"]=1;
        d.run("discovery-snapshot-validated");
        CHECK(testState.selectorWrites==5124);
        CHECK(testState.apertureCpuWrites==0 && testState.apertureFlushWrites==0);
    }
    for (const char *argument : {"", "0", "2", "-1", "1x", "true"}) {
        Device d; stagingDevice(d); testState.stagingBoot=argument;
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,StagingStatus"));
        CHECK(testState.apertureCpuWrites==8);
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
    }
    {
        Device d; stagingDevice(d, false);
        d.run("discovery-snapshot-validated");
        CHECK(stagingStatus(d)=="synthetic-zero-copy-and-restore-verified");
        CHECK(d.service.strings.at("CobaltSurvey,StagingFlushRoute")=="isolated-remap");
        CHECK(d.service.strings.at("CobaltSurvey,StagingGuardMapping")=="read-only-nbif");
        CHECK(testState.apertureCpuWrites==555656 && testState.apertureFlushWrites==3);
        CHECK(testState.apertureCpu==testState.apertureGpu);
        for(size_t i=0;i<testState.apertureCpu.size();++i)
            CHECK(testState.apertureCpu[i]==stagingOriginal(i));
    }
    {
        Device d; stagingDevice(d); testState.apertureBootPresent=false;
        d.run("discovery-snapshot-validated");
        CHECK(!d.service.strings.count("CobaltSurvey,StagingStatus"));
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
    }
    for (unsigned missing=0;missing<3;++missing) {
        Device d; stagingDevice(d);
        if (missing==0) testState.indexedBootPresent=false;
        if (missing==1) testState.stateBootPresent=false;
        if (missing==2) testState.apertureBootPresent=false;
        CHECK(d.service.start(&d.pci)); CHECK(d.service.registered);
        CHECK(d.service.numbers.at("CobaltSurvey,Ready")==0);
        CHECK(!d.service.strings.count("CobaltSurvey,StagingStatus"));
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.apertureCpuWrites==0 && testState.apertureFlushWrites==0);
    }
    {
        Device d; stagingDevice(d);
        d.vram.onMap=[&d] { if(testState.openCalls>=2) d.vram.mapFail=true; };
        d.run("discovery-snapshot-validated");
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.apertureCpuWrites==0);
        CHECK(testState.apertureFlushWrites==0);
        CHECK(testState.mapsLive==0 && testState.backingDescriptorsLive==0);
    }
    {
        Device d; stagingDevice(d); testState.stagingClaimFail=true;
        d.run("discovery-snapshot-validated");
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.selectorWrites==5124);
        CHECK(testState.apertureCpuWrites==0 && testState.apertureFlushWrites==0);
        CHECK(testState.apertureDataReads==0);
    }
    {
        Device d; stagingDevice(d); testState.failAllocationCall=2;
        d.run("discovery-snapshot-validated");
        CHECK(testState.selectorWrites==5124);
        CHECK(testState.apertureCpuWrites==0 && testState.apertureFlushWrites==0);
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.allocations==0);
    }
    {
        Device d; stagingDevice(d); testState.failAllocationCall=3;
        d.run("discovery-snapshot-validated");
        CHECK(testState.selectorWrites==5124);
        CHECK(testState.apertureCpuWrites==0 && testState.apertureFlushWrites==0);
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
        CHECK(testState.allocations==0);
    }
    {
        Device d; stagingDevice(d); testState.apertureCpuRead=[](unsigned read,uint32_t value) {
            return read==262144 ? value^1 : value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(testState.selectorWrites==5124);
        CHECK(testState.apertureCpuWrites==0 && testState.apertureFlushWrites==0);
        CHECK(!d.pci.getProperty("CobaltSurvey,StagingAttempt-v1"));
    }
    {
        Device d; stagingDevice(d);
        testState.apertureCpuRead=[](unsigned read,uint32_t value) {
            return read==524288+12345 ? value^1 : value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.numbers.at("CobaltSurvey,StagingZeroVerified")==0);
        CHECK(d.service.strings.at("CobaltSurvey,StagingVramCleanup")=="restored-observed");
        CHECK(testState.apertureCpuWrites>262144 && testState.apertureFlushWrites==2);
        for(size_t i=0;i<testState.apertureCpu.size();++i) {
            CHECK(testState.apertureCpu[i]==stagingOriginal(i));
            CHECK(testState.apertureGpu[i]==stagingOriginal(i));
        }
    }
    for (const unsigned corruptAt : {0u, 512u, 1024u}) {
        Device d; stagingDevice(d);
        testState.apertureDataRead=[corruptAt](unsigned read,uint32_t value) {
            return read==corruptAt ? value^1 : value;
        };
        d.run("discovery-snapshot-validated");
        CHECK(d.service.numbers.at("CobaltSurvey,StagingRestoreVerified")== (corruptAt==0 ? 0u : 1u));
        CHECK(d.service.strings.at("CobaltSurvey,StagingVramCleanup")==
            (corruptAt==0 ? "not-needed" : "restored-observed"));
        CHECK(d.service.strings.at("CobaltSurvey,StagingSelectorCleanup")=="restored-observed");
        CHECK(testState.apertureFlushWrites==(corruptAt==0 ? 0u : corruptAt==512 ? 2u : 3u));
        for(size_t i=0;i<testState.apertureCpu.size();++i) {
            CHECK(testState.apertureCpu[i]==stagingOriginal(i));
            CHECK(testState.apertureGpu[i]==stagingOriginal(i));
        }
    }
    // Context loss at representative chunk boundaries is sticky. Even if the
    // fake hardware state is changed back immediately, no cleanup write may
    // reuse the stale mappings or selectors.
    for (const unsigned writeAt : {1024u, 131072u, 262144u, 263168u, 293512u,
                                   294536u, 425608u, 555656u}) {
        Device d; stagingDevice(d); bool changed=false;
        testState.onAperture=[&](const MmioEvent &event) {
            if (!changed && event.operation=='v' && testState.apertureCpuWrites==writeAt) {
                changed=true; d.pci.command=0;
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed);
        CHECK(testState.apertureCpuWrites==writeAt);
        CHECK(testState.apertureFlushWrites<=2);
        CHECK(testState.apertureCpuWrites<=555656);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingContextLost")==1);
        CHECK(testState.mapsLive==0 && testState.backingDescriptorsLive==0);
        CHECK(testState.openLive==0 && testState.allocations==0);
    }
    const uint32_t stateOffsets[] = {0x458c,0x4644,0xa950,0xa954};
    const unsigned stateMutationWrites[] = {1024,131072,263168,294536};
    for (unsigned field=0;field<4;++field) {
        Device d; stagingDevice(d); bool changed=false;
        const auto read=testState.stateRead;
        testState.stateRead=[read,&changed,offset=stateOffsets[field]](uint32_t observedOffset,uint32_t value) {
            const uint32_t actual=read(observedOffset,value);
            return changed && observedOffset==offset ? actual^1 : actual;
        };
        testState.onAperture=[&](const MmioEvent &event) {
            if (!changed && event.operation=='v' &&
                testState.apertureCpuWrites==stateMutationWrites[field]) changed=true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed);
        CHECK(testState.apertureCpuWrites==stateMutationWrites[field]);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingContextLost")==1);
        CHECK(testState.apertureFlushWrites<=2);
        CHECK(testState.mapsLive==0 && testState.backingDescriptorsLive==0);
        CHECK(testState.openLive==0 && testState.allocations==0);
    }
    for (unsigned kind=0;kind<2;++kind) {
        Device d; stagingDevice(d); bool changed=false;
        const uint32_t changedOffset=(testState.apertureNbifSegmentBase+(kind==0 ? 0x12d : 0xc3))*4;
        testState.apertureRegisterRead=[&](uint32_t offset,uint32_t value) {
            return changed && offset==changedOffset ? value^1 : value;
        };
        testState.onAperture=[&](const MmioEvent &event) {
            if (!changed && event.operation=='v' && testState.apertureCpuWrites==263168) changed=true;
        };
        d.run("discovery-snapshot-validated");
        CHECK(changed);
        CHECK(testState.apertureCpuWrites==263168);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingContextLost")==1);
        CHECK(testState.apertureFlushWrites==1);
    }
    {
        Device d; stagingDevice(d); bool changed=false;
        testState.onAperture=[&](const MmioEvent &event) {
            if (!changed && event.operation=='v' && testState.apertureCpuWrites==1024) {
                changed=true; d.pci.command=0;
            }
        };
        d.pci.onClose=[&d] { d.pci.command=2; };
        d.run("discovery-snapshot-validated");
        CHECK(changed && d.pci.command==2);
        CHECK(testState.apertureCpuWrites==1024);
        CHECK(testState.apertureFlushWrites==0);
    }
    {
        Device d; stagingDevice(d); bool armed=false, badReturned=false;
        unsigned selectorWritesAtLoss=0;
        const auto read=testState.stateRead;
        testState.stateRead=[read,&armed,&badReturned](uint32_t offset,uint32_t value) {
            const uint32_t actual=read(offset,value);
            if (armed && !badReturned) { badReturned=true; return actual^1; }
            return actual;
        };
        testState.onAperture=[&](const MmioEvent &event) {
            if (!armed && event.operation=='v' && testState.apertureCpuWrites==1024) {
                armed=true; selectorWritesAtLoss=testState.selectorWrites;
            }
        };
        d.run("discovery-snapshot-validated");
        CHECK(badReturned);
        CHECK(testState.apertureCpuWrites==1024);
        CHECK(testState.apertureFlushWrites==0);
        CHECK(testState.selectorWrites==selectorWritesAtLoss);
        CHECK(d.service.numbers.at("CobaltSurvey,StagingContextLost")==1);
        CHECK(d.service.strings.at("CobaltSurvey,StagingVramCleanup")=="restore-skipped-or-unverified");
    }
}

int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--kdb-only") {
            kdbTests();
            std::cout << "CobaltNavi44Survey KDB host checks passed: " << checks << "\n";
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--spl-only") {
            kdbSplTests();
            std::cout << "CobaltNavi44Survey KDB-to-SPL host checks passed: " << checks << "\n";
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--presos-only") {
            preSosTests();
            std::cout << "CobaltNavi44Survey pre-SOS host checks passed: " << checks << "\n";
            return 0;
        }
        activeTestPhase = "gates"; gates();
        activeTestPhase = "pciGuards"; pciGuards();
        activeTestPhase = "mappingFailures"; mappingFailures();
        activeTestPhase = "memsizeGuards"; memsizeGuards();
        activeTestPhase = "apertureGuards"; apertureGuards();
        activeTestPhase = "revalidation"; revalidation();
        activeTestPhase = "parserAndPublication"; parserAndPublication();
        activeTestPhase = "indexedGatesAndPreflight"; indexedGatesAndPreflight();
        activeTestPhase = "indexedExactTransfer"; indexedExactTransfer();
        activeTestPhase = "indexedFaults"; indexedFaults();
        activeTestPhase = "passiveState"; passiveState();
        activeTestPhase = "passiveConsoleTests"; passiveConsoleTests();
        activeTestPhase = "apertureTests"; apertureTests();
        activeTestPhase = "nativeApertureTests"; nativeApertureTests();
        activeTestPhase = "stagingTests"; stagingTests();
        activeTestPhase = "kdbTests"; kdbTests();
        activeTestPhase = "kdbSplTests"; kdbSplTests();
        activeTestPhase = "preSosTests"; preSosTests();
        std::cout << "CobaltNavi44Survey actual-service host checks passed: " << checks << "\n";
    } catch (const std::exception &e) {
        std::cerr << "phase=" << activeTestPhase << ": " << e.what() << "\n"; return 1;
    }
    return 0;
}
