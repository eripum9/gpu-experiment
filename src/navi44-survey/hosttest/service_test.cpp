#include "CobaltNavi44Survey.hpp"
#include <FakeIOKit.hpp>
#include "ipdiscovery.hpp"
#include <iostream>

static unsigned checks = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) throw std::runtime_error( \
    std::string("line ") + std::to_string(__LINE__) + ": " #expression); } while (0)
using Bytes = std::vector<uint8_t>;
static void put16(Bytes &b, size_t p, uint16_t v) { b[p] = uint8_t(v); b[p+1] = uint8_t(v >> 8); }
static void put32(Bytes &b, size_t p, uint32_t v) { for (unsigned i=0; i<4; ++i) b[p+i] = uint8_t(v >> (8*i)); }
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

int main() {
    try {
        gates(); pciGuards(); mappingFailures(); memsizeGuards(); apertureGuards();
        revalidation(); parserAndPublication();
        indexedGatesAndPreflight(); indexedExactTransfer(); indexedFaults(); passiveState(); passiveConsoleTests();
        std::cout << "CobaltNavi44Survey actual-service host checks passed: " << checks << "\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n"; return 1;
    }
    return 0;
}
