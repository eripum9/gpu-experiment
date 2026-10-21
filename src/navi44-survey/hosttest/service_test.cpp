#include "CobaltNavi44Survey.hpp"
#include <FakeIOKit.hpp>
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
    }
    void load(const Bytes &b) { std::memcpy(vram.storage.data(),b.data(),b.size()); }
    void run(const char *expected) {
        CHECK(service.start(&pci)); CHECK(service.registered);
        CHECK(service.strings.at("CobaltSurvey,Status")==expected);
        CHECK(service.numbers.at("CobaltSurvey,Ready")==0);
        CHECK(testState.mapsLive==0); CHECK(testState.allocations==0);
        CHECK(testState.backingDescriptorsLive==0);
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

int main() {
    try {
        gates(); pciGuards(); mappingFailures(); memsizeGuards(); apertureGuards();
        revalidation(); parserAndPublication();
        std::cout << "CobaltNavi44Survey actual-service host checks passed: " << checks << "\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n"; return 1;
    }
    return 0;
}
