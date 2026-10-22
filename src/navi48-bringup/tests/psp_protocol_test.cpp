// Execute the actual pre-SOS loader against a bounded in-memory bus.
// No GPU, PCI, mapping or DMA API is linked into this host executable.
#include "psp.hpp"
#include "psp_container.hpp"
#include "ipdiscovery.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

static_assert(!std::is_copy_constructible<n48::PspLoader>::value, "preflight authorization cannot be copied");
static_assert(!std::is_copy_assignable<n48::PspLoader>::value, "preflight authorization cannot be assigned");
static_assert(!std::is_move_constructible<n48::PspLoader>::value, "preflight authorization cannot be moved");
static_assert(!std::is_move_assignable<n48::PspLoader>::value, "preflight authorization cannot be move-assigned");
static unsigned checks=0;
#define CHECK(expr) do { ++checks; if(!(expr)) throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": " #expr); } while(0)
using Bytes=std::vector<uint8_t>;
static constexpr uint32_t kReady=0x80000000, kSosCmd=0x20000, kAddressReg=0x64, kCommandReg=0x63, kSosReg=0x91;
static constexpr uint64_t kOffset=32ULL<<20;
static void put32(Bytes &b,size_t off,uint32_t value) { for(unsigned n=0;n<4;++n)b[off+n]=uint8_t(value>>(8*n)); }
static Bytes package(bool all=true, unsigned oversizeType=0) {
    const std::vector<uint32_t> types=all ? std::vector<uint32_t>{3,5,2,7,8,9,10,11,1,4,6} : std::vector<uint32_t>{2,1};
    const uint32_t payload=256;
    uint32_t size=payload;
    for(uint32_t type:types)size+=type==oversizeType ? n48::PspLoader::kFwPriSize+1 : 16;
    Bytes b(size); put32(b,0,size);put32(b,4,36);put32(b,8,2);put32(b,20,size-payload);put32(b,24,payload);put32(b,32,uint32_t(types.size()));
    uint32_t off=0;
    for(size_t i=0;i<types.size();++i) {
        const uint32_t type=types[i], len=type==oversizeType ? n48::PspLoader::kFwPriSize+1 : 16;
        put32(b,36+i*16,type);put32(b,40+i*16,0x100+type);put32(b,44+i*16,off);put32(b,48+i*16,len);
        std::fill(b.begin()+payload+off,b.begin()+payload+off+len,uint8_t(type));off+=len;
    }
    return b;
}
struct Event { char op; uint64_t offset; uint32_t value; size_t size; const void *source=nullptr; };
struct Bus final:n48::HwAccess {
    uint32_t bl=kReady, sol=0, base=0x8000, top=0x83fb;
    uint64_t expectedOffset=kOffset;
    bool sosTimeout=false, readyTimeout=false, timeoutAfterCommand=false;
    unsigned writes=0, failWrite=0, solReads=0;
    unsigned solDelay=0;
    bool issuedSos=false;
    std::vector<Event> events;
    Bytes window=Bytes(n48::PspLoader::kFwPriSize,0xa5);
    std::function<uint32_t(unsigned,uint32_t)> onSolRead;
    uint32_t regReadIp(uint16_t h,uint8_t inst,uint8_t seg,uint32_t reg) override {
        CHECK(inst==0);
        uint32_t result=0;
        if(h==IpDiscovery::HwMp0) {
            CHECK(seg==0);
            if(reg==kCommandReg)result=readyTimeout || (timeoutAfterCommand && writes) ? 0 : bl;
            else if(reg==kSosReg) {
                ++solReads;
                result=issuedSos && !sosTimeout && solReads>solDelay ? 0x3b0f0d : sol;
                if(onSolRead)result=onSolRead(solReads,result);
            } else throw std::runtime_error("unexpected MP0 read");
        } else if(h==IpDiscovery::HwMmhub) {
            CHECK(seg==0); CHECK(reg==0x554 || reg==0x555 || reg==0x4c7);
            result=reg==0x555?top:base;
        } else if(h==IpDiscovery::HwDmu) { CHECK(seg==2 && reg==0x475); result=base; }
        else throw std::runtime_error("unexpected IP read");
        events.push_back({'R',reg,result,h});return result;
    }
    bool allow(char op,uint64_t offset,uint32_t value,size_t size) {
        events.push_back({op,offset,value,size});++writes;return writes!=failWrite;
    }
    bool regWriteIp(uint16_t h,uint8_t inst,uint8_t seg,uint32_t reg,uint32_t value) override {
        CHECK(h==IpDiscovery::HwMp0 && inst==0 && seg==0);
        CHECK(reg==kAddressReg || reg==kCommandReg);
        if(!allow('W',reg,value,4))return false;
        if(reg==kCommandReg && value==kSosCmd)issuedSos=true;
        return true;
    }
    bool vramWrite(uint64_t off,const void *src,size_t len) override {
        CHECK(off==expectedOffset);CHECK(src && len && len<=window.size());
        const bool permitted=allow('C',off,0,len);
        events.back().source=src;
        if(!permitted)return false;
        std::memcpy(window.data(),src,len);return true;
    }
    bool vramMemset(uint64_t off,uint8_t value,size_t len) override {
        CHECK(off==expectedOffset);CHECK(value==0 && len==window.size());
        if(!allow('Z',off,value,len))return false;
        std::fill(window.begin(),window.end(),value);return true;
    }
    std::vector<Event> writeEvents() const { std::vector<Event> out;for(const auto &e:events)if(e.op!='R')out.push_back(e);return out; }
};
static void parsed(n48::PspLoader &loader,const Bytes &b) {CHECK(loader.parseContainer(b.data(),b.size()));}
static void prepare(n48::PspLoader &loader,const Bytes &b,uint64_t offset=kOffset) {
    parsed(loader,b);CHECK(loader.setFwPriOffset(offset));CHECK(loader.preflight());
}
static void noWrites(const Bus &bus) {CHECK(bus.writes==0);CHECK(bus.writeEvents().empty());}
static void checkOrder(const Bus &bus,const Bytes &b) {
    cobalt::psp::Package pkg{};CHECK(cobalt::psp::parse(b.data(),b.size(),pkg));
    const uint32_t types[]={3,5,2,7,8,9,10,11,1};
    const uint32_t commands[]={0x80000,0x10000000,0x10000,0xb0000,0xd0000,0xc0000,0xe0000,0xf0000,0x20000};
    const auto events=bus.writeEvents();size_t at=0;
    for(unsigned i=0;i<9;++i) {
        if(!pkg.part[types[i]].data)continue;
        CHECK(at+4<=events.size());
        CHECK(events[at].op=='Z' && events[at].offset==bus.expectedOffset && events[at].size==n48::PspLoader::kFwPriSize);++at;
        CHECK(events[at].op=='C' && events[at].offset==bus.expectedOffset && events[at].size==pkg.part[types[i]].size);
        CHECK(events[at].source==pkg.part[types[i]].data);++at;
        CHECK(events[at].op=='W' && events[at].offset==kAddressReg && events[at].value==(((uint64_t(bus.base)<<24)+bus.expectedOffset)>>20));++at;
        CHECK(events[at].op=='W' && events[at].offset==kCommandReg && events[at].value==commands[i]);++at;
    }
    CHECK(at==events.size());
    const auto &sos=pkg.part[cobalt::psp::Sos];
    CHECK(std::equal(bus.window.begin(),bus.window.begin()+sos.size,sos.data));
    CHECK(std::all_of(bus.window.begin()+sos.size,bus.window.end(),[](uint8_t v){return v==0;}));
}
static void prerequisiteTests() {
    const auto good=package();
    { Bus b;n48::PspLoader p(b);CHECK(!p.runChain());CHECK(b.events.empty()); }
    { Bus b;n48::PspLoader p(b);parsed(p,good);CHECK(!p.preflight());CHECK(!p.runChain());CHECK(b.events.empty()); }
    { Bus b;n48::PspLoader p(b);CHECK(p.setFwPriOffset(kOffset));CHECK(!p.preflight());CHECK(b.events.empty()); }
    { Bus b;n48::PspLoader p(b);prepare(p,good,0);b.expectedOffset=0;CHECK(p.runChain());checkOrder(b,good); }
    const uint64_t invalidOffsets[]={1,UINT64_MAX,UINT64_MAX&~uint64_t(n48::PspLoader::kFwPriSize-1)};
    for(uint64_t off:invalidOffsets) {
        Bus b;n48::PspLoader p(b);prepare(p,good);CHECK(!p.setFwPriOffset(off));CHECK(!p.preflight());CHECK(!p.runChain());noWrites(b);
    }
    for(unsigned change=0;change<5;++change) {
        Bus b;n48::PspLoader p(b);prepare(p,good);
        if(change==0)CHECK(p.setFwPriOffset(kOffset));
        if(change==1)parsed(p,good);
        if(change==2)CHECK(!p.parseContainer(nullptr,0));
        if(change==3)p.sos.size=n48::PspLoader::kFwPriSize+1;
        if(change==4)p.sys.data=nullptr;
        CHECK(!p.runChain());noWrites(b);
    }
    // All selected components must be valid before any write, including late SOS/IPKEY.
    for(unsigned type:{1u,2u,3u,5u,7u,8u,9u,10u,11u}) {
        const auto bad=package(true,type);Bus b;n48::PspLoader p(b);parsed(p,bad);CHECK(p.setFwPriOffset(kOffset));
        CHECK(!p.preflight());CHECK(!p.runChain());noWrites(b);
    }
    for(unsigned kind=0;kind<4;++kind) {
        Bus b;n48::PspLoader p(b);prepare(p,good);
        if(kind==0)++p.ipkey.version;
        if(kind==1)++p.ipkey.data;
        if(kind==2)++p.ipkey.size;
        if(kind==3) {p.ras.data=nullptr;p.ras.size=0;}
        CHECK(!p.runChain());noWrites(b);
    }
    { auto source=good;Bus b;n48::PspLoader p(b);prepare(p,source);put32(source,0,0);CHECK(!p.runChain());noWrites(b); }
    // Rejected preflight clears an earlier successful authorization.
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.bl=0;CHECK(!p.preflight());b.bl=kReady;CHECK(!p.runChain());noWrites(b); }
}
static void addressTests() {
    const auto good=package(false);
    for(unsigned kind=0;kind<7;++kind) {
        Bus b;n48::PspLoader p(b);parsed(p,good);
        uint64_t off=kOffset;
        if(kind==0)b.base=0;
        if(kind==1)b.top=b.base-1;
        if(kind==2)b.base=UINT32_MAX;
        if(kind==3)b.top=UINT32_MAX;
        if(kind==4)off=UINT64_MAX-((1ULL<<21)-1); // aligned offset+size fits, base+offset wraps
        if(kind==5)off=1ULL<<52; // MC>>20 cannot fit the mailbox
        if(kind==6)off=(uint64_t(b.top+1-b.base)<<24); // exactly outside the upper edge
        CHECK(p.setFwPriOffset(off));CHECK(!p.preflight());CHECK(!p.runChain());noWrites(b);
    }
    { Bus b;n48::PspLoader p(b);parsed(p,good);const uint64_t off=(uint64_t(b.top+1-b.base)<<24)-n48::PspLoader::kFwPriSize;
      b.expectedOffset=off;CHECK(p.setFwPriOffset(off));CHECK(p.preflight());CHECK(p.runChain());checkOrder(b,good); }
}
static void protocolTests(const Bytes &good) {
    { Bus b;n48::PspLoader p(b);prepare(p,good);CHECK(p.runChain());checkOrder(b,good);
      const auto count=b.writes;CHECK(!p.runChain());CHECK(b.writes==count); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.sol=0x55;CHECK(p.runChain());noWrites(b);CHECK(!p.runChain()); }
    { Bus b;b.sol=0x55;b.bl=0;n48::PspLoader p(b);prepare(p,good);CHECK(p.runChain());noWrites(b); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.readyTimeout=true;CHECK(!p.runChain());noWrites(b);CHECK(!p.runChain()); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.timeoutAfterCommand=true;CHECK(!p.runChain());CHECK(b.writes==4);CHECK(!p.runChain()); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.sosTimeout=true;CHECK(!p.runChain());CHECK(b.issuedSos);const auto count=b.writes;CHECK(!p.runChain());CHECK(b.writes==count); }
    // Every failed bus operation must be the last write attempted.
    Bus reference;n48::PspLoader successful(reference);prepare(successful,good);CHECK(successful.runChain());
    for(unsigned fail=1;fail<=reference.writes;++fail) {
        Bus b;b.failWrite=fail;n48::PspLoader p(b);prepare(p,good);CHECK(!p.runChain());CHECK(b.writes==fail);
        CHECK(!p.runChain());CHECK(b.writes==fail);
    }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.failWrite=1;CHECK(!p.runChain());
      b.failWrite=0;CHECK(p.preflight());CHECK(p.runChain()); }
}
static void unreadableSosTests() {
    const auto good=package(false);
    { Bus b;b.sol=UINT32_MAX;n48::PspLoader p(b);parsed(p,good);CHECK(p.setFwPriOffset(kOffset));
      CHECK(!p.preflight());CHECK(!p.runChain());noWrites(b); }
    // Read1 belongs to preflight,2 to runChain,3 to SYS,4 to SOS,
    // 5 after SOS staging and6 to the final sign-of-life wait.
    for(unsigned failAt=2;failAt<=6;++failAt) {
        Bus b;n48::PspLoader p(b);prepare(p,good);
        b.onSolRead=[failAt](unsigned at,uint32_t value) {return at==failAt?UINT32_MAX:value;};
        CHECK(!p.runChain());
        const unsigned expected=failAt<=3?0u:failAt==4?4u:failAt==5?6u:8u;
        CHECK(b.writes==expected);CHECK(b.solReads==failAt);
        CHECK(p.lastBootloaderStatus()==UINT32_MAX);
        const size_t events=b.events.size();CHECK(!p.runChain());CHECK(b.writes==expected);CHECK(b.events.size()==events);
    }
}
int main(int argc,char **argv) {
    try {
        prerequisiteTests();addressTests();unreadableSosTests();protocolTests(package());protocolTests(package(false));
        for(int i=1;i<argc;++i) {
            std::ifstream f(argv[i],std::ios::binary);CHECK(f.good());
            const Bytes bytes((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
            protocolTests(bytes);std::printf("Validated actual PSP protocol with package: %s\n",argv[i]);
        }
        std::printf("Actual PSP loader protocol checks passed: %u\n",checks);
    } catch(const std::exception &e) {std::fprintf(stderr,"%s\n",e.what());return 1;}
}
