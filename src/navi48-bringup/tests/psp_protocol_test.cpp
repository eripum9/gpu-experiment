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
static constexpr uint64_t kSplOffset=kOffset+n48::PspLoader::kFwPriSize;
static constexpr uint64_t kSysOffset=kSplOffset+n48::PspLoader::kFwPriSize;
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
    unsigned commandReads=0;
    unsigned solDelay=0;
    bool issuedSos=false;
	bool dualWindow=false, tripleWindow=false, mailboxAttempted=false;
    uint64_t splOffset=kSplOffset;
	uint64_t sysOffset=kSysOffset;
    std::vector<Event> events;
    Bytes window=Bytes(n48::PspLoader::kFwPriSize,0xa5);
    Bytes splWindow=Bytes(n48::PspLoader::kFwPriSize,0xa5);
    Bytes sysWindow=Bytes(n48::PspLoader::kFwPriSize,0xa5);
    std::function<uint32_t(unsigned,uint32_t)> onSolRead;
    std::function<uint32_t(unsigned,uint32_t)> onCommandRead;
    uint32_t regReadIp(uint16_t h,uint8_t inst,uint8_t seg,uint32_t reg) override {
        CHECK(inst==0);
        uint32_t result=0;
        if(h==IpDiscovery::HwMp0) {
            CHECK(seg==0);
            if(reg==kCommandReg) {
                ++commandReads;
                result=readyTimeout || (timeoutAfterCommand && writes) ? 0 : bl;
                if(onCommandRead)result=onCommandRead(commandReads,result);
            }
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
        mailboxAttempted=true; // Includes a failed address-store attempt.
        if(!allow('W',reg,value,4))return false;
        if(reg==kCommandReg && value==kSosCmd)issuedSos=true;
        return true;
    }
    bool vramWrite(uint64_t off,const void *src,size_t len) override {
		CHECK((!dualWindow && !tripleWindow) || !mailboxAttempted);
		CHECK(off==expectedOffset || ((dualWindow || tripleWindow) && off==splOffset) || (tripleWindow && off==sysOffset));CHECK(src && len && len<=window.size());
        const bool permitted=allow('C',off,0,len);
        events.back().source=src;
        if(!permitted)return false;
		auto &target=off==expectedOffset?window:off==splOffset?splWindow:sysWindow;
        std::memcpy(target.data(),src,len);return true;
    }
    bool vramMemset(uint64_t off,uint8_t value,size_t len) override {
		CHECK((!dualWindow && !tripleWindow) || !mailboxAttempted);
		CHECK(off==expectedOffset || ((dualWindow || tripleWindow) && off==splOffset) || (tripleWindow && off==sysOffset));CHECK(value==0 && len==window.size());
        if(!allow('Z',off,value,len))return false;
		auto &target=off==expectedOffset?window:off==splOffset?splWindow:sysWindow;
        std::fill(target.begin(),target.end(),value);return true;
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
static void checkKdbOnly(const Bus &bus,const Bytes &source) {
    cobalt::psp::Package pkg{};CHECK(cobalt::psp::parse(source.data(),source.size(),pkg));
    const auto &kdb=pkg.part[cobalt::psp::Kdb];CHECK(kdb.data && kdb.size);
    const auto events=bus.writeEvents();CHECK(events.size()==4);
    CHECK(events[0].op=='Z' && events[0].offset==bus.expectedOffset && events[0].size==n48::PspLoader::kFwPriSize);
    CHECK(events[1].op=='C' && events[1].offset==bus.expectedOffset && events[1].size==kdb.size);
    CHECK(events[1].source==kdb.data);
    CHECK(events[2].op=='W' && events[2].offset==kAddressReg);
    CHECK(events[2].value==(((uint64_t(bus.base)<<24)+bus.expectedOffset)>>20));
    CHECK(events[3].op=='W' && events[3].offset==kCommandReg && events[3].value==0x80000);
    CHECK(std::equal(bus.window.begin(),bus.window.begin()+kdb.size,kdb.data));
    CHECK(std::all_of(bus.window.begin()+kdb.size,bus.window.end(),[](uint8_t v){return v==0;}));
    CHECK(std::count_if(events.begin(),events.end(),[](const Event &e){return e.op=='W' && e.offset==kCommandReg;})==1);
}
static void keyDatabaseTests(const Bytes &good) {
    { Bus b;n48::PspLoader p(b);prepare(p,good);CHECK(p.runKeyDatabase());checkKdbOnly(b,good);
      const auto n=b.writes;CHECK(!p.runKeyDatabase());CHECK(!p.runChain());CHECK(b.writes==n); }
    { const auto noKdb=package(false);Bus b;n48::PspLoader p(b);prepare(p,noKdb);CHECK(!p.runKeyDatabase());noWrites(b);CHECK(!p.runChain()); }
    // A KDB probe consumes the same one-shot token as runChain, on success or failure.
    { Bus b;n48::PspLoader p(b);prepare(p,good);CHECK(p.runChain());const auto n=b.writes;CHECK(!p.runKeyDatabase());CHECK(b.writes==n); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.bl=0;CHECK(!p.preflight());b.bl=kReady;
      CHECK(!p.runKeyDatabase());noWrites(b); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.readyTimeout=true;CHECK(!p.runKeyDatabase());noWrites(b);CHECK(!p.runChain()); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.timeoutAfterCommand=true;CHECK(!p.runKeyDatabase());CHECK(b.writes==4);CHECK(!p.runChain()); }
    for(unsigned fail=1;fail<=4;++fail) {
        Bus b;n48::PspLoader p(b);prepare(p,good);b.failWrite=fail;
        CHECK(!p.runKeyDatabase());CHECK(b.writes==fail);
        const size_t events=b.events.size();
        CHECK(!p.runKeyDatabase());CHECK(!p.runChain());
        CHECK(b.writes==fail && b.events.size()==events);
    }
    // Busy zero may transition directly to ready; no busy-low handshake is required.
    { Bus b;n48::PspLoader p(b);prepare(p,good);
      b.onCommandRead=[](unsigned at,uint32_t value){return at==2?0u:value;};
      CHECK(p.runKeyDatabase());checkKdbOnly(b,good);CHECK(b.commandReads>=4); }
    // Invalidated or mutated public views/window cannot use the preflight token.
    for(unsigned kind=0;kind<5;++kind) {
        Bus b;n48::PspLoader p(b);prepare(p,good);
        if(kind==0)++p.kdb.version;
        if(kind==1)++p.kdb.data;
        if(kind==2)++p.kdb.size;
        if(kind==3)p.sys.data=nullptr;
        if(kind==4)CHECK(p.setFwPriOffset(kOffset));
        CHECK(!p.runKeyDatabase());noWrites(b);CHECK(!p.runChain());
    }
    { Bus b;n48::PspLoader p(b);parsed(p,good);CHECK(p.setFwPriOffset(kOffset));CHECK(!p.runKeyDatabase());noWrites(b); }
    { Bus b;n48::PspLoader p(b);prepare(p,good);b.sol=0x55;CHECK(!p.runKeyDatabase());noWrites(b); }
    // A single bad bootloader-status read is terminal even if a later read
    // would report ready; strict polling must never turn that into success.
    for(unsigned badRead:{2u,3u}) {
      Bus b;n48::PspLoader p(b);prepare(p,good);
      b.onCommandRead=[badRead](unsigned at,uint32_t value){return at==badRead?UINT32_MAX:value;};
      CHECK(!p.runKeyDatabase());CHECK(b.commandReads==badRead);CHECK(b.writes==(badRead==2?0u:4u));CHECK(!p.runChain());
    }
    // SOS transitions/unreadable reads at each strict checkpoint stop before
    // any later staging or mailbox action. Read 1 is preflight.
    const unsigned phases[]={2,3,4,5,6,7,8,9};
    for(unsigned phase:phases)for(uint32_t state:{0x55u,UINT32_MAX}) {
        Bus b;n48::PspLoader p(b);prepare(p,good);
        b.onSolRead=[phase,state](unsigned at,uint32_t value){return at==phase?state:value;};
        CHECK(!p.runKeyDatabase());
        const unsigned expected=phase<=5?0u:phase==6?2u:phase==7?3u:4u;
        CHECK(b.writes==expected);
        const auto events=b.writeEvents();
        CHECK(std::count_if(events.begin(),events.end(),[](const Event &e){return e.op=='Z' || e.op=='C';})==(expected>=2?2:0));
        CHECK(std::count_if(events.begin(),events.end(),[](const Event &e){return e.op=='W' && e.offset==kCommandReg;})==(phase>=8?1:0));
        CHECK(!p.runChain());CHECK(b.writes==expected);
    }
}
static void consumed(n48::PspLoader &p,const Bus &b) {
    const size_t count=b.events.size();
    CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(!p.runKeyDatabase());CHECK(!p.runChain());
    CHECK(b.events.size()==count);
}
static void stagedPair(const Bus &b,const Bytes &source) {
    cobalt::psp::Package pkg{};CHECK(cobalt::psp::parse(source.data(),source.size(),pkg));
    const Bytes *windows[]={&b.window,&b.splWindow};
    const auto parts={cobalt::psp::Kdb,cobalt::psp::Spl};unsigned at=0;
    for(const auto part:parts) {
        const auto &bin=pkg.part[part];const auto &window=*windows[at++];
        CHECK(bin.data && bin.size);
        CHECK(std::equal(window.begin(),window.begin()+bin.size,bin.data));
        CHECK(std::all_of(window.begin()+bin.size,window.end(),[](uint8_t v){return v==0;}));
    }
}
static void checkPair(const Bus &b,const Bytes &source) {
    cobalt::psp::Package pkg{};CHECK(cobalt::psp::parse(source.data(),source.size(),pkg));
    const auto events=b.writeEvents();CHECK(events.size()==8);
    const auto &kdb=pkg.part[cobalt::psp::Kdb], &spl=pkg.part[cobalt::psp::Spl];
    CHECK(events[0].op=='Z' && events[0].offset==b.expectedOffset && events[0].size==n48::PspLoader::kFwPriSize);
    CHECK(events[1].op=='C' && events[1].offset==b.expectedOffset && events[1].size==kdb.size && events[1].source==kdb.data);
    CHECK(events[2].op=='Z' && events[2].offset==b.splOffset && events[2].size==n48::PspLoader::kFwPriSize);
    CHECK(events[3].op=='C' && events[3].offset==b.splOffset && events[3].size==spl.size && events[3].source==spl.data);
    for(unsigned i=0;i<2;++i) {
        const auto &address=events[4+i*2], &command=events[5+i*2];
        const uint64_t offset=i==0?b.expectedOffset:b.splOffset;
        CHECK(address.op=='W' && address.offset==kAddressReg && address.value==(((uint64_t(b.base)<<24)+offset)>>20));
        CHECK(command.op=='W' && command.offset==kCommandReg && command.value==(i==0?0x80000u:0x10000000u));
    }
    CHECK(events[4].value!=events[6].value);CHECK(!b.issuedSos);
    stagedPair(b,source);
}
static void keyDatabaseAndSplPrerequisites() {
    const auto good=package();
    { Bus b;n48::PspLoader p(b);CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.events.empty()); }
    { Bus b;n48::PspLoader p(b);parsed(p,good);CHECK(p.setFwPriOffset(kOffset));
      CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.events.empty()); }
    const uint64_t invalid[]={kOffset,kOffset+1,kOffset+n48::PspLoader::kFwPriSize-1,1,
        UINT64_MAX,UINT64_MAX&~uint64_t(n48::PspLoader::kFwPriSize-1),
        UINT64_MAX-((1ULL<<21)-1),1ULL<<52,(uint64_t(0x83fb+1-0x8000)<<24)};
    for(uint64_t off:invalid) {
        Bus b;n48::PspLoader p(b);prepare(p,good);const auto reads=b.events.size();
        CHECK(!p.runKeyDatabaseAndSpl(off));CHECK(b.events.size()==reads);noWrites(b);consumed(p,b);
    }
    // Each required component is independently absent in an otherwise valid package.
    for(unsigned descriptor:{0u,1u}) {
        auto source=good;put32(source,36+descriptor*16,0);
        Bus b;n48::PspLoader p(b);prepare(p,source);const auto reads=b.events.size();
        CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.events.size()==reads);noWrites(b);consumed(p,b);
    }
    // Revalidate the whole selected chain, including components this probe will not dispatch.
    for(unsigned slot=0;slot<9;++slot)for(unsigned field=0;field<3;++field) {
        Bus b;n48::PspLoader p(b);prepare(p,good);
        n48::SubBin *slots[]={&p.kdb,&p.spl,&p.sys,&p.soc,&p.intf,&p.dbg,&p.ras,&p.ipkey,&p.sos};
        if(field==0)++slots[slot]->data;
        if(field==1)++slots[slot]->size;
        if(field==2)++slots[slot]->version;
        const auto reads=b.events.size();CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));
        CHECK(b.events.size()==reads);noWrites(b);consumed(p,b);
    }
    for(unsigned kind=0;kind<5;++kind) {
        auto source=good;Bus b;n48::PspLoader p(b);prepare(p,source);
        if(kind==0)put32(source,0,0);
        if(kind==1)parsed(p,source);
        if(kind==2)CHECK(!p.parseContainer(nullptr,0));
        if(kind==3)CHECK(p.setFwPriOffset(kOffset));
        if(kind==4)CHECK(!p.setFwPriOffset(1));
        const auto reads=b.events.size();CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));
        CHECK(b.events.size()==reads);noWrites(b);consumed(p,b);
    }
    for(unsigned type:{1u,2u,3u,5u,7u,8u,9u,10u,11u}) {
        const auto bad=package(true,type);Bus b;n48::PspLoader p(b);parsed(p,bad);CHECK(p.setFwPriOffset(kOffset));
        CHECK(!p.preflight());const auto reads=b.events.size();CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));
        CHECK(b.events.size()==reads);noWrites(b);
    }
    // A fresh token used by any API cannot subsequently authorize any other API.
    for(unsigned first=0;first<3;++first) {
        Bus b;b.dualWindow=first==2;n48::PspLoader p(b);prepare(p,good);
        CHECK(first==0?p.runChain():first==1?p.runKeyDatabase():p.runKeyDatabaseAndSpl(kSplOffset));consumed(p,b);
    }
    // Either physical order and the upper posted boundary are legal when disjoint.
    for(unsigned layout=0;layout<3;++layout) {
        Bus b;b.dualWindow=true;
        b.expectedOffset=layout==0?0:layout==1?kSplOffset:kOffset;
        b.splOffset=layout==0?n48::PspLoader::kFwPriSize:layout==1?kOffset:
            (uint64_t(b.top+1-b.base)<<24)-n48::PspLoader::kFwPriSize;
        n48::PspLoader p(b);prepare(p,good,b.expectedOffset);
        CHECK(p.runKeyDatabaseAndSpl(b.splOffset));checkPair(b,good);consumed(p,b);
    }
}
// Number of writes before the nth occurrence of a particular register read.
static unsigned writesBeforeRead(const Bus &b,uint32_t reg,unsigned nth) {
    unsigned writes=0,reads=0;
    for(const auto &event:b.events) {
        if(event.op!='R')++writes;
        else if(event.offset==reg && ++reads==nth)return writes;
    }
    throw std::runtime_error("missing reference read");
}
static void keyDatabaseAndSplTests(const Bytes &good) {
    Bus reference;reference.dualWindow=true;n48::PspLoader successful(reference);prepare(successful,good);
    CHECK(successful.runKeyDatabaseAndSpl(kSplOffset));checkPair(reference,good);
    CHECK(std::string(successful.lastStep())=="SPL");CHECK(successful.lastBootloaderStatus()==kReady);consumed(successful,reference);
    // Every failing staging/address/command attempt terminates at exactly that prefix.
    for(unsigned fail=1;fail<=8;++fail) {
        Bus b;b.dualWindow=true;b.failWrite=fail;n48::PspLoader p(b);prepare(p,good);
        CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.writes==fail);
        const auto actual=b.writeEvents(),expected=reference.writeEvents();
        for(unsigned i=0;i<fail;++i) {
            CHECK(actual[i].op==expected[i].op && actual[i].offset==expected[i].offset &&
                actual[i].value==expected[i].value && actual[i].size==expected[i].size && actual[i].source==expected[i].source);
        }
        if(fail>=5)stagedPair(b,good);
        consumed(p,b);
    }
    // Exercise every strict SOS checkpoint before, between, and after components.
    for(unsigned phase=2;phase<=reference.solReads;++phase)for(uint32_t state:{0x55u,UINT32_MAX}) {
        Bus b;b.dualWindow=true;n48::PspLoader p(b);prepare(p,good);
        b.onSolRead=[phase,state](unsigned at,uint32_t value){return at==phase?state:value;};
        CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.solReads==phase);
        CHECK(b.writes==writesBeforeRead(reference,kSosReg,phase));
        if(state==UINT32_MAX)CHECK(p.lastBootloaderStatus()==UINT32_MAX);
        if(b.writes>=4)stagedPair(b,good);
        consumed(p,b);
    }
    // The first unreadable status is terminal at every readiness poll.
    for(unsigned phase=2;phase<=reference.commandReads;++phase) {
        Bus b;b.dualWindow=true;n48::PspLoader p(b);prepare(p,good);
        b.onCommandRead=[phase](unsigned at,uint32_t value){return at==phase?UINT32_MAX:value;};
        CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.commandReads==phase);
        CHECK(b.writes==writesBeforeRead(reference,kCommandReg,phase));CHECK(p.lastBootloaderStatus()==UINT32_MAX);
        if(b.writes>=4)stagedPair(b,good);
        consumed(p,b);
    }
    // Every staging and mailbox operation has a direct ready check. An
    // unexpected busy read there must fail immediately, even if the next read
    // would be ready; only the explicit initial/completion waits may poll.
    unsigned commandRead=0,latestRead=0;
    for(const auto &event:reference.events) {
        if(event.op=='R' && event.offset==kCommandReg)latestRead=++commandRead;
        if(event.op=='R')continue;
        Bus b;b.dualWindow=true;n48::PspLoader p(b);prepare(p,good);
        b.onCommandRead=[latestRead](unsigned at,uint32_t value){return at==latestRead?0u:value;};
        CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.commandReads==latestRead);
        CHECK(b.writes==writesBeforeRead(reference,kCommandReg,latestRead));CHECK(p.lastBootloaderStatus()==0);
        if(b.writes>=4)stagedPair(b,good);
        consumed(p,b);
    }
    // Each wait also permits busy-low followed by ready, including after each command.
    { Bus b;b.dualWindow=true;n48::PspLoader p(b);prepare(p,good);
      bool initial=false,kdb=false,spl=false;
      b.onCommandRead=[&](unsigned,uint32_t value){
          bool *seen=b.writes==0?&initial:b.writes==6?&kdb:b.writes==8?&spl:nullptr;
          if(seen && !*seen) {*seen=true;return 0u;}return value;
      };
      CHECK(p.runKeyDatabaseAndSpl(kSplOffset));CHECK(initial && kdb && spl);
      CHECK(b.commandReads==reference.commandReads+3);checkPair(b,good); }
    // Unready before preparation/dispatch, then completion timeouts at KDB/SPL.
    for(unsigned threshold:{0u,4u,6u,8u}) {
        Bus b;b.dualWindow=true;n48::PspLoader p(b);prepare(p,good);
        b.onCommandRead=[&b,threshold](unsigned,uint32_t value){return b.writes>=threshold?0u:value;};
        CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(b.writes==threshold);CHECK(p.lastBootloaderStatus()==0);
        if(threshold>=4)stagedPair(b,good);
        if(threshold==6)CHECK(std::string(p.lastStep())=="KDB");
        if(threshold==8)CHECK(std::string(p.lastStep())=="SPL");
        consumed(p,b);
    }
}
static void consumedTriple(n48::PspLoader &p,const Bus &b) {
    const size_t count=b.events.size();
    CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));
    CHECK(!p.runKeyDatabaseAndSpl(kSplOffset));CHECK(!p.runKeyDatabase());CHECK(!p.runChain());
    CHECK(b.events.size()==count);
}
static void checkTriple(const Bus &b,const Bytes &source) {
    cobalt::psp::Package pkg{};CHECK(cobalt::psp::parse(source.data(),source.size(),pkg));
    const auto events=b.writeEvents();CHECK(events.size()==12);
    const uint32_t parts[]={cobalt::psp::Kdb,cobalt::psp::Spl,cobalt::psp::SysDrv};
    const uint64_t offsets[]={b.expectedOffset,b.splOffset,b.sysOffset};
    const Bytes *windows[]={&b.window,&b.splWindow,&b.sysWindow};
    for(unsigned i=0;i<3;++i) {
        const auto &bin=pkg.part[parts[i]];
        CHECK(bin.data && bin.size);
        CHECK(events[i*2].op=='Z' && events[i*2].offset==offsets[i] && events[i*2].size==n48::PspLoader::kFwPriSize);
        CHECK(events[i*2+1].op=='C' && events[i*2+1].offset==offsets[i] && events[i*2+1].size==bin.size && events[i*2+1].source==bin.data);
        CHECK(std::equal(windows[i]->begin(),windows[i]->begin()+bin.size,bin.data));
        CHECK(std::all_of(windows[i]->begin()+bin.size,windows[i]->end(),[](uint8_t v){return v==0;}));
    }
    const uint32_t commands[]={0x80000,0x10000000,0x10000};
    for(unsigned i=0;i<3;++i) {
        const auto &address=events[6+i*2], &command=events[7+i*2];
        CHECK(address.op=='W' && address.offset==kAddressReg && address.value==(((uint64_t(b.base)<<24)+offsets[i])>>20));
        CHECK(command.op=='W' && command.offset==kCommandReg && command.value==commands[i]);
    }
    CHECK(!b.issuedSos);
}
static void keyDatabaseSplAndSysTests(const Bytes &good) {
    { Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);
      CHECK(p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));checkTriple(b,good);
      CHECK(std::string(p.lastStep())=="SYS_DRV");CHECK(p.lastBootloaderStatus()==kReady);consumedTriple(p,b); }
    // The three windows may occupy any of six aligned, disjoint layouts.
    for(unsigned permutation=0;permutation<6;++permutation) {
        const uint64_t positions[]={0,n48::PspLoader::kFwPriSize,2ULL*n48::PspLoader::kFwPriSize};
        static const unsigned perms[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
        Bus b;b.tripleWindow=true;b.expectedOffset=kOffset+positions[perms[permutation][0]];
        b.splOffset=kOffset+positions[perms[permutation][1]];b.sysOffset=kOffset+positions[perms[permutation][2]];
        n48::PspLoader p(b);prepare(p,good,b.expectedOffset);
        CHECK(p.runKeyDatabaseSplAndSys(b.splOffset,b.sysOffset));checkTriple(b,good);
    }
    // Adjacent windows and windows ending exactly at the posted top are valid.
    { Bus b;b.tripleWindow=true;b.expectedOffset=0;b.splOffset=n48::PspLoader::kFwPriSize;
      b.sysOffset=2ULL*n48::PspLoader::kFwPriSize;n48::PspLoader p(b);prepare(p,good,0);
      CHECK(p.runKeyDatabaseSplAndSys(b.splOffset,b.sysOffset));checkTriple(b,good); }
    { Bus b;b.tripleWindow=true;const uint64_t end=(uint64_t(b.top+1-b.base)<<24);
      b.expectedOffset=end-3ULL*n48::PspLoader::kFwPriSize;b.splOffset=end-2ULL*n48::PspLoader::kFwPriSize;
      b.sysOffset=end-n48::PspLoader::kFwPriSize;n48::PspLoader p(b);prepare(p,good,b.expectedOffset);
      CHECK(p.runKeyDatabaseSplAndSys(b.splOffset,b.sysOffset));checkTriple(b,good); }
    const uint64_t invalid[][2]={{kOffset,kSysOffset},{kOffset+1,kSysOffset},{kSplOffset,kSplOffset},
        {kOffset,kOffset},{kSysOffset,kSysOffset},{kSysOffset+1,kSplOffset},
        {UINT64_MAX,kSysOffset},{UINT64_MAX&~uint64_t(n48::PspLoader::kFwPriSize-1),kSysOffset},
        {1ULL<<52,kSysOffset},{(uint64_t(0x83fb+1-0x8000)<<24),kSysOffset},
        {kSplOffset,kOffset},{kSplOffset,kOffset+1},{kSplOffset,kSplOffset},
        {kOffset,kOffset},{kOffset,kSysOffset+1},
        {kSplOffset,UINT64_MAX},{kSplOffset,UINT64_MAX&~uint64_t(n48::PspLoader::kFwPriSize-1)},
        {kSplOffset,1ULL<<52},{kSplOffset,(uint64_t(0x83fb+1-0x8000)<<24)}};
    for(const auto &pair:invalid) {
        Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);const auto reads=b.events.size();
        CHECK(!p.runKeyDatabaseSplAndSys(pair[0],pair[1]));CHECK(b.events.size()==reads);noWrites(b);consumedTriple(p,b);
    }
    if(good.size()==432) {
        for(unsigned descriptor:{0u,1u}) {
            auto source=good;put32(source,36+descriptor*16,0);
            Bus b;b.tripleWindow=true;n48::PspLoader p(b);parsed(p,source);CHECK(p.setFwPriOffset(kOffset));
            CHECK(p.preflight());const auto reads=b.events.size();CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));
            CHECK(b.events.size()==reads);noWrites(b);
        }
        auto source=good;put32(source,36+2*16,0);Bus b;n48::PspLoader p(b);
        CHECK(!p.parseContainer(source.data(),source.size()));CHECK(!p.preflight());noWrites(b);
    }
    for(unsigned slot=0;slot<9;++slot)for(unsigned field=0;field<3;++field) {
        Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);
        n48::SubBin *slots[]={&p.kdb,&p.spl,&p.sys,&p.soc,&p.intf,&p.dbg,&p.ras,&p.ipkey,&p.sos};
        if(field==0)++slots[slot]->data;if(field==1)++slots[slot]->size;if(field==2)++slots[slot]->version;
        const size_t reads=b.events.size();CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));
        CHECK(b.events.size()==reads);noWrites(b);consumedTriple(p,b);
    }
    // Every one of the twelve mutating calls is a terminal prefix on failure.
    Bus reference;reference.tripleWindow=true;n48::PspLoader success(reference);prepare(success,good);
    CHECK(success.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));checkTriple(reference,good);
    for(unsigned fail=1;fail<=12;++fail) {
        Bus b;b.tripleWindow=true;b.failWrite=fail;n48::PspLoader p(b);prepare(p,good);
        CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));CHECK(b.writes==fail);
        const auto actual=b.writeEvents(),expected=reference.writeEvents();CHECK(actual.size()==fail);
        for(unsigned i=0;i<fail;++i) {
            CHECK(actual[i].op==expected[i].op && actual[i].offset==expected[i].offset &&
                actual[i].value==expected[i].value && actual[i].size==expected[i].size && actual[i].source==expected[i].source);
        }
        consumedTriple(p,b);
    }
    // Direct ready reads followed by SOS-down reads immediately before each mutation
    // abort on busy or unreadable, independently of the polling reads.
    unsigned cmdRead=0,guardTargets=0;
    for(size_t i=0;i+2<reference.events.size();++i) {
        if(reference.events[i].op=='R' && reference.events[i].offset==kCommandReg)++cmdRead;
        if(reference.events[i].op!='R' || reference.events[i].offset!=kCommandReg ||
           reference.events[i+1].op!='R' || reference.events[i+1].offset!=kSosReg ||
           reference.events[i+2].op=='R')continue;
        ++guardTargets;
        const unsigned target=cmdRead;
        for(uint32_t state:{0u,UINT32_MAX}) {
            Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);
            b.onCommandRead=[target,state](unsigned at,uint32_t value){return at==target?state:value;};
            CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));
            CHECK(b.commandReads==target);CHECK(b.writes==writesBeforeRead(reference,kCommandReg,target));
            CHECK(!p.runChain());
        }
    }
    CHECK(guardTargets==12);
    // Strict SOS-down checks around preparation, all staging and every dispatch.
    unsigned sosRead=0;
    for(size_t i=0;i<reference.events.size();++i) {
        if(reference.events[i].op!='R' || reference.events[i].offset!=kSosReg)continue;
        const unsigned target=++sosRead;
        if(target<=1)continue; // The one preflight SOS read occurs before callback installation.
        for(uint32_t state:{0x55u,UINT32_MAX}) {
            Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);
            b.onSolRead=[target,state](unsigned at,uint32_t value){return at==target?state:value;};
            CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));CHECK(b.solReads==target);
            CHECK(b.writes==writesBeforeRead(reference,kSosReg,target));CHECK(!p.runChain());
        }
    }
    // Strict completion polls must stop on the first all-ones status read.
    for(unsigned phase=2;phase<=reference.commandReads;++phase) {
        Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);
        b.onCommandRead=[phase](unsigned at,uint32_t value){return at==phase?UINT32_MAX:value;};
        CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));CHECK(b.commandReads==phase);
        CHECK(b.writes==writesBeforeRead(reference,kCommandReg,phase));CHECK(p.lastBootloaderStatus()==UINT32_MAX);
    }
    // Initial and each completion wait may transition from busy to ready.
    { Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);bool initial=false,kdb=false,spl=false,sys=false;
      b.onCommandRead=[&](unsigned,uint32_t value){bool *seen=b.writes==0?&initial:b.writes==8?&kdb:
          b.writes==10?&spl:b.writes==12?&sys:nullptr;if(seen && !*seen){*seen=true;return 0u;}return value;};
      CHECK(p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));CHECK(initial&&kdb&&spl&&sys);checkTriple(b,good); }
    // Shared authorization is consumed by every entry point, after success and refusal.
    for(unsigned first=0;first<4;++first) {
        Bus b;b.tripleWindow=first!=0;n48::PspLoader p(b);prepare(p,good);
        const bool result=first==0?p.runChain():first==1?p.runKeyDatabase():first==2?
            p.runKeyDatabaseAndSpl(kSplOffset):p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset);
        CHECK(result);const size_t count=b.events.size();consumedTriple(p,b);CHECK(b.events.size()==count);
    }
    for(unsigned first=0;first<4;++first) {
        Bus b;b.dualWindow=first==2;b.tripleWindow=first==3;n48::PspLoader p(b);prepare(p,good);b.failWrite=1;
        const bool result=first==0?p.runChain():first==1?p.runKeyDatabase():first==2?
            p.runKeyDatabaseAndSpl(kSplOffset):p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset);
        CHECK(!result);b.failWrite=0;consumedTriple(p,b);
    }
    // Completion timeouts stop after the relevant command, without later mailbox writes.
    for(unsigned threshold:{6u,8u,10u,12u}) {
        Bus b;b.tripleWindow=true;n48::PspLoader p(b);prepare(p,good);
        b.onCommandRead=[&b,threshold](unsigned,uint32_t value){return b.writes>=threshold?0u:value;};
        CHECK(!p.runKeyDatabaseSplAndSys(kSplOffset,kSysOffset));CHECK(b.writes==threshold);
        CHECK(!p.runChain());
    }
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
        prerequisiteTests();addressTests();unreadableSosTests();protocolTests(package());protocolTests(package(false));keyDatabaseTests(package());
        keyDatabaseAndSplPrerequisites();keyDatabaseAndSplTests(package());
        keyDatabaseSplAndSysTests(package());
        for(int i=1;i<argc;++i) {
            std::ifstream f(argv[i],std::ios::binary);CHECK(f.good());
            const Bytes bytes((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
            if(std::string(argv[i]).find("14_0_2")!=std::string::npos) {
                cobalt::psp::Package pinned{};CHECK(cobalt::psp::parse(bytes.data(),bytes.size(),pinned));
                const auto &spl=pinned.part[cobalt::psp::Spl], &kdb=pinned.part[cobalt::psp::Kdb];
                CHECK(spl.version==0x01003b00 && spl.size==832 && spl.data-bytes.data()==0x66a20);
                CHECK(kdb.size==6816 && kdb.data-bytes.data()==256);
                const auto &sys=pinned.part[cobalt::psp::SysDrv];
                CHECK(sys.version==0x003b0f0d && sys.size==78272 && sys.data-bytes.data()==0x1ba0);
            }
            protocolTests(bytes);keyDatabaseTests(bytes);keyDatabaseAndSplTests(bytes);keyDatabaseSplAndSysTests(bytes);
            std::printf("Validated actual PSP protocol with package: %s\n",argv[i]);
        }
        std::printf("Actual PSP loader protocol checks passed: %u\n",checks);
    } catch(const std::exception &e) {std::fprintf(stderr,"%s\n",e.what());return 1;}
}
