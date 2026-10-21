// Shared PSP parser corpus; PSP_ADAPTER_TEST also executes both real loader TUs.
#include "psp_container.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
#ifdef PSP_ADAPTER_TEST
#include "psp.hpp"
#include "amd/amdgpu_psp.h"
namespace amdgpu { void n48_logf(const char *, ...) {} }
#ifdef _WIN32
extern "C" void bzero(void *p, size_t size) { std::memset(p, 0, size); }
#endif
struct NoHardware : n48::HwAccess {
    uint32_t regReadIp(uint16_t, uint8_t, uint8_t, uint32_t) override { std::abort(); }
    bool regWriteIp(uint16_t, uint8_t, uint8_t, uint32_t, uint32_t) override { std::abort(); }
    bool vramWrite(uint64_t, const void *, size_t) override { std::abort(); }
    bool vramMemset(uint64_t, uint8_t, size_t) override { std::abort(); }
};
#endif
using namespace cobalt::psp;
using Bytes = std::vector<uint8_t>;
static unsigned checks;
static void expect(bool ok, const char *what) {
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", what); std::exit(1); }
}
static void put(Bytes &b, size_t off, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (i * 8));
}
static Bytes fixture(unsigned minor = 0, uint32_t total = 2, uint32_t aux = 0) {
    Bytes b(512, 0);
    put(b, 0, 512); put(b, 4, minor ? 40 : 36);
    put(b, 8, 2 | (minor << 16)); put(b, 12, 14);
    put(b, 20, 256); put(b, 24, 256); put(b, 32, total);
    if (minor) put(b, 36, aux);
    for (uint32_t i = 0; i < total && i < 12; ++i) {
        const size_t at = (minor ? 40u : 36u) + i * 16;
        put(b, at, i + 1); put(b, at + 4, 0x100 + i);
        put(b, at + 8, i * 8); put(b, at + 12, 8);
    }
    return b;
}
static bool empty(const Package &p) {
    if (p.count) return false;
    for (const auto &bin : p.part) if (bin.data || bin.size || bin.version) return false;
    return true;
}
static void check(const uint8_t *data, size_t size, bool valid, const char *what) {
    Package p{};
    p.count = 19;
    for (auto &bin : p.part) bin = {data, 42, 123};
    expect(parse(data, size, p) == valid, what);
    if (!valid) expect(empty(p), "failed parse clears entire shared output");
#ifdef PSP_ADAPTER_TEST
    NoHardware hw;
    n48::PspLoader pre(hw);
    amdgpu::PSPContext post{};
    const auto good = fixture(0, 12);
    expect(pre.parseContainer(good.data(), good.size()), "seed pre adapter");
    expect(amdgpu::psp_parse_sos_microcode(post, good.data(), good.size()) == kIOReturnSuccess,
           "seed post adapter");
    post.sys_drv_aux = {good.data(), 7, 31};
    post.sos_aux = {good.data(), 9, 41};
    expect(pre.parseContainer(data, size) == valid, what);
    expect((amdgpu::psp_parse_sos_microcode(post, data, size) == kIOReturnSuccess) == valid, what);
    const n48::SubBin *preSlots[PartCount] = {nullptr, &pre.sos, &pre.sys, &pre.kdb,
        &pre.toc, &pre.spl, &pre.rl, &pre.soc, &pre.intf, &pre.dbg, &pre.ras, &pre.ipkey, &pre.spdm};
    const amdgpu::PSPContext::PSPSubBin *postSlots[PartCount] = {nullptr, &post.sos,
        &post.sys, &post.kdb, &post.toc, &post.spl, &post.rl, &post.soc_drv,
        &post.intf_drv, &post.dbg_drv, &post.ras_drv, &post.ipkeymgr_drv, &post.spdm_drv};
    for (unsigned i = 1; i < PartCount; ++i) {
        expect(preSlots[i]->data == p.part[i].data && preSlots[i]->size == p.part[i].size &&
               preSlots[i]->version == p.part[i].version, "pre adapter has transactional slots");
        expect(postSlots[i]->start_addr == p.part[i].data && postSlots[i]->size_bytes == p.part[i].size &&
               postSlots[i]->fw_version == p.part[i].version, "post adapter has transactional slots");
    }
    expect(post.sos_fw_blob == (valid ? data : nullptr) && post.sos_fw_blob_size == (valid ? size : 0),
           "post adapter has transactional blob metadata");
    expect(!post.sys_drv_aux.start_addr && !post.sys_drv_aux.size_bytes && !post.sys_drv_aux.fw_version &&
           !post.sos_aux.start_addr && !post.sos_aux.size_bytes && !post.sos_aux.fw_version,
           "auxiliary slots stay empty");
#endif
}
static void check(const Bytes &b, bool valid, const char *what) { check(b.data(), b.size(), valid, what); }
static void changed(const Bytes &good, size_t off, uint32_t value, const char *what) {
    auto b = good; put(b, off, value); check(b, false, what);
}
int main(int argc, char **argv) {
    const auto good = fixture();
    check(good, true, "valid v2.0");
    Package p{}; expect(parse(good.data(), good.size(), p), "parse known values");
    expect(p.count == 2 && p.part[Sos].data == good.data() + 256 &&
           p.part[SysDrv].data == good.data() + 264 && p.part[Sos].size == 8 &&
           p.part[Sos].version == 0x100, "descriptor offsets, lengths, versions");
    check(fixture(1), true, "v2.1 no auxiliary");
    auto aux = fixture(1, 4, 2);
    put(aux, 40 + 2 * 16, Sos); put(aux, 40 + 3 * 16, SysDrv);
    check(aux, true, "auxiliary duplicate known types do not override primary");
    expect(parse(aux.data(), aux.size(), p) && p.count == 2 && p.part[Sos].data == aux.data() + 256,
           "Linux primary prefix selected");
    auto asymmetric = fixture(1, 5, 2);
    put(asymmetric, 40 + 3 * 16, Sos); put(asymmetric, 40 + 4 * 16, SysDrv);
    check(asymmetric, true, "v2.1 asymmetric primary and auxiliary counts");
    expect(parse(asymmetric.data(), asymmetric.size(), p) && p.count == 3 &&
           p.part[Kdb].data == asymmetric.data() + 272 &&
           p.part[Kdb].version == 0x102 && p.part[Sos].data == asymmetric.data() + 256,
           "Linux total minus auxiliary selection differs from auxiliary-index interpretation");
    changed(aux, 40 + 3 * 16 + 8, 256, "auxiliary descriptor bounds checked");
    changed(aux, 36, 5, "auxiliary count above total");
    changed(aux, 36, 4, "no primary SOS or SYS");
    changed(aux, 36, 3, "SYS only in auxiliary is insufficient");
    auto unknown = fixture(0, 3); put(unknown, 36 + 32, 99);
    check(unknown, true, "unknown primary allowed after range validation");
    changed(unknown, 36 + 32 + 8, 256, "unknown primary range checked");
    put(unknown, 36 + 32, 0); check(unknown, true, "reserved type skipped after range validation");
    changed(unknown, 36 + 32 + 12, 0, "unknown primary must be nonempty");
    auto overlap = good; put(overlap, 36 + 16 + 8, 0); check(overlap, true, "payload aliases allowed");
    auto trailing = good; trailing.resize(520); check(trailing, true, "physical trailing bytes permitted");
    auto unaligned = good; unaligned.insert(unaligned.begin(), 0);
    check(unaligned.data() + 1, good.size(), true, "unaligned input");
    check(nullptr, 512, false, "null input");
    for (size_t n = 0; n < good.size(); ++n) check(good.data(), n, false, "every v2.0 truncation");
    for (size_t n = 0; n < aux.size(); ++n) check(aux.data(), n, false, "every v2.1 truncation");
    changed(good, 0, 513, "declared container exceeds actual input");
    changed(good, 0, 35, "declared container below fixed header");
    changed(good, 0, 511, "payload exceeds declared size despite physical bytes");
    changed(good, 4, 35, "header below fixed prefix");
    changed(good, 4, 513, "header beyond declared size");
    changed(good, 4, 257, "header beyond payload start");
    changed(good, 8, 2 | (2 << 16), "future minor rejected");
    changed(good, 8, 3, "future major rejected");
    changed(good, 20, 0, "empty payload");
    changed(good, 20, 0xffffffffu, "payload size overflow attempt");
    changed(good, 24, 0xffffffffu, "payload offset overflow attempt");
    changed(good, 24, 35, "payload before header");
    changed(good, 24, 64, "descriptor table overlaps payload");
    changed(good, 32, 0, "empty table");
    changed(good, 32, 32, "Linux descriptor limit exclusive");
    changed(good, 32, 31, "table extends into payload");
    changed(good, 32, 0xffffffffu, "descriptor count overflow attempt");
    changed(good, 36 + 16, Sos, "duplicate primary known type");
    changed(good, 36, Kdb, "missing SOS");
    changed(good, 36 + 16, Kdb, "missing SYS");
    changed(good, 36 + 12, 0, "empty selected known image");
    changed(good, 36 + 8, 256, "image beyond payload");
    changed(good, 36 + 8, 0xffffffffu, "image offset overflow attempt");
    changed(good, 36 + 12, 0xffffffffu, "image length overflow attempt");
    // 31 descriptors are accepted when the complete table precedes the payload.
    auto max = fixture(); max.resize(1280); put(max, 0, 1280); put(max, 24, 1024); put(max, 32, 31);
    for (uint32_t i = 2; i < 31; ++i) {
        put(max, 36 + i * 16, 99); put(max, 36 + i * 16 + 12, 1);
    }
    check(max, true, "31 complete descriptors accepted");
    for (int i = 1; i < argc; ++i) {
        std::ifstream stream(argv[i], std::ios::binary);
        expect(stream.good(), "open real firmware");
        Bytes bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        check(bytes, true, argv[i]);
        expect(parse(bytes.data(), bytes.size(), p), "real parser result");
        const uint32_t base = le16(bytes.data() + 10) ? 40 : 36;
        for (uint32_t j = 0; j < p.count; ++j) {
            const uint8_t *d = bytes.data() + base + j * 16;
            const uint32_t type = le32(d);
            if (!type || type >= PartCount) continue;
            expect(p.part[type].data == bytes.data() + le32(bytes.data() + 24) + le32(d + 8) &&
                   p.part[type].version == le32(d + 4) && p.part[type].size == le32(d + 12),
                   "every real descriptor retains its offset, size and version");
        }
        std::printf("Validated real PSP package: %s (%u primary descriptors)\n", argv[i], p.count);
    }
    std::printf("PSP container checks passed: %u\n", checks);
}
