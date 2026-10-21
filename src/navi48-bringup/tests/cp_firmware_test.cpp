#include "../src/cp_firmware_builder.hpp"
#include <stdio.h>
#include <string.h>
#include <initializer_list>

namespace {
unsigned failures;
#define CHECK(expr) do { if (!(expr)) { printf("FAIL line %d: %s\n", __LINE__, #expr); ++failures; } } while (0)

cobalt_gpu_info_v1 identity(bool navi44 = false) {
    cobalt_gpu_info_v1 id {};
    id.version = 1; id.size = sizeof(id);
    id.flags = COBALT_GPU_INFO_CAPACITY_VALID | (navi44 ? 0u : COBALT_GPU_INFO_BRINGUP_ENABLED);
    id.pci_vendor = 0x1002; id.pci_device = navi44 ? 0x7590 : 0x7550;
    id.gfx_target = navi44 ? 1200 : 1201; id.gc_major = 12; id.gc_revision = navi44 ? 0 : 1;
    id.shader_engines = 2; id.shader_arrays_per_engine = 2;
    id.wgp_per_array = 4; id.cu_per_array = 8; id.max_compute_units = 32;
    id.render_backends_per_engine = 4; id.max_waves_per_simd = 16;
    return id;
}
bool zero(const cobalt_cp_firmware_v1 &r) {
    cobalt_cp_firmware_v1 empty {};
    return memcmp(&r, &empty, sizeof(r)) == 0;
}
void put32(uint8_t *b, unsigned offset, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) b[offset + i] = static_cast<uint8_t>(value >> (8u * i));
}
struct Entry { uint32_t fw_type; const uint8_t *src; uint32_t size; bool staged; };
struct Fixture {
    // One extra byte makes every header unaligned, including the 60-byte reads.
    uint8_t storage[3][321] {};
    cobalt::CpFirmwareBlob blobs[3] {};
    Entry entries[9] {};
    cobalt_gpu_info_v1 id;
    explicit Fixture(bool navi44 = false) : id(identity(navi44)) {
        const uint32_t versions[] = {3110, 3220, 3490};
        for (unsigned i = 0; i < 3; ++i) {
            uint8_t *b = storage[i] + 1;
            blobs[i] = {b, 320};
            put32(b, 0, 320); put32(b, 4, 60); put32(b, 8, 2); put32(b, 12, 12);
            put32(b, 16, versions[i]); put32(b, 20, 64); put32(b, 24, 256);
            put32(b, 32, 29); put32(b, 36, 32); put32(b, 40, 256);
            put32(b, 44, 32); put32(b, 48, 288);
        }
        const unsigned types[] = {87, 90, 88, 92, 89, 94, 95};
        const unsigned owners[] = {1, 1, 0, 0, 2, 2, 2};
        for (unsigned i = 0; i < 7; ++i)
            entries[i] = {types[i], blobs[owners[i]].data + ((i == 0 || i == 2 || i == 4) ? 256 : 288), 32, true};
    }
    bool build(cobalt_cp_firmware_v1 &out, uint32_t count = 7, bool completed = true) {
        return cobalt::make_cp_firmware(id, blobs, entries, count, completed, out);
    }
    void rejected() {
        cobalt_cp_firmware_v1 out; memset(&out, 0xa5, sizeof(out));
        CHECK(!build(out)); CHECK(zero(out));
    }
};
void bad_wire(const cobalt_cp_firmware_v1 &record, const cobalt_gpu_info_v1 &id) {
    cobalt_cp_firmware_v1 out; memset(&out, 0xa5, sizeof(out));
    CHECK(!cobalt_cp_firmware_v1_decode(&record, sizeof(record), &id, &out)); CHECK(zero(out));
}
} // namespace

int main() {
    Fixture f;
    cobalt_cp_firmware_v1 r {};
    CHECK(f.build(r));
    CHECK(r.me_version == 3110 && r.pfp_version == 3220 && r.mec_version == 3490);
    CHECK(r.me_feature == 29 && r.pfp_feature == 29 && r.mec_feature == 29);
    CHECK(r.flags == COBALT_CP_FIRMWARE_PSP_LOAD_COMPLETED && r.gc_version == 0x0c0001);
    for (unsigned i = 0; i < 6; ++i) CHECK(r.reserved[i] == 0);
    Fixture n44(true); cobalt_cp_firmware_v1 r44 {};
    CHECK(n44.build(r44) && r44.gc_version == 0x0c0000);
    // A fixture representing the second family uses its own blob addresses.
    CHECK(r44.me_version == r.me_version && r44.pfp_version == r.pfp_version && r44.mec_version == r.mec_version);
    for (unsigned i = 0; i < 3; ++i) {
        Fixture padded; put32(padded.storage[i] + 1, 4, 256); CHECK(padded.build(r));
    }
    CHECK(cobalt::cp_firmware_fresh_load_ready(false, false, 8));
    CHECK(cobalt::cp_firmware_fresh_load_ready(false, false, 17));
    for (unsigned reached = 0; reached < 8; ++reached) CHECK(!cobalt::cp_firmware_fresh_load_ready(false, false, reached));
    CHECK(!cobalt::cp_firmware_fresh_load_ready(true, false, 17));
    CHECK(!cobalt::cp_firmware_fresh_load_ready(false, true, 17));
    CHECK(!f.build(r, 7, false) && zero(r));
    CHECK(!f.build(r, 0) && zero(r));
    CHECK(!f.build(r, 65) && zero(r));
    CHECK(!cobalt::make_cp_firmware(f.id, f.blobs, static_cast<const Entry *>(nullptr), 7, true, r) && zero(r));
    for (unsigned i = 0; i < 7; ++i) {
        Fixture missing; missing.entries[i].fw_type = 18; missing.rejected();
        Fixture unstaged; unstaged.entries[i].staged = false; unstaged.rejected();
        Fixture offset; offset.entries[i].src++; offset.rejected();
        Fixture size; size.entries[i].size--; size.rejected();
        Fixture duplicate; duplicate.entries[7] = duplicate.entries[i];
        CHECK(!duplicate.build(r, 8) && zero(r));
    }
    for (unsigned unexpected : {91u, 93u, 96u, 97u}) {
        Fixture extra; extra.entries[7] = {unexpected, extra.blobs[0].data + 288, 32, true};
        CHECK(!extra.build(r, 8) && zero(r));
    }
    Fixture unrelated; unrelated.entries[7] = {18, nullptr, 0, false}; CHECK(unrelated.build(r, 8));
    Fixture foreign; foreign.entries[0].src = n44.entries[0].src; foreign.rejected();
    Fixture invalidId; invalidId.id.max_compute_units--; invalidId.rejected();

    // Every truncation, including the 60-byte header boundary, fails closed.
    for (unsigned i = 0; i < 3; ++i) {
        for (size_t length = 0; length < 320; ++length) {
            Fixture truncated; truncated.blobs[i].size = length; truncated.rejected();
        }
        Fixture absent; absent.blobs[i].data = nullptr; absent.rejected();
        struct Mutation { unsigned offset; uint32_t value; };
        const Mutation mutations[] = {
            {0, 319}, {0, 321}, {4, 59}, {4, 257}, {4, UINT32_MAX},
            {8, 1}, {8, 0x00010002}, {12, 11}, {12, 0x0001000c},
            {16, 0}, {16, UINT32_MAX}, {20, 0}, {20, 63}, {20, UINT32_MAX},
            {24, 59}, {24, UINT32_MAX}, {32, UINT32_MAX}, {36, 0},
            {36, 65}, {36, UINT32_MAX}, {40, 257}, {44, 0}, {44, 33},
            {44, UINT32_MAX}, {48, 255}, {48, 287}, {48, 321}, {48, UINT32_MAX}
        };
        for (const auto &mutation : mutations) {
            Fixture malformed; put32(malformed.storage[i] + 1, mutation.offset, mutation.value); malformed.rejected();
        }
    }
    // No pinned version substitution: metadata follows accepted blob fields.
    Fixture changed; put32(changed.storage[0] + 1, 16, 4001); put32(changed.storage[1] + 1, 32, 0);
    CHECK(changed.build(r) && r.me_version == 4001 && r.pfp_feature == 0);
    cobalt_cp_firmware_v1 saved {}; CHECK(f.build(saved));
    cobalt_cp_firmware_v1 restored {};
    CHECK(cobalt_cp_firmware_v1_decode(&saved, sizeof(saved), &f.id, &restored));
    CHECK(restored.me_version == 3110); // Saved provisioning survives a newer build's blobs.
    bad_wire(saved, n44.id); // Saved GC revision cannot cross owners/families.

    const unsigned offsets[] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36};
    const uint32_t invalids[] = {0, 63, 0, 0x0c0000, 0, UINT32_MAX, 0, UINT32_MAX, 0, UINT32_MAX};
    for (unsigned i = 0; i < 10; ++i) {
        cobalt_cp_firmware_v1 bad = saved;
        put32(reinterpret_cast<uint8_t *>(&bad), offsets[i], invalids[i]); bad_wire(bad, f.id);
    }
    for (unsigned i = 0; i < 6; ++i) { auto bad = saved; bad.reserved[i] = 1; bad_wire(bad, f.id); }
    for (uint32_t flag : {2u, 3u, UINT32_MAX}) { auto bad = saved; bad.flags = flag; bad_wire(bad, f.id); }
    for (unsigned i : {16u, 24u, 32u}) {
        auto bad = saved; put32(reinterpret_cast<uint8_t *>(&bad), i, UINT32_MAX); bad_wire(bad, f.id);
    }
    for (size_t length = 0; length < sizeof(saved); ++length) {
        memset(&restored, 0xa5, sizeof(restored));
        CHECK(!cobalt_cp_firmware_v1_decode(&saved, length, &f.id, &restored) && zero(restored));
    }
    CHECK(!cobalt_cp_firmware_v1_decode(&saved, sizeof(saved) + 1, &f.id, &restored) && zero(restored));
    CHECK(!cobalt_cp_firmware_v1_decode(nullptr, sizeof(saved), &f.id, &restored) && zero(restored));
    CHECK(!cobalt_cp_firmware_v1_decode(&saved, sizeof(saved), nullptr, &restored) && zero(restored));
    CHECK(!cobalt_cp_firmware_v1_decode(&saved, sizeof(saved), &f.id, nullptr));
    alignas(cobalt_cp_firmware_v1) uint8_t bytes[sizeof(saved) + 8] {};
    memcpy(bytes + 1, &saved, sizeof(saved));
    CHECK(cobalt_cp_firmware_v1_decode(bytes + 1, sizeof(saved), &f.id, &restored));
    memcpy(bytes + 4, &saved, sizeof(saved));
    CHECK(cobalt_cp_firmware_v1_decode(bytes + 4, sizeof(saved), &f.id,
        reinterpret_cast<cobalt_cp_firmware_v1 *>(bytes)));
    CHECK(memcmp(bytes, &saved, sizeof(saved)) == 0);
    memcpy(bytes, &saved, sizeof(saved));
    CHECK(cobalt_cp_firmware_v1_decode(bytes, sizeof(saved), &f.id,
        reinterpret_cast<cobalt_cp_firmware_v1 *>(bytes + 4)));
    CHECK(memcmp(bytes + 4, &saved, sizeof(saved)) == 0);
    CHECK(cobalt_cp_firmware_v1_decode(&saved, sizeof(saved), &f.id, &saved));
    printf("cp_firmware_test: %s (%u failures)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
