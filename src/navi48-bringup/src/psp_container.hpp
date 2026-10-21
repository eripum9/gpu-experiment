// PSP v2 container parser, adapted from RX4Darwin amdfw.cpp/amdfw.hpp
// commit 49f7f20c00dd154384418078f8a09e79c400a06a (parsePsp, LE helpers).
// Hardened declared-size/table/payload validation and transactional output.
// ABI and primary-package selection checked against Linux v6.19
// drivers/gpu/drm/amd/amdgpu/amdgpu_psp.c:psp_init_sos_microcode.
/*
BSD 3-Clause License

Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef COBALT_PSP_CONTAINER_HPP
#define COBALT_PSP_CONTAINER_HPP
#include <stddef.h>
#include <stdint.h>

namespace cobalt { namespace psp {
enum Part : uint32_t {
    Sos = 1, SysDrv, Kdb, Toc, Spl, Rl, SocDrv, IntfDrv, DbgDrv,
    RasDrv, IpKeyMgrDrv, SpdmDrv, PartCount
};
struct Bin {
    const uint8_t *data;
    uint32_t size;
    uint32_t version;
};
struct Package {
    Bin part[PartCount];
    uint32_t count;       // selected primary descriptors, including unknown types
};
inline uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}
inline uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline bool inside(uint64_t size, uint64_t off, uint64_t len) {
    return off <= size && len <= size - off;
}
// Allocation-free views into the caller-owned input, including unaligned input.
// Accept only v2.0/v2.1. Validate ranges, not CRC/signatures or overlap between
// image ranges: authentication remains the PSP's responsibility.
inline bool parse(const uint8_t *data, uint64_t size, Package &out) {
    out = Package{};
    if (!data || size < 36 || le16(data + 8) != 2) return false;
    const uint16_t minor = le16(data + 10);
    if (minor > 1) return false;
    const uint32_t descBase = minor == 1 ? 40 : 36;
    const uint32_t declared = le32(data);
    const uint32_t header = le32(data + 4);
    if (declared > size || declared < descBase || header < descBase ||
        header > declared) return false;
    const uint32_t total = le32(data + 32);
    if (total == 0 || total >= 32) return false;
    uint32_t count = total;
    if (minor == 1) {
        const uint32_t aux = le32(data + 36);
        if (aux > total) return false;
        // Linux v6.19 normal-package policy: count -= psp_aux_fw_bin_index.
        // Select the first (total - aux) descriptors. The remaining suffix
        // is bounds-validated but never selected, even for duplicate types.
        count -= aux;
    }
    const uint32_t payloadOff = le32(data + 24);
    const uint32_t payloadSize = le32(data + 20);
    const uint64_t tableSize = static_cast<uint64_t>(total) * 16;
    if (!inside(declared, descBase, tableSize) ||
        !inside(payloadOff, descBase, tableSize) || payloadOff < header ||
        !payloadSize || !inside(declared, payloadOff, payloadSize)) return false;
    Package parsed{};
    for (uint32_t i = 0; i < total; ++i) {
        const uint8_t *desc = data + descBase + i * 16;
        const uint32_t type = le32(desc);
        const uint32_t offset = le32(desc + 8);
        const uint32_t length = le32(desc + 12);
        // Apply the same nonempty payload-range rule to known, unknown and
        // auxiliary descriptors. Only selected known types populate slots.
        if (!length || !inside(payloadSize, offset, length)) return false;
        if (i >= count || type == 0 || type >= PartCount) continue;
        if (parsed.part[type].data) return false;
        parsed.part[type] = {data + payloadOff + offset, length, le32(desc + 4)};
    }
    if (!parsed.part[Sos].data || !parsed.part[SysDrv].data) return false;
    parsed.count = count;
    out = parsed;
    return true;
}
} } // namespace cobalt::psp
#endif
