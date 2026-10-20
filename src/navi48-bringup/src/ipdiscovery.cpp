#include "ipdiscovery.hpp"

// AMD discovery.h v6.19: binary_header v1 table_list begins at byte 12;
// table_info is 8 bytes. IPDS v3 uses the 32-bit ip_v3 base-address layout.
static constexpr uint32_t kBinarySignature = 0x28211407;
static constexpr uint32_t kIpdsSignature = 0x53445049;
static constexpr uint32_t kGcSignature = 0x4347;
static constexpr size_t kBinaryHeaderV1Size = 12 + 6 * 8;
static constexpr size_t kIpdsV3HeaderSize = 80; // 12 + num_dies + 16 die_info + u16 padding

bool IpDiscovery::readU8(size_t off, uint8_t &v) const {
	if (off >= size) return false;
	v = data[off];
	return true;
}

bool IpDiscovery::readU16(size_t off, uint16_t &v) const {
	if (off > size || size - off < 2) return false;
	v = static_cast<uint16_t>(data[off] | (static_cast<uint16_t>(data[off + 1]) << 8));
	return true;
}

bool IpDiscovery::readU32(size_t off, uint32_t &v) const {
	if (off > size || size - off < 4) return false;
	v = static_cast<uint32_t>(data[off]) |
	    (static_cast<uint32_t>(data[off + 1]) << 8) |
	    (static_cast<uint32_t>(data[off + 2]) << 16) |
	    (static_cast<uint32_t>(data[off + 3]) << 24);
	return true;
}

bool IpDiscovery::validateIpList(size_t dieOffset, size_t tableEnd, uint16_t count) const {
	if (dieOffset > tableEnd || tableEnd - dieOffset < 4 || count == 0 || count > 256)
		return false;
	size_t p = dieOffset + 4;
	for (uint16_t i = 0; i < count; ++i) {
		if (p > tableEnd || tableEnd - p < 8) return false;
		uint8_t nbase;
		if (!readU8(p + 3, nbase) || nbase > MaxBases) return false;
		const size_t baseBytes = static_cast<size_t>(nbase) * 4;
		if (tableEnd - p - 8 < baseBytes) return false;
		p += 8 + baseBytes;
	}
	return true;
}

bool IpDiscovery::validateBinary(size_t offset) {
	uint16_t major, minor, checksum, binSize;
	uint32_t sig;
	if (!readU32(offset, sig) || sig != kBinarySignature ||
	    !readU16(offset + 4, major) || !readU16(offset + 6, minor) ||
	    !readU16(offset + 8, checksum) || !readU16(offset + 10, binSize)) return false;
	// Only the documented v1 header is implemented; don't guess at v2 layouts.
	if (major != 1 || minor != 3 || binSize < kBinaryHeaderV1Size ||
	    offset > size || size - offset < binSize) return false;
	const size_t binEnd = offset + binSize;
	uint16_t sum = 0;
	for (size_t i = offset + 10; i < binEnd; ++i)
		sum = static_cast<uint16_t>(sum + data[i]);
	if (sum != checksum) return false;

	uint16_t tableOffset, tableChecksum, tableSize;
	if (!readU16(offset + 12, tableOffset) || !readU16(offset + 14, tableChecksum) ||
	    !readU16(offset + 16, tableSize) || tableOffset < kBinaryHeaderV1Size || tableSize < kIpdsV3HeaderSize ||
	    tableOffset > binSize || tableSize > binSize - tableOffset) return false;
	const size_t ipds = offset + tableOffset;

	uint32_t ipdsSig;
	uint16_t ipdsVersion, ipdsSize, numDies;
	if (!readU32(ipds, ipdsSig) || ipdsSig != kIpdsSignature ||
	    !readU16(ipds + 4, ipdsVersion) || !readU16(ipds + 6, ipdsSize) ||
	    !readU16(ipds + 12, numDies) || ipdsVersion != 3 || ipdsSize < kIpdsV3HeaderSize ||
	    ipdsSize > tableSize || numDies != 1) return false;
	// Linux verifies IP_DISCOVERY using ip_discovery_header.size as the
	// checksum length. The enclosing table_info.size is an independent bound.
	uint16_t tableSum = 0;
	for (size_t i = ipds; i < ipds + ipdsSize; ++i)
		tableSum = static_cast<uint16_t>(tableSum + data[i]);
	if (tableSum != tableChecksum) return false;
	uint16_t listedDieId, dieOffset;
	if (!readU16(ipds + 14, listedDieId) || listedDieId != 0 ||
	    !readU16(ipds + 16, dieOffset) || dieOffset < tableOffset + kIpdsV3HeaderSize ||
	    dieOffset > tableOffset + ipdsSize) return false;
	const size_t die = offset + dieOffset;
	uint16_t dieId, nips;
	const size_t ipdsEnd = ipds + ipdsSize;
	if (!readU16(die, dieId) || dieId != 0 || !readU16(die + 2, nips) ||
	    !validateIpList(die, ipdsEnd, nips)) return false;

	binBase = offset;
	dieBase = die;
	dieEnd = ipdsEnd;
	numIps = nips;
	return true;
}

bool IpDiscovery::init(const uint8_t *buffer, size_t bufferSize) {
	data = buffer;
	size = bufferSize;
	valid = false;
	binBase = dieBase = dieEnd = 0;
	numIps = 0;
	if (!data || size < kBinaryHeaderV1Size) return false;
	const size_t lastStart = size - kBinaryHeaderV1Size;
	for (size_t off = 0; off <= lastStart;) {
		uint32_t sig;
		if (readU32(off, sig) && sig == kBinarySignature && validateBinary(off)) {
			valid = true;
			return true;
		}
		if (lastStart - off < 4) break;
		off += 4;
	}
	return false;
}

bool IpDiscovery::ipAt(uint16_t index, IpEntry &out) const {
	if (!valid || index >= numIps) return false;
	size_t p = dieBase + 4;
	for (uint16_t i = 0; i <= index; ++i) {
		if (p > dieEnd || dieEnd - p < 8) return false;
		uint16_t hwId;
		uint8_t inst, nbase, major, minor, rev;
		if (!readU16(p, hwId) || !readU8(p + 2, inst) || !readU8(p + 3, nbase) ||
		    !readU8(p + 4, major) || !readU8(p + 5, minor) || !readU8(p + 6, rev)) return false;
		out.hwId = hwId;
		out.instance = inst;
		out.major = major;
		out.minor = minor;
		out.revision = rev;
		out.numBases = nbase;
		if (nbase > MaxBases || dieEnd - p - 8 < static_cast<size_t>(nbase) * 4) return false;
		for (uint8_t b = 0; b < nbase; ++b)
			if (!readU32(p + 8 + static_cast<size_t>(b) * 4, out.bases[b])) return false;
		if (i == index) return true;
		p += 8 + static_cast<size_t>(nbase) * 4;
	}
	return false;
}

bool IpDiscovery::findIp(uint16_t hwId, uint8_t instance, IpEntry &out) const {
	for (uint16_t i = 0; i < numIps; ++i) {
		if (!ipAt(i, out)) return false;
		if (out.hwId == hwId && out.instance == instance) return true;
	}
	return false;
}

bool IpDiscovery::gcTopology(GcTopology &out) const {
	out = {};
	if (!valid) return false;
	uint16_t binSize, tableOffset, tableChecksum, tableSize;
	if (!readU16(binBase + 10, binSize) || !readU16(binBase + 20, tableOffset) ||
	    !readU16(binBase + 22, tableChecksum) || !readU16(binBase + 24, tableSize)) return false;
	// The table_info entry bounds the complete GC table independently of the
	// binary header and of the declared inner table size.
	if (tableOffset < kBinaryHeaderV1Size || tableOffset > binSize ||
	    tableSize < 12 || tableSize > binSize - tableOffset) return false;
	const size_t gc = binBase + tableOffset;
	const size_t gcEnd = gc + tableSize;
	if ((gc < dieEnd && gcEnd > binBase + 60) || gcEnd < gc) return false;
	uint32_t signature;
	uint16_t major, minor;
	if (!readU32(gc, signature) || signature != kGcSignature ||
	    !readU16(gc + 4, major) || !readU16(gc + 6, minor)) return false;
	// gpu_info_header.size is a 32-bit value; require it inside table_info.
	uint32_t declaredSize;
	if (!readU32(gc + 8, declaredSize) || declaredSize < 12 || declaredSize > tableSize) return false;
	size_t minimumSize;
	if (major != 1) return false;
	switch (minor) {
	case 0: minimumSize = 88; break;
	case 1: minimumSize = 100; break;
	case 2: minimumSize = 132; break;
	case 3: minimumSize = 164; break;
	default: return false;
	}
	if (declaredSize < minimumSize) return false;
	uint16_t sum = 0;
	for (size_t i = gc; i < gc + declaredSize; ++i)
		sum = static_cast<uint16_t>(sum + data[i]);
	if (sum != tableChecksum) return false;
	uint32_t se, wgp0, wgp1, rb, waves, sa;
	if (!readU32(gc + 12, se) || !readU32(gc + 16, wgp0) ||
	    !readU32(gc + 20, wgp1) || !readU32(gc + 24, rb) ||
	    !readU32(gc + 60, waves) || !readU32(gc + 76, sa)) return false;
	const uint64_t wgp = static_cast<uint64_t>(wgp0) + wgp1;
	// Bound individual geometry before multiplication; these are generous
	// architectural limits, not a claim about active/harvested hardware.
	if (!se || se > 16 || !sa || sa > 16 || !wgp || wgp > 32 ||
	    !rb || rb > 64 || !waves || waves > 1024) return false;
	const uint64_t cuPerArray = wgp * 2;
	const uint64_t maxCus = static_cast<uint64_t>(se) * sa * cuPerArray;
	if (maxCus > 16384) return false;
	out.shaderEngines = se;
	out.shaderArraysPerEngine = sa;
	out.wgpPerArray = static_cast<uint32_t>(wgp);
	out.renderBackendsPerEngine = rb;
	out.maxWavesPerSimd = waves;
	out.cuPerArray = static_cast<uint32_t>(cuPerArray);
	out.maxComputeUnits = static_cast<uint32_t>(maxCus);
	return true;
}

bool IpDiscovery::regByteOffset(uint16_t hwId, uint8_t instance, uint8_t segment,
                                uint32_t regDwordOffset, uint32_t &byteOffset) const {
	IpEntry ip;
	if (!findIp(hwId, instance, ip) || segment >= ip.numBases) return false;
	const uint64_t dword = static_cast<uint64_t>(ip.bases[segment]) + regDwordOffset;
	const uint64_t bytes = dword * 4;
	if (bytes > UINT32_MAX) return false;
	byteOffset = static_cast<uint32_t>(bytes);
	return true;
}
