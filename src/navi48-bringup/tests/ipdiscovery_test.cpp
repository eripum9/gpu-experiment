#include "../src/ipdiscovery.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;
static unsigned failures = 0;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; ++failures; } } while (0)

static void put16(Bytes &b, size_t p, uint16_t v) { b[p] = uint8_t(v); b[p + 1] = uint8_t(v >> 8); }
static void put32(Bytes &b, size_t p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) b[p + i] = uint8_t(v >> (i * 8)); }
static uint16_t sum16(const Bytes &b, size_t begin, size_t end) {
	uint16_t s = 0; for (size_t i = begin; i < end; ++i) s = uint16_t(s + b[i]); return s;
}
static size_t u16(const Bytes &b, size_t p) { return size_t(b[p]) | (size_t(b[p + 1]) << 8); }
static void repairBinaryChecksum(Bytes &b) {
	const size_t prefix = 0x100, size = u16(b, prefix + 10);
	put16(b, prefix + 8, sum16(b, prefix + 10, prefix + size));
}
static void repairTableChecksum(Bytes &b) {
	const size_t prefix = 0x100, offset = u16(b, prefix + 12), tableSize = u16(b, prefix + 60 + 6);
	put16(b, prefix + 14, sum16(b, prefix + offset, prefix + offset + tableSize));
}

// Generates the documented binary v1.3 / IPDS v3 32-bit-base layout.
static Bytes fixture(bool includeGc = true, uint8_t gcRevision = 0) {
	const size_t prefix = 0x100, bin = 60, ipds = prefix + bin, die = ipds + 80;
	const unsigned count = includeGc ? 2 : 1;
	const size_t records = 4 + (includeGc ? 12 : 0) + 12;
	const size_t tableSize = 80 + records;
	const size_t binSize = bin + tableSize;
	Bytes b(prefix + binSize + 32, 0); // trailing ROM padding must not legitimize bad nested bounds
	put32(b, prefix, 0x28211407); put16(b, prefix + 4, 1); put16(b, prefix + 6, 3); put16(b, prefix + 10, uint16_t(binSize));
	put16(b, prefix + 12, uint16_t(bin)); put16(b, prefix + 16, uint16_t(tableSize));
	put32(b, ipds, 0x53445049); put16(b, ipds + 4, 3); put16(b, ipds + 6, uint16_t(tableSize));
	put16(b, ipds + 12, 1); put16(b, ipds + 14, 0); put16(b, ipds + 16, uint16_t(die - prefix));
	put16(b, die, 0); put16(b, die + 2, uint16_t(count));
	size_t p = die + 4;
	if (includeGc) {
		put16(b, p, 11); b[p+2] = 0; b[p+3] = 1; b[p+4] = 12; b[p+5] = 0; b[p+6] = gcRevision;
		put32(b, p + 8, 0x1000); p += 12;
	}
	put16(b, p, 108); b[p+2] = 0; b[p+3] = 1; b[p+4] = 6; b[p+5] = 3; b[p+6] = 1; put32(b, p + 8, 0x2000);
	repairTableChecksum(b);
	repairBinaryChecksum(b);
	return b;
}

static void writeFixture(const fs::path &p, const Bytes &b) {
	std::ofstream out(p, std::ios::binary); out.write(reinterpret_cast<const char *>(b.data()), static_cast<std::streamsize>(b.size()));
}

int main(int argc, char **argv) {
	if (argc == 3 && std::string(argv[1]) == "--write-fixtures") {
		fs::create_directories(argv[2]);
		writeFixture(fs::path(argv[2]) / "navi44.bin", fixture(true, 0));
		writeFixture(fs::path(argv[2]) / "navi48.bin", fixture(true, 1));
		writeFixture(fs::path(argv[2]) / "missing-gc.bin", fixture(false));
		Bytes malformed = fixture(); put16(malformed, 0x100 + 60 + 6, uint16_t((malformed[0x100 + 60 + 6] | (malformed[0x100 + 60 + 7] << 8)) - 1)); // IP list beyond declared IPDS size
		put16(malformed, 0x100 + 14, sum16(malformed, 0x100 + 60, 0x100 + 60 + (malformed[0x100 + 60 + 6] | (malformed[0x100 + 60 + 7] << 8))));
		put16(malformed, 0x100 + 8, sum16(malformed, 0x100 + 10, 0x100 + (malformed[0x100 + 10] | (malformed[0x100 + 11] << 8))));
		writeFixture(fs::path(argv[2]) / "malformed.bin", malformed);
		return 0;
	}
	IpDiscovery d;
	Bytes a = fixture(true, 0);
	CHECK(d.init(a.data(), a.size())); CHECK(d.ipCount() == 2); CHECK(d.binaryOffset() == 0x100);
	IpDiscovery::IpEntry ip {};
	CHECK(d.findIp(IpDiscovery::HwGc, 0, ip)); CHECK(ip.major == 12 && ip.minor == 0 && ip.revision == 0);
	uint32_t off = 0;
	CHECK(d.regByteOffset(IpDiscovery::HwGc, 0, 0, 3, off) && off == 0x400c);
	CHECK(!d.regByteOffset(IpDiscovery::HwGc, 0, 0, UINT32_MAX, off));

	Bytes b = fixture(true, 1); CHECK(d.init(b.data(), b.size())); CHECK(d.findIp(IpDiscovery::HwGc, 0, ip) && ip.revision == 1);
	Bytes paddedTable = fixture();
	put16(paddedTable, 0x100 + 16, uint16_t(u16(paddedTable, 0x100 + 16) + 8));
	put16(paddedTable, 0x100 + 10, uint16_t(u16(paddedTable, 0x100 + 10) + 8));
	paddedTable[0x100 + 60 + u16(paddedTable, 0x100 + 60 + 6)] = 0xa5;
	repairBinaryChecksum(paddedTable);
	CHECK(d.init(paddedTable.data(), paddedTable.size())); // enclosing table padding is outside IPDS checksum
	Bytes bad = fixture(); bad[0x100 + 20] ^= 1; CHECK(!d.init(bad.data(), bad.size())); // binary checksum
	bad = fixture(); put16(bad, 0x100 + 4, 2); // unsupported binary header v2
	repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); bad[0x100 + 60 + 80] ^= 1; repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size())); // IPDS table checksum
	bad = fixture(); put16(bad, 0x100 + 60 + 6, 80 + 4 + 12 + 7); repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size())); // truncated second record, despite trailing ROM padding
	bad = fixture(); put16(bad, 0x100 + 60 + 4, 4); bad[0x100 + 60 + 78] = 1; // IPDS v4 with 64-bit bases is unsupported
	repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); put16(bad, 0x100 + 60 + 12, 2); // multi-die unsupported
	repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); put16(bad, 0x100 + 60 + 80, 1); // only die 0 is supported
	repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); put16(bad, 0x100 + 60 + 14, 1); // die_info must also identify die 0
	repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(false); CHECK(d.init(bad.data(), bad.size())); CHECK(!d.findIp(IpDiscovery::HwGc, 0, ip));
	bad = fixture(); put16(bad, 0x100 + 60 + 6, 80 + 4 + 12 + 11); // nested table truncation despite trailing ROM padding
	repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); put16(bad, 0x100 + 16, 80); repairBinaryChecksum(bad); // table_info bounds an otherwise larger IPDS table
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); put16(bad, 0x100 + 12, 59); repairBinaryChecksum(bad); // table overlaps binary header
	CHECK(!d.init(bad.data(), bad.size()));
	bad = fixture(); put16(bad, 0x100 + 60 + 16, 60 + 79); repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size())); // die_header overlaps final byte of IPDS header
	bad = fixture(); bad[0x100 + 60 + 80 + 4 + 12 + 3] = 2; // second record claims more bases than remain
	repairTableChecksum(bad); repairBinaryChecksum(bad);
	CHECK(!d.init(bad.data(), bad.size())); CHECK(!d.isValid());
	Bytes base = fixture(); Bytes truncated(base.begin(), base.begin() + 15); CHECK(!d.init(truncated.data(), truncated.size()));
	if (failures) return 1;
	std::cout << "ipdiscovery fixtures and bounds checks passed\n";
	return 0;
}
