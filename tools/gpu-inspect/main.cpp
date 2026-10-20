#include "../../src/navi48-bringup/src/ipdiscovery.hpp"
#include "../../src/navi48-bringup/src/gpu_profile.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace {
constexpr size_t kMaxRomSize = 64u * 1024u * 1024u;

std::string jsonEscape(const std::string &s) {
	std::string out;
	for (unsigned char c : s) {
		switch (c) {
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\b': out += "\\b"; break;
		case '\f': out += "\\f"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default: if (c < 0x20) { static const char h[] = "0123456789abcdef"; out += "\\u00"; out += h[c >> 4]; out += h[c & 15]; } else out += static_cast<char>(c);
		}
	}
	return out;
}

bool parseHex4(const std::string &s, size_t pos, uint16_t &v) {
	if (pos + 4 > s.size()) return false;
	v = 0;
	for (size_t i = pos; i < pos + 4; ++i) {
		const char c = s[i];
		unsigned d;
		if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
		else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A' + 10);
		else return false;
		v = static_cast<uint16_t>((v << 4) | d);
	}
	return true;
}

int errorJson(const std::string &error) {
	std::cout << "{\"ok\":false,\"error\":\"" << jsonEscape(error)
	          << "\",\"bringup_enabled\":false}\n";
	return 2;
}

void version(std::ostream &o, uint8_t major, uint8_t minor, uint8_t revision) {
	o << '{' << "\"major\":" << unsigned(major) << ",\"minor\":" << unsigned(minor)
	  << ",\"revision\":" << unsigned(revision) << '}';
}
}

int main(int argc, char **argv) {
	if (argc < 2 || argc > 4) return errorJson("usage: gpu-inspect ROM [--pci VVVV:DDDD]");
	const std::string path = argv[1];
	bool havePci = false;
	uint16_t vendor = 0, device = 0;
	if (argc > 2) {
		if (argc != 4 || std::string(argv[2]) != "--pci") return errorJson("expected --pci VVVV:DDDD");
		const std::string p = argv[3];
		if (p.size() != 9 || p[4] != ':' || !parseHex4(p, 0, vendor) || !parseHex4(p, 5, device))
			return errorJson("PCI ID must be exactly four hex digits, colon, four hex digits");
		havePci = true;
	}
	std::ifstream in(path, std::ios::binary | std::ios::ate);
	if (!in) return errorJson("cannot open input file");
	const std::streamoff length = in.tellg();
	if (length < 0 || static_cast<uint64_t>(length) > kMaxRomSize) return errorJson("input exceeds 64 MiB limit");
	std::vector<uint8_t> bytes(static_cast<size_t>(length));
	in.seekg(0);
	if (!bytes.empty() && !in.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
		return errorJson("failed to read input file");
	IpDiscovery discovery;
	if (!discovery.init(bytes.data(), bytes.size())) return errorJson("malformed or unsupported IP discovery binary");

	IpDiscovery::IpEntry gc {};
	bool hasGc = discovery.findIp(IpDiscovery::HwGc, 0, gc);
	IpDiscovery::GcTopology topology {};
	const bool hasTopology = discovery.gcTopology(topology);
	const cobalt::GpuProfile *profile = havePci ? cobalt::profile_for_pci(vendor, device) : nullptr;
	const bool compatible = profile && hasGc && cobalt::gc_matches(*profile, {gc.major, gc.minor, gc.revision});
	const bool unknownPci = havePci && !profile;
	const bool incompatiblePci = havePci && profile && !compatible;
	std::cout << "{\"ok\":" << ((unknownPci || incompatiblePci) ? "false" : "true") << ",\"source\":\"" << jsonEscape(path) << "\"";
	if (unknownPci) std::cout << ",\"error\":\"unknown PCI ID\"";
	else if (incompatiblePci) std::cout << ",\"error\":\"GC version does not match profile\"";
	if (havePci) std::cout << ",\"pci\":{\"vendor\":" << vendor << ",\"device\":" << device << '}';
	std::cout << ",\"discovery_offset\":" << discovery.binaryOffset()
	          << ",\"ip_count\":" << discovery.ipCount() << ",\"gc_present\":" << (hasGc ? "true" : "false")
	          << ",\"gc_version\":";
	if (hasGc) version(std::cout, gc.major, gc.minor, gc.revision); else std::cout << "null";
	std::cout << ",\"gc_topology\":";
	if (hasTopology) {
		std::cout << "{\"status\":\"capacity\",\"shader_engines\":" << topology.shaderEngines
		          << ",\"shader_arrays_per_engine\":" << topology.shaderArraysPerEngine
		          << ",\"wgp_per_array\":" << topology.wgpPerArray
		          << ",\"render_backends_per_engine\":" << topology.renderBackendsPerEngine
		          << ",\"max_waves_per_simd\":" << topology.maxWavesPerSimd
		          << ",\"cu_per_array\":" << topology.cuPerArray
		          << ",\"max_compute_units\":" << topology.maxComputeUnits
		          << ",\"meaning\":\"maximum capacity; active/harvested CU count is not reported\"}";
	} else std::cout << "null";
	std::cout << ",\"profile\":";
	if (profile) {
		std::cout << "{\"name\":\"" << jsonEscape(profile->name) << "\",\"gfx_target\":\"" << jsonEscape(profile->gfxTarget)
		          << "\",\"expected_gc\":";
		version(std::cout, profile->gc.major, profile->gc.minor, profile->gc.revision);
		std::cout << ",\"gc_compatible\":" << (compatible ? "true" : "false") << '}';
	} else std::cout << "null";
	std::cout << ",\"bringup_enabled\":" << (compatible && profile->bringupEnabled ? "true" : "false") << ",\"ips\":[";
	for (uint16_t i = 0; i < discovery.ipCount(); ++i) {
		IpDiscovery::IpEntry ip {};
		if (!discovery.ipAt(i, ip)) return errorJson("validated IP list became unreadable");
		if (i) std::cout << ',';
		std::cout << "{\"hw_id\":" << ip.hwId << ",\"instance\":" << unsigned(ip.instance) << ",\"version\":";
		version(std::cout, ip.major, ip.minor, ip.revision);
		std::cout << ",\"bases\":[";
		for (uint8_t b = 0; b < ip.numBases; ++b) { if (b) std::cout << ','; std::cout << ip.bases[b]; }
		std::cout << "]}";
	}
	std::cout << "]}\n";
	if (unknownPci) return 3;
	if (havePci && !compatible) return 4;
	return 0;
}
