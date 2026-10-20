#include "../src/gfx_topology.hpp"

#include <stdio.h>
#include <stdint.h>

namespace {

int failures = 0;

void expect(const char *name, bool actual, bool wanted) {
	if (actual != wanted) {
		printf("FAIL: %s (got %s, wanted %s)\n", name,
		       actual ? "true" : "false", wanted ? "true" : "false");
		++failures;
	}
}

IpDiscovery::GcTopology topology(uint32_t se = 2, uint32_t sa = 2,
	                                uint32_t wgp = 4, uint32_t rb = 4,
                                uint32_t waves = 16, uint32_t cu = 8,
	                                uint32_t totalCu = 32) {
	IpDiscovery::GcTopology result = { se, sa, wgp, rb, waves, cu, totalCu };
	return result;
}

bool valid(const IpDiscovery::GcTopology &t,
	       cobalt::Family family = cobalt::Family::Navi48,
	       cobalt::Version gc = {12, 0, 1}) {
	return cobalt::gfx_topology_compatible(family, gc, t);
}

} // namespace

int main() {
	using cobalt::Family;

	expect("realistic 2x2x4 WGP, 32 CU topology", valid(topology()), true);
	expect("realistic 4x2x4 WGP, 64 CU topology",
           valid(topology(4, 2, 4, 4, 32, 8, 64)), true);
	expect("disabled Navi44 profile data remains valid",
	       valid(topology(), Family::Navi44, {12, 0, 0}), true);

	expect("unknown family rejected", valid(topology(), Family::Unknown), false);
	expect("invalid enum family rejected",
	       valid(topology(), static_cast<Family>(255)), false);
	expect("GC version mismatch rejected",
	       valid(topology(), Family::Navi48, {12, 0, 0}), false);
	expect("Navi44 GC mismatch rejected",
	       valid(topology(), Family::Navi44, {12, 0, 1}), false);

	const uint32_t zeroFields[] = { 0, 1, 2, 3, 4, 5, 6 };
	for (uint32_t field : zeroFields) {
		IpDiscovery::GcTopology t = topology();
		switch (field) {
		case 0: t.shaderEngines = 0; break;
		case 1: t.shaderArraysPerEngine = 0; break;
		case 2: t.wgpPerArray = 0; break;
		case 3: t.renderBackendsPerEngine = 0; break;
		case 4: t.maxWavesPerSimd = 0; break;
		case 5: t.cuPerArray = 0; break;
		default: t.maxComputeUnits = 0; break;
		}
		expect("zero topology field rejected", valid(t), false);
	}

	expect("shader engine limit enforced", valid(topology(5, 2, 4, 8, 32, 8, 80)), false);
	expect("shader array limit enforced", valid(topology(2, 3, 4, 6, 32, 8, 48)), false);
	expect("WGP parser bound enforced", valid(topology(1, 1, 17, 1, 32, 34, 34)), false);
	expect("CU per array limit enforced", valid(topology(1, 1, 16, 1, 32, 33, 33)), false);
	expect("wave parser bound enforced", valid(topology(1, 1, 4, 1, 1025, 8, 8)), false);
	expect("UINT32_MAX WGP rejected safely",
	       valid(topology(1, 1, UINT32_MAX, 1, 32, UINT32_MAX, UINT32_MAX)), false);
	expect("UINT32_MAX render backend rejected safely",
	       valid(topology(1, 1, 4, UINT32_MAX, 32, 8, 8)), false);
	expect("render backends must divide evenly across arrays",
	       valid(topology(2, 2, 4, 3, 32, 8, 32)), false);
	expect("render backend mask capacity capped at 32",
           valid(topology(4, 2, 4, 10, 32, 8, 64)), false);
	expect("WGP/CU relation enforced", valid(topology(2, 2, 4, 4, 32, 7, 28)), false);
	expect("derived compute-unit total enforced", valid(topology(2, 2, 4, 4, 32, 8, 31)), false);
	expect("nonpositive derived capacity rejected", valid(topology(2, 2, 4, 4, 32, 8, 0)), false);

	expect("maximum supported geometry accepted",
	       valid(topology(4, 2, 16, 8, 1024, 32, 256)), true);
	expect("single-engine single-array boundary accepted",
	       valid(topology(1, 1, 1, 1, 1, 2, 2)), true);
	expect("exactly 32 render backends accepted",
	       valid(topology(4, 2, 4, 8, 32, 8, 64)), true);

	if (failures == 0) printf("gfx topology tests passed\n");
	return failures;
}
