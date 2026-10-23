//
//  psp.cpp — PSP bootloader chain (see psp.hpp). Protocol per Linux
//  psp_v14_0.c via mac-amdgpu's macOS port; register offsets from the
//  mp_14_0_2 / mmhub_4_1_0 headers, resolved at runtime through IP discovery.
//
#include "psp.hpp"
#include "psp_container.hpp"
#include "regs.hpp"
#include "ipdiscovery.hpp"
#include <IOKit/IOLib.h>

// Standard C++17 forwarding, including calls with only a format string.
// Each message supplies its own newline, preserving a single IOLog call.
#define PSPLOG(...) IOLog("Navi48Bringup: psp: " __VA_ARGS__)

namespace n48 {

// ---- PSP bootloader commands (psp_v14_0.c PSP_BL__*) --------------------------
namespace BlCmd {
	static constexpr uint32_t LoadKeyDatabase = 0x00080000;
	static constexpr uint32_t LoadTosSPLTable = 0x10000000;
	static constexpr uint32_t LoadSysDrv      = 0x00010000;
	static constexpr uint32_t LoadSocDrv      = 0x000B0000;
	static constexpr uint32_t LoadIntfDrv     = 0x000D0000;
	static constexpr uint32_t LoadHADDrv      = 0x000C0000;   // "dbg_drv was renamed to had_drv in psp v14"
	static constexpr uint32_t LoadRASDrv      = 0x000E0000;
	static constexpr uint32_t LoadIPKeyMgrDrv = 0x000F0000;
	static constexpr uint32_t LoadSOSDrv      = 0x00020000;
}

// MP0 (PSP) scratch regs, segment 0.
static constexpr uint8_t  kMp0Seg   = 0;
static constexpr uint32_t kC2PMsg35 = n48::kPspC2PMsg35;   // cmd / status (bit31 = ready)
static constexpr uint32_t kC2PMsg36 = 0x0064;              // fw_pri MC addr >> 20
static constexpr uint32_t kC2PMsg81 = n48::kPspC2PMsg81;   // SOS sign-of-life
// MMHUB (mmhub_4_1_0), segment 0.
static constexpr uint8_t  kMmhubSeg = 0;
static constexpr uint32_t kMmhubFbLocationBase = 0x0554;   // regMMMC_VM_FB_LOCATION_BASE
static constexpr uint32_t kMmhubFbLocationTop  = 0x0555;   // regMMMC_VM_FB_LOCATION_TOP
static constexpr uint32_t kMmhubFbOffset       = 0x04c7;   // regMMMC_VM_FB_OFFSET (per mac-amdgpu)
// DCN's own copy of the FB location (DMU segment 2) — what RDNA4FB uses.
static constexpr uint8_t  kDmuSeg = 2;
static constexpr uint32_t kDcnVmFbLocationBase = 0x0475;
static constexpr uint32_t kFbMask  = 0x00FFFFFF;
static constexpr uint32_t kFbShift = 24;                    // 16 MiB units

// ---- container parse ----------------------------------------------------------
bool PspLoader::parseContainer(const uint8_t *fw, size_t fwSize) {
	preflightOK = false;
	parsedData = nullptr; parsedSize = 0;
	kdb = spl = sys = sos = soc = intf = dbg = ras = ipkey = toc = rl = spdm = SubBin{};
	cobalt::psp::Package package{};
	if (!cobalt::psp::parse(fw, fwSize, package)) {
		PSPLOG("parse: invalid or unsupported PSP v2 container (%zu bytes)\n", fwSize);
		return false;
	}
	sos = {package.part[cobalt::psp::Sos].data, package.part[cobalt::psp::Sos].size, package.part[cobalt::psp::Sos].version};
	sys = {package.part[cobalt::psp::SysDrv].data, package.part[cobalt::psp::SysDrv].size, package.part[cobalt::psp::SysDrv].version};
	kdb = {package.part[cobalt::psp::Kdb].data, package.part[cobalt::psp::Kdb].size, package.part[cobalt::psp::Kdb].version};
	toc = {package.part[cobalt::psp::Toc].data, package.part[cobalt::psp::Toc].size, package.part[cobalt::psp::Toc].version};
	spl = {package.part[cobalt::psp::Spl].data, package.part[cobalt::psp::Spl].size, package.part[cobalt::psp::Spl].version};
	rl = {package.part[cobalt::psp::Rl].data, package.part[cobalt::psp::Rl].size, package.part[cobalt::psp::Rl].version};
	soc = {package.part[cobalt::psp::SocDrv].data, package.part[cobalt::psp::SocDrv].size, package.part[cobalt::psp::SocDrv].version};
	intf = {package.part[cobalt::psp::IntfDrv].data, package.part[cobalt::psp::IntfDrv].size, package.part[cobalt::psp::IntfDrv].version};
	dbg = {package.part[cobalt::psp::DbgDrv].data, package.part[cobalt::psp::DbgDrv].size, package.part[cobalt::psp::DbgDrv].version};
	ras = {package.part[cobalt::psp::RasDrv].data, package.part[cobalt::psp::RasDrv].size, package.part[cobalt::psp::RasDrv].version};
	ipkey = {package.part[cobalt::psp::IpKeyMgrDrv].data, package.part[cobalt::psp::IpKeyMgrDrv].size, package.part[cobalt::psp::IpKeyMgrDrv].version};
	spdm = {package.part[cobalt::psp::SpdmDrv].data, package.part[cobalt::psp::SpdmDrv].size, package.part[cobalt::psp::SpdmDrv].version};
	PSPLOG("parse: KDB %u SPL %u SYS %u SOC %u INTF %u DBG %u RAS %u IPKEY %u SOS %u bytes (SOS ver 0x%08x)\n",
	       kdb.size, spl.size, sys.size, soc.size, intf.size, dbg.size, ras.size, ipkey.size,
	       sos.size, sos.version);
	parsedData = fw; parsedSize = fwSize;
	return true;
}

bool PspLoader::setFwPriOffset(uint64_t vramOffset) {
	preflightOK = false;
	fwPriConfigured = false;
	fwPriOff = 0;
	if ((vramOffset & (kFwPriSize - 1)) || vramOffset > UINT64_MAX - kFwPriSize) {
		PSPLOG("fw_pri offset 0x%llx is unaligned or its 1 MiB extent overflows\n", vramOffset);
		return false;
	}
	fwPriOff = vramOffset;
	fwPriConfigured = true;
	return true;
}

// Validate the public inspection slots against the parser-owned views again.
// They do not become arbitrary caller-supplied pointers after parsing.
bool PspLoader::chainValid() const {
	cobalt::psp::Package package{};
	if (!parsedData || !cobalt::psp::parse(parsedData, parsedSize, package)) return false;
	const SubBin *slots[] = {&kdb, &spl, &sys, &soc, &intf, &dbg, &ras, &ipkey, &sos};
	const cobalt::psp::Part parts[] = {cobalt::psp::Kdb, cobalt::psp::Spl, cobalt::psp::SysDrv,
		cobalt::psp::SocDrv, cobalt::psp::IntfDrv, cobalt::psp::DbgDrv, cobalt::psp::RasDrv,
		cobalt::psp::IpKeyMgrDrv, cobalt::psp::Sos};
	for (unsigned i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
		const auto &expected = package.part[parts[i]];
		const SubBin &actual = *slots[i];
		if (actual.data != expected.data || actual.size != expected.size ||
			actual.version != expected.version || actual.size > kFwPriSize) return false;
	}
	return sos.present() && sys.present();
}

bool PspLoader::windowValid() const {
	return fwPriConfigured && windowValid(fwPriOff);
}

bool PspLoader::windowValid(uint64_t vramOffset) const {
	if ((vramOffset & (kFwPriSize - 1)) || vramOffset > UINT64_MAX - kFwPriSize ||
		vramMcBase == 0 || vramMcTop <= vramMcBase ||
		vramOffset > UINT64_MAX - vramMcBase) return false;
	const uint64_t mc = vramMcBase + vramOffset;
	if (mc >= vramMcTop || kFwPriSize > vramMcTop - mc ||
		mc > UINT64_MAX - kFwPriSize || (mc >> 20) > UINT32_MAX) return false;
	return true;
}

// ---- hardware protocol ----------------------------------------------------------
bool PspLoader::sosAlive() const {
	uint32_t v = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
	return v != 0 && v != 0xFFFFFFFF;
}

bool PspLoader::waitBootloader(uint32_t budgetMs, uint32_t *lastValue, bool strictSosDown) {
	uint32_t v = 0;
	for (uint32_t ms = 0; ms < budgetMs; ms++) {
		v = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35);
		if (strictSosDown && v == UINT32_MAX) {
			if (lastValue) *lastValue = v;
			lastStatus = v;
			return false;
		}
		if (strictSosDown) {
			const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
			if (sol == UINT32_MAX || sol != 0) {
				if (lastValue) *lastValue = v;
				lastStatus = sol == UINT32_MAX ? sol : v;
				return false;
			}
		}
		if (v != 0xFFFFFFFF && (v & n48::kPspBootReadyBit)) {
			if (lastValue) *lastValue = v;
			lastStatus = v;
			return true;
		}
		IOSleep(1);
	}
	if (lastValue) *lastValue = v;
	lastStatus = v;
	return false;
}

bool PspLoader::preflight() {
	lastStepName = "preflight";
	preflightOK = false;
	vramMcBase = vramMcTop = 0;
	if (!fwPriConfigured || !chainValid()) {
		PSPLOG("preflight: explicit staging window and valid bounded chain required\n"); return false;
	}
	const uint32_t bl  = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35);
	const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
	const uint32_t fbBase = hw.regReadIp(IpDiscovery::HwMmhub, 0, kMmhubSeg, kMmhubFbLocationBase);
	const uint32_t fbTop  = hw.regReadIp(IpDiscovery::HwMmhub, 0, kMmhubSeg, kMmhubFbLocationTop);
	const uint32_t fbOff  = hw.regReadIp(IpDiscovery::HwMmhub, 0, kMmhubSeg, kMmhubFbOffset);
	const uint32_t dcnBase = hw.regReadIp(IpDiscovery::HwDmu, 0, kDmuSeg, kDcnVmFbLocationBase);

	PSPLOG("preflight: C2PMSG_35=0x%08x (%s) C2PMSG_81=0x%08x (%s)\n",
	       bl, (bl & n48::kPspBootReadyBit) ? "bootloader READY" : "bootloader NOT ready",
	       sol, sol ? "SOS alive" : "SOS down");
	PSPLOG("preflight: MMHUB FB_LOCATION base=0x%08x top=0x%08x FB_OFFSET=0x%08x  DCN FB_LOCATION base=0x%08x\n",
	       fbBase, fbTop, fbOff, dcnBase);

	if (bl == 0xFFFFFFFF || sol == 0xFFFFFFFF || fbBase == 0xFFFFFFFF || fbTop == 0xFFFFFFFF) {
		PSPLOG("preflight: MP0/MMHUB registers unreadable; refusing\n"); return false;
	}
	vramMcBase = (uint64_t)(fbBase & kFbMask) << kFbShift;
	vramMcTop  = ((uint64_t)(fbTop & kFbMask) << kFbShift) + (1ULL << kFbShift);
	if (vramMcBase == 0 || vramMcTop <= vramMcBase) {
		PSPLOG("preflight: FB_LOCATION not posted (base 0x%llx top 0x%llx); refusing\n", vramMcBase, vramMcTop);
		return false;
	}
	if (dcnBase != 0xFFFFFFFF && (dcnBase & kFbMask) != (fbBase & kFbMask))
		PSPLOG("preflight: WARNING DCN and MMHUB disagree on FB base (0x%06x vs 0x%06x)\n",
		       dcnBase & kFbMask, fbBase & kFbMask);
	if (fbOff != 0xFFFFFFFF && (fbOff & kFbMask) != (fbBase & kFbMask))
		PSPLOG("preflight: NOTE FB_OFFSET 0x%06x != FB_LOCATION_BASE 0x%06x — deriving mailbox address from FB_LOCATION_BASE; caller must establish MC mapping\n",
		       fbOff & kFbMask, fbBase & kFbMask);

	if (!windowValid()) {
		PSPLOG("preflight: staging window outside MC range or not representable; refusing\n"); return false;
	}
	const uint64_t mc = vramMcBase + fwPriOff;
	PSPLOG("preflight: VRAM MC [0x%llx, 0x%llx) = %llu MiB; fw_pri at vram+0x%llx = MC 0x%llx (C2PMSG_36 will be 0x%08x)\n",
	       vramMcBase, vramMcTop, (vramMcTop - vramMcBase) >> 20, fwPriOff, mc, (uint32_t)(mc >> 20));

	if (sol != 0)        { PSPLOG("preflight: SOS already alive — nothing to load\n"); preflightOK = true; return true; }
	if (!(bl & n48::kPspBootReadyBit)) { PSPLOG("preflight: bootloader not ready; refusing\n"); return false; }
	preflightOK = true;
	return true;
}

bool PspLoader::loadComponent(const char *name, const SubBin &bin, uint32_t blCmd, bool strictSosDown) {
	lastStepName = name;
	auto requireSosDown = [&]() -> bool {
		const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
		if (sol != 0) {
			lastStatus = sol;
			PSPLOG("%s: strict probe requires readable SOS-down state (0x%08x)\n", name, sol);
			return false;
		}
		return true;
	};
	if (strictSosDown && !requireSosDown()) return false;
	if (!bin.present()) {
		if (strictSosDown) { PSPLOG("%s: required image absent\n", name); return false; }
		PSPLOG("%s: not in container, skipping\n", name); return true;
	}
	if (bin.size > kFwPriSize) { PSPLOG("%s: %u bytes exceeds fw_pri\n", name, bin.size); return false; }
	const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
	if (sol == UINT32_MAX) { lastStatus = sol; PSPLOG("%s: SOS register unreadable\n", name); return false; }
	if (sol != 0) {
		if (strictSosDown) { lastStatus = sol; PSPLOG("%s: strict probe refuses live SOS\n", name); return false; }
		PSPLOG("%s: SOS already alive, skip\n", name); return true;
	}

	uint32_t st;
	if (!waitBootloader(10000, &st, strictSosDown)) { PSPLOG("%s: bootloader not ready (0x%08x)\n", name, st); return false; }
	// In strict mode this read is deliberately adjacent to staging: SOS must
	// still be down after the readiness wait and before any VRAM write.
	if (strictSosDown && !requireSosDown()) return false;

	// Zero the whole 1 MiB window first, then copy the image (psp_copy_fw).
	if (!hw.vramMemset(fwPriOff, 0, kFwPriSize))   { PSPLOG("%s: fw_pri memset failed\n", name); return false; }
	if (!hw.vramWrite(fwPriOff, bin.data, bin.size)) { PSPLOG("%s: fw_pri write failed\n", name); return false; }
	if (strictSosDown && !requireSosDown()) return false;

	const uint64_t mc = vramMcBase + fwPriOff;
	if (!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg36, (uint32_t)(mc >> 20))) {
		PSPLOG("%s: address register write failed\n", name); return false;
	}
	if (strictSosDown && !requireSosDown()) return false;
	if (!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35, blCmd)) {
		PSPLOG("%s: register write failed\n", name); return false;
	}
	if (!waitBootloader(10000, &st, strictSosDown)) {
		PSPLOG("%s: FAILED — bootloader status 0x%08x after cmd 0x%x\n", name, st, blCmd);
		return false;
	}
	if (strictSosDown && !requireSosDown()) return false;
	PSPLOG("%s: ok (%u bytes, cmd 0x%x, status 0x%08x)\n", name, bin.size, blCmd, st);
	return true;
}

bool PspLoader::loadSOS() {
	lastStepName = "SOS";
	const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
	if (sol == UINT32_MAX) { lastStatus = sol; PSPLOG("SOS: register unreadable\n"); return false; }
	if (sol != 0) { PSPLOG("SOS: already alive\n"); return true; }
	if (sos.size > kFwPriSize) { PSPLOG("SOS: %u bytes exceeds fw_pri\n", sos.size); return false; }
	uint32_t st;
	if (!waitBootloader(10000, &st)) { PSPLOG("SOS: bootloader not ready (0x%08x)\n", st); return false; }

	if (!hw.vramMemset(fwPriOff, 0, kFwPriSize)) return false;
	if (!hw.vramWrite(fwPriOff, sos.data, sos.size)) return false;

	const uint32_t solBefore = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
	if (solBefore == UINT32_MAX) { lastStatus = solBefore; PSPLOG("SOS: register unreadable after staging\n"); return false; }
	const uint64_t mc = vramMcBase + fwPriOff;
	if (!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg36, (uint32_t)(mc >> 20)) ||
	    !hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35, BlCmd::LoadSOSDrv)) {
		PSPLOG("SOS: register write failed\n"); return false;
	}
	IOSleep(20);   // upstream: "there might be handshake issue with hardware which needs delay"

	// Done when the sign-of-life register changes from its pre-load value to
	// nonzero. Normally well under a second; allow 5 s.
	for (uint32_t ms = 0; ms < 5000; ms++) {
		uint32_t v = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
		if (v == UINT32_MAX) { lastStatus = v; PSPLOG("SOS: sign-of-life read failed\n"); return false; }
		if (v != solBefore && v != 0 && v != 0xFFFFFFFF) {
			PSPLOG("SOS ALIVE — C2PMSG_81 0x%08x -> 0x%08x after ~%u ms\n", solBefore, v, ms + 20);
			lastStatus = v;
			return true;
		}
		IOSleep(1);
	}
	lastStatus = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35);
	PSPLOG("SOS: timeout — C2PMSG_81 unchanged (0x%08x), bootloader status 0x%08x\n", solBefore, lastStatus);
	return false;
}

bool PspLoader::runChain() {
	const bool authorized = preflightOK;
	preflightOK = false; // Success and failure both consume the one-shot authorization.
	if (!authorized || !chainValid() || !windowValid()) {
		lastStepName = "preflight-required";
		PSPLOG("chain: fresh successful preflight and unchanged bounded chain required\n"); return false;
	}
	const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
	if (sol == UINT32_MAX) { lastStepName = "sos-unreadable"; lastStatus = sol; return false; }
	if (sol != 0) { PSPLOG("chain: SOS already alive, skipping\n"); return true; }
	struct Step { const char *name; const SubBin *bin; uint32_t cmd; } steps[] = {
		// Order from Linux psp_hw_start; identical to mac-amdgpu's proven
		// psp_load_sos_package (no SPDM_DRV: psp_14_0_3 ships none).
		{ "KDB",      &kdb,   BlCmd::LoadKeyDatabase },
		{ "SPL",      &spl,   BlCmd::LoadTosSPLTable },
		{ "SYS_DRV",  &sys,   BlCmd::LoadSysDrv      },
		{ "SOC_DRV",  &soc,   BlCmd::LoadSocDrv      },
		{ "INTF_DRV", &intf,  BlCmd::LoadIntfDrv     },
		{ "HAD_DRV",  &dbg,   BlCmd::LoadHADDrv      },
		{ "RAS_DRV",  &ras,   BlCmd::LoadRASDrv      },
		{ "IPKEYMGR", &ipkey, BlCmd::LoadIPKeyMgrDrv },
	};
	for (auto &s : steps)
		if (!loadComponent(s.name, *s.bin, s.cmd)) return false;
	return loadSOS();
}

bool PspLoader::runKeyDatabase() {
	const bool authorized = preflightOK;
	preflightOK = false; // Consume the shared one-shot authorization on entry.
	if (!authorized || !chainValid() || !windowValid() || !kdb.present()) {
		lastStepName = "preflight-required";
		PSPLOG("KDB probe: fresh successful preflight, unchanged bounded chain, and KDB required\n");
		return false;
	}
	// Deliberately stop after this single command. This proves only that the
	// command reached an observed bootloader-ready state while SOS stayed down.
	return loadComponent("KDB", kdb, BlCmd::LoadKeyDatabase, true);
}

bool PspLoader::runKeyDatabaseAndSpl(uint64_t splOffset) {
	const bool authorized = preflightOK;
	preflightOK = false; // All run entry points share this one-shot authorization.
	if (!authorized || !chainValid() || !kdb.present() || !spl.present() ||
		!windowValid() || !windowValid(splOffset) ||
		!(fwPriOff + kFwPriSize <= splOffset || splOffset + kFwPriSize <= fwPriOff)) {
		lastStepName = "preflight-required";
		PSPLOG("KDB+SPL probe: fresh preflight, unchanged chain, both images, and distinct bounded windows required\n");
		return false;
	}
	auto requireSosDown = [&]() -> bool {
		const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
		if (sol == 0) return true;
		lastStatus = sol;
		PSPLOG("%s: strict probe requires readable SOS-down state (0x%08x)\n", lastStepName, sol);
		return false;
	};
	auto requireReady = [&]() -> bool {
		const uint32_t bl = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35);
		lastStatus = bl;
		if (bl == UINT32_MAX || !(bl & n48::kPspBootReadyBit)) {
			PSPLOG("%s: expected readable bootloader-ready state (0x%08x)\n", lastStepName, bl);
			return false;
		}
		return requireSosDown();
	};
	uint32_t st;
	lastStepName = "KDB+SPL-prepare";
	if (!requireSosDown() || !waitBootloader(10000, &st, true)) return false;

	// Each hardware call completes globally visible writes before returning.
	// Prepare both independent windows before any mailbox attempt: after that
	// point either window may be PSP-owned, including on an uncertain failure.
	lastStepName = "KDB-stage";
	if (!requireReady() || !hw.vramMemset(fwPriOff, 0, kFwPriSize) ||
		!requireReady() || !hw.vramWrite(fwPriOff, kdb.data, kdb.size)) return false;
	lastStepName = "SPL-stage";
	if (!requireReady() || !hw.vramMemset(splOffset, 0, kFwPriSize) ||
		!requireReady() || !hw.vramWrite(splOffset, spl.data, spl.size)) return false;

	// Deliberately contains no staging, cleanup, retry, or chain continuation.
	auto dispatch = [&](const char *name, uint64_t offset, uint32_t cmd) -> bool {
		lastStepName = name;
		if (!requireReady()) return false;
		const uint64_t mc = vramMcBase + offset;
		if (!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg36, (uint32_t)(mc >> 20)) ||
			!requireReady() ||
			!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35, cmd)) return false;
		if (!waitBootloader(10000, &st, true) || !requireSosDown()) return false;
		PSPLOG("%s: command 0x%x issued, bootloader-ready observed (0x%08x)\n", name, cmd, st);
		return true;
	};
	return dispatch("KDB", fwPriOff, BlCmd::LoadKeyDatabase) &&
		dispatch("SPL", splOffset, BlCmd::LoadTosSPLTable);
}

bool PspLoader::runKeyDatabaseSplAndSys(uint64_t splOffset, uint64_t sysOffset) {
	const bool authorized = preflightOK;
	preflightOK = false; // Every entry point consumes the same one-shot authorization.
	auto disjoint = [](uint64_t a, uint64_t b) -> bool {
		return a < b ? b - a >= kFwPriSize : a - b >= kFwPriSize;
	};
	if (!authorized || !chainValid() || !kdb.present() || !spl.present() || !sys.present() ||
		!windowValid() || !windowValid(splOffset) || !windowValid(sysOffset) ||
		!disjoint(fwPriOff, splOffset) || !disjoint(fwPriOff, sysOffset) ||
		!disjoint(splOffset, sysOffset)) {
		lastStepName = "preflight-required";
		PSPLOG("KDB+SPL+SYS_DRV probe: fresh preflight, unchanged chain, all images, and three disjoint bounded windows required\n");
		return false;
	}
	auto requireSosDown = [&]() -> bool {
		const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
		if (sol == 0) return true;
		lastStatus = sol;
		PSPLOG("%s: strict probe requires readable SOS-down state (0x%08x)\n", lastStepName, sol);
		return false;
	};
	auto requireReady = [&]() -> bool {
		const uint32_t bl = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35);
		lastStatus = bl;
		if (bl == UINT32_MAX || !(bl & n48::kPspBootReadyBit)) {
			PSPLOG("%s: expected readable bootloader-ready state (0x%08x)\n", lastStepName, bl);
			return false;
		}
		return requireSosDown();
	};
	uint32_t st;
	lastStepName = "KDB+SPL+SYS_DRV-prepare";
	if (!requireSosDown() || !waitBootloader(10000, &st, true)) return false;

	// Stage every window before the first mailbox store. From that point onward,
	// any failed mailbox attempt leaves all three windows potentially PSP-owned.
	struct Stage { const char *name; const SubBin *bin; uint64_t offset; };
	const Stage stages[] = {{"KDB-stage", &kdb, fwPriOff}, {"SPL-stage", &spl, splOffset},
		{"SYS_DRV-stage", &sys, sysOffset}};
	for (const auto &stage : stages) {
		lastStepName = stage.name;
		if (!requireReady() || !hw.vramMemset(stage.offset, 0, kFwPriSize) ||
			!requireReady() || !hw.vramWrite(stage.offset, stage.bin->data, stage.bin->size)) return false;
	}

	auto dispatch = [&](const char *name, uint64_t offset, uint32_t cmd) -> bool {
		lastStepName = name;
		if (!requireReady()) return false;
		const uint64_t mc = vramMcBase + offset;
		if (!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg36, (uint32_t)(mc >> 20)) ||
			!requireReady() ||
			!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35, cmd)) return false;
		if (!waitBootloader(10000, &st, true) || !requireSosDown()) return false;
		PSPLOG("%s: command 0x%x issued, bootloader-ready observed (0x%08x)\n", name, cmd, st);
		return true;
	};
	return dispatch("KDB", fwPriOff, BlCmd::LoadKeyDatabase) &&
		dispatch("SPL", splOffset, BlCmd::LoadTosSPLTable) &&
		dispatch("SYS_DRV", sysOffset, BlCmd::LoadSysDrv);
}

bool PspLoader::runPreSos(const uint64_t *windowOffsets, size_t windowCount) {
	const bool authorized = preflightOK;
	preflightOK = false; // The shared preflight is consumed on every outcome.
	struct Component { const char *name; const SubBin *view; uint32_t command; };
	const Component canonical[] = {
		{"KDB", &kdb, BlCmd::LoadKeyDatabase},
		{"SPL", &spl, BlCmd::LoadTosSPLTable},
		{"SYS_DRV", &sys, BlCmd::LoadSysDrv},
		{"SOC_DRV", &soc, BlCmd::LoadSocDrv},
		{"INTF_DRV", &intf, BlCmd::LoadIntfDrv},
		{"HAD_DRV", &dbg, BlCmd::LoadHADDrv},
		{"RAS_DRV", &ras, BlCmd::LoadRASDrv},
		{"IPKEYMGR", &ipkey, BlCmd::LoadIPKeyMgrDrv},
	};
	if (!authorized || !windowOffsets || !chainValid() || !kdb.present() ||
		!spl.present() || !sys.present() || !windowValid()) {
		lastStepName = "preflight-required";
		PSPLOG("pre-SOS batch: fresh preflight, unchanged chain, and required KDB/SPL/SYS images required\n");
		return false;
	}
	Component selected[kPreSosMaxComponents]{};
	size_t expectedCount = 0;
	for (const auto &component : canonical)
		if (component.view->present()) selected[expectedCount++] = component;
	if (windowCount != expectedCount || windowCount < 3 || windowCount > kPreSosMaxComponents ||
		windowOffsets[0] != fwPriOff) {
		lastStepName = "preflight-required";
		PSPLOG("pre-SOS batch: exact canonical window count and fw_pri first offset required\n");
		return false;
	}
	for (size_t i = 0; i < expectedCount; ++i) {
		if (!windowValid(windowOffsets[i])) {
			lastStepName = "preflight-required";
			PSPLOG("pre-SOS batch: invalid 1 MiB window for %s\n", selected[i].name);
			return false;
		}
		for (size_t j = 0; j < i; ++j) {
			const uint64_t a = windowOffsets[i], b = windowOffsets[j];
			if ((a < b ? b - a : a - b) < kFwPriSize) {
				lastStepName = "preflight-required";
				PSPLOG("pre-SOS batch: overlapping windows for %s\n", selected[i].name);
				return false;
			}
		}
	}
	// Snapshot parser-validated views and offsets before any hardware callback.
	SubBin bins[kPreSosMaxComponents]{};
	uint64_t offsets[kPreSosMaxComponents]{};
	for (size_t i = 0; i < expectedCount; ++i) {
		bins[i] = *selected[i].view;
		offsets[i] = windowOffsets[i];
	}
	auto requireSosDown = [&]() -> bool {
		const uint32_t sol = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg81);
		if (sol == 0) return true;
		lastStatus = sol;
		PSPLOG("%s: strict probe requires readable SOS-down state (0x%08x)\n", lastStepName, sol);
		return false;
	};
	auto requireReady = [&]() -> bool {
		const uint32_t bl = hw.regReadIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35);
		lastStatus = bl;
		if (bl == UINT32_MAX || !(bl & n48::kPspBootReadyBit)) {
			PSPLOG("%s: expected readable bootloader-ready state (0x%08x)\n", lastStepName, bl);
			return false;
		}
		return requireSosDown();
	};
	uint32_t st;
	lastStepName = "pre-SOS-prepare";
	if (!requireSosDown() || !waitBootloader(10000, &st, true)) return false;
	// Stage all selected images before the first mailbox attempt. After any
	// mailbox attempt, the PSP may own every staged window, including on failure.
	for (size_t i = 0; i < expectedCount; ++i) {
		lastStepName = selected[i].name;
		if (!requireReady() || !hw.vramMemset(offsets[i], 0, kFwPriSize) ||
			!requireReady() || !hw.vramWrite(offsets[i], bins[i].data, bins[i].size)) return false;
	}
	for (size_t i = 0; i < expectedCount; ++i) {
		lastStepName = selected[i].name;
		if (!requireReady()) return false;
		const uint64_t mc = vramMcBase + offsets[i];
		if (!hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg36, (uint32_t)(mc >> 20))) return false;
		if (!requireReady() || !hw.regWriteIp(IpDiscovery::HwMp0, 0, kMp0Seg, kC2PMsg35, selected[i].command)) return false;
		if (!waitBootloader(10000, &st, true) || !requireSosDown()) return false;
		PSPLOG("%s: command 0x%x issued, bootloader-ready observed (0x%08x)\n", selected[i].name, selected[i].command, st);
	}
	return true;
}

} // namespace n48
