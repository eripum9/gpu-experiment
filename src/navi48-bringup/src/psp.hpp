//
//  psp.hpp — PSP (Platform Security Processor) bootloader chain for Navi 48.
//
//  Ports mac-amdgpu's psp_v14_0 pre-SOS sequence (MIT) — itself a port of
//  Linux psp_v14_0.c — into a freestanding loader driven through a small
//  hardware-access interface: the bring-up kext supplies register and VRAM
//  access, this module owns the protocol.
//
//  What it does (the FIRST stage that writes to the GPU):
//    1. Parse psp_14_0_3_sos.bin (a v2.0 container of 11 sub-images).
//    2. For each pre-SOS component, in upstream order — KDB, SPL, SYS_DRV,
//       SOC_DRV, INTF_DRV, DBG/HAD_DRV, RAS_DRV, IPKEYMGR — stage it in a
//       1 MiB, 1 MiB-aligned fw_pri window in VRAM (written through the BAR0
//       aperture), hand the bootloader its MC address (>>20) in C2PMSG_36 and
//       the load command in C2PMSG_35, then wait for "bootloader ready".
//    3. Load SOS the same way; completion is C2PMSG_81 changing to nonzero.
//
//  MC addressing uses the posted FB_LOCATION_BASE to derive the mailbox address.
//  This path validates that arithmetic; it does not prove Navi 48 memory-controller
//  mapping or GPU execution.
//
//  Image authentication belongs to the PSP. This module validates its source
//  views and address arithmetic; the caller must establish VRAM ownership,
//  BAR/MC translation, device lifetime, and write visibility independently.
//
#ifndef Navi48_psp_hpp
#define Navi48_psp_hpp

#include <stdint.h>
#include <stddef.h>

namespace n48 {

// Minimal hardware access the loader needs; implemented by the kext.
struct HwAccess {
	// MMIO register access resolved through IP discovery:
	// (hwId, instance, segment, dwordOffset) -> value. 0xFFFFFFFF on failure.
	virtual uint32_t regReadIp (uint16_t hwId, uint8_t inst, uint8_t seg, uint32_t dword) = 0;
	virtual bool     regWriteIp(uint16_t hwId, uint8_t inst, uint8_t seg, uint32_t dword, uint32_t value) = 0;
	// CPU writes into VRAM through the BAR0 aperture, at a VRAM byte offset.
	// Must be globally visible (fenced) on return.
	virtual bool vramWrite (uint64_t vramOffset, const void *src, size_t len) = 0;
	virtual bool vramMemset(uint64_t vramOffset, uint8_t value, size_t len) = 0;
protected:
	~HwAccess() = default;   // never destroyed through the interface (kext ABI: no deleting dtors)
};

struct SubBin {
	const uint8_t *data { nullptr };
	uint32_t size { 0 };
	uint32_t version { 0 };
	bool present() const { return data != nullptr && size != 0; }
};

class PspLoader {
public:
	static constexpr uint32_t kFwPriSize = 1024u * 1024u;   // PSP_1_MEG
	static constexpr size_t kPreSosMaxComponents = 8;
	static constexpr size_t kSosMaxComponents = 9;

	explicit PspLoader(HwAccess &hw) : hw(hw) {}
	PspLoader(const PspLoader &) = delete;
	PspLoader &operator=(const PspLoader &) = delete;
	PspLoader(PspLoader &&) = delete;
	PspLoader &operator=(PspLoader &&) = delete;

	// Parse the sos.bin container (header v2.0/v2.1). Returns false on a
	// malformed container. Keeps pointers into `fw`; caller owns it and must keep
	// it alive through any run entry point. Every parse attempt invalidates
	// prior preflight.
	bool parseContainer(const uint8_t *fw, size_t fwSize);

	// Where in VRAM (byte offset, 1 MiB aligned) the 1 MiB fw_pri staging
	// window lives. The kext picks a spot clear of the boot framebuffer and other
	// reserved memory. Every call invalidates preflight; failure unconfigures it.
	bool setFwPriOffset(uint64_t vramOffset);
	uint64_t fwPriOffset() const { return fwPriOff; }

	// Read-only preflight: MP0 bootloader ready? SOS already alive? MMHUB FB
	// location posted and fw_pri inside it? Source views and all selected sizes
	// must also be valid. Success authorizes one attempt through any run entry
	// point; this does not prove that the staging window is free or correctly
	// mapped by the caller.
	bool preflight();

	// Run the full pre-SOS chain then load SOS. Returns true when SOS reports
	// alive (C2PMSG_81 nonzero). Refuses without a successful preflight, consumes
	// that authorization once, and revalidates all selected views before writes.
	bool runChain();

	// Bounded protocol probe: issue only KDB 0x80000
	// and wait for bootloader-ready with SOS observed down throughout. Returns
	// true only when that command was issued and readiness was observed; it does
	// not claim authentication, GPU execution, or MC mapping correctness.
	bool runKeyDatabase();

	// Bounded protocol checkpoint: prepare KDB at fwPriOffset() and SPL
	// at splOffset in distinct, complete 1 MiB windows before either mailbox is
	// attempted. Both windows must remain reserved and preserved through cold reset;
	// the caller establishes their mapping, ownership, and globally visible writes.
	// Consumes the shared fresh preflight even on failure. Returns true only for
	// KDB then SPL commands issued and ready observed with SOS down throughout;
	// this does not establish authentication, execution, or MC mapping correctness.
	bool runKeyDatabaseAndSpl(uint64_t splOffset);

	// Offline, unwired SYS_DRV checkpoint. The caller must own, map, and reserve
	// all three complete windows (KDB at fwPriOffset(), SPL at splOffset, SYS_DRV
	// at sysOffset) and preserve them until cold reset. Consumes the shared fresh
	// preflight even on refusal. Stops after KDB, SPL, and SYS_DRV each report
	// bootloader-ready with SOS down; this does not establish authentication,
	// execution, or MC mapping correctness.
	bool runKeyDatabaseSplAndSys(uint64_t splOffset, uint64_t sysOffset);

	// Run the complete pre-SOS component batch in canonical KDB, SPL, SYS_DRV,
	// SOC_DRV, INTF_DRV, HAD/DBG_DRV, RAS_DRV, IPKEYMGR order. Supply one
	// caller-owned, aligned and disjoint 1 MiB VRAM window per present component;
	// offsets correspond to present components in that canonical order, with the
	// first equal to fwPriOffset(). The caller owns, maps, and reserves every
	// window, establishes globally visible writes, and preserves them through cold
	// reset. Consumes the shared preflight on all outcomes. Returns true only when
	// all commands were issued and readiness was
	// observed; it does not establish authentication, execution or MC mapping.
	bool runPreSos(const uint64_t *windowOffsets, size_t windowCount);

	// Prepare the complete canonical pre-SOS chain plus SOS in caller-owned,
	// aligned and disjoint 1 MiB VRAM windows before any mailbox attempt. Supply
	// one offset per present image in KDB, SPL, SYS_DRV, SOC_DRV, INTF_DRV,
	// HAD/DBG_DRV, RAS_DRV, IPKEYMGR, SOS order; the first equals fwPriOffset().
	// KDB/SPL/SYS_DRV/SOS are required. The caller owns, maps, reserves, and
	// preserves every window through cold reset. Consumes shared preflight on all
	// outcomes. Returns true only when the strict pre-SOS ready protocol completes
	// and a fresh readable nonzero SOS sign of life is observed; boot-ready after
	// SOS is not required. This does not establish authentication, execution, or
	// MC mapping correctness.
	bool runSosCheckpoint(const uint64_t *windowOffsets, size_t windowCount);

	// State / report
	bool     sosAlive() const;                 // live register check
	uint64_t mcBase() const { return vramMcBase; }         // FB_LOCATION_BASE << 24
	uint64_t fwPriMC() const { return vramMcBase + fwPriOff; }
	uint32_t sosVersion() const { return sos.version; }
	uint32_t lastBootloaderStatus() const { return lastStatus; }
	const char *lastStep() const { return lastStepName; }

	// Parsed sub-images (public for logging/inspection)
	SubBin kdb, spl, sys, sos, soc, intf, dbg, ras, ipkey, toc, rl, spdm;

private:
	bool chainValid() const;
	bool windowValid() const;
	bool windowValid(uint64_t vramOffset) const;
	bool waitBootloader(uint32_t budgetMs, uint32_t *lastValue, bool strictSosDown = false);
	bool loadComponent(const char *name, const SubBin &bin, uint32_t blCmd, bool strictSosDown = false);
	bool loadSOS();

	HwAccess &hw;
	uint64_t vramMcBase { 0 };      // MC address of VRAM offset 0
	uint64_t vramMcTop  { 0 };      // MC address one past the last VRAM byte
	uint64_t fwPriOff   { 0 };      // VRAM byte offset of fw_pri
	bool fwPriConfigured { false };
	bool preflightOK { false };
	const uint8_t *parsedData { nullptr };
	size_t parsedSize { 0 };
	uint32_t lastStatus { 0 };
	const char *lastStepName { "none" };
};

} // namespace n48

#endif /* Navi48_psp_hpp */
