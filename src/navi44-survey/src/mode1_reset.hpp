#ifndef CobaltNavi44_Mode1Reset_hpp
#define CobaltNavi44_Mode1Reset_hpp

#include <stdint.h>

namespace cobalt::reset {

struct Observation {
	uint32_t bootloader { 0 };
	uint32_t sos { 0 };
	uint32_t memsize { 0 };
};

// The adapter owns all hardware-specific policy and access. The protocol calls
// these methods in a fixed order and never retains the Io instance.
struct Io {
	virtual ~Io() = default;
	virtual bool preflight(Observation &initial) = 0;
	virtual bool savePci() = 0;
	// True means the adapter disabled BM and verified the resulting config state;
	// do not expose setBusMasterEnable(false)'s previous-state return directly.
	virtual bool disableBusMaster() = 0;
	virtual bool readyToWrite() = 0;
	virtual void parameterZero() = 0;
	virtual void mode1Command() = 0;
	virtual void clearDebugResponse() = 0;
	virtual void quiesce() = 0; // Fences and exactly 1000 ms with no hardware access.
	virtual bool restorePci() = 0;
	virtual bool sampleRecovery(Observation &sample) = 0; // false means context lost.
	virtual void pausePoll() = 0;
	virtual bool postflight() = 0;
};

struct Result {
	bool pciSaved { false };
	bool busMasterDisabled { false };
	bool parameterAttempted { false };
	bool commandAttempted { false };
	bool responseAttempted { false };
	bool quiesced { false };
	bool pciRestored { false };
	bool recoveryObserved { false };
	bool resetTransitionObserved { false };
	bool success { false };
	uint32_t phase { 0 };
	uint32_t storesIssued { 0 };
	uint32_t polls { 0 };
	Observation initial {};
	Observation final {};
	const char *status { "not-run" };
};

// Phase values are stable telemetry shared with the hardware adapter.
static constexpr uint32_t kPhaseInitial = 0;
static constexpr uint32_t kPhasePciSaved = 1;
static constexpr uint32_t kPhaseBusMasterOff = 2;
static constexpr uint32_t kPhaseParameter = 3;
static constexpr uint32_t kPhaseCommand = 4;
static constexpr uint32_t kPhaseResponse = 5;
static constexpr uint32_t kPhaseQuiesced = 6;
static constexpr uint32_t kPhasePciRestored = 7;
static constexpr uint32_t kPhaseRecovered = 8;

static constexpr uint32_t kBootReadyBit = 0x80000000u;
static constexpr uint32_t kMaxPolls = 5000;

inline Result run(Io &io) {
	Result result{};
	Observation initial{};
	if (!io.preflight(initial) || initial.bootloader == UINT32_MAX || initial.sos == UINT32_MAX ||
		initial.memsize < 1024u || initial.memsize > 65536u) {
		result.initial = initial;
		result.status = "preflight-failed";
		return result;
	}
	result.initial = initial;
	if (!io.savePci()) {
		result.status = "pci-save-failed";
		return result;
	}
	result.pciSaved = true;
	result.phase = kPhasePciSaved;

	auto restoreOnce = [&]() -> bool {
		if (io.restorePci()) {
			result.pciRestored = true;
			result.phase = kPhasePciRestored;
			return true;
		}
		result.status = "pci-restore-failed";
		return false;
	};

	if (!io.disableBusMaster()) {
		result.status = "bus-master-disable-failed";
		restoreOnce();
		return result;
	}
	result.busMasterDisabled = true;
	result.phase = kPhaseBusMasterOff;
	if (!io.readyToWrite()) {
		result.status = "pre-burst-guard-failed";
		restoreOnce();
		return result;
	}

	// These three calls are one fixed protocol burst. Do not add callbacks,
	// logging, guards, or other I/O between them.
	result.parameterAttempted = true;
	++result.storesIssued;
	result.phase = kPhaseParameter;
	io.parameterZero();
	result.commandAttempted = true;
	++result.storesIssued;
	result.phase = kPhaseCommand;
	io.mode1Command();
	result.responseAttempted = true;
	++result.storesIssued;
	result.phase = kPhaseResponse;
	io.clearDebugResponse();

	result.phase = kPhaseQuiesced;
	io.quiesce();
	result.quiesced = true;
	if (!restoreOnce()) return result;

	uint32_t consecutive = 0;
	for (uint32_t poll = 0; poll < kMaxPolls; ++poll) {
		Observation sample{};
		++result.polls;
		if (!io.sampleRecovery(sample)) {
			result.status = "recovery-context-lost";
			return result;
		}
		result.final = sample;
		const bool ready = sample.bootloader != UINT32_MAX && (sample.bootloader & kBootReadyBit);
		const bool sosDown = sample.sos == 0;
		const bool sameMemory = sample.memsize == initial.memsize;
		if (ready && sosDown && sameMemory) {
			++consecutive;
			if (consecutive == 2) {
				result.recoveryObserved = true;
				result.phase = kPhaseRecovered;
				result.resetTransitionObserved = initial.sos != 0 && sample.sos == 0;
				if (!io.postflight()) {
					result.status = "postflight-failed";
					return result;
				}
				result.success = true;
				result.status = "mode1-issued-recovery-observed";
				return result;
			}
		} else {
			consecutive = 0;
		}
		if (poll + 1 < kMaxPolls) io.pausePoll();
	}
	result.status = "recovery-timeout";
	return result;
}

} // namespace cobalt::reset

#endif // CobaltNavi44_Mode1Reset_hpp
