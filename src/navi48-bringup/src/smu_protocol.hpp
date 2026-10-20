#ifndef Cobalt64_smu_protocol_hpp
#define Cobalt64_smu_protocol_hpp

#include "gpu_profile.hpp"

namespace cobalt {

enum class SmuMessage : uint32_t {
	TestMessage = 0x01,
	GetSmuVersion = 0x02,
	GetDriverIfVersion = 0x03,
	SetAllowedFeaturesMaskLow = 0x04,
	SetAllowedFeaturesMaskHigh = 0x05,
	EnableAllSmuFeatures = 0x06,
	DisableAllSmuFeatures = 0x07,
	GetRunningSmuFeaturesLow = 0x0C,
	GetRunningSmuFeaturesHigh = 0x0D,
	SetDriverDramAddrHigh = 0x0E,
	SetDriverDramAddrLow = 0x0F,
	SetToolsDramAddrHigh = 0x10,
	SetToolsDramAddrLow = 0x11,
	TransferTableSmu2Dram = 0x12,
	TransferTableDram2Smu = 0x13,
	UseDefaultPPTable = 0x14,
	SetSoftMinByFreq = 0x19,
	SetSoftMaxByFreq = 0x1A,
	NotifyPowerSource = 0x35,
	RunDcBtc = 0x36
};

struct SmuProtocol {
	Family family;
	Version mp1;
	uint32_t mailboxSegment;
	uint32_t messageOffset;
	uint32_t argumentOffset;
	uint32_t responseOffset;
	uint32_t expectedDriverIfVersion;
	uint32_t gfxClock;
	uint32_t socClock;
	uint32_t acPowerSource;
	uint32_t dcPowerSource;
	bool legacyPowerPolicies;
};

inline constexpr SmuProtocol kNavi44SmuProtocol = {
	Family::Navi44, {14, 0, 2}, 1, 0x82, 0x92, 0x9A, 0x2E,
	0, 1, 0, 1, false
};

// Pinned Linux commit 05f7e89ab9731565d8a62e3b5d1ec206485eeb0b uses the
// shared smu_v14_0_2_ppsmc map for Navi 48's 14.0.3 SMU. This protocol data
// and matching driver interface descriptor do not enable Navi 44 attachment.
inline constexpr SmuProtocol kNavi48SmuProtocol = {
	Family::Navi48, {14, 0, 3}, 1, 0x82, 0x92, 0x9A, 0x2E,
	0, 1, 0, 1, true
};

constexpr const SmuProtocol *smu_protocol(Family family, Version actual) {
	if (family == Family::Navi44 && version_matches(kNavi44SmuProtocol.mp1, actual))
		return &kNavi44SmuProtocol;
	if (family == Family::Navi48 && version_matches(kNavi48SmuProtocol.mp1, actual))
		return &kNavi48SmuProtocol;
	return nullptr;
}

constexpr bool smu_message_known(uint32_t raw) {
	switch (static_cast<SmuMessage>(raw)) {
	case SmuMessage::TestMessage:
	case SmuMessage::GetSmuVersion:
	case SmuMessage::GetDriverIfVersion:
	case SmuMessage::SetAllowedFeaturesMaskLow:
	case SmuMessage::SetAllowedFeaturesMaskHigh:
	case SmuMessage::EnableAllSmuFeatures:
	case SmuMessage::DisableAllSmuFeatures:
	case SmuMessage::GetRunningSmuFeaturesLow:
	case SmuMessage::GetRunningSmuFeaturesHigh:
	case SmuMessage::SetDriverDramAddrHigh:
	case SmuMessage::SetDriverDramAddrLow:
	case SmuMessage::SetToolsDramAddrHigh:
	case SmuMessage::SetToolsDramAddrLow:
	case SmuMessage::TransferTableSmu2Dram:
	case SmuMessage::TransferTableDram2Smu:
	case SmuMessage::UseDefaultPPTable:
	case SmuMessage::SetSoftMinByFreq:
	case SmuMessage::SetSoftMaxByFreq:
	case SmuMessage::NotifyPowerSource:
	case SmuMessage::RunDcBtc:
		return true;
	default:
		return false;
	}
}

constexpr bool smu_message_allowed(const SmuProtocol &protocol, uint32_t raw) {
	if (!smu_message_known(raw)) return false;
	if (protocol.family == Family::Navi48) return true;
	return protocol.family == Family::Navi44 &&
	       (raw == static_cast<uint32_t>(SmuMessage::TestMessage) ||
	        raw == static_cast<uint32_t>(SmuMessage::GetSmuVersion) ||
	        raw == static_cast<uint32_t>(SmuMessage::GetDriverIfVersion));
}

} // namespace cobalt

#endif
