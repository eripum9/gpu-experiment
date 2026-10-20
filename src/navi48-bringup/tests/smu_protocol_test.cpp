#include "../src/smu_protocol.hpp"

#include <stdio.h>
#include <limits.h>

using namespace cobalt;

namespace {
int failures = 0;
}

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
		++failures; \
	} \
} while (0)

int main() {
	const SmuMessage messages[] = {
		SmuMessage::TestMessage, SmuMessage::GetSmuVersion,
		SmuMessage::GetDriverIfVersion, SmuMessage::SetAllowedFeaturesMaskLow,
		SmuMessage::SetAllowedFeaturesMaskHigh, SmuMessage::EnableAllSmuFeatures,
		SmuMessage::DisableAllSmuFeatures, SmuMessage::GetRunningSmuFeaturesLow,
		SmuMessage::GetRunningSmuFeaturesHigh, SmuMessage::SetDriverDramAddrHigh,
		SmuMessage::SetDriverDramAddrLow, SmuMessage::SetToolsDramAddrHigh,
		SmuMessage::SetToolsDramAddrLow, SmuMessage::TransferTableSmu2Dram,
		SmuMessage::TransferTableDram2Smu, SmuMessage::UseDefaultPPTable,
		SmuMessage::SetSoftMinByFreq, SmuMessage::SetSoftMaxByFreq,
		SmuMessage::NotifyPowerSource, SmuMessage::RunDcBtc
	};
	const uint32_t ids[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0C, 0x0D, 0x0E,
		0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x19, 0x1A, 0x35, 0x36
	};
	static_assert(sizeof(messages) / sizeof(messages[0]) == 20, "20 SMU messages");
	for (unsigned i = 0; i < sizeof(messages) / sizeof(messages[0]); ++i) {
		CHECK(static_cast<uint32_t>(messages[i]) == ids[i]);
		CHECK(smu_message_allowed(kNavi48SmuProtocol, ids[i]));
		CHECK(smu_message_known(ids[i]));
	}

	CHECK(smu_protocol(Family::Navi44, {14, 0, 2}) == &kNavi44SmuProtocol);
	CHECK(smu_protocol(Family::Navi48, {14, 0, 3}) == &kNavi48SmuProtocol);
	CHECK(smu_protocol(Family::Navi44, {14, 0, 3}) == nullptr);
	CHECK(smu_protocol(Family::Navi48, {14, 0, 2}) == nullptr);
	CHECK(smu_protocol(Family::Unknown, {14, 0, 3}) == nullptr);
	CHECK(smu_protocol(static_cast<Family>(255), {14, 0, 3}) == nullptr);
	CHECK(smu_protocol(Family::Navi44, {0, 0, 0}) == nullptr);
	CHECK(smu_protocol(Family::Navi48, {0, 0, 0}) == nullptr);
	CHECK(smu_protocol(Family::Navi44, {14, 1, 2}) == nullptr);
	CHECK(smu_protocol(Family::Navi44, {14, 0, 3}) == nullptr);
	CHECK(smu_protocol(Family::Navi48, {14, 1, 3}) == nullptr);
	CHECK(smu_protocol(Family::Navi48, {14, 0, 2}) == nullptr);
	CHECK(smu_protocol(Family::Navi44, {13, 0, 2}) == nullptr);
	CHECK(smu_protocol(Family::Navi48, {13, 0, 3}) == nullptr);

	const SmuProtocol *protocols[] = {&kNavi44SmuProtocol, &kNavi48SmuProtocol};
	for (const SmuProtocol *protocol : protocols) {
		CHECK(protocol->mailboxSegment == 1);
		CHECK(protocol->messageOffset == 0x82);
		CHECK(protocol->argumentOffset == 0x92);
		CHECK(protocol->responseOffset == 0x9A);
		CHECK(protocol->expectedDriverIfVersion == 0x2E);
		CHECK(protocol->gfxClock == 0);
		CHECK(protocol->socClock == 1);
		CHECK(protocol->acPowerSource == 0);
		CHECK(protocol->dcPowerSource == 1);
	}
	CHECK(!kNavi44SmuProtocol.legacyPowerPolicies);
	CHECK(kNavi48SmuProtocol.legacyPowerPolicies);
	CHECK(!kNavi44Profile.bringupEnabled);

	CHECK(smu_message_allowed(kNavi44SmuProtocol,
	                         static_cast<uint32_t>(SmuMessage::TestMessage)));
	CHECK(smu_message_allowed(kNavi44SmuProtocol,
	                         static_cast<uint32_t>(SmuMessage::GetSmuVersion)));
	CHECK(smu_message_allowed(kNavi44SmuProtocol,
	                         static_cast<uint32_t>(SmuMessage::GetDriverIfVersion)));
	for (unsigned i = 3; i < sizeof(ids) / sizeof(ids[0]); ++i)
		CHECK(!smu_message_allowed(kNavi44SmuProtocol, ids[i]));

	CHECK(!smu_message_known(0));
	CHECK(!smu_message_known(UINT_MAX));
	CHECK(!smu_message_allowed(kNavi44SmuProtocol, 0));
	CHECK(!smu_message_allowed(kNavi48SmuProtocol, UINT_MAX));
	CHECK(!smu_message_allowed(kNavi48SmuProtocol,
	                          static_cast<uint32_t>(static_cast<SmuMessage>(0x08))));
	CHECK(!smu_message_allowed(kNavi48SmuProtocol,
	                          static_cast<uint32_t>(static_cast<SmuMessage>(UINT_MAX))));

	return failures == 0 ? 0 : 1;
}
