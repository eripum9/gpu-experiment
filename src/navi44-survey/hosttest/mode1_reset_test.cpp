#include "../src/mode1_reset.hpp"

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using cobalt::reset::Io;
using cobalt::reset::Observation;
using cobalt::reset::Result;

static unsigned checks = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) throw std::runtime_error(std::string("line ") + std::to_string(__LINE__) + ": " #expr); } while (0)

static constexpr uint32_t kReady = 0x80000000u;
static constexpr uint32_t kBusy = 0x00000001u;

struct Sample {
	Observation value;
	bool context { true };
};

struct FakeIo final : Io {
	Observation initial { kReady, 0, 8192 };
	std::vector<Sample> samples;
	std::vector<std::string> events;
	bool failPreflight { false };
	bool failSave { false };
	bool failDisable { false };
	bool failGuard { false };
	bool failRestore { false };
	bool failPostflight { false };
	bool saved { false };
	bool disabled { false };
	bool quiet { false };
	bool restored { false };
	unsigned restoreCalls { 0 };
	unsigned sampleAt { 0 };
	unsigned pauses { 0 };

	void push(const char *event) { events.emplace_back(event); }
	bool preflight(Observation &out) override {
		push("preflight");out = initial;return !failPreflight;
	}
	bool savePci() override {
		push("save");saved = !failSave;return saved;
	}
	bool disableBusMaster() override {
		CHECK(saved);push("disable");disabled = !failDisable;return disabled;
	}
	bool readyToWrite() override {
		CHECK(disabled);CHECK(!quiet);push("guard");return !failGuard;
	}
	void parameterZero() override {
		CHECK(disabled && !quiet && !restored);push("param:0");
	}
	void mode1Command() override {
		CHECK(disabled && !quiet && !restored);push("command:2");
	}
	void clearDebugResponse() override {
		CHECK(disabled && !quiet && !restored);push("response:0");
	}
	void quiesce() override {
		CHECK(disabled && !quiet && !restored);push("quiesce:1000ms");quiet = true;
	}
	bool restorePci() override {
		CHECK(saved);++restoreCalls;push("restore");restored = !failRestore;
		return restored;
	}
	bool sampleRecovery(Observation &out) override {
		CHECK(quiet && restored);push("sample");
		if (sampleAt < samples.size()) {
			const Sample item = samples[sampleAt++];out = item.value;return item.context;
		}
		++sampleAt;out = {kReady, 0, initial.memsize};return true;
	}
	void pausePoll() override {
		CHECK(quiet && restored);++pauses;push("pause:1ms");
	}
	bool postflight() override {
		CHECK(quiet && restored);push("postflight");return !failPostflight;
	}
};

static void checkTail(const FakeIo &io, std::initializer_list<const char *> expected) {
	CHECK(io.events.size() >= expected.size());
	auto at = io.events.end() - static_cast<std::ptrdiff_t>(expected.size());
	for (const char *item : expected) CHECK(*at++ == item);
}

static void preflightAndSaveFailures() {
	{
		FakeIo io;io.failPreflight = true;const Result r = cobalt::reset::run(io);
		CHECK(!r.success && !r.pciSaved && r.storesIssued == 0 && r.polls == 0);
		CHECK(std::string(r.status) == "preflight-failed");CHECK(io.events.size() == 1);
	}
	for (const Observation invalid : {Observation{UINT32_MAX,0,8192},Observation{kReady,UINT32_MAX,8192},
		Observation{kReady,0,1023},Observation{kReady,0,65537}}) {
		FakeIo io;io.initial = invalid;const Result r = cobalt::reset::run(io);
		CHECK(!r.success && !r.pciSaved && r.storesIssued == 0);
		CHECK(std::string(r.status) == "preflight-failed");CHECK(io.events.size() == 1);
	}
	{
		FakeIo io;io.failSave = true;const Result r = cobalt::reset::run(io);
		CHECK(!r.pciSaved && io.restoreCalls == 0 && r.storesIssued == 0);
		CHECK(std::string(r.status) == "pci-save-failed");checkTail(io,{"preflight","save"});
	}
}

static void preBurstRestoreFailures() {
	for (unsigned failure = 0; failure < 2; ++failure) {
		FakeIo io;
		if (failure == 0) io.failDisable = true; else io.failGuard = true;
		const Result r = cobalt::reset::run(io);
		CHECK(r.pciSaved && r.busMasterDisabled == (failure == 1));
		CHECK(r.pciRestored == !io.failRestore);
		CHECK(io.restoreCalls == 1 && r.storesIssued == 0 && r.polls == 0);
		CHECK(!r.parameterAttempted && !r.commandAttempted && !r.responseAttempted && !r.quiesced);
		CHECK(std::string(r.status) == (failure == 0 ? "bus-master-disable-failed" : "pre-burst-guard-failed"));
		if (failure == 0) checkTail(io,{"disable","restore"});
		else checkTail(io,{"guard","restore"});
	}
	{
		FakeIo io;io.failGuard = true;io.failRestore = true;const Result r = cobalt::reset::run(io);
		CHECK(io.restoreCalls == 1 && !r.pciRestored);
		CHECK(std::string(r.status) == "pci-restore-failed");
	}
}

static void fixedBurstAndSuccess() {
	FakeIo io;
	io.initial = {kReady,0x55,8192};
	io.samples = {{{kReady,0,8192},true},{{kReady,0,8192},true}};
	const Result r = cobalt::reset::run(io);
	CHECK(r.success && r.pciSaved && r.busMasterDisabled && r.pciRestored && r.quiesced);
	CHECK(r.parameterAttempted && r.commandAttempted && r.responseAttempted && r.storesIssued == 3);
	CHECK(r.phase == cobalt::reset::kPhaseRecovered && r.recoveryObserved && r.resetTransitionObserved);
	CHECK(r.polls == 2 && io.pauses == 1 && io.restoreCalls == 1);
	CHECK(r.initial.sos == 0x55 && r.final.sos == 0 && r.final.memsize == 8192);
	CHECK(std::string(r.status) == "mode1-issued-recovery-observed");
	const auto param = std::find(io.events.begin(),io.events.end(),"param:0");
	CHECK(param != io.events.end());
	const size_t p = static_cast<size_t>(param - io.events.begin());
	CHECK(p + 3 < io.events.size());
	CHECK(io.events[p+1] == "command:2" && io.events[p+2] == "response:0" && io.events[p+3] == "quiesce:1000ms");
	const auto quiet = std::find(io.events.begin(),io.events.end(),"quiesce:1000ms");
	CHECK(quiet != io.events.end() && quiet + 1 != io.events.end() && *(quiet + 1) == "restore");
	checkTail(io,{"pause:1ms","sample","postflight"});
}

static void restoreAndContextFailures() {
	{
		FakeIo io;io.failRestore = true;const Result r = cobalt::reset::run(io);
		CHECK(!r.success && r.quiesced && !r.pciRestored && r.polls == 0 && r.storesIssued == 3);
		CHECK(std::string(r.status) == "pci-restore-failed");checkTail(io,{"quiesce:1000ms","restore"});
	}
	{
		FakeIo io;io.samples = {{{kReady,0,8192},true},{{kReady,0,8192},false}};
		const Result r = cobalt::reset::run(io);
		CHECK(!r.success && !r.recoveryObserved && r.polls == 2 && io.pauses == 1);
		CHECK(std::string(r.status) == "recovery-context-lost");checkTail(io,{"sample"});
	}
	{
		FakeIo io;io.failPostflight = true;const Result r = cobalt::reset::run(io);
		CHECK(!r.success && r.recoveryObserved && !r.resetTransitionObserved);
		CHECK(std::string(r.status) == "postflight-failed");
	}
}

static void recoveryFilteringAndTimeout() {
	{
		FakeIo io;io.initial = {kReady,0,4096};
		io.samples = {{{UINT32_MAX,0,4096},true},{{kReady,0x1234,4096},true},
			{{kBusy,0,4096},true},{{kReady,0,8192},true},
			{{kReady,0,4096},true},{{kReady,0,4096},true}};
		const Result r = cobalt::reset::run(io);
		CHECK(r.success && r.polls == 6 && io.pauses == 5);
		CHECK(!r.resetTransitionObserved && r.initial.sos == 0 && r.final.sos == 0);
	}
	{
		FakeIo io;io.samples.assign(cobalt::reset::kMaxPolls,Sample{{kBusy,0,8192},true});
		const Result r = cobalt::reset::run(io);
		CHECK(!r.success && !r.recoveryObserved && r.polls == cobalt::reset::kMaxPolls);
		CHECK(io.pauses == cobalt::reset::kMaxPolls - 1);
		CHECK(std::string(r.status) == "recovery-timeout");
	}
}

int main() {
	try {
		preflightAndSaveFailures();
		preBurstRestoreFailures();
		fixedBurstAndSuccess();
		restoreAndContextFailures();
		recoveryFilteringAndTimeout();
		std::printf("Mode 1 reset protocol checks passed: %u\n", checks);
		return 0;
	} catch (const std::exception &e) {
		std::fprintf(stderr,"%s\n",e.what());
		return 1;
	}
}
