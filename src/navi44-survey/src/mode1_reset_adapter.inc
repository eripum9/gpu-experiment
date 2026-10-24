// Included in CobaltNavi44Survey.cpp's anonymous namespace. This adapter is
// derived from the pinned protocol facts, with independent local policy.
struct Mode1AdapterResult {
    cobalt::reset::Result protocol {};
    Mode1DebugTarget debug {};
    const char *reason {"prerequisites-unavailable"};
    bool consoleRecovered {false};
    bool pciMutationAttempted {false};
    struct PeerCensus {
        bool observed {false}, iteratorPresent {false}, iteratorValid {false}, exhausted {false};
        uint32_t clientCount {0}, selfCount {0}, unexpectedCount {0};
        char firstUnexpectedClass[96] {};
        bool firstUnexpectedClassTruncated {false};
        const char *status {"not-observed"};
    } peerCensus;
};

using Mode1PeerCensus = Mode1AdapterResult::PeerCensus;

bool mode1PeerCensus(IOPCIDevice *pci, IOService *service, Mode1PeerCensus &census) {
    census.observed = true;
    OSIterator *iterator = pci->getClientIterator();
    if (!iterator) {
        census.status = "iterator-unavailable";
        return false;
    }
    census.iteratorPresent = true;
    OSObject *entry = nullptr;
    while (census.clientCount < 64 && (entry = iterator->getNextObject())) {
        ++census.clientCount;
        if (entry == service) ++census.selfCount;
        else {
            ++census.unexpectedCount;
            if (census.unexpectedCount == 1) {
                const char *className = entry->getMetaClass()->getClassName();
                const int written = snprintf(census.firstUnexpectedClass,
                    sizeof(census.firstUnexpectedClass), "%s", className ? className : "unknown");
                census.firstUnexpectedClassTruncated = written < 0 ||
                    static_cast<size_t>(written) >= sizeof(census.firstUnexpectedClass);
            }
        }
    }
    census.iteratorValid = iterator->isValid();
    census.exhausted = census.iteratorValid && census.clientCount < 64 && entry == nullptr;
    iterator->release();
    if (!census.iteratorValid) census.status = "iterator-invalid";
    else if (!census.exhausted) census.status = "client-limit";
    else if (census.unexpectedCount) census.status = "additional-clients";
    else if (census.selfCount != 1) census.status = "self-missing";
    else census.status = "self-only";
    return census.iteratorValid && census.exhausted && census.clientCount == 1 &&
        census.selfCount == 1 && census.unexpectedCount == 0;
}

bool mode1AnyAttempt(IOPCIDevice *pci) {
    const char *keys[] = {"CobaltSurvey,Mode1ResetAttempt-v1", "CobaltSurvey,ApertureAttempt-v1",
        "CobaltSurvey,StagingAttempt-v1", "CobaltSurvey,KdbAttempt-v1", "CobaltSurvey,KdbSplAttempt-v1",
        "CobaltSurvey,PreSosAttempt-v1", "CobaltSurvey,SosBootAttempt-v1"};
    for (const char *key : keys) if (pci->getProperty(key)) return true;
    return false;
}

const char *const kMode1Properties[] = {"Armed", "Attempted", "Phase", "StoresIssued", "PciSaved",
    "BusMasterDisabled", "PciRestored", "PciMutationAttempted", "Quiesced", "RecoveryObserved", "ResetTransitionObserved",
    "ColdCycleReplacementValidated", "InitialBootloaderRaw", "FinalBootloaderRaw", "InitialSosRaw",
    "FinalSosRaw", "InitialMemsizeMiB", "FinalMemsizeMiB", "Polls", "Status", "Reason",
    "ParameterByteOffset", "MessageByteOffset", "ResponseByteOffset", "ConsoleRecovered", "ReadOnly", "Success",
    "PeerCensusObserved", "PeerCensusIteratorPresent", "PeerCensusIteratorValid", "PeerCensusExhausted",
    "PeerCensusClientCount", "PeerCensusSelfCount", "PeerCensusUnexpectedCount", "PeerCensusFirstUnexpectedClass",
    "PeerCensusFirstUnexpectedClassTruncated", "PeerCensusStatus"};

void clearMode1Properties(IOService *service) {
    for (const char *name : kMode1Properties) {
        char key[96]; snprintf(key, sizeof(key), "CobaltSurvey,Mode1Reset%s", name);
        service->removeProperty(key);
    }
}

bool publishMode1(IOService *service, const Mode1AdapterResult &result) {
    const auto &r = result.protocol;
    // Revoke a previous commit before beginning this publication transaction.
    service->removeProperty("CobaltSurvey,Schema");
    bool published = service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
#define MODE1_BOOL(name, value) published = service->setProperty("CobaltSurvey,Mode1Reset" name, value) && published
#define MODE1_NUM(name, value) published = service->setProperty("CobaltSurvey,Mode1Reset" name, value, 32) && published
    MODE1_BOOL("Armed", false);
    MODE1_BOOL("Attempted", true);
    MODE1_NUM("Phase", r.phase);
    MODE1_NUM("StoresIssued", r.storesIssued);
    MODE1_BOOL("PciSaved", r.pciSaved);
    MODE1_BOOL("BusMasterDisabled", r.busMasterDisabled);
    MODE1_BOOL("PciRestored", r.pciRestored);
    MODE1_BOOL("PciMutationAttempted", result.pciMutationAttempted);
    MODE1_BOOL("Quiesced", r.quiesced);
    MODE1_BOOL("RecoveryObserved", r.recoveryObserved);
    MODE1_BOOL("ResetTransitionObserved", r.resetTransitionObserved);
    MODE1_BOOL("ColdCycleReplacementValidated", false);
    MODE1_NUM("InitialBootloaderRaw", r.initial.bootloader);
    MODE1_NUM("FinalBootloaderRaw", r.final.bootloader);
    MODE1_NUM("InitialSosRaw", r.initial.sos);
    MODE1_NUM("FinalSosRaw", r.final.sos);
    MODE1_NUM("InitialMemsizeMiB", r.initial.memsize);
    MODE1_NUM("FinalMemsizeMiB", r.final.memsize);
    MODE1_NUM("Polls", r.polls);
    MODE1_BOOL("Status", r.status);
    MODE1_BOOL("Reason", result.reason);
    MODE1_NUM("ParameterByteOffset", result.debug.parameter);
    MODE1_NUM("MessageByteOffset", result.debug.message);
    MODE1_NUM("ResponseByteOffset", result.debug.response);
    MODE1_BOOL("ConsoleRecovered", result.consoleRecovered);
    MODE1_BOOL("ReadOnly", !result.pciMutationAttempted && r.storesIssued == 0);
    MODE1_BOOL("Success", r.success);
    const auto &census = result.peerCensus;
    MODE1_BOOL("PeerCensusObserved", census.observed);
    MODE1_BOOL("PeerCensusIteratorPresent", census.iteratorPresent);
    MODE1_BOOL("PeerCensusIteratorValid", census.iteratorValid);
    MODE1_BOOL("PeerCensusExhausted", census.exhausted);
    MODE1_NUM("PeerCensusClientCount", census.clientCount);
    MODE1_NUM("PeerCensusSelfCount", census.selfCount);
    MODE1_NUM("PeerCensusUnexpectedCount", census.unexpectedCount);
    MODE1_BOOL("PeerCensusFirstUnexpectedClassTruncated", census.firstUnexpectedClassTruncated);
    published = service->setProperty("CobaltSurvey,Mode1ResetPeerCensusFirstUnexpectedClass",
        census.firstUnexpectedClass) && published;
    published = service->setProperty("CobaltSurvey,Mode1ResetPeerCensusStatus", census.status) && published;
#undef MODE1_BOOL
#undef MODE1_NUM
    published = service->setProperty("CobaltSurvey,AccessMode", "smu-debug-mode1-reset") && published;
    service->removeProperty("CobaltSurvey,Ready");
    published = service->setProperty("CobaltSurvey,Ready", false) && published;
    // Indexed boot collection already used selector stores, including when
    // the later reset request is refused without touching PCI or debug MMIO.
    published = service->setProperty("CobaltSurvey,ReadOnly", false) && published;
    if (published && r.success && result.consoleRecovered &&
        service->setProperty("CobaltSurvey,Schema", 11ULL, 32)) return true;
    // Failure must not leave an apparently committed success, even if the
    // property setter failed partway through the transaction.
    service->removeProperty("CobaltSurvey,Schema");
    service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
    if (!published || r.success) {
        service->removeProperty("CobaltSurvey,Mode1ResetSuccess");
        service->setProperty("CobaltSurvey,Mode1ResetSuccess", false);
        service->removeProperty("CobaltSurvey,Mode1ResetStatus");
        service->setProperty("CobaltSurvey,Mode1ResetStatus", "metadata-publication-failed");
    }
    return false;
}

class Mode1Transaction final : public cobalt::reset::Io {
    IOService *service;
    IOPCIDevice *pci;
    ProviderSession &session;
    PciState saved, disabled;
    const Aperture &mmio, &vram;
    Mode1DebugMapping debug;
    const volatile uint8_t *readPages[4];
    uint32_t offsets[7]; // boot, SOS, MC base/top/offset, DCN base, memsize
    uint32_t initial[7] {};
    ConsoleObservation console {};
    Mode1AdapterResult &result;
    bool lost {false}, pciWasSaved {false}, restored {false};

    bool fail(const char *reason) { result.reason = reason; lost = true; return false; }
    bool providerSafe() const {
        return service->getProvider() == pci && session.owns() && apertureOnlyClient(pci, service);
    }
    bool guard(const PciState &expected) {
        if (lost) return false;
        if (!providerSafe() || !consoleGuard(pci, expected, mmio, vram)) return fail("device-context-changed");
        return true;
    }
    uint32_t read(unsigned index) const {
        const unsigned page = index < 2 ? 0 : index < 5 ? 1 : index == 5 ? 2 : 3;
        const auto *word = reinterpret_cast<const volatile uint32_t *>(readPages[page] + (offsets[index] & 0xfff));
#if defined(COBALT_SURVEY_HOSTTEST)
        return cobaltSurveyTestMode1Read32(word, offsets[index]);
#else
        return OSSwapLittleToHostInt32(*word);
#endif
    }
    bool stableState(const PciState &expected, bool captureInitial) {
        for (unsigned pass = 0; pass < 2; ++pass) for (unsigned n = 0; n < 7; ++n) {
            if (!guard(expected)) return false;
            const uint32_t value = read(n);
            if (!guard(expected)) return false;
            if (value == UINT32_MAX) return fail("preflight-register-unreadable");
            if (captureInitial && pass == 0) initial[n] = value;
            else if (value != initial[n]) return fail("fresh-state-changed");
        }
        return plausibleMemsize(initial[6]) || fail("preflight-memsize-invalid");
    }
    bool stableConsole(const PciState &expected, bool captureInitial) {
        ConsoleObservation current {};
        if (!guard(expected)) return false;
        const char *failure = passiveConsole(pci, expected, mmio, vram, current);
        if (failure) return fail(failure);
        if (!current.span) return fail("console-range-invalid");
        if (captureInitial) console = current;
        else for (unsigned n = 0; n < kConsoleScalarCount; ++n)
            if (current.values[n] != console.values[n]) return fail("console-layout-changed");
        return guard(expected);
    }
public:
    Mode1Transaction(IOService *s, IOPCIDevice *p, ProviderSession &owner, const PciState &state,
        const Aperture &m, const Aperture &v, Mode1DebugMapping d,
        const volatile uint8_t *const (&pages)[4], const uint32_t (&regs)[7], Mode1AdapterResult &r)
        : service(s), pci(p), session(owner), saved(state), disabled(state), mmio(m), vram(v), debug(d), result(r) {
        disabled.command = static_cast<uint16_t>(saved.command & ~4u);
        for (unsigned n = 0; n < 4; ++n) readPages[n] = pages[n];
        for (unsigned n = 0; n < 7; ++n) offsets[n] = regs[n];
    }
    bool preflight(cobalt::reset::Observation &observation) override {
        if (!debug.valid() || !stableState(saved, true)) return false;
        observation = {initial[0], initial[1], initial[6]};
        if (!stableConsole(saved, true) || !guard(saved)) return false;
        if (mode1AnyAttempt(pci)) return fail("provider-already-attempted");
        if (!pci->setProperty("CobaltSurvey,Mode1ResetAttempt-v1", true)) return fail("provider-claim-failed");
        return guard(saved);
    }
    bool savePci() override {
        if (!guard(saved)) return false;
        pciWasSaved = pci->saveDeviceState(0) == kIOReturnSuccess;
        if (!pciWasSaved) { result.reason = "pci-save-failed"; return false; }
        return true;
    }
    bool disableBusMaster() override {
        if (!guard(saved)) return false;
        // The API returns the previous bus-master state, not a success code.
        result.pciMutationAttempted = true;
        (void)pci->setBusMasterEnable(false);
        return guard(disabled);
    }
    bool readyToWrite() override {
        if (!stableState(disabled, false) || !stableConsole(disabled, false) || !guard(disabled)) return false;
        IOLog("CobaltNavi44Survey: issuing manually requested SMU debug Mode1 reset\n");
        return guard(disabled);
    }
    void parameterZero() override { debug.parameterZero(); }
    void mode1Command() override { debug.mode1Command(); }
    void clearDebugResponse() override { debug.clearDebugResponse(); }
    void quiesce() override {
#if defined(COBALT_SURVEY_HOSTTEST)
        std::atomic_thread_fence(std::memory_order_seq_cst);
#else
        __sync_synchronize();
#endif
        IOSleep(1000);
#if defined(COBALT_SURVEY_HOSTTEST)
        std::atomic_thread_fence(std::memory_order_seq_cst);
#else
        __sync_synchronize();
#endif
    }
    bool restorePci() override {
        // Restoration deliberately ignores the sticky MMIO guard: a failed
        // pre-burst readback still deserves one safe PCI restoration attempt.
        // Never restore through a removed provider or changed identity.
        if (!pciWasSaved || restored || !providerSafe() ||
            pci->configRead32(static_cast<UInt8>(0)) != saved.identity) {
            result.reason = "pci-restore-unsafe"; return false;
        }
        restored = true;
        result.pciMutationAttempted = true;
        if (pci->restoreDeviceState(0) != kIOReturnSuccess) {
            result.reason = "pci-restore-failed"; return false;
        }
        if (!providerSafe() || !consoleGuard(pci, saved, mmio, vram)) {
            result.reason = "pci-restore-readback-failed"; return false;
        }
        return true;
    }
    bool sampleRecovery(cobalt::reset::Observation &sample) override {
        if (!guard(saved)) return false;
        sample.bootloader = read(0);
        if (!guard(saved)) return false;
        sample.sos = read(1);
        if (!guard(saved)) return false;
        sample.memsize = read(6);
        return guard(saved);
    }
    void pausePoll() override { IOSleep(1); }
    bool postflight() override {
        if (!stableConsole(saved, false)) return false;
        for (unsigned pass = 0; pass < 2; ++pass) for (unsigned n = 0; n < 7; ++n) {
            if (!guard(saved)) return false;
            const uint32_t value = read(n);
            if (!guard(saved)) return false;
            if (value == UINT32_MAX || (n == 0 && !(value & cobalt::reset::kBootReadyBit)) ||
                (n == 1 && value != 0)) return fail("postflight-recovery-changed");
            if (n >= 2 && value != initial[n]) return fail("postflight-layout-changed");
        }
        result.consoleRecovered = guard(saved);
        if (result.consoleRecovered) result.reason = "stable-pci-memory-and-console-observed";
        return result.consoleRecovered;
    }
};

COBALT_SURVEY_NOINLINE void runMode1(IOService *service, IOPCIDevice *pci, OSData *snapshot,
    Mode1AdapterResult &result) {
    if (!snapshot || snapshot->getLength() != kDiscoverySize) { result.reason = "snapshot-unavailable"; return; }
    IpDiscovery discovery;
    IpDiscovery::GcTopology topology {};
    if (!discovery.init(static_cast<const uint8_t *>(snapshot->getBytesNoCopy()), snapshot->getLength()) ||
        !criticalIps(discovery) || !discovery.gcTopology(topology) ||
        !cobalt::gfx_topology_compatible(cobalt::Family::Navi44, cobalt::kNavi44Profile.gc, topology)) {
        result.reason = "retained-discovery-invalid"; return;
    }
    const uint16_t ids[] = {IpDiscovery::HwMp0, IpDiscovery::HwMp1, IpDiscovery::HwMmhub,
        IpDiscovery::HwDmu, IpDiscovery::HwNbif};
    const cobalt::Version versions[] = {{14,0,2}, {14,0,2}, {4,1,0}, {4,1,0}, {6,3,1}};
    const unsigned bases[] = {1, 2, 1, 3, 3};
    for (unsigned n = 0; n < 5; ++n) {
        unsigned count = 0;
        for (uint16_t i = 0; i < discovery.ipCount(); ++i) {
            IpDiscovery::IpEntry ip {};
            if (!discovery.ipAt(i, ip)) { result.reason = "ip-record-invalid"; return; }
            if (ip.hwId != ids[n]) continue;
            ++count;
            if (ip.instance || ip.numBases < bases[n] ||
                !cobalt::version_matches(versions[n], {ip.major, ip.minor, ip.revision})) {
                result.reason = "ip-version-or-instance-mismatch"; return;
            }
        }
        if (count != 1) { result.reason = "ip-record-missing-or-duplicate"; return; }
    }
    PciState state {};
    if (!capture(pci, state) || !validHeaderClass(state) || !(state.command & 2u)) {
        result.reason = "pci-preflight-invalid"; return;
    }
    const Aperture mmio = aperture(pci, 5), vram = aperture(pci, 0);
    const uint64_t mmioBase = state.bars[5] & ~0xfu;
    const uint64_t vramBase = (static_cast<uint64_t>(state.bars[1]) << 32) | (state.bars[0] & ~0xfu);
    if ((state.bars[5] & 0xfu) || (state.bars[4] & 7u) == 4u || (state.bars[0] & 7u) != 4u ||
        !apertureValid(mmio, mmioBase) || mmio.length > (1ULL << 32) - mmioBase ||
        !apertureValid(vram, vramBase)) { result.reason = "bar-descriptor-invalid"; return; }
    uint32_t offsets[7] {};
    const uint16_t hw[] = {ids[0], ids[0], ids[2], ids[2], ids[2], ids[3], ids[4]};
    const uint32_t words[] = {0x63, 0x91, 0x554, 0x555, 0x4c7, 0x475, 0xc3};
    for (unsigned n = 0; n < 7; ++n)
        if (!discovery.regByteOffset(hw[n], 0, n >= 5 ? 2 : 0, words[n], offsets[n])) {
            result.reason = "register-offset-unavailable"; return;
        }
    if (offsets[6] != kMemsizePage + kMemsizeInPage ||
        !discovery.regByteOffset(ids[1], 0, 1, 0x75, result.debug.parameter) ||
        !discovery.regByteOffset(ids[1], 0, 1, 0x8b, result.debug.message) ||
        !discovery.regByteOffset(ids[1], 0, 1, 0x76, result.debug.response) || !result.debug.valid()) {
        result.reason = "debug-or-memsize-offset-invalid"; return;
    }
    const uint32_t pages[] = {offsets[0] & ~0xfffu, offsets[2] & ~0xfffu,
        offsets[5] & ~0xfffu, offsets[6] & ~0xfffu, result.debug.page()};
    for (unsigned n = 0; n < 5; ++n) {
        if (!pages[n] || pages[n] == 0x7f000 || pages[n] > mmio.length || 4096 > mmio.length - pages[n]) {
            result.reason = "register-page-out-of-range"; return;
        }
        // MP0's read-only status endpoints and MP1's typed debug endpoints
        // share a physical page on the target. Permit only this role alias;
        // each independent view still undergoes the full mapping proof.
        for (unsigned i = 0; i < n; ++i) if (pages[i] == pages[n] && !(n == 4 && i == 0)) {
            result.reason = "register-page-collision"; return;
        }
    }
    for (unsigned n = 0; n < 7; ++n) {
        const unsigned page = n < 2 ? 0 : n < 5 ? 1 : n == 5 ? 2 : 3;
        if ((offsets[n] & 3u) || (offsets[n] & ~0xfffu) != pages[page]) {
            result.reason = "register-offset-invalid"; return;
        }
        if (offsets[n] == result.debug.parameter || offsets[n] == result.debug.message ||
            offsets[n] == result.debug.response) {
            result.reason = "register-endpoint-collision"; return;
        }
    }
    if (!mode1PeerCensus(pci, service, result.peerCensus)) { result.reason = "peer-refused"; return; }
    ProviderSession session(pci, service);
    if (!session.open()) { result.reason = "provider-busy"; return; }
    if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
        result.reason = "device-context-changed"; return;
    }
    Map readMaps[4], debugMap;
    const volatile uint8_t *readPages[4] {};
    for (unsigned n = 0; n < 4; ++n) {
        if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
            result.reason = "device-context-changed"; return;
        }
        if (!readMaps[n].create(mmio, pages[n], 4096)) { result.reason = "read-map-failed"; return; }
        readPages[n] = readMaps[n].bytes();
        if (!readPages[n] || (reinterpret_cast<uintptr_t>(readPages[n]) & 3u)) {
            result.reason = "read-map-invalid"; return;
        }
    }
    if (!session.owns() || !consoleGuard(pci, state, mmio, vram) || !apertureOnlyClient(pci, service)) {
        result.reason = "device-context-changed"; return;
    }
    if (!debugMap.createMode1DebugPage(mmio, result.debug)) { result.reason = "debug-map-failed"; return; }
    const Mode1DebugMapping debug = debugMap.mode1Debug(result.debug);
    if (!debug.valid()) { result.reason = "debug-map-invalid"; return; }
    Mode1Transaction transaction(service, pci, session, state, mmio, vram, debug, readPages, offsets, result);
    result.protocol = cobalt::reset::run(transaction);
    if (!result.protocol.success && !strcmp(result.reason, "prerequisites-unavailable"))
        result.reason = result.protocol.status;
}

// Consumes the caller's two retained references. No GPU mappings, provider
// opens, temporary snapshot references or retained PCI references survive into
// result publication (the immutable registry snapshot is observational data).
COBALT_SURVEY_NOINLINE bool runAndPublishMode1(IOService *service, IOPCIDevice *pci, OSData *snapshot) {
    Mode1AdapterResult result;
    runMode1(service, pci, snapshot, result);
    if (snapshot) snapshot->release();
    if (pci) pci->release();
    return publishMode1(service, result);
}
