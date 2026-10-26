// Included after the standalone adapters. This is one synchronous capability-
// guarded reset -> fresh discovery -> fixed eight-image SOS transaction.
struct EarlyInitContext {
    // Class-specific placement construction keeps all default result values
    // without requiring a large aggregate temporary on the kernel stack.
    static void *operator new(size_t, void *storage) { return storage; }
    ProviderSession session;
    EarlyInitAuthorization authorization;
    Mode1AdapterResult reset {};
    SosBootResult sos {};
    PciState state {};
    Aperture mmio {}, vram {};
    StateObservation prior {};
    ConsoleObservation console {};
    ApertureProof apertureProof {};
    KdbProof firmwareProof {};
    uint8_t *fresh {nullptr};
    uint32_t mib {0};
    const char *status {"early-prerequisites-unavailable"};
    bool attempted {false}, success {false}, published {true};
    bool consoleRePauseAttempted {false}, consoleRePaused {false};
    bool discoveryVerified {false};
    uint32_t discoveryReads {0}, discoverySelectorWrites {0};
    EarlyInitContext(IOService *service, IOPCIDevice *pci)
        : session(pci, service), authorization(service, pci, session) { reset.earlyBoot = true; }
    ~EarlyInitContext() { if (fresh) IOFree(fresh, 2 * kDiscoverySize); }
};

void clearEarlyInitProperties(IOService *service) {
    const char *names[] = {"Requested", "Trigger", "Attempted", "Phase", "Status", "Success",
        "ColdCycleReplacementValidated", "ConsoleRePauseAttempted", "ConsoleRePaused",
        "DiscoveryVerified", "DiscoveryDataReads", "DiscoverySelectorWrites"};
    for (const char *name : names) {
        char key[96]; snprintf(key, sizeof(key), "CobaltSurvey,EarlyInit%s", name);
        service->removeProperty(key);
    }
}

bool earlyInitPhase(IOService *service, EarlyInitContext &context) {
    const bool ok = service->setProperty("CobaltSurvey,EarlyInitPhase", context.authorization.currentPhase(), 32);
    context.published = ok && context.published;
    if (!ok) context.status = "metadata-publication-failed";
    return ok;
}

bool earlyInitGuard(IOService *service, IOPCIDevice *pci, EarlyInitContext &context) {
    if (!context.authorization.owns(service, pci, context.session) || !context.authorization.guard() ||
        !consoleGuard(pci, context.state, context.mmio, context.vram)) return false;
    ConsoleObservation observed {};
    if (passiveConsole(pci, context.state, context.mmio, context.vram, observed) || !observed.span) return false;
    for (unsigned n = 0; n < kConsoleScalarCount; ++n)
        if (observed.values[n] != context.console.values[n]) return false;
    return context.authorization.guard() && consoleGuard(pci, context.state, context.mmio, context.vram);
}

// Every read uses a newly created post-reset mapping. The retained snapshot is
// an equality baseline only: it never supplies the firmware-phase permission.
COBALT_SURVEY_NOINLINE bool earlyInitRefresh(IOService *service, IOPCIDevice *pci,
    OSData *retained, EarlyInitContext &context) {
    if (!context.authorization.discoveryAuthorized() || !earlyInitGuard(service, pci, context)) {
        context.status = "post-reset-context-changed"; return false;
    }
    PciState freshState {};
    if (!capture(pci, freshState) || !validHeaderClass(freshState) || !(freshState.command & 2u)) {
        context.status = "post-reset-pci-invalid"; return false;
    }
    const Aperture mmio = aperture(pci, 5), vram = aperture(pci, 0);
    const uint64_t mmioBase = freshState.bars[5] & ~0xfu;
    const uint64_t vramBase = (static_cast<uint64_t>(freshState.bars[1]) << 32) | (freshState.bars[0] & ~0xfu);
    if ((freshState.bars[5] & 0xfu) || (freshState.bars[4] & 7u) == 4u ||
        (freshState.bars[0] & 7u) != 4u || !apertureValid(mmio, mmioBase) ||
        mmio.length != 0x80000 || vram.length != (256ULL << 20) || !apertureValid(vram, vramBase) ||
        !earlyInitGuard(service, pci, context)) {
        context.status = "post-reset-bar-invalid"; return false;
    }
    context.state = freshState; context.mmio = mmio; context.vram = vram;
    Map memsize;
    if (!memsize.create(mmio, kMemsizePage, kMemsizePageSize) || !memsize.bytes() ||
        (reinterpret_cast<uintptr_t>(memsize.bytes()) & 3u) || !earlyInitGuard(service, pci, context)) {
        context.status = "post-reset-memsize-map-failed"; return false;
    }
    const uint32_t first = readMemsize(memsize.bytes());
    if (!earlyInitGuard(service, pci, context)) { context.status = "post-reset-context-changed"; return false; }
    const uint32_t second = readMemsize(memsize.bytes());
    if (!earlyInitGuard(service, pci, context) || first != second || !plausibleMemsize(first) ||
        first != context.reset.protocol.final.memsize) {
        context.status = "post-reset-memsize-invalid"; return false;
    }
    context.mib = first;
    context.fresh = static_cast<uint8_t *>(IOMalloc(2 * kDiscoverySize));
    if (!context.fresh) { context.status = "post-reset-discovery-allocation-failed"; return false; }
    {
        Map selectors;
        if (!earlyInitGuard(service, pci, context) || !selectors.createIndexedPage(mmio) || !selectors.selectorPage()) {
            context.status = "post-reset-discovery-map-failed"; return false;
        }
        IndexedTransaction capture(service, pci, context.state, mmio, vram, context.session,
            selectors.selectorPage(), &context.authorization);
        const char *failure = capture.save();
        if (failure) { context.status = failure; return false; }
        failure = capture.copy(static_cast<uint64_t>(first) << 20, context.fresh);
        if (earlyInitGuard(service, pci, context)) {
            if (readMemsize(memsize.bytes()) != first && !failure) failure = "post-reset-memsize-changed";
        } else if (!failure) failure = "post-reset-context-changed";
        // No firmware callback is reachable unless restoration is observed.
        const bool restored = capture.cleanup();
        context.discoveryReads = capture.dataReads();
        context.discoverySelectorWrites = capture.selectorWrites();
        if (!restored) { context.status = "post-reset-discovery-cleanup-unverified"; return false; }
        if (failure) { context.status = failure; return false; }
    }
    if (!earlyInitGuard(service, pci, context) || !retained || retained->getLength() != kDiscoverySize ||
        memcmp(context.fresh, retained->getBytesNoCopy(), kDiscoverySize)) {
        context.status = "post-reset-discovery-changed"; return false;
    }
    IpDiscovery discovery;
    IpDiscovery::GcTopology topology {};
    if (!discovery.init(context.fresh, kDiscoverySize) || !criticalIps(discovery) ||
        !discovery.gcTopology(topology) || !cobalt::gfx_topology_compatible(
            cobalt::Family::Navi44, cobalt::kNavi44Profile.gc, topology)) {
        context.status = "post-reset-discovery-invalid"; return false;
    }
    const char *failure = passiveState(pci, context.state, mmio, vram, discovery, context.prior);
    if (failure || !earlyInitGuard(service, pci, context)) {
        context.status = failure ? failure : "post-reset-context-changed"; return false;
    }
    context.apertureProof = apertureProof(discovery, context.prior, mmio);
    context.firmwareProof = kdbProof(discovery, context.apertureProof, mmio);
    if (context.apertureProof.failure || context.firmwareProof.failure) {
        context.status = context.apertureProof.failure ? context.apertureProof.failure : context.firmwareProof.failure;
        return false;
    }
    if (readMemsize(memsize.bytes()) != first || !earlyInitGuard(service, pci, context) ||
        context.prior.values[0] != 0x80000000u || context.prior.values[1] != 0) {
        context.status = "post-reset-state-invalid"; return false;
    }
    context.discoveryVerified = true;
    return true;
}

// Read-only postflight: after the final SOS store the adapter may never issue
// staging, mailbox, selector or flush writes, including restoration writes.
COBALT_SURVEY_NOINLINE bool earlyInitPostflight(IOService *service, IOPCIDevice *pci, EarlyInitContext &context) {
    if (!earlyInitGuard(service, pci, context)) return false;
    Map nbif, mp0, mmhub, dmu;
    const uint32_t pages[] = {context.apertureProof.remapOffset & ~0xfffu,
        context.firmwareProof.offsets[0] & ~0xfffu, context.firmwareProof.offsets[2] & ~0xfffu,
        context.firmwareProof.offsets[5] & ~0xfffu};
    Map *maps[] = {&nbif, &mp0, &mmhub, &dmu};
    for (unsigned n = 0; n < 4; ++n) {
        if (!earlyInitGuard(service, pci, context) || !maps[n]->create(context.mmio, pages[n], 4096) ||
            !maps[n]->bytes() || (reinterpret_cast<uintptr_t>(maps[n]->bytes()) & 3u)) return false;
    }
    for (unsigned pass = 0; pass < 2; ++pass) {
        const uint32_t nbifOffsets[] = {context.apertureProof.remapOffset, context.apertureProof.memsizeOffset};
        const uint32_t expected[] = {context.sos.flushOffset, context.mib};
        for (unsigned n = 0; n < 2; ++n) {
            if (!earlyInitGuard(service, pci, context)) return false;
            const auto *word = reinterpret_cast<const volatile uint32_t *>(nbif.bytes() + (nbifOffsets[n] & 0xfff));
            if (apertureRegisterRead(word, nbifOffsets[n]) != expected[n] || !earlyInitGuard(service, pci, context)) return false;
        }
        for (unsigned n = 0; n < 6; ++n) {
            if (!earlyInitGuard(service, pci, context)) return false;
            const volatile uint8_t *page = n < 2 ? mp0.bytes() : n < 5 ? mmhub.bytes() : dmu.bytes();
            const uint32_t offset = context.firmwareProof.offsets[n];
            const auto *word = reinterpret_cast<const volatile uint32_t *>(page + (offset & 0xfff));
#if defined(COBALT_SURVEY_HOSTTEST)
            const uint32_t value = cobaltSurveyTestReadState32(const_cast<volatile uint32_t *>(word), offset);
#else
            const uint32_t value = *word;
#endif
            if (!earlyInitGuard(service, pci, context) || value == UINT32_MAX ||
                (n == 1 && (value == 0 || value != context.sos.finalSosRaw)) ||
                (n >= 2 && value != context.sos.raw[n])) return false;
            // SOS has its own liveness register; no boot-ready assertion is
            // inferred or required after its final command.
        }
    }
    return earlyInitGuard(service, pci, context);
}

COBALT_SURVEY_NOINLINE void runEarlyInitHardware(IOService *service, IOPCIDevice *pci,
    OSData *retained, EarlyInitContext &context) {
    if (!initBootFlagsValid() || !retained || retained->getLength() != kDiscoverySize ||
        !capture(pci, context.state) || !validHeaderClass(context.state) || !(context.state.command & 2u)) return;
    context.mmio = aperture(pci, 5); context.vram = aperture(pci, 0);
    const char *consoleFailure = passiveConsole(pci, context.state, context.mmio, context.vram, context.console);
    if (consoleFailure || !context.console.span) {
        context.status = consoleFailure ? consoleFailure : "console-range-invalid"; return;
    }
    if (!context.session.open()) { context.status = "provider-busy"; return; }
    if (!context.authorization.claim()) { context.status = "compound-claim-refused"; return; }
    context.attempted = true;
    if (!earlyInitPhase(service, context) || !earlyInitGuard(service, pci, context)) return;
    runMode1(service, pci, retained, context.reset, &context.session, &context.authorization);
    if (!context.reset.protocol.success || !context.reset.protocol.pciRestored || !context.reset.protocol.recoveryObserved ||
        !context.reset.consoleRecovered || !context.reset.consolePaused || !earlyInitGuard(service, pci, context)) {
        context.status = context.reset.reason; return;
    }
    if (!context.authorization.resetRecovered() || !earlyInitPhase(service, context)) return;
    if (!earlyInitRefresh(service, pci, retained, context)) return;
    IOFree(context.fresh, 2 * kDiscoverySize); context.fresh = nullptr;
    if (!context.authorization.discoveryVerified() || !earlyInitPhase(service, context)) return;
    runSosBootSurvey(service, pci, context.state, context.mmio, context.vram, context.mib,
        context.apertureProof, context.firmwareProof, context.prior, context.console, context.sos,
        &context.session, &context.authorization);
    if (!sosBootComplete(context.sos) || !earlyInitGuard(service, pci, context)) {
        context.status = context.sos.status; return;
    }
    if (!context.authorization.firmwareCompleted() || !earlyInitPhase(service, context) ||
        !earlyInitPostflight(service, pci, context)) {
        context.status = "sos-postflight-refused"; return;
    }
    IOPlatformExpert *platform = IOService::getPlatform();
    if (!platform || !earlyInitGuard(service, pci, context)) {
        context.status = "console-resume-context-unavailable"; return;
    }
    // Platform console resume is the explicit OS boundary after safe SOS
    // success. It is not an adapter staging/MMIO/mailbox/selector/flush write.
    context.reset.consoleResumeAttempted = true;
    if (platform->setConsoleInfo(nullptr, kPEEnableScreen) != kIOReturnSuccess) {
        context.reset.consoleRecovered = false; context.status = "console-resume-failed"; return;
    }
    context.reset.consoleResumed = true;
    if (!earlyInitPostflight(service, pci, context) || !context.authorization.finish()) {
        context.reset.consoleRecovered = false;
        context.consoleRePauseAttempted = true;
        context.consoleRePaused = platform->setConsoleInfo(nullptr, kPEDisableScreen) == kIOReturnSuccess;
        context.status = context.consoleRePaused ? "console-resume-postflight-refused" : "console-repause-failed";
        return;
    }
    context.success = true;
    context.status = "reset-and-sos-transition-observed";
}

COBALT_SURVEY_NOINLINE bool publishEarlyInit(IOService *service, EarlyInitContext *context,
    const char *refusal = "early-prerequisites-unavailable") {
    service->removeProperty("CobaltSurvey,Schema");
    bool published = service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
    if (context) {
        published = publishMode1(service, context->reset, true) && published;
        published = publishSosBoot(service, context->sos, true) && published;
        published = context->published && published;
    }
    const bool success = context && context->success && context->reset.protocol.success &&
        context->reset.consoleRecovered && context->reset.consolePaused && context->reset.consoleResumed && context->sos.success;
#define EARLY_PROPERTY(name, value) published = service->setProperty("CobaltSurvey,EarlyInit" name, value) && published
    EARLY_PROPERTY("Requested", initBootSelected());
    EARLY_PROPERTY("Trigger", "early-boot");
    EARLY_PROPERTY("Attempted", context && context->attempted);
    published = service->setProperty("CobaltSurvey,EarlyInitPhase", context ? context->authorization.currentPhase() : 0u, 32) && published;
    EARLY_PROPERTY("Status", context ? context->status : refusal);
    EARLY_PROPERTY("Success", success);
    EARLY_PROPERTY("ColdCycleReplacementValidated", false);
    EARLY_PROPERTY("ConsoleRePauseAttempted", context && context->consoleRePauseAttempted);
    EARLY_PROPERTY("ConsoleRePaused", context && context->consoleRePaused);
    EARLY_PROPERTY("DiscoveryVerified", context && context->discoveryVerified);
    published = service->setProperty("CobaltSurvey,EarlyInitDiscoveryDataReads", context ? context->discoveryReads : 0u, 32) && published;
    published = service->setProperty("CobaltSurvey,EarlyInitDiscoverySelectorWrites", context ? context->discoverySelectorWrites : 0u, 32) && published;
#undef EARLY_PROPERTY
    published = service->setProperty("CobaltSurvey,BuildVersion", "0.13.0") && published;
    published = service->setProperty("CobaltSurvey,AccessMode", "early-mode1-and-sos-initialization") && published;
    service->removeProperty("CobaltSurvey,Ready");
    published = service->setProperty("CobaltSurvey,Ready", false) && published;
    published = service->setProperty("CobaltSurvey,ColdCycleReplacementValidated", false) && published;
    published = service->setProperty("CobaltSurvey,ReadOnly", false) && published;
    if (published && success && service->setProperty("CobaltSurvey,Schema", 13ULL, 32)) return true;
    service->removeProperty("CobaltSurvey,Schema");
    service->setProperty("CobaltSurvey,Schema", 4ULL, 32);
    service->removeProperty("CobaltSurvey,EarlyInitSuccess");
    service->setProperty("CobaltSurvey,EarlyInitSuccess", false);
    if (!published || success) {
        service->removeProperty("CobaltSurvey,EarlyInitStatus");
        service->setProperty("CobaltSurvey,EarlyInitStatus", "metadata-publication-failed");
    }
    return false;
}

// Consumes retained snapshot/provider references; publication happens only after
// every mapping and the continuous ownership session have been released.
COBALT_SURVEY_NOINLINE bool runAndPublishEarlyInit(IOService *service, IOPCIDevice *pci, OSData *retained) {
    void *storage = IOMalloc(sizeof(EarlyInitContext));
    EarlyInitContext *context = storage ? new (storage) EarlyInitContext(service, pci) : nullptr;
    if (context) {
        runEarlyInitHardware(service, pci, retained, *context);
        if (!context->success) context->authorization.fail();
        context->session.close();
        if (context->fresh) { IOFree(context->fresh, 2 * kDiscoverySize); context->fresh = nullptr; }
    }
    if (retained) retained->release();
    if (pci) pci->release();
    const bool published = publishEarlyInit(service, context, "early-context-allocation-failed");
    if (context) { context->~EarlyInitContext(); IOFree(storage, sizeof(EarlyInitContext)); }
    return published;
}
