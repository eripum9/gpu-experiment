namespace dmaCopy {
namespace protocol = cobalt::survey::pspMmhubCopy;
using Register = protocol::Register;

// Linux v6.19 MMHUB 4.1.0 and LSDMA 7.0.0 segment-zero indices. The
// two segment bases are from the target's fresh, verified discovery.
constexpr uint32_t mmhubPage = 0x69000, lsdmaPage = 0x45000;
constexpr uint32_t mmhubBase = 0x68000, lsdmaBase = 0x45000;
constexpr uint16_t lsdmaIp = 91;
struct Location { uint16_t dword; bool lsdma; };
constexpr Location locations[] = {
    {0x0564, false}, {0x05cf, false}, {0x05d0, false}, {0x05ef, false},
    {0x05f0, false}, {0x060f, false}, {0x0610, false}, {0x055b, false},
    {0x04e4, false}, {0x04e6, false}, {0x04fd, false}, {0x0070, true},
    {0x0071, true}, {0x0072, true}, {0x0073, true}, {0x0076, true},
    {0x04e5, false}, {0x0503, false}, {0x0559, false}, {0x055a, false},
    {0x0558, false}, {0x0557, false}, {0x0556, false}, {0x04c7, false},
    {0x0554, false}, {0x0555, false}, {0x007a, true}, {0x0074, true},
};
static_assert(sizeof(locations) / sizeof(locations[0]) == static_cast<unsigned>(Register::PioCommand) + 1);

constexpr uint32_t byteOffset(Location reg) {
    return (reg.lsdma ? lsdmaBase : mmhubBase) + reg.dword * 4u;
}

class Adapter final : public protocol::Io {
    IOPCIDevice *pci;
    EarlyInitContext &context;
    Map mmhub, lsdma;
    cobalt::PspDmaPage table, data;
    bool guardLost {false};

    volatile uint32_t *word(Location reg) const {
        const auto *base = reg.lsdma ? lsdma.bytes() : mmhub.bytes();
        return reinterpret_cast<volatile uint32_t *>(
            const_cast<volatile uint8_t *>(base + (byteOffset(reg) & 0xfffu)));
    }
    bool load(Location reg, uint32_t &value) {
        if (!guard()) return false;
        value = *word(reg);
        return value != UINT32_MAX && guard();
    }
    bool store(Location reg, uint32_t value) {
        if (!guard()) return false;
        *word(reg) = value;
        __asm__ volatile("mfence" ::: "memory");
        return guard();
    }
    bool otherClientsIdle() {
        uint32_t control;
        for (uint16_t reg = 0x0565; reg <= 0x0573; ++reg)
            if (!load({reg, false}, control) || (control & 1u)) return false;
        constexpr uint16_t queues[] = {0x0080, 0x00d8};
        for (uint16_t reg : queues)
            if (!load({reg, true}, control) || (control & 1u)) return false;
        return true;
    }

public:
    Adapter(IOPCIDevice *p, EarlyInitContext &c) : pci(p), context(c) {}
    bool guard() override {
        if (!guardLost && (!(context.state.command & 4u) || !context.authorization.copyAuthorized() ||
            !consoleGuard(pci, context.state, context.mmio, context.vram))) guardLost = true;
        return !guardLost;
    }
    bool open() {
        if (!guard() || !mmhub.createDmaCopyPage(context.mmio, false) ||
            !lsdma.createDmaCopyPage(context.mmio, true)) return false;
        const auto *mm = mmhub.bytes(), *ls = lsdma.bytes();
        return mm && ls && !((reinterpret_cast<uintptr_t>(mm) | reinterpret_cast<uintptr_t>(ls)) & 3u) &&
            otherClientsIdle();
    }
    bool read(Register reg, uint32_t &value) override {
        return load(locations[static_cast<unsigned>(reg)], value);
    }
    bool write(Register reg, uint32_t value) override {
        if (reg == Register::PioCommand && !otherClientsIdle()) return false;
        return store(locations[static_cast<unsigned>(reg)], value);
    }
    bool prepare(cobalt::survey::pspMemory::Layout &layout) override {
        uint32_t fbBase, fbTop;
        if (!read(Register::FbBase, fbBase) || !read(Register::FbTop, fbTop) ||
            !table.allocate(pci) || !data.allocate(pci) || !data.bytes() ||
            !cobalt::survey::pspMemory::makeLayout(table.deviceAddress().value,
                data.deviceAddress().value, fbBase, fbTop, layout) ||
            !table.initializeTable(layout.leaf)) return false;
        protocol::seedCopyPage(data.bytes());
        return data.synchronize(kIODirectionOut) && guard();
    }
    bool syncDataToCpu(const uint8_t *&page) override {
        if (!guard() || !data.synchronize(kIODirectionIn)) return false;
        page = data.bytes();
        return page && guard();
    }
    void delayUs(uint32_t microseconds) override { IODelay(microseconds); }

    bool invalidateVmid0() override {
        // AMD's PF sequence uses engine 17 with a power-gate semaphore.
        // Restore its range registers after the VMID0 invalidation completes.
        constexpr Location sem {0x0586, false}, req {0x0598, false}, ack {0x05aa, false};
        constexpr Location low {0x05cd, false}, high {0x05ce, false};
        constexpr Location privateCache {0x0500, false};
        constexpr uint32_t flush = 0x00f80001u;
        uint32_t value = 0;
        bool acquired = false;
        for (unsigned i = 0; i < protocol::pollLimit; ++i) {
            if (!load(sem, value)) return false;
            if (value & 1u) { acquired = true; break; }
            delayUs(protocol::pollDelayUs);
        }
        if (!acquired) return false;
        // The low range register may legitimately contain all ones. Read it
        // with the same guard, and validate the narrower high register.
        uint32_t savedHigh = 0;
        bool completed = false;
        if (load(high, savedHigh)) {
            const uint32_t savedLow = *word(low);
            if (store(low, UINT32_MAX) && store(high, 0x1f) && store(req, flush)) {
                for (unsigned i = 0; i < protocol::pollLimit; ++i) {
                    if (!load(ack, value)) break;
                    if (value & 1u) { completed = true; break; }
                    delayUs(protocol::pollDelayUs);
                }
                if (completed) {
                    completed = store(low, savedLow) && store(high, savedHigh) && guard() &&
                        *word(low) == savedLow && load(high, value) && value == savedHigh;
                }
            }
        }
        const bool released = store(sem, 0) && load(ack, value);
        // GFX12 PF invalidation also flushes the private MMHUB cache. The
        // ordered readback follows AMD's gmc_v12_0_flush_vm_hub sequence.
        return completed && released && load(privateCache, value) &&
            store(privateCache, value | (1u << 25)) && load(privateCache, value);
    }

    void keepPages() {
        table.retainForBoot();
        data.retainForBoot();
    }
};
} // namespace dmaCopy

bool verifyDmaCopyLayout(const IpDiscovery &discovery, const Aperture &mmio) {
    unsigned matches = 0;
    for (uint16_t i = 0; i < discovery.ipCount(); ++i) {
        IpDiscovery::IpEntry entry {};
        if (!discovery.ipAt(i, entry)) return false;
        if (entry.hwId != dmaCopy::lsdmaIp) continue;
        if (entry.instance || entry.major != 7 || entry.minor || entry.revision || !entry.numBases)
            return false;
        ++matches;
    }
    if (matches != 1 || mmio.length < dmaCopy::mmhubPage + 4096 ||
        mmio.length < dmaCopy::lsdmaPage + 4096) return false;
    for (const auto &reg : dmaCopy::locations) {
        uint32_t offset;
        if (!discovery.regByteOffset(reg.lsdma ? dmaCopy::lsdmaIp : uint16_t(IpDiscovery::HwMmhub),
            0, 0, reg.dword, offset) || offset != dmaCopy::byteOffset(reg) ||
            (offset & ~0xfffu) != (reg.lsdma ? dmaCopy::lsdmaPage : dmaCopy::mmhubPage)) return false;
    }
    return true;
}

COBALT_SURVEY_NOINLINE void runPspDmaCopy(IOService *service, IOPCIDevice *pci, EarlyInitContext &context) {
    context.dmaCopyStatus = "copy-layout-refused";
    if (!earlyInitGuard(service, pci, context)) return;
    context.dmaCopyRebootAllowed = true;
    if (!context.dmaCopyLayoutVerified) return;
    dmaCopy::Adapter io(pci, context);
    context.dmaCopyStatus = "copy-access-refused";
    if (!io.open()) return;
    const auto result = dmaCopy::protocol::run(io);
    if (result.retainPages) io.keepPages();
    context.dmaCopyStatus = result.status;
    context.dmaCopyRebootAllowed = result.rebootAllowed;
    context.dmaCopyIssued = result.commandAttempted;
    context.dmaCopyProven = result.copyProven;
    context.dmaCopyRestored = result.restored;
    context.dmaCopyRetained = result.retainPages;
    context.dmaCopyPolls = result.polls;
    context.dmaCopyPioStatus = result.lastPioStatus;
}
