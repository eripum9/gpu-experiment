#pragma once
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <utility>

using SInt32 = int32_t;
using UInt8 = uint8_t;
using IOOptionBits = uint32_t;
using IOByteCount = uint64_t;
using task_t = void *;
inline task_t kernel_task = reinterpret_cast<void *>(1);
constexpr IOOptionBits kIOMapAnywhere = 1, kIOMapUnique = 0x04000000;
constexpr IOOptionBits kIOMapReadOnly = 0x1000, kIOMapInhibitCache = 0x100;
constexpr IOOptionBits kIOMapCacheMask = 0xf00, kIOMemoryMapperNone = 0x800;

class IOService;
class IOPlatformExpert;
using IOReturn = int32_t;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnUnsupported = -1000;
constexpr IOReturn kIOReturnBadArgument = -1001;
constexpr IOReturn kIOReturnNotPrivileged = -1002;
constexpr IOReturn kIOReturnBusy = -1003;
constexpr IOReturn kIOReturnNotReady = -1004;
constexpr IOReturn kIOReturnError = -1005;
constexpr IOReturn kIOReturnNoDevice = -1006;
constexpr unsigned kPEDisableScreen = 7, kPEEnableScreen = 6;
// Match the production LP64 scalar width even when Windows unsigned long is32bit.
struct PE_Video {
    uint64_t v_baseAddr=0, v_rowBytes=0, v_width=0, v_height=0, v_depth=0, v_display=0;
    char v_pixelFormat[64] {};
    uint64_t v_offset=0, v_length=0;
    uint8_t v_rotate=0, v_scale=0;
};
struct MmioEvent { char operation; uint32_t offset, value; };
struct Mode1Page { uint64_t offset; IOOptionBits options; uintptr_t address; };

struct TestState {
    std::string boot = "1";
    bool bootPresent = true, superStart = true, allocFail = false, dataFail = false;
    bool publicationFail = false;
    std::string indexedBoot = "1";
    bool indexedBootPresent = false, claimFail = false;
    std::string stateBoot = "1";
    bool stateBootPresent = false;
    std::string apertureBoot = "1";
    bool apertureBootPresent = false, apertureClaimFail = false, apertureClaimed = false;
    std::string stagingBoot = "1";
    bool stagingBootPresent = false, stagingEnabled = false, stagingClaimFail = false, stagingClaimed = false;
    std::string kdbBoot = "1";
    bool kdbBootPresent = false, kdbEnabled = false, kdbClaimFail = false, kdbClaimed = false;
    std::string splBoot = "1";
    bool splBootPresent = false, splEnabled = false, splClaimFail = false, splClaimed = false;
    std::string preSosBoot = "1";
    bool preSosBootPresent = false, preSosEnabled = false, preSosClaimFail = false, preSosClaimed = false;
    std::string sosBoot = "1";
    bool sosBootPresent = false, sosEnabled = false, sosClaimFail = false, sosClaimed = false;
    std::string mode1Boot = "1";
    bool mode1BootPresent = false, mode1Enabled = false, mode1Claimed = false, mode1ClaimFail = false;
    std::string mode1EarlyBoot = "1";
    bool mode1EarlyBootPresent = false;
    std::string earlyInitBoot = "1";
    bool earlyInitBootPresent = false, earlyInitEnabled = false;
    unsigned earlyInitPhase = 0;
    bool failEarlyInitSchema13 = false;
    std::vector<uint64_t> earlyInitSchemaWrites;
    std::vector<unsigned> earlyInitPhases;
    std::vector<std::string> earlyInitEvents;
    unsigned earlyInitRefreshDataReads = 0;
    void *earlyInitMarker = nullptr, *mode1Marker = nullptr, *sosMarker = nullptr;
    unsigned metadataAllocations = 0;
    std::map<void *, uint64_t> metadataPointers;
    bool consolePaused = false, consolePauseFail = false, consoleResumeFail = false;
    unsigned consolePauseCalls = 0, consoleResumeCalls = 0;
    std::function<void(unsigned)> onConsoleControl;
    bool mode1Quiet = false, mode1RequestAdmin = true, mode1LockBusy = false;
    unsigned mode1ReadCalls = 0, mode1WriteCalls = 0, mode1SaveCalls = 0, mode1RestoreCalls = 0;
    unsigned mode1SleepCalls = 0, mode1PropertyCalls = 0, mode1PrivilegeCalls = 0;
    unsigned mode1LockAllocations = 0, mode1LocksLive = 0, mode1ProvidersLive = 0;
    unsigned mode1MapsLive = 0;
    bool mode1SaveFail = false, mode1RestoreFail = false, mode1BusMasterState = true;
    bool mode1BusMasterPrevious = true, mode1MmioBeforeRestore = false;
    bool mode1SavedBusMaster = true;
    std::vector<std::pair<uint32_t, uint32_t>> mode1Writes;
    std::vector<std::pair<const volatile uint32_t *, uint32_t>> mode1WritePointers;
    std::vector<std::pair<uint64_t, IOOptionBits>> mode1MapRequests;
    std::vector<Mode1Page> mode1MappedPages;
    std::vector<std::string> mode1Events;
    std::function<void()> onMode1Sleep;
    std::function<uint32_t(uint32_t, uint32_t)> mode1Read;
    std::function<void(uint32_t, uint32_t)> mode1Write;
    bool sosFinalStoreSeen = false;
    unsigned sosWrites = 0;
    struct SosEvent { uint32_t offset, value; };
    std::vector<SosEvent> sosEvents;
    std::function<void(const SosEvent &)> onSos;
    uint64_t apertureOffset = 64ULL << 20;
    uint32_t apertureRemap = 0x7f000, apertureMemsize = 16304;
    uint32_t apertureNbifSegmentBase = 0xd20;
    bool apertureNativeRoute = false, apertureNbifReadLive = false;
    unsigned allocationCalls = 0, failAllocationCall = 0;
    unsigned apertureRegisterReads = 0, apertureDataReads = 0, apertureCpuReads = 0;
    unsigned apertureCpuWrites = 0, apertureFlushWrites = 0, apertureFences = 0;
    bool probeMapLive = false, flushMapLive = false;
    volatile uint32_t *probePage = nullptr, *flushPage = nullptr;
    bool splMapLive = false;
    volatile uint32_t *splPage = nullptr;
    const volatile uint32_t *nbifPage = nullptr;
    std::function<void()> onApertureNbifRelease;
    std::vector<uint32_t> apertureCpu = std::vector<uint32_t>(262144, 0xabc01234);
    std::vector<uint32_t> apertureGpu = std::vector<uint32_t>(262144, 0xabc01234);
    std::vector<uint32_t> splCpu = std::vector<uint32_t>(262144, 0xdef05678);
    std::vector<uint32_t> splGpu = std::vector<uint32_t>(262144, 0xdef05678);
    std::vector<std::vector<uint32_t>> preSosCpu;
    std::vector<std::vector<uint32_t>> preSosGpu;
    std::vector<bool> preSosWindowLive = std::vector<bool>(7, false);
    std::vector<volatile uint32_t *> preSosPages = std::vector<volatile uint32_t *>(7, nullptr);
    std::vector<std::vector<uint32_t>> sosCpu;
    std::vector<std::vector<uint32_t>> sosGpu;
    std::vector<bool> sosWindowLive = std::vector<bool>(8, false);
    std::vector<volatile uint32_t *> sosPages = std::vector<volatile uint32_t *>(8, nullptr);
    int preSosMapFailIndex = -1, preSosMapInvalidIndex = -1;
    unsigned preSosWrites = 0;
    struct PreSosEvent { uint32_t offset, value; };
    std::vector<PreSosEvent> preSosEvents;
    std::function<void(const PreSosEvent &)> onPreSos;
    std::vector<uint32_t> apertureFlush = std::vector<uint32_t>(1024);
    std::vector<MmioEvent> apertureEvents;
    std::function<void(const MmioEvent &)> onAperture;
    std::function<uint32_t(uint32_t, uint32_t)> apertureRegisterRead;
    std::function<uint32_t(unsigned, uint32_t)> apertureDataRead, apertureCpuRead;
    std::function<void(const std::string &)> onAperturePublication;
    std::string propertyFailKey;
    bool platformAvailable = false, failConsoleSchema = false, failApertureSchema = false;
    unsigned platformCalls = 0, consoleCalls = 0;
    PE_Video console;
    IOReturn consoleResult = kIOReturnSuccess;
    std::function<void(unsigned, PE_Video &)> onConsole;
    std::function<void(const std::string &)> onConsolePublication;
    unsigned openCalls = 0, closeCalls = 0, openLive = 0, iteratorsLive = 0;
    unsigned selectorWrites = 0, indexedDataReads = 0;
    struct KdbEvent { uint32_t offset, value; };
    unsigned kdbWrites = 0, sleepCalls = 0;
    std::vector<KdbEvent> kdbEvents;
    std::function<void(const KdbEvent &)> onKdb;
    unsigned splWrites = 0;
    std::vector<KdbEvent> splEvents;
    std::function<void(const KdbEvent &)> onSpl;
    uint32_t splAddressByteOffset = 0x4590, splCommandByteOffset = 0x458c;
    std::function<void()> onSleep;
    uint32_t kdbAddressByteOffset = 0x190, kdbCommandByteOffset = 0x18c;
    uint32_t kdbMailboxPageOffset = 0x4000;
    bool kdbMailboxMapLive = false;
    volatile uint32_t *kdbMailboxPage = nullptr;
    std::vector<uint32_t> kdbStateOffsets = {0x458c, 0x4644, 0xa950, 0xa954, 0xad1c, 0x5d14};
    unsigned stateReads = 0;
    std::vector<std::pair<uint64_t, IOOptionBits>> stateMapRequests;
    std::vector<std::pair<uint64_t, uintptr_t>> stateMapBases;
    std::vector<std::pair<uint32_t, uint32_t>> stateEvents;
    std::vector<uint32_t> stateAllowedOffsets = {0x458c,0x4644,0xa950,0xa954};
    std::function<uint32_t(uint32_t, uint32_t)> stateRead;
    std::function<void(unsigned)> onMapRelease;
    std::function<void()> onDiscoverySnapshotPublication;
    bool indexedMapLive = false;
    volatile uint32_t *indexedPage = nullptr;
    IOService *indexedOwner = nullptr;
    uint64_t discoveryOffset = 0;
    std::vector<uint8_t> discovery;
    std::vector<MmioEvent> mmioEvents;
    std::function<void(const MmioEvent &)> onMmio;
    std::function<uint32_t(uint32_t, uint32_t)> selectorRead;
    std::function<uint32_t(unsigned, uint32_t)> dataRead;
    unsigned allocations = 0, mapsLive = 0, mapRequests = 0, mapReleases = 0;
    unsigned failMapRequest = 0;
    unsigned memsizeReads = 0, backingDescriptorsLive = 0, backingDescriptorReleases = 0;
    std::vector<uint32_t> memsizeValues;
    std::function<void(unsigned)> onMemsize;
};
inline TestState testState;
inline bool earlyInitPathActive() { return testState.earlyInitEnabled; }
inline bool sosPathActive() { return testState.sosEnabled || earlyInitPathActive(); }
inline void earlyInitEvent(const std::string &event) {
    if (earlyInitPathActive()) testState.earlyInitEvents.push_back(event);
}
struct IOLock { bool held = false; };
inline IOLock *IOLockAlloc() {
    ++testState.mode1LockAllocations;
    auto *lock = new IOLock;
    ++testState.mode1LocksLive;
    return lock;
}
inline bool IOLockTryLock(IOLock *lock) {
    if (!lock || testState.mode1LockBusy || lock->held) return false;
    lock->held = true; return true;
}
inline void IOLockLock(IOLock *lock) { if (!lock || lock->held) throw std::runtime_error("invalid blocking lock operation"); lock->held = true; }
inline void IOLockUnlock(IOLock *lock) { if (!lock || !lock->held) throw std::runtime_error("unlock of unheld lock"); lock->held = false; }
inline void IOLockFree(IOLock *lock) {
    if (!lock || lock->held) throw std::runtime_error("free of invalid/held lock");
    delete lock; --testState.mode1LocksLive;
}
inline task_t current_task() { return reinterpret_cast<task_t>(2); }
constexpr const char *kIOClientPrivilegeAdministrator = "admin";
inline bool aperturePhase() {
    return (testState.apertureBootPresent || earlyInitPathActive()) && testState.openCalls >= 2 && testState.openLive == 1;
}
inline bool stagingPhase() {
    return (testState.stagingEnabled || testState.kdbEnabled || testState.splEnabled || testState.preSosEnabled || sosPathActive()) && testState.openCalls >= 2 && testState.openLive == 1;
}
inline void requireExplicitWritableMode();
inline void apertureEvent(char operation, uint32_t offset, uint32_t value) {
    const MmioEvent event {operation, offset, value};
    // Staging performs millions of dword accesses. Keep the legacy event
    // transcript for the 16-byte experiment, while still delivering callbacks
    // so tests can inject context changes at transaction boundaries.
    if (!stagingPhase()) testState.apertureEvents.push_back(event);
    if (testState.onAperture) testState.onAperture(event);
}

#define OSDeclareDefaultStructors(T) public: T() = default; ~T() override = default;
#define OSDefineMetaClassAndStructors(T, B)
#define OSDynamicCast(T, value) dynamic_cast<T *>(value)

class OSObject {
    unsigned refs = 1;
public:
    struct MetaClass {
        const char *name = "FakeIOService";
        const char *getClassName() const { return name; }
    } meta;
    const MetaClass *getMetaClass() const { return &meta; }
    virtual ~OSObject() = default;
    void retain() { ++refs; }
    void release() { if (--refs == 0) delete this; }
};
class OSIterator : public OSObject {
    std::vector<OSObject *> objects;
    size_t next = 0;
    bool valid;
public:
    OSIterator(std::vector<OSObject *> entries, bool good) : objects(std::move(entries)), valid(good) {
        ++testState.iteratorsLive;
    }
    ~OSIterator() override { --testState.iteratorsLive; }
    OSObject *getNextObject() { return next < objects.size() ? objects[next++] : nullptr; }
    bool isValid() const { return valid; }
};
class OSData : public OSObject {
public:
    std::vector<uint8_t> bytes;
    unsigned getLength() const { return static_cast<unsigned>(bytes.size()); }
    const void *getBytesNoCopy() const { return bytes.empty() ? nullptr : bytes.data(); }
    static OSData *withBytes(const void *p, unsigned n) {
        if (testState.dataFail) return nullptr;
        auto *data = new OSData;
        const auto *start = static_cast<const uint8_t *>(p);
        data->bytes.assign(start, start + n);
        return data;
    }
};

class OSNumber : public OSObject {
    uint64_t value_ = 0;
    unsigned bits_ = 64;
public:
    OSNumber(uint64_t value, unsigned bits) : value_(value), bits_(bits) {}
    static OSNumber *withNumber(uint64_t value, unsigned bits) { return new OSNumber(value, bits); }
    uint64_t unsigned64BitValue() const { return value_; }
    unsigned numberOfBits() const { return bits_; }
};

class OSDictionary : public OSObject {
    std::map<std::string, OSObject *> objects_;
public:
    static OSDictionary *withCapacity(unsigned) { return new OSDictionary; }
    void setObject(const char *key, OSObject *value) {
        auto found = objects_.find(key);
        if (found != objects_.end()) found->second->release();
        value->retain(); objects_[key] = value;
    }
    unsigned getCount() const { return static_cast<unsigned>(objects_.size()); }
    OSObject *getObject(const char *key) const {
        const auto found = objects_.find(key);
        return found == objects_.end() ? nullptr : found->second;
    }
    ~OSDictionary() override { for (auto &entry : objects_) entry.second->release(); }
};

class IOService : public OSObject {
public:
    bool registered = false;
    bool inactive = false;
    unsigned stopCalls = 0, startCalls = 0;
    IOService *providerService = nullptr;
    std::map<std::string, std::string> strings;
    std::map<std::string, uint64_t> numbers;
    std::map<std::string, std::vector<uint8_t>> blobs;
    std::map<std::string, OSObject *> markerObjects;
    ~IOService() override { for (auto &entry : markerObjects) entry.second->release(); }
    virtual IOService *probe(IOService *, SInt32 *) { return this; }
    virtual bool start(IOService *newProvider) { ++startCalls; if (testState.superStart) providerService = newProvider; return testState.superStart; }
    virtual void stop(IOService *) { ++stopCalls; providerService = nullptr; }
    virtual IOReturn setProperties(OSObject *) { ++testState.mode1PropertyCalls; return kIOReturnUnsupported; }
    IOService *getProvider() { return providerService; }
    virtual bool clientHasPrivilege(task_t, const char *) { ++testState.mode1PrivilegeCalls; return testState.mode1RequestAdmin; }
    bool isInactive() const { return inactive; }
    static IOPlatformExpert *getPlatform();
    void consolePublication(const char *key) {
        if ((std::string(key).find("CobaltSurvey,Aperture") == 0 ||
             std::string(key).find("CobaltSurvey,Staging") == 0 ||
             std::string(key).find("CobaltSurvey,Kdb") == 0 ||
             std::string(key).find("CobaltSurvey,PreSos") == 0 ||
             std::string(key).find("CobaltSurvey,SosBoot") == 0) &&
            std::string(key) != "CobaltSurvey,ApertureAttempt-v1" &&
            std::string(key) != "CobaltSurvey,StagingAttempt-v1" &&
            std::string(key) != "CobaltSurvey,KdbAttempt-v1" &&
            std::string(key) != "CobaltSurvey,KdbSplAttempt-v1" &&
            std::string(key) != "CobaltSurvey,PreSosAttempt-v1" &&
            std::string(key) != "CobaltSurvey,SosBootAttempt-v1") {
            if (testState.mapsLive || testState.backingDescriptorsLive || testState.allocations ||
                testState.openLive || testState.iteratorsLive)
                throw std::runtime_error("GPU resources retained at aperture/staging publication");
            if (testState.onAperturePublication) testState.onAperturePublication(key);
        }
        if (std::string(key).find("CobaltSurvey,Mode1Reset") == 0 &&
            std::string(key) != "CobaltSurvey,Mode1ResetAttempt-v1") {
            if (testState.mapsLive || testState.backingDescriptorsLive || testState.allocations ||
                testState.openLive || testState.iteratorsLive || testState.mode1MapsLive)
                throw std::runtime_error("Mode 1 metadata published while GPU/provider resources remain live");
        }
        if (std::string(key).find("CobaltSurvey,Console") != 0) return;
        if (testState.mapsLive || testState.backingDescriptorsLive || testState.allocations ||
            testState.openLive || testState.iteratorsLive)
            throw std::runtime_error("GPU resources retained at console publication");
        if (testState.onConsolePublication) testState.onConsolePublication(key);
    }
    bool setProperty(const char *key, const char *value) {
        consolePublication(key);
        if (testState.propertyFailKey == key) return false;
        strings[key] = value; return true;
    }
    bool setProperty(const char *key, uint64_t value, unsigned) {
        consolePublication(key);
        if (std::string(key) == "CobaltSurvey,Schema" && earlyInitPathActive()) {
            testState.earlyInitSchemaWrites.push_back(value);
            if (testState.failEarlyInitSchema13 && value == 13) return false;
        }
        if (std::string(key) == "CobaltSurvey,EarlyInitPhase") {
            testState.earlyInitPhase = static_cast<unsigned>(value);
            testState.earlyInitPhases.push_back(static_cast<unsigned>(value));
            earlyInitEvent("phase-" + std::to_string(value));
        }
        if (testState.failConsoleSchema && std::string(key)=="CobaltSurvey,Schema" && value==4) return false;
        if (testState.failApertureSchema && std::string(key)=="CobaltSurvey,Schema" && value==5) return false;
        if (testState.propertyFailKey == key) return false;
        numbers[key] = value; return true;
    }
    bool setProperty(const char *key, bool value) {
        consolePublication(key);
        if (testState.propertyFailKey == key) return false;
        if (std::string(key) == "CobaltSurvey,IndexedAttempt-v1" && testState.claimFail) return false;
        if (std::string(key) == "CobaltSurvey,ApertureAttempt-v1" && testState.apertureClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,ApertureAttempt-v1") testState.apertureClaimed = true;
        if (std::string(key) == "CobaltSurvey,StagingAttempt-v1" && testState.stagingClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,StagingAttempt-v1") testState.stagingClaimed = true;
        if (std::string(key) == "CobaltSurvey,KdbAttempt-v1" && testState.kdbClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,KdbAttempt-v1") testState.kdbClaimed = true;
        if (std::string(key) == "CobaltSurvey,KdbSplAttempt-v1" && testState.splClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,KdbSplAttempt-v1") testState.splClaimed = true;
        if (std::string(key) == "CobaltSurvey,PreSosAttempt-v1" && testState.preSosClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,PreSosAttempt-v1") testState.preSosClaimed = true;
        if (std::string(key) == "CobaltSurvey,SosBootAttempt-v1" && testState.sosClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,SosBootAttempt-v1") testState.sosClaimed = true;
        if (std::string(key) == "CobaltSurvey,Mode1ResetAttempt-v1" && testState.mode1ClaimFail) return false;
        if (std::string(key) == "CobaltSurvey,Mode1ResetAttempt-v1") testState.mode1Claimed = true;
        numbers[key] = value ? 1 : 0; return true;
    }
    OSObject *getProperty(const char *key) {
        const auto marker = markerObjects.find(key);
        if (marker != markerObjects.end()) return marker->second;
        return numbers.count(key) || strings.count(key) || blobs.count(key) ? this : nullptr;
    }
    bool setProperty(const char *key, OSObject *object) {
        const std::string name(key);
        if (earlyInitPathActive() && (name == "CobaltSurvey,EarlyInitAttempt-v1" ||
            name == "CobaltSurvey,Mode1ResetAttempt-v1" || name == "CobaltSurvey,SosBootAttempt-v1")) {
            if (testState.openLive != 1 || testState.iteratorsLive || !object)
                throw std::runtime_error("compound claim without continuous provider ownership");
            if (testState.propertyFailKey == key ||
                (name == "CobaltSurvey,Mode1ResetAttempt-v1" && testState.mode1ClaimFail) ||
                (name == "CobaltSurvey,SosBootAttempt-v1" && testState.sosClaimFail)) return false;
            if (markerObjects.count(name)) throw std::runtime_error("compound marker claimed twice");
            object->retain(); markerObjects[name] = object;
            if (name == "CobaltSurvey,EarlyInitAttempt-v1") testState.earlyInitMarker = object;
            if (name == "CobaltSurvey,Mode1ResetAttempt-v1") { testState.mode1Marker = object; testState.mode1Claimed = true; }
            if (name == "CobaltSurvey,SosBootAttempt-v1") { testState.sosMarker = object; testState.sosClaimed = true; }
            return true;
        }
        if (testState.mapsLive || testState.backingDescriptorsLive || testState.openLive || testState.iteratorsLive)
            throw std::runtime_error("GPU resources retained at snapshot publication");
        if (testState.publicationFail) return false;
        if (std::string(key) == "CobaltSurvey,DiscoverySnapshot" && testState.onDiscoverySnapshotPublication)
            testState.onDiscoverySnapshotPublication();
        auto *value = dynamic_cast<OSData *>(object);
        if (!value) throw std::runtime_error("non OSData publication");
        if (std::string(key) == "CobaltSurvey,EarlyInitAttempt-v1") testState.earlyInitMarker = object;
        if (std::string(key) == "CobaltSurvey,Mode1ResetAttempt-v1") testState.mode1Marker = object;
        if (std::string(key) == "CobaltSurvey,SosBootAttempt-v1") testState.sosMarker = object;
        blobs[key] = value->bytes; return true;
    }
    void removeProperty(const char *key) {
        const auto marker = markerObjects.find(key);
        if (marker != markerObjects.end()) { marker->second->release(); markerObjects.erase(marker); }
        strings.erase(key); numbers.erase(key); blobs.erase(key);
    }
    void registerService() {
        if (testState.mapsLive || testState.backingDescriptorsLive || testState.allocations ||
            testState.openLive || testState.iteratorsLive)
            throw std::runtime_error("GPU resources retained at registerService");
        registered = true;
        if (testState.mode1Enabled) testState.mode1Events.push_back("register-service");
    }
    virtual void free() {}
};

class IOUserClient {
public:
    static IOReturn clientHasPrivilege(task_t, const char *) {
        ++testState.mode1PrivilegeCalls;
        return testState.mode1RequestAdmin ? kIOReturnSuccess : -1002;
    }
};
inline void requireExplicitWritableMode() {
    if (!testState.indexedOwner) throw std::runtime_error("missing indexed owner");
    if (earlyInitPathActive()) {
        const bool initial = testState.earlyInitPhase == 0 && testState.openCalls == 1 &&
            !testState.earlyInitMarker && !testState.mode1Marker && !testState.sosMarker;
        const bool refresh = testState.earlyInitPhase == 2 && testState.earlyInitMarker &&
            testState.mode1Marker == testState.earlyInitMarker && !testState.sosMarker;
        const bool firmware = testState.earlyInitPhase == 3 && testState.earlyInitMarker &&
            testState.mode1Marker == testState.earlyInitMarker && testState.sosMarker == testState.earlyInitMarker;
        if (!initial && !refresh && !firmware)
            throw std::runtime_error("compound PSP write without the one shared early-init marker");
        const auto ready = testState.indexedOwner->numbers.find("CobaltSurvey,Ready");
        if (ready == testState.indexedOwner->numbers.end() || ready->second != 0)
            throw std::runtime_error("compound PSP write outside non-ready mode");
        return;
    }
    const auto readOnly = testState.indexedOwner->numbers.find("CobaltSurvey,ReadOnly");
    const auto ready = testState.indexedOwner->numbers.find("CobaltSurvey,Ready");
    if (readOnly == testState.indexedOwner->numbers.end() || ready == testState.indexedOwner->numbers.end())
        throw std::runtime_error("writable-mode properties were not published");
    if (readOnly->second != 0 || ready->second != 0)
        throw std::runtime_error("explicit writable mode not active");
}

class IOPlatformExpert {
public:
    IOReturn getConsoleInfo(PE_Video *video) {
        if (testState.mode1Quiet || (!testState.mode1Writes.empty() && testState.mode1SleepCalls == 0))
            throw std::runtime_error("console API during Mode 1 burst or quiet interval");
        const bool kdbTransactionLive = testState.kdbEnabled && testState.openLive == 1 &&
            testState.mapsLive >= 4 && testState.mapsLive <= 8;
        const bool preSosTransactionLive = testState.preSosEnabled && testState.openLive == 1 &&
            (testState.mapsLive == 12 || testState.mapsLive == 13);
        const bool sosTransactionLive = sosPathActive() && testState.openLive == 1 &&
            (testState.mapsLive == 13 || testState.mapsLive == 14);
        const bool mode1TransactionLive = testState.mode1Enabled && testState.openLive == 1 && testState.mode1MapsLive == 5;
        const bool compoundLive = earlyInitPathActive() && testState.earlyInitMarker && testState.openLive == 1;
        if ((!compoundLive && !kdbTransactionLive && !preSosTransactionLive && !sosTransactionLive && !mode1TransactionLive &&
             (testState.mapsLive || testState.backingDescriptorsLive || testState.allocations)) ||
            (testState.openLive && !compoundLive && !aperturePhase() && !mode1TransactionLive) || testState.iteratorsLive)
            throw std::runtime_error("GPU resources retained at console API");
        ++testState.consoleCalls;
        *video = testState.console;
        if (testState.onConsole) testState.onConsole(testState.consoleCalls, *video);
        return testState.consoleResult;
    }
    IOReturn setConsoleInfo(PE_Video *video, unsigned operation) {
        if (video || (operation != kPEDisableScreen && operation != kPEEnableScreen) ||
            !(testState.mode1EarlyBootPresent || testState.earlyInitBootPresent) || !testState.mode1Enabled || testState.openLive != 1 ||
            (testState.mode1MapsLive != 5 && !(earlyInitPathActive() && testState.earlyInitPhase >= 4 &&
                testState.mapsLive == 0 && testState.allocations == 0)) || testState.iteratorsLive)
            throw std::runtime_error("console control outside owned early Mode 1 transaction");
        if (testState.mode1Quiet || (!testState.mode1Writes.empty() && testState.mode1SleepCalls == 0))
            throw std::runtime_error("console control during Mode 1 burst or quiet interval");
        const bool pause = operation == kPEDisableScreen;
        if (!pause && (testState.mode1RestoreCalls != 1 || testState.mode1Writes.size() != 3 ||
            testState.mode1ReadCalls < 48))
            throw std::runtime_error("console resume before PCI recovery and full postflight");
        if (pause) ++testState.consolePauseCalls;
        else ++testState.consoleResumeCalls;
        testState.mode1Events.push_back(pause ? "console-pause" : "console-resume");
        earlyInitEvent(pause ? "console-pause" : "console-resume");
        if (testState.onConsoleControl) testState.onConsoleControl(operation);
        if (pause ? testState.consolePauseFail : testState.consoleResumeFail) return kIOReturnError;
        // Like PE_initialize_console(nullptr,...), preserve PE_Video geometry.
        testState.consolePaused = pause;
        return kIOReturnSuccess;
    }
};
inline IOPlatformExpert fakePlatform;
inline IOPlatformExpert *IOService::getPlatform() {
    ++testState.platformCalls;
    return testState.platformAvailable ? &fakePlatform : nullptr;
}

class IOMemoryDescriptor;
class IOMemoryMap : public OSObject {
public:
    uint64_t physical = 0, length = 0;
    uintptr_t address = 0;
    IOOptionBits options = 0;
    IOMemoryDescriptor *descriptor = nullptr;
    bool ownsDescriptor = false;
    IOByteCount descriptorOffset = 0;
    bool fragmented = false, wrongSegment = false;
    bool indexedMapping = false, splMapping = false;
    bool mode1Mapping = false;
    bool probeMapping = false, flushMapping = false, nbifMapping = false, nativeFlushMapping = false;
    bool kdbMailboxMapping = false, preSosWindowMapping = false, sosWindowMapping = false;
    unsigned preSosWindowIndex = 0;
    unsigned sosWindowIndex = 0;
    std::function<void()> onAddress;
    IOMemoryMap() { ++testState.mapsLive; }
    ~IOMemoryMap() override;
    uint64_t getPhysicalAddress() { return physical; }
    IOByteCount getLength() { return length; }
    uintptr_t getVirtualAddress() { if (onAddress) onAddress(); return address; }
    IOOptionBits getMapOptions() { return options; }
    IOMemoryDescriptor *getMemoryDescriptor() { return descriptor; }
    uint64_t getPhysicalSegment(IOByteCount offset, IOByteCount *n, IOOptionBits segmentOptions);
};

class IOMemoryDescriptor : public OSObject {
public:
    uint64_t physical = 0, length = 0, contiguous = 0;
    std::vector<uint32_t> storage; // aligned backing for the mapped test window only
    bool mapFail = false, mapTruncated = false, mapWrongPhysical = false;
    bool mapWritable = false, mapCached = false, mapNullAddress = false;
    bool mapForceReadOnly = false, mapMisalignedAddress = false;
    bool mapWrongDescriptor = false, mapFragmented = false;
    bool mapOriginalDescriptor = false, mapDescriptorWrongLength = false;
    bool mapDescriptorWrongPhysical = false, mapDescriptorFragmented = false;
    bool mapDescriptorWrongSegment = false, mapSegmentWrongPhysical = false;
    bool sourceWrongSegment = false, sourceFragmented = false;
    bool physicalSegmentWrong = false;
    bool uniqueBacking = false;
    bool indexedMapFail = false, indexedMapReadOnly = false;
    std::vector<uint32_t> selectorStorage = std::vector<uint32_t>(1024);
    uint64_t expectedOffset = 0, expectedLength = 0;
    unsigned requests = 0;
    std::function<void()> onMap, onAddress;
    ~IOMemoryDescriptor() override {
        if (uniqueBacking) { --testState.backingDescriptorsLive; ++testState.backingDescriptorReleases; }
    }
    uint64_t getPhysicalAddress() { return physical; }
    IOByteCount getLength() { return length; }
    uint64_t getPhysicalSegment(IOByteCount offset, IOByteCount *n, IOOptionBits options) {
        if (options != kIOMemoryMapperNone) throw std::runtime_error("translated physical descriptor");
        if (offset >= length || offset >= contiguous) { *n = 0; return 0; }
        *n = contiguous - offset;
        if (sourceFragmented && offset) *n = expectedLength - 1;
        return physical + offset + ((sourceWrongSegment && offset) || physicalSegmentWrong ? 4 : 0);
    }
    IOMemoryMap *createMappingInTask(task_t task, uint64_t address, IOOptionBits options,
                                   uint64_t offset, uint64_t n) {
        ++testState.mapRequests; ++requests;
        const bool indexed = offset == 0 && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool preSosWindow = testState.preSosEnabled && physical == 0x1000000000ULL &&
            offset >= testState.apertureOffset && offset < testState.apertureOffset + (7ULL << 20) &&
            ((offset - testState.apertureOffset) & ((1ULL << 20)-1)) == 0 && n == (1ULL << 20) &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const unsigned preSosIndex = preSosWindow ? static_cast<unsigned>((offset - testState.apertureOffset) >> 20) : 0;
        const bool sosWindow = sosPathActive() && physical == 0x1000000000ULL &&
            offset >= testState.apertureOffset && offset < testState.apertureOffset + (8ULL << 20) &&
            ((offset - testState.apertureOffset) & ((1ULL << 20)-1)) == 0 && n == (1ULL << 20) &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const unsigned sosIndex = sosWindow ? static_cast<unsigned>((offset - testState.apertureOffset) >> 20) : 0;
        const bool staging = !testState.preSosEnabled && stagingPhase() && physical == 0x1000000000ULL &&
            (offset == testState.apertureOffset || (testState.splEnabled && offset == testState.apertureOffset + (1ULL << 20))) && n == (1ULL << 20) &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool kdbMailbox = (testState.kdbEnabled || sosPathActive()) && physical == 0xc0000000 &&
            offset == (earlyInitPathActive() ? 0x1000u : 0x4000u) && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool probe = aperturePhase() && physical == 0x1000000000ULL &&
            offset == testState.apertureOffset && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool flush = aperturePhase() && physical == 0xc0000000 && offset == 0x7f000 && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool nbifRead = aperturePhase() && physical == 0xc0000000 &&
            (offset == 0x3000 || offset == 0x7f000) && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache);
        const bool nativeFlush = aperturePhase() && physical == 0xc0000000 && offset == 0x3000 && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool mode1ReadPage = testState.mode1Enabled && physical == 0xc0000000 &&
            (offset == 0x1000 || offset == 0x3000 || offset == 0x6000 || offset == 0xa000) && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache);
        const bool mode1WritePage = testState.mode1Enabled && physical == 0xc0000000 && offset == 0x1000 && n == 4096 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache);
        const bool mode1Map = mode1ReadPage || mode1WritePage;
        const bool stateMap = testState.stateBootPresent && n == 4096 && offset != 0x3000 &&
            options == (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache);
        if (kdbMailbox) {
            testState.stateMapRequests.emplace_back(offset, options);
            testState.stateMapBases.emplace_back(offset, reinterpret_cast<uintptr_t>(storage.data()));
        }
        if (stateMap) {
            testState.stateMapRequests.emplace_back(offset, options);
            testState.stateMapBases.emplace_back(offset, reinterpret_cast<uintptr_t>(storage.data()));
        }
        if (mode1Map) testState.mode1MapRequests.emplace_back(offset, options);
        if (nativeFlush && testState.apertureNbifReadLive)
            throw std::runtime_error("native flush RW map aliases a live read-only NBIF map");
        if (task != kernel_task || address != 0 || (!indexed && !stateMap && !mode1Map && !kdbMailbox && !probe && !staging && !preSosWindow && !sosWindow && !flush && !nbifRead && !nativeFlush &&
            (offset != expectedOffset || n != expectedLength ||
             options != (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache))))
            throw std::runtime_error("unexpected mapping request");
        if (indexed && physical != 0xc0000000)
            throw std::runtime_error("writable mapping outside BAR5 page zero");
        if (onMap) onMap();
        if (mapFail || (indexed && indexedMapFail) ||
            (preSosWindow && static_cast<int>(preSosIndex) == testState.preSosMapFailIndex) ||
            (sosWindow && static_cast<int>(sosIndex) == testState.preSosMapFailIndex) ||
            (testState.failMapRequest && testState.mapRequests == testState.failMapRequest)) return nullptr;
        auto *map = new IOMemoryMap;
        map->physical = physical + offset + (mapWrongPhysical ? 4 : 0);
        map->length = n - (mapTruncated ? 1 : 0);
        map->fragmented = mapFragmented;
        map->wrongSegment = mapSegmentWrongPhysical;
        map->options = options & ~(mapWritable ? kIOMapReadOnly : 0u);
        if (indexed && indexedMapReadOnly) map->options |= kIOMapReadOnly;
        if (mapForceReadOnly) map->options |= kIOMapReadOnly;
        if (mapCached) map->options &= ~kIOMapCacheMask;
        // Reproduce XNU makeMapping's unique-physical branch: withAddressRange
        // creates a separate exact-length descriptor; the map offset is zero.
        if (!mapWrongDescriptor) {
            if (mapOriginalDescriptor) {
                map->descriptor = this;
                map->descriptorOffset = offset;
            } else {
                auto *backing = new IOMemoryDescriptor;
                backing->uniqueBacking = true;
                ++testState.backingDescriptorsLive;
                backing->physical = physical + offset + (mapDescriptorWrongPhysical ? 4 : 0);
                backing->length = n + (mapDescriptorWrongLength ? 1 : 0);
                backing->contiguous = n - (mapDescriptorFragmented ? 1 : 0);
                // A deliberately inconsistent descriptor must fail independently
                // of the map's reported start/length.
                backing->physicalSegmentWrong = mapDescriptorWrongSegment;
                map->descriptor = backing;
                map->ownsDescriptor = true;
            }
        }
        const bool splWindow = staging && offset == testState.apertureOffset + (1ULL << 20);
        map->address = (mapNullAddress || (preSosWindow && static_cast<int>(preSosIndex) == testState.preSosMapInvalidIndex) ||
            (sosWindow && static_cast<int>(sosIndex) == testState.preSosMapInvalidIndex)) ? 0 : reinterpret_cast<uintptr_t>(
            indexed ? selectorStorage.data() : sosWindow ? testState.sosCpu[sosIndex].data() : preSosWindow ? testState.preSosCpu[preSosIndex].data() : splWindow ? testState.splCpu.data() : (probe || staging) ? testState.apertureCpu.data() :
                (flush || nbifRead || nativeFlush) ? testState.apertureFlush.data() : storage.data());
        if (mapMisalignedAddress && map->address) ++map->address;
        if (indexed) {
            map->indexedMapping = true;
            testState.indexedMapLive = true;
            testState.indexedPage = selectorStorage.data();
        }
        if (mode1Map) {
            map->mode1Mapping = true;
            ++testState.mode1MapsLive;
            testState.mode1Events.push_back("map-" + std::to_string(offset));
            testState.mode1MappedPages.push_back({offset, options, map->address});
        }
        if (preSosWindow) {
            map->preSosWindowMapping = true;
            map->preSosWindowIndex = preSosIndex;
            testState.preSosWindowLive[preSosIndex] = true;
            testState.preSosPages[preSosIndex] = testState.preSosCpu[preSosIndex].data();
        }
        if (sosWindow) {
            map->sosWindowMapping = true;
            map->sosWindowIndex = sosIndex;
            testState.sosWindowLive[sosIndex] = true;
            testState.sosPages[sosIndex] = testState.sosCpu[sosIndex].data();
        }
        if (probe || staging) {
            if (splWindow) { map->splMapping = true; testState.splMapLive = true; testState.splPage = testState.splCpu.data(); }
            else { map->probeMapping = true; testState.probeMapLive = true; testState.probePage = testState.apertureCpu.data(); }
        }
        if (flush) {
            map->flushMapping = true; testState.flushMapLive = true;
            testState.flushPage = testState.apertureFlush.data();
        }
        if (nbifRead) {
            map->nbifMapping = true;
            testState.apertureNbifReadLive = true;
            testState.nbifPage = testState.apertureFlush.data();
        }
        if (nativeFlush) {
            map->nativeFlushMapping = true;
            testState.flushMapLive = true;
            testState.flushPage = testState.apertureFlush.data();
            testState.nbifPage = testState.apertureFlush.data();
        }
        if (kdbMailbox) {
            map->kdbMailboxMapping = true;
            testState.kdbMailboxMapLive = true;
            testState.kdbMailboxPage = storage.data();
        }
        map->onAddress = onAddress;
        return map;
    }
};
inline IOMemoryMap::~IOMemoryMap() {
    if (mode1Mapping) {
        --testState.mode1MapsLive;
        const uint64_t offset = physical - 0xc0000000ULL;
        testState.mode1Events.push_back("unmap-" + std::to_string(offset));
        testState.mode1MappedPages.erase(std::remove_if(testState.mode1MappedPages.begin(), testState.mode1MappedPages.end(),
            [offset, this](const auto &page) { return page.offset == offset && page.options == options && page.address == address; }),
            testState.mode1MappedPages.end());
    }
    if (indexedMapping) testState.indexedMapLive = false;
    if (probeMapping) testState.probeMapLive = false;
    if (splMapping) { testState.splMapLive = false; testState.splPage = nullptr; }
    if (flushMapping) testState.flushMapLive = false;
    if (nbifMapping) {
        testState.apertureNbifReadLive = false;
        testState.nbifPage = nullptr;
        if (testState.onApertureNbifRelease) testState.onApertureNbifRelease();
    }
    if (nativeFlushMapping) {
        testState.flushMapLive = false;
        testState.nbifPage = nullptr;
    }
    if (kdbMailboxMapping) {
        testState.kdbMailboxMapLive = false;
        testState.kdbMailboxPage = nullptr;
    }
    if (preSosWindowMapping) {
        testState.preSosWindowLive[preSosWindowIndex] = false;
        testState.preSosPages[preSosWindowIndex] = nullptr;
    }
    if (sosWindowMapping) {
        testState.sosWindowLive[sosWindowIndex] = false;
        testState.sosPages[sosWindowIndex] = nullptr;
    }
    if (ownsDescriptor) descriptor->release();
    --testState.mapsLive; ++testState.mapReleases;
    if (testState.onMapRelease) testState.onMapRelease(testState.mapReleases);
}
inline uint64_t IOMemoryMap::getPhysicalSegment(IOByteCount offset, IOByteCount *n, IOOptionBits segmentOptions) {
    if (!descriptor) throw std::runtime_error("null mapping descriptor");
    const uint64_t result = descriptor->getPhysicalSegment(descriptorOffset + offset, n, segmentOptions);
    if (fragmented) *n = length - 1;
    return result + (wrongSegment ? 4 : 0);
}
using IODeviceMemory = IOMemoryDescriptor;

class IOPCIDevice : public IOService {
public:
    IOService *owner = nullptr;
    IOService *successfulOpenClient = nullptr;
    bool openBusy = false, iteratorFail = false, iteratorInvalid = false;
    std::vector<OSObject *> clients;
    std::function<void()> onOpen, onClose, onCensus;
    bool open(IOService *client, IOOptionBits options) {
        if (options != 0) throw std::runtime_error("nonzero provider open flags");
        ++testState.openCalls;
        if (openBusy || owner) return false;
        owner = successfulOpenClient = client; ++testState.openLive; testState.indexedOwner = client;
        if (onOpen) onOpen();
        return true;
    }
    void close(IOService *client, IOOptionBits options) {
        if (options != 0 || successfulOpenClient != client) throw std::runtime_error("invalid provider close");
        if (owner == client) owner = nullptr;
        successfulOpenClient = nullptr; --testState.openLive; ++testState.closeCalls;
        earlyInitEvent("provider-close");
        if (onClose) onClose();
    }
    bool isOpen(const IOService *client) const { return owner == client; }
    OSIterator *getClientIterator() const {
        if (onCensus) onCensus();
        return iteratorFail ? nullptr : new OSIterator(clients, !iteratorInvalid);
    }
    uint32_t identity = 0x75901002, classRevision = 0x030000c0, subsystem = 0x12341002;
    uint16_t command = 2;
    uint16_t savedCommand = 2;
    uint32_t savedBars[6] = {};
    uint8_t header = 0;
    uint32_t bars[6] = {0x0c, 0x10, 0, 0, 0, 0xc0000000};
    IODeviceMemory *memories[6] = {};
    unsigned identityReads = 0, otherReads = 0, descriptorReads = 0;
    std::function<void(uint8_t)> onRead;
    uint32_t configRead32(uint8_t offset) {
        if (testState.mode1Quiet) throw std::runtime_error("PCI config read during Mode 1 quiet interval");
        if (testState.mode1Writes.size() == 3 && testState.mode1RestoreCalls == 0 && offset != 0)
            throw std::runtime_error("PCI config read before Mode 1 PCI restore");
        if (onRead) onRead(offset);
        if (offset == 0) { ++identityReads; return identity; }
        ++otherReads;
        if (offset == 8) return classRevision;
        if (offset == 0x2c) return subsystem;
        if (offset >= 0x10 && offset <= 0x24 && offset % 4 == 0) return bars[(offset - 0x10) / 4];
        throw std::runtime_error("unexpected config32 read");
    }
    uint16_t configRead16(uint8_t offset) {
        if (testState.mode1Quiet) throw std::runtime_error("PCI config read during Mode 1 quiet interval");
        if (testState.mode1Writes.size() == 3 && testState.mode1RestoreCalls == 0)
            throw std::runtime_error("PCI config read before Mode 1 PCI restore");
        ++otherReads;
        if (onRead) onRead(offset);
        if (offset == 4) return command;
        throw std::runtime_error("unexpected config16 read");
    }
    uint8_t configRead8(uint8_t offset) {
        if (testState.mode1Quiet) throw std::runtime_error("PCI config read during Mode 1 quiet interval");
        if (testState.mode1Writes.size() == 3 && testState.mode1RestoreCalls == 0)
            throw std::runtime_error("PCI config read before Mode 1 PCI restore");
        ++otherReads;
        if (onRead) onRead(offset);
        if (offset == 0x0e) return header;
        throw std::runtime_error("unexpected config8 read");
    }
    IODeviceMemory *getDeviceMemoryWithRegister(uint8_t offset) {
        if (testState.mode1Quiet) throw std::runtime_error("PCI descriptor read during Mode 1 quiet interval");
        if (testState.mode1Writes.size() == 3 && testState.mode1RestoreCalls == 0)
            throw std::runtime_error("PCI descriptor read before Mode 1 PCI restore");
        ++descriptorReads;
        if (offset < 0x10 || offset > 0x24 || offset % 4) throw std::runtime_error("unexpected descriptor");
        return memories[(offset - 0x10) / 4];
    }
    IOReturn saveDeviceState(IOOptionBits options) {
        if (options != 0) throw std::runtime_error("nonzero saveDeviceState options");
        ++testState.mode1SaveCalls; testState.mode1Events.push_back("save-pci");
        if (testState.mode1SaveFail) return -1003;
        savedCommand = command; std::copy(std::begin(bars), std::end(bars), savedBars);
        testState.mode1SavedBusMaster = (command & 4u) != 0;
        return kIOReturnSuccess;
    }
    IOReturn restoreDeviceState(IOOptionBits options) {
        if (options != 0) throw std::runtime_error("nonzero restoreDeviceState options");
        ++testState.mode1RestoreCalls; testState.mode1Events.push_back("restore-pci");
        earlyInitEvent("restore-pci");
        if (testState.mode1RestoreFail) return -1004;
        command = savedCommand; std::copy(std::begin(savedBars), std::end(savedBars), bars);
        testState.mode1BusMasterState = testState.mode1SavedBusMaster;
        return kIOReturnSuccess;
    }
    bool setBusMasterEnable(bool enabled) {
        if (!testState.mode1SaveCalls) throw std::runtime_error("bus-master change before PCI state save");
        const bool previous = (command & 4u) != 0;
        testState.mode1BusMasterPrevious = previous;
        testState.mode1BusMasterState = enabled;
        testState.mode1Events.push_back(enabled ? "bus-master-on" : "bus-master-off");
        if (enabled) command = static_cast<uint16_t>(command | 4u);
        else command = static_cast<uint16_t>(command & ~4u);
        return previous;
    }
    // Deliberately no config-write, enable, DMA or IRQ methods.
};

inline uint32_t cobaltSurveyTestRead32(volatile uint32_t *address) {
    if (!testState.indexedMapLive || testState.openLive != 1 || !testState.indexedPage)
        throw std::runtime_error("MMIO read without mapping and ownership");
    const auto offset = static_cast<uint32_t>(address - testState.indexedPage) * 4;
    uint32_t value = 0;
    if (offset == 0 || offset == 0x18) {
        value = *address;
        if (testState.selectorRead) value = testState.selectorRead(offset, value);
    } else if (offset == 4) {
        const uint32_t low = testState.indexedPage[0], high = testState.indexedPage[6];
        const uint64_t pos = (uint64_t(high) << 31) | (low & 0x7fffffffu);
        if (aperturePhase() && !(earlyInitPathActive() && testState.earlyInitPhase == 2)) {
            const uint64_t windowBytes = testState.splEnabled ? (2ULL << 20) : stagingPhase() ? (1ULL << 20) : 16;
            const uint64_t activeWindowBytes = sosPathActive() ? (8ULL << 20) : testState.preSosEnabled ? (7ULL << 20) : windowBytes;
            if ((!testState.preSosEnabled && !sosPathActive() && !testState.probeMapLive) || !(low & 0x80000000u) || (pos & 3) ||
                pos < testState.apertureOffset || pos >= testState.apertureOffset + activeWindowBytes)
                throw std::runtime_error("aperture MM_DATA outside fixed survey window");
            if (sosPathActive()) {
                const unsigned index = static_cast<unsigned>((pos - testState.apertureOffset) >> 20);
                if (index >= testState.sosWindowLive.size() || !testState.sosWindowLive[index])
                    throw std::runtime_error("MM_DATA outside mapped SOS CPU window");
                const size_t word = static_cast<size_t>((pos - testState.apertureOffset) & ((1u << 20)-1)) / 4;
                value = testState.sosGpu[index][word];
            } else if (testState.preSosEnabled) {
                const unsigned index = static_cast<unsigned>((pos - testState.apertureOffset) >> 20);
                if (index >= testState.preSosWindowLive.size() || !testState.preSosWindowLive[index])
                    throw std::runtime_error("pre-SOS MM_DATA without its bounded window map");
                value = testState.preSosGpu[index][static_cast<size_t>((pos - testState.apertureOffset - (static_cast<uint64_t>(index) << 20))/4)];
            } else {
            const bool splWindow = testState.splEnabled && pos >= testState.apertureOffset + (1ULL << 20);
            if (splWindow && !testState.splMapLive) throw std::runtime_error("SPL MM_DATA without its bounded window map");
            value = (splWindow ? testState.splGpu : testState.apertureGpu)[static_cast<size_t>((pos-(testState.apertureOffset + (splWindow ? (1ULL << 20) : 0)))/4)];
            }
            if (testState.apertureDataRead) value = testState.apertureDataRead(testState.apertureDataReads, value);
            ++testState.apertureDataReads;
            apertureEvent('d', static_cast<uint32_t>(pos-testState.apertureOffset), value);
        } else {
        if (!(low & 0x80000000u) || (pos & 3) || pos < testState.discoveryOffset ||
            pos + 4 > testState.discoveryOffset + 10240 || testState.discovery.size() != 10240)
            throw std::runtime_error("MM_DATA read outside fixed discovery range");
        std::memcpy(&value, testState.discovery.data() + (pos - testState.discoveryOffset), 4);
        if (testState.dataRead) value = testState.dataRead(testState.indexedDataReads, value);
        ++testState.indexedDataReads;
        if (earlyInitPathActive() && testState.mode1Writes.size() == 3 && testState.mode1RestoreCalls)
            ++testState.earlyInitRefreshDataReads;
        }
    } else throw std::runtime_error("unexpected register read");
    const MmioEvent event {'r', offset, value}; testState.mmioEvents.push_back(event);
    if (testState.onMmio) testState.onMmio(event);
    return value;
}
inline uint32_t cobaltSurveyTestReadState32(volatile uint32_t *address, uint32_t offset) {
    const bool expectedMaps = testState.mapsLive == 2 || testState.mapsLive == 4 ||
        (earlyInitPathActive() && testState.openLive == 1 && testState.earlyInitMarker && testState.mapsLive == 3) ||
        (stagingPhase() && testState.mapsLive >= 4 && testState.mapsLive <= 8) ||
        (testState.preSosEnabled && (testState.mapsLive == 12 || testState.mapsLive == 13)) ||
        (sosPathActive() && (testState.mapsLive == 13 || testState.mapsLive == 14));
    if (!testState.stateBootPresent || !expectedMaps ||
        (std::find(testState.stateAllowedOffsets.begin(), testState.stateAllowedOffsets.end(), offset) ==
            testState.stateAllowedOffsets.end() && (!(testState.kdbEnabled || earlyInitPathActive()) ||
             std::find(testState.kdbStateOffsets.begin(), testState.kdbStateOffsets.end(), offset) == testState.kdbStateOffsets.end())))
        throw std::runtime_error("state MMIO outside fixed passive allowlist");
    const uint64_t page = offset & ~uint32_t(0xfff);
    bool mappedAddress = false;
    for (const auto &mapping : testState.stateMapBases)
        if (mapping.first == page && reinterpret_cast<uintptr_t>(address) ==
            mapping.second + (offset & 0xfffu)) mappedAddress = true;
    if (!mappedAddress) throw std::runtime_error("state MMIO pointer outside mapped page");
    uint32_t observed = 0;
    if (testState.kdbBootPresent || testState.preSosEnabled || sosPathActive()) {
        if (offset == 0x458c) observed = 0x80000000u;
        else if (offset == 0x4644) observed = 0;
        else if (offset == 0xa950 || offset == 0x5d14) observed = 0x33;
        else if (offset == 0xa954) observed = 0x44;
        else if (offset == 0xad1c) observed = 0x55;
    } else {
        const uint32_t values[] = {0x11u, 0x22u, 0x33u, 0x44u};
        observed = values[testState.stateReads % 4];
    }
    const uint32_t actual = testState.stateRead ? testState.stateRead(offset, observed) : observed;
    testState.stateEvents.emplace_back(offset, actual);
    ++testState.stateReads;
    return actual;
}
inline void cobaltSurveyTestKdbWrite32(volatile uint32_t *address, uint32_t value, uint32_t offset) {
    if ((!testState.kdbEnabled && !testState.splEnabled && !testState.preSosEnabled && !sosPathActive()) || testState.openLive != 1 || !testState.indexedOwner ||
        !testState.kdbMailboxMapLive || !testState.kdbMailboxPage ||
        (!(testState.kdbClaimed || testState.splClaimed || testState.preSosClaimed || testState.sosClaimed)))
        throw std::runtime_error("PSP mailbox write without owned attempt");
    requireExplicitWritableMode();
    if (sosPathActive()) {
        if (testState.sosFinalStoreSeen) throw std::runtime_error("write after final SOS command store");
        if (testState.sosWrites == 0) {
            for (unsigned i = 0; i < testState.sosWindowLive.size(); ++i) {
                if (!testState.sosWindowLive[i] || testState.sosCpu[i].size() != 262144 ||
                    testState.sosGpu[i].size() != 262144 || testState.sosCpu[i] != testState.sosGpu[i])
                    throw std::runtime_error("first mailbox store before all eight SOS images are staged and visible");
            }
            earlyInitEvent("all-eight-images-visible");
        }
        if (offset != testState.kdbAddressByteOffset && offset != testState.kdbCommandByteOffset)
            throw std::runtime_error("SOS mailbox write outside fixed C2P allowlist");
        auto *expected = reinterpret_cast<volatile uint32_t *>(
            reinterpret_cast<volatile uint8_t *>(testState.kdbMailboxPage) + (offset & 0xfffu));
        if (address != expected) throw std::runtime_error("SOS mailbox pointer outside mapped C2P word");
        ++testState.sosWrites;
        testState.sosEvents.push_back({offset, value});
        earlyInitEvent(offset == testState.kdbCommandByteOffset && value == 0x00020000u ? "sos-final-command" : "sos-mailbox-store");
        if (testState.onSos) testState.onSos(testState.sosEvents.back());
        if (offset == testState.kdbCommandByteOffset && value == 0x00020000u) testState.sosFinalStoreSeen = true;
        return;
    }
    if (testState.preSosEnabled) {
        if (offset != testState.kdbAddressByteOffset && offset != testState.kdbCommandByteOffset)
            throw std::runtime_error("pre-SOS mailbox write outside fixed C2P allowlist");
        auto *expected = reinterpret_cast<volatile uint32_t *>(
            reinterpret_cast<volatile uint8_t *>(testState.kdbMailboxPage) + (offset & 0xfffu));
        if (address != expected) throw std::runtime_error("pre-SOS mailbox pointer outside mapped C2P word");
        ++testState.preSosWrites;
        testState.preSosEvents.push_back({offset, value});
        if (testState.onPreSos) testState.onPreSos(testState.preSosEvents.back());
        return;
    }
    const bool splStore = testState.splEnabled && (testState.kdbWrites + testState.splWrites) >= 2;
    const bool splAddress = splStore && offset == testState.splAddressByteOffset;
    const bool splCommand = splStore && offset == testState.splCommandByteOffset;
    if (!splAddress && !splCommand && offset != testState.kdbAddressByteOffset && offset != testState.kdbCommandByteOffset)
        throw std::runtime_error("PSP mailbox write outside fixed C2P allowlist");
    auto *expected = reinterpret_cast<volatile uint32_t *>(
        reinterpret_cast<volatile uint8_t *>(testState.kdbMailboxPage) + (offset & 0xfffu));
    if (address != expected)
        throw std::runtime_error("KDB mailbox write pointer outside proven mapped C2P word");
    if (splAddress || splCommand) {
        ++testState.splWrites; testState.splEvents.push_back({offset, value});
        if (testState.onSpl) testState.onSpl(testState.splEvents.back());
    } else {
        ++testState.kdbWrites; testState.kdbEvents.push_back({offset, value});
        if (testState.onKdb) testState.onKdb(testState.kdbEvents.back());
    }
}
inline void cobaltSurveyTestWriteSelector32(volatile uint32_t *address, uint32_t value) {
    if (sosPathActive() && testState.sosFinalStoreSeen)
        throw std::runtime_error("selector write after final SOS command store");
    if (!testState.indexedMapLive || testState.openLive != 1 || !testState.indexedOwner)
        throw std::runtime_error("selector write without explicit writable mode");
    requireExplicitWritableMode();
    const auto offset = static_cast<uint32_t>(address - testState.indexedPage) * 4;
    if (sosPathActive() && testState.sosFinalStoreSeen)
        throw std::runtime_error("selector write after final SOS command store");
    if (offset != 0 && offset != 0x18) throw std::runtime_error("write outside selectors");
    *address = value; ++testState.selectorWrites;
    const MmioEvent event {'w', offset, value}; testState.mmioEvents.push_back(event);
    if (aperturePhase()) {
        if (!testState.apertureClaimed && !testState.stagingClaimed && !testState.kdbClaimed && !testState.splClaimed && !testState.preSosClaimed && !testState.sosClaimed &&
            !(earlyInitPathActive() && testState.earlyInitPhase == 2 && testState.earlyInitMarker &&
                testState.mode1Marker == testState.earlyInitMarker && !testState.sosMarker))
            throw std::runtime_error("aperture selector write before persistent claim");
        apertureEvent('s', offset, value);
    }
    if (testState.onMmio) testState.onMmio(event);
}

inline void apertureIoOwnership(bool permitStagingBackupRead = false) {
    if (!aperturePhase() || !testState.indexedOwner ||
        (!testState.apertureClaimed && !testState.stagingClaimed && !testState.kdbClaimed && !testState.splClaimed && !testState.preSosClaimed && !testState.sosClaimed &&
         !(permitStagingBackupRead && stagingPhase())))
        throw std::runtime_error("aperture access without owned explicit attempt");
    if (permitStagingBackupRead && earlyInitPathActive() && testState.earlyInitPhase == 3 &&
        testState.earlyInitMarker && testState.mode1Marker == testState.earlyInitMarker && !testState.sosMarker)
        return; // bounded original-buffer reads only, before the firmware claim
    requireExplicitWritableMode();
}
inline uint32_t cobaltSurveyTestApertureRegisterRead(const volatile uint32_t *address, uint32_t offset) {
    const uint32_t remapOffset = (testState.apertureNbifSegmentBase + 0x12d) * 4;
    const uint32_t memsizeOffset = (testState.apertureNbifSegmentBase + 0xc3) * 4;
    if (!aperturePhase() || !testState.nbifPage ||
        (offset != remapOffset && offset != memsizeOffset) ||
        address != testState.nbifPage + (offset & 0xfff)/4)
        throw std::runtime_error("aperture register read outside proven NBIF allowlist");
    uint32_t value = offset == remapOffset ? testState.apertureRemap : testState.apertureMemsize;
    if (testState.apertureRegisterRead) value = testState.apertureRegisterRead(offset, value);
    ++testState.apertureRegisterReads;
    apertureEvent('n', offset, value);
    return value;
}
inline uint32_t cobaltSurveyTestApertureCpuRead(volatile uint32_t *address) {
    apertureIoOwnership(true);
    const size_t maxWords = stagingPhase() ? 262144 : 4;
    const uintptr_t pointer = reinterpret_cast<uintptr_t>(address);
    if (sosPathActive()) for (unsigned i = 0; i < testState.sosPages.size(); ++i) {
        const auto base = reinterpret_cast<uintptr_t>(testState.sosPages[i]);
        if (testState.sosWindowLive[i] && base && pointer >= base && pointer < base + maxWords * sizeof(uint32_t)) {
            uint32_t value = *address;
            if (testState.apertureCpuRead) value = testState.apertureCpuRead(testState.apertureCpuReads, value);
            ++testState.apertureCpuReads;
            apertureEvent('c', i * (1u << 20) + static_cast<uint32_t>(pointer - base), value);
            return value;
        }
    }
    for (unsigned i = 0; i < testState.preSosPages.size(); ++i) {
        const auto base = reinterpret_cast<uintptr_t>(testState.preSosPages[i]);
        if (testState.preSosWindowLive[i] && base && pointer >= base && pointer < base + maxWords * sizeof(uint32_t)) {
            uint32_t value = *address;
            if (testState.apertureCpuRead) value = testState.apertureCpuRead(testState.apertureCpuReads, value);
            ++testState.apertureCpuReads;
            apertureEvent('c', i * (1u << 20) + static_cast<uint32_t>(pointer - base), value);
            return value;
        }
    }
    const bool inKdb = testState.probeMapLive && pointer >= reinterpret_cast<uintptr_t>(testState.probePage) && pointer < reinterpret_cast<uintptr_t>(testState.probePage+maxWords);
    const bool inSpl = testState.splMapLive && pointer >= reinterpret_cast<uintptr_t>(testState.splPage) && pointer < reinterpret_cast<uintptr_t>(testState.splPage+maxWords);
    if (!inKdb && !inSpl)
        throw std::runtime_error("CPU read outside fixed survey window");
    uint32_t value = *address;
    if (testState.apertureCpuRead) value = testState.apertureCpuRead(testState.apertureCpuReads, value);
    ++testState.apertureCpuReads;
    const uintptr_t base = reinterpret_cast<uintptr_t>(inSpl ? testState.splPage : testState.probePage);
    apertureEvent('c', static_cast<uint32_t>(pointer - base + (inSpl ? (1ULL << 20) : 0)), value);
    return value;
}
inline void cobaltSurveyTestApertureCpuWrite(volatile uint32_t *address, uint32_t value) {
    apertureIoOwnership();
    if (sosPathActive() && testState.sosWrites)
        throw std::runtime_error("CPU window write after an SOS mailbox attempt");
    const size_t maxWords = stagingPhase() ? 262144 : 4;
    if (testState.preSosEnabled && testState.preSosWrites)
        throw std::runtime_error("CPU window write after a pre-SOS mailbox attempt");
    if (testState.splEnabled && testState.kdbWrites + testState.splWrites)
        throw std::runtime_error("CPU window write after a PSP mailbox attempt");
    const uintptr_t pointer = reinterpret_cast<uintptr_t>(address);
    if (sosPathActive()) for (unsigned i = 0; i < testState.sosPages.size(); ++i) {
        const auto base = reinterpret_cast<uintptr_t>(testState.sosPages[i]);
        if (testState.sosWindowLive[i] && base && pointer >= base && pointer < base + maxWords * sizeof(uint32_t)) {
            *address = value; ++testState.apertureCpuWrites;
            apertureEvent('v', i * (1u << 20) + static_cast<uint32_t>(pointer - base), value);
            return;
        }
    }
    for (unsigned i = 0; i < testState.preSosPages.size(); ++i) {
        const auto base = reinterpret_cast<uintptr_t>(testState.preSosPages[i]);
        if (testState.preSosWindowLive[i] && base && pointer >= base && pointer < base + maxWords * sizeof(uint32_t)) {
            *address = value; ++testState.apertureCpuWrites;
            apertureEvent('v', i * (1u << 20) + static_cast<uint32_t>(pointer - base), value);
            return;
        }
    }
    const bool inKdb = testState.probeMapLive && pointer >= reinterpret_cast<uintptr_t>(testState.probePage) && pointer < reinterpret_cast<uintptr_t>(testState.probePage+maxWords);
    const bool inSpl = testState.splMapLive && pointer >= reinterpret_cast<uintptr_t>(testState.splPage) && pointer < reinterpret_cast<uintptr_t>(testState.splPage+maxWords);
    if (!inKdb && !inSpl)
        throw std::runtime_error("CPU write outside fixed survey window");
    *address = value; ++testState.apertureCpuWrites;
    const uintptr_t base = reinterpret_cast<uintptr_t>(inSpl ? testState.splPage : testState.probePage);
    apertureEvent('v', static_cast<uint32_t>(pointer - base + (inSpl ? (1ULL << 20) : 0)), value);
}
inline void cobaltSurveyTestApertureFence() {
    apertureIoOwnership();
    ++testState.apertureFences;
    apertureEvent('f', 0, 0);
}
inline void cobaltSurveyTestApertureFlush(volatile uint32_t *address) {
    apertureIoOwnership();
    if (sosPathActive() && testState.sosWrites)
        throw std::runtime_error("HDP flush after an SOS mailbox attempt");
    if (testState.preSosEnabled && testState.preSosWrites)
        throw std::runtime_error("HDP flush after a pre-SOS mailbox attempt");
    if ((testState.splEnabled && testState.kdbWrites + testState.splWrites) ||
        (testState.preSosEnabled && testState.preSosWrites))
        throw std::runtime_error("HDP flush after a PSP mailbox attempt");
    const uint32_t nativeFlushOffset = (testState.apertureNbifSegmentBase + 0xf7) * 4;
    volatile uint32_t *expected = testState.apertureNativeRoute
        ? testState.apertureFlush.data() + (nativeFlushOffset & 0xfff) / 4
        : testState.apertureFlush.data();
    if (!testState.flushMapLive || address != expected ||
        testState.apertureFences != testState.apertureFlushWrites+1)
        throw std::runtime_error("HDP flush outside fixed page or without fence");
    *address = 0;
    const size_t words = stagingPhase() ? 262144 : 4;
    std::copy_n(testState.apertureCpu.data(), words, testState.apertureGpu.data());
    if (testState.splMapLive)
        std::copy_n(testState.splCpu.data(), words, testState.splGpu.data());
    for (unsigned i = 0; i < testState.preSosWindowLive.size(); ++i)
        if (testState.preSosWindowLive[i])
            std::copy_n(testState.preSosCpu[i].data(), 262144, testState.preSosGpu[i].data());
    for (unsigned i = 0; i < testState.sosWindowLive.size(); ++i)
        if (testState.sosWindowLive[i])
            std::copy_n(testState.sosCpu[i].data(), 262144, testState.sosGpu[i].data());
    ++testState.apertureFlushWrites;
    apertureEvent('h', 0, 0);
}

inline bool PE_parse_boot_argn(const char *key, void *out, int n) {
    const auto enabled = [](bool present, const std::string &argument) {
        const std::string token = argument.substr(0, argument.find_first_of(" \t"));
        char *end = nullptr;
        const auto numeric = std::strtoll(token.c_str(), &end, 0);
        return present && !token.empty() && end && *end == '\0' && numeric == 1;
    };
    testState.earlyInitEnabled = enabled(testState.earlyInitBootPresent, testState.earlyInitBoot);
    testState.mode1Enabled = enabled(testState.mode1BootPresent, testState.mode1Boot) ||
        enabled(testState.mode1EarlyBootPresent, testState.mode1EarlyBoot) || testState.earlyInitEnabled;
    const bool indexed = std::string(key) == "cobalt-survey-indexed";
    const bool state = std::string(key) == "cobalt-survey-state";
    const bool aperture = std::string(key) == "cobalt-survey-aperture";
    const bool staging = std::string(key) == "cobalt-survey-staging";
    const bool kdb = std::string(key) == "cobalt-survey-kdb";
    const bool spl = std::string(key) == "cobalt-survey-spl";
    const bool preSos = std::string(key) == "cobalt-survey-presos";
    const bool sos = std::string(key) == "cobalt-survey-sos";
    const bool mode1 = std::string(key) == "cobalt-survey-mode1";
    const bool mode1Early = std::string(key) == "cobalt-survey-mode1boot";
    const bool initBoot = std::string(key) == "cobalt-survey-initboot";
    if (std::string(key) != "cobalt-survey" && !indexed && !state && !aperture && !staging && !kdb && !spl && !preSos && !sos && !mode1 && !mode1Early && !initBoot) throw std::runtime_error("unexpected boot argument");
    if (indexed ? !testState.indexedBootPresent : state ? !testState.stateBootPresent :
        initBoot ? !testState.earlyInitBootPresent :
        mode1Early ? !testState.mode1EarlyBootPresent : mode1 ? !testState.mode1BootPresent : sos ? !testState.sosBootPresent : preSos ? !testState.preSosBootPresent :
        spl ? !testState.splBootPresent : kdb ? !testState.kdbBootPresent :
        aperture ? !testState.apertureBootPresent : staging ? !testState.stagingBootPresent : !testState.bootPresent) return false;
    // Reproduce XNU's integer conversion first, including decimal/hex/octal.
    // The real API does not choose string versus integer from buffer size.
    // Space and tab terminate the value in the actual boot-argument string.
    const auto &argument = indexed ? testState.indexedBoot : state ? testState.stateBoot : initBoot ? testState.earlyInitBoot : mode1Early ? testState.mode1EarlyBoot : mode1 ? testState.mode1Boot : sos ? testState.sosBoot : preSos ? testState.preSosBoot : spl ? testState.splBoot : kdb ? testState.kdbBoot :
        aperture ? testState.apertureBoot : staging ? testState.stagingBoot : testState.boot;
    const std::string token = argument.substr(0, argument.find_first_of(" \t"));
    char *end = nullptr;
    const auto numeric = std::strtoll(token.c_str(), &end, 0);
    if (!token.empty() && end && *end == '\0') {
        const uint32_t integer = static_cast<uint32_t>(numeric);
        if (staging) testState.stagingEnabled = integer == 1;
        if (kdb) testState.kdbEnabled = integer == 1;
        if (spl) testState.splEnabled = integer == 1;
        if (preSos) testState.preSosEnabled = integer == 1 && !testState.sosEnabled;
        if (sos) testState.sosEnabled = integer == 1;
        if (initBoot) testState.earlyInitEnabled = integer == 1;
        std::memcpy(out, &integer, static_cast<size_t>(n) < sizeof(integer) ? static_cast<size_t>(n) : sizeof(integer));
    } else {
        if (staging) testState.stagingEnabled = false;
        if (kdb) testState.kdbEnabled = false;
        if (spl) testState.splEnabled = false;
        if (preSos) testState.preSosEnabled = false;
        if (sos) testState.sosEnabled = false;
        if (initBoot) testState.earlyInitEnabled = false;
        std::memset(out, 0, static_cast<size_t>(n));
        std::memcpy(out, token.data(), token.size() < static_cast<size_t>(n) ? token.size() : static_cast<size_t>(n));
    }
    return true;
}
inline void *IOMalloc(uint64_t n) {
    const bool metadata = earlyInitPathActive() && n > 0 && n < 10240;
    if (!metadata && n != 10240 && n != 20480 && n != (1ULL << 20) && n != 125472)
        throw std::runtime_error("unbounded allocation");
    const unsigned call = ++testState.allocationCalls;
    if (testState.allocFail || (testState.failAllocationCall && call == testState.failAllocationCall)) return nullptr;
    void *p = std::malloc(static_cast<size_t>(n));
    if (!p) return nullptr;
    if (metadata) { ++testState.metadataAllocations; testState.metadataPointers[p] = n; }
    else ++testState.allocations;
    return p;
}
inline void IOFree(void *p, uint64_t n) {
    const auto metadata = testState.metadataPointers.find(p);
    if (metadata != testState.metadataPointers.end()) {
        if (metadata->second != n) throw std::runtime_error("metadata free size mismatch");
        testState.metadataPointers.erase(metadata); --testState.metadataAllocations; std::free(p); return;
    }
    if (!p || (n != 10240 && n != 20480 && n != (1ULL << 20) && n != 125472))
        throw std::runtime_error("invalid IOFree");
    --testState.allocations; std::free(p);
}
inline void IOLog(const char *, ...) { if (testState.mode1Quiet) throw std::runtime_error("IOLog during Mode 1 quiet interval"); }
inline void IOSleep(unsigned milliseconds) {
    ++testState.sleepCalls;
    if (testState.mode1Writes.size() == 3 && testState.mode1SleepCalls == 0) {
        if (milliseconds < 1000) throw std::runtime_error("Mode 1 quiet interval shorter than one second");
        testState.mode1Quiet = true;
        testState.mode1Events.push_back("quiet-begin");
        earlyInitEvent("quiet-begin");
        ++testState.mode1SleepCalls;
    }
    if (testState.onMode1Sleep) testState.onMode1Sleep();
    if (testState.onSleep) testState.onSleep();
    if (testState.mode1Writes.size() == 3 && testState.mode1SleepCalls == 1 && testState.mode1Quiet) {
        testState.mode1Quiet = false;
        testState.mode1Events.push_back("quiet-end");
        earlyInitEvent("quiet-end");
    }
}
inline uint32_t OSSwapLittleToHostInt32(uint32_t value) {
    const unsigned index = testState.memsizeReads++;
    if (testState.onMemsize) testState.onMemsize(index);
    return index < testState.memsizeValues.size() ? testState.memsizeValues[index] : value;
}

inline uint32_t cobaltSurveyTestMode1Read32(const volatile uint32_t *word, uint32_t byteOffset) {
    if (!testState.mode1Enabled || testState.mode1Quiet)
        throw std::runtime_error("Mode 1 read outside active/nonquiet test window");
    if (testState.mode1Writes.size() == 3 && testState.mode1RestoreCalls == 0)
        throw std::runtime_error("Mode 1 MMIO read before PCI restore");
    if (!word) throw std::runtime_error("null Mode 1 read word");
    const uint64_t pageOffset = byteOffset & ~uint64_t(0xfff);
    const uint32_t within = byteOffset & 0xfffu;
    const auto page = std::find_if(testState.mode1MappedPages.begin(), testState.mode1MappedPages.end(),
        [pageOffset](const auto &entry) { return entry.offset == pageOffset &&
            entry.options == (kIOMapAnywhere | kIOMapUnique | kIOMapReadOnly | kIOMapInhibitCache); });
    if (page == testState.mode1MappedPages.end() ||
        reinterpret_cast<uintptr_t>(word) != page->address + within)
        throw std::runtime_error("Mode 1 read outside one of four fixed read-only pages");
    ++testState.mode1ReadCalls;
    testState.mode1Events.push_back("read-" + std::to_string(byteOffset));
    const uint32_t value = testState.mode1Read ? testState.mode1Read(byteOffset, *word) : *word;
    return value;
}
inline void cobaltSurveyTestMode1Write32(volatile uint32_t *word, uint32_t value, uint32_t byteOffset) {
    static constexpr uint32_t expectedOffsets[] = {0x11d4u, 0x122cu, 0x11d8u};
    static constexpr uint32_t expectedValues[] = {0u, 2u, 0u};
    const unsigned index = static_cast<unsigned>(testState.mode1Writes.size());
    if (!testState.mode1Enabled || !word || index >= 3 || byteOffset != expectedOffsets[index] || value != expectedValues[index])
        throw std::runtime_error("Mode 1 store outside exact three-register burst");
    if (index && testState.mode1RestoreCalls == 0 && testState.mode1SleepCalls)
        throw std::runtime_error("Mode 1 store after quiet interval");
    const uint64_t pageOffset = byteOffset & ~uint64_t(0xfff);
    const uint32_t within = byteOffset & 0xfffu;
    const auto page = std::find_if(testState.mode1MappedPages.begin(), testState.mode1MappedPages.end(),
        [pageOffset](const auto &entry) { return entry.offset == pageOffset &&
            entry.options == (kIOMapAnywhere | kIOMapUnique | kIOMapInhibitCache); });
    if (page == testState.mode1MappedPages.end() ||
        reinterpret_cast<uintptr_t>(word) != page->address + within)
        throw std::runtime_error("Mode 1 write outside the fixed MP1 debug page");
    testState.mode1Writes.emplace_back(byteOffset, value);
    testState.mode1WritePointers.emplace_back(word, value);
    testState.mode1Events.push_back("write-" + std::to_string(byteOffset));
    earlyInitEvent("mode1-write-" + std::to_string(byteOffset));
    *word = value;
    if (testState.mode1Write) testState.mode1Write(byteOffset, value);
}
