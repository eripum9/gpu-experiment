#ifndef COBALT_NAVI44_SURVEY_HPP
#define COBALT_NAVI44_SURVEY_HPP

#include <IOKit/IOService.h>
#include <IOKit/IOLocks.h>

// Independent observation service. No persistent GPU resources or user clients.
class CobaltNavi44Survey : public IOService {
    OSDeclareDefaultStructors(CobaltNavi44Survey)
public:
    IOService *probe(IOService *provider, SInt32 *score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    IOReturn setProperties(OSObject *properties) override;
private:
    IOLock *mode1Lock {nullptr};
    class OSData *mode1Snapshot {nullptr};
    bool mode1Accepting {false}, mode1Attempted {false}, mode1BootCheckpoint {false};
    void survey(class IOPCIDevice *pci);
    void status(const char *value);
};

#endif
