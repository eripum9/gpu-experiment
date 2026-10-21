#ifndef COBALT_NAVI44_SURVEY_HPP
#define COBALT_NAVI44_SURVEY_HPP

#include <IOKit/IOService.h>

// Independent observation service. No persistent GPU resources or user clients.
class CobaltNavi44Survey : public IOService {
    OSDeclareDefaultStructors(CobaltNavi44Survey)
public:
    IOService *probe(IOService *provider, SInt32 *score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
private:
    void survey(class IOPCIDevice *pci);
    void status(const char *value);
};

#endif
