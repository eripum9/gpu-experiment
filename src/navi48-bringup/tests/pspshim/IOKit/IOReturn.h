// Host-only return codes; reused from the existing kernel test shim.
#pragma once
#include "../../dalshim/IOKit/IOReturn.h"
#define kIOReturnInvalid iokit_common_err(0x2c3)
#define kIOReturnNotAligned iokit_common_err(0x2d0)
