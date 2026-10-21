// PSP parser adapter tests only. No hardware operation is invoked.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "IOReturn.h"
#ifdef _MSC_VER
#define __attribute__(...)
#define __asm__
#define __volatile__(...)
#endif
inline void IOLog(const char *, ...) {}
inline void IOSleep(unsigned) {}
