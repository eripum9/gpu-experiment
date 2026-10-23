#ifndef CobaltNavi44Survey_psp_firmware_hpp
#define CobaltNavi44Survey_psp_firmware_hpp

#include <stddef.h>
#include <stdint.h>

namespace cobalt {
namespace survey {

struct FirmwareView {
	const uint8_t *data;
	size_t size;
};

FirmwareView psp1402Firmware();

} // namespace survey
} // namespace cobalt

#endif
