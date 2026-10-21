#include <mach/mach_types.h>
#include <libkern/OSKextLib.h>

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
static kern_return_t survey_start(kmod_info_t *ki, void *data) {
    (void)ki; (void)data; return KERN_SUCCESS;
}
static kern_return_t survey_stop(kmod_info_t *ki, void *data) {
    (void)ki; (void)data; return KERN_SUCCESS;
}
KMOD_EXPLICIT_DECL(com.cobalt.navi44-survey, "0.1.2", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = survey_start;
__private_extern__ kmod_stop_func_t *_antimain = survey_stop;
