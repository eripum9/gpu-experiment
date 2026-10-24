/* Explicit user-space trigger for the one-shot Mode 1 reset diagnostic. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>

static void usage(FILE *stream, const char *program) {
    fprintf(stream,
            "Usage: %s --help | --run-mode1-reset\n"
            "\n"
            "  --help               Show this help; does not contact IOKit.\n"
            "  --run-mode1-reset    Send the single explicit Mode 1 reset request.\n",
            program);
}

static void print_property(io_registry_entry_t service, const char *name) {
    CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, name,
                                                kCFStringEncodingUTF8);
    if (!key) {
        printf("  %s: unable to create lookup key\n", name);
        return;
    }

    CFTypeRef value = IORegistryEntryCreateCFProperty(service, key,
                                                       kCFAllocatorDefault, 0);
    CFRelease(key);
    if (!value) {
        printf("  %s: not available\n", name);
        return;
    }

    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        char text[512] = {0};
        if (CFStringGetCString((CFStringRef)value, text, sizeof(text),
                               kCFStringEncodingUTF8)) {
            printf("  %s: %s\n", name, text);
        } else {
            printf("  %s: string value is not valid UTF-8 or is too long\n", name);
        }
    } else if (CFGetTypeID(value) == CFNumberGetTypeID()) {
        int64_t number = 0;
        if (CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &number)) {
            printf("  %s: %lld\n", name, (long long)number);
        } else {
            printf("  %s: numeric value could not be read\n", name);
        }
    } else if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
        printf("  %s: %s\n", name,
               CFBooleanGetValue((CFBooleanRef)value) ? "true" : "false");
    } else {
        printf("  %s: present (CoreFoundation type %lu)\n", name,
               (unsigned long)CFGetTypeID(value));
    }
    CFRelease(value);
}

static int find_unique_survey_service(io_service_t *out_service) {
    *out_service = IO_OBJECT_NULL;
    CFMutableDictionaryRef matching = IOServiceMatching("CobaltNavi44Survey");
    if (!matching) {
        fprintf(stderr, "lookup error: IOServiceMatching could not create a match.\n");
        return 1;
    }

    io_iterator_t iterator = IO_OBJECT_NULL;
    /* MACH_PORT_NULL is the default IOKit master port, including on macOS 11. */
    kern_return_t kr = IOServiceGetMatchingServices(MACH_PORT_NULL, matching,
                                                     &iterator);
    /* IOServiceGetMatchingServices consumes the matching dictionary. */
    if (kr != KERN_SUCCESS) {
        fprintf(stderr,
                "lookup error: IOServiceGetMatchingServices returned 0x%08x.\n",
                (unsigned int)kr);
        return 1;
    }

    unsigned count = 0;
    io_service_t only_service = IO_OBJECT_NULL;
    io_service_t service = IO_OBJECT_NULL;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        ++count;
        if (count == 1) {
            only_service = service;
        } else {
            IOObjectRelease(service);
        }
    }
    if (iterator != IO_OBJECT_NULL) IOObjectRelease(iterator);

    if (count == 0) {
        fprintf(stderr, "refusal: no CobaltNavi44Survey service was found.\n");
        return 2;
    }
    if (count != 1) {
        IOObjectRelease(only_service);
        fprintf(stderr,
                "refusal: expected exactly one CobaltNavi44Survey service; found %u.\n",
                count);
        return 3;
    }

    *out_service = only_service;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout, argv[0]);
        return 0;
    }
    if (argc != 2 || strcmp(argv[1], "--run-mode1-reset") != 0) {
        usage(stderr, argv[0]);
        fprintf(stderr,
                "refusal: an exact explicit --run-mode1-reset argument is required.\n");
        return 2;
    }

    puts("WARNING: Mode 1 reset may blank the display. Use test-software-reset.sh --run for automatic capture and reboot.");
    if (geteuid() != 0) {
        fprintf(stderr, "refusal: run this explicit test as root (for example, with sudo).\n");
        return 3;
    }

    io_service_t service = IO_OBJECT_NULL;
    int lookup_result = find_unique_survey_service(&service);
    if (lookup_result != 0) return 10 + lookup_result;

    const int32_t request_value = 1;
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
                                       &request_value);
    if (!number) {
        IOObjectRelease(service);
        fprintf(stderr, "request error: could not create numeric request value.\n");
        return 4;
    }

    const void *keys[] = { CFSTR("CobaltSurvey,RunMode1Reset") };
    const void *values[] = { number };
    CFDictionaryRef properties = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(number);
    if (!properties) {
        IOObjectRelease(service);
        fprintf(stderr, "request error: could not create the single-entry request dictionary.\n");
        return 4;
    }

    puts("Sending the single CobaltSurvey,RunMode1Reset=1 request.");
    kern_return_t kr = IORegistryEntrySetCFProperties(service, properties);
    CFRelease(properties);
    printf("IORegistryEntrySetCFProperties: 0x%08x\n", (unsigned int)kr);
    if (kr == KERN_SUCCESS) {
        puts("request accepted by IOKit; this does not itself prove reset recovery.");
    } else {
        puts("request error: IOKit refused the explicit property request.");
    }

    puts("Post-request service properties:");
    print_property(service, "CobaltSurvey,Mode1ResetStatus");
    print_property(service, "CobaltSurvey,Mode1ResetRecoveryObserved");
    print_property(service, "CobaltSurvey,Mode1ResetResetTransitionObserved");
    IOObjectRelease(service);
    return kr == KERN_SUCCESS ? 0 : 5;
}
