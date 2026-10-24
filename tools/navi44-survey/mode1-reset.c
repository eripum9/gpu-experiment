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
            "Usage: %s --help | --inspect-peers | --run-mode1-reset\n"
            "\n"
            "  --help               Show this help; does not contact IOKit.\n"
            "  --inspect-peers      Read-only direct provider-child inventory.\n"
            "  --run-mode1-reset    Send the single explicit Mode 1 reset request.\n",
            program);
}

/* Enumerates direct IOServicePlane client children. This is observational and
 * does not prove exclusive ownership or reproduce the kernel's exact check. */
static int inspect_parent_children(io_service_t service) {
    io_service_t parent = IO_OBJECT_NULL;
    kern_return_t kr = IORegistryEntryGetParentEntry(service, kIOServicePlane,
                                                      &parent);
    if (kr != KERN_SUCCESS || parent == IO_OBJECT_NULL) {
        printf("Peer inventory: unable to obtain direct IOServicePlane parent (0x%08x).\n",
               (unsigned int)kr);
        return 1;
    }
    if (!IOObjectConformsTo(parent, "IOPCIDevice")) {
        io_name_t parent_class = {0};
        (void)IOObjectGetClass(parent, parent_class);
        printf("Peer inventory: refusal; direct parent class is %s, not IOPCIDevice.\n",
               parent_class[0] ? parent_class : "<unknown>");
        IOObjectRelease(parent);
        return 1;
    }

    uint64_t parent_id = 0;
    kr = IORegistryEntryGetRegistryEntryID(parent, &parent_id);
    if (kr != KERN_SUCCESS) {
        printf("Peer inventory: unable to read parent registry entry ID (0x%08x).\n",
               (unsigned int)kr);
        IOObjectRelease(parent);
        return 1;
    }
    printf("Direct IOPCIDevice parent ID: 0x%llx\n", (unsigned long long)parent_id);

    io_iterator_t iterator = IO_OBJECT_NULL;
    kr = IORegistryEntryGetChildIterator(parent, kIOServicePlane, &iterator);
    if (kr != KERN_SUCCESS || iterator == IO_OBJECT_NULL) {
        printf("Peer inventory: child iterator unavailable (0x%08x).\n",
               (unsigned int)kr);
        IOObjectRelease(parent);
        return 1;
    }
    IOObjectRelease(parent);
    puts("Direct IOServicePlane children (bounded to 64; observational inventory only):");
    unsigned count = 0, self_count = 0, unexpected_count = 0;
    int metadata_valid = 1, saw_null = 0, limit_reached = 0;
    io_service_t child = IO_OBJECT_NULL;
    while (count < 64) {
        child = IOIteratorNext(iterator);
        if (child == IO_OBJECT_NULL) {
            saw_null = 1;
            break;
        }
        io_name_t class_name = {0}, registry_name = {0};
        uint64_t entry_id = 0;
        kern_return_t class_kr = IOObjectGetClass(child, class_name);
        kern_return_t name_kr = IORegistryEntryGetName(child, registry_name);
        kern_return_t id_kr = IORegistryEntryGetRegistryEntryID(child, &entry_id);
        int is_self = IOObjectIsEqualTo(child, service);
        if (is_self) ++self_count;
        else ++unexpected_count;
        if (class_kr != KERN_SUCCESS || name_kr != KERN_SUCCESS || id_kr != KERN_SUCCESS ||
            !memchr(class_name, '\0', sizeof(class_name)) ||
            !memchr(registry_name, '\0', sizeof(registry_name))) {
            metadata_valid = 0;
            printf("  child[%u]: invalid/incomplete registry metadata (class=0x%08x name=0x%08x id=0x%08x)\n",
                   count, (unsigned int)class_kr, (unsigned int)name_kr, (unsigned int)id_kr);
        } else {
            printf("  child[%u]: class=%s name=%s entryID=0x%llx%s\n", count,
                   class_name, registry_name, (unsigned long long)entry_id,
                   is_self ? " [SELF]" : "");
        }
        ++count;
        IOObjectRelease(child);
    }
    if (count == 64) limit_reached = 1;
    int iterator_valid = IOIteratorIsValid(iterator) ? 1 : 0;
    int exhausted = saw_null && iterator_valid;
    IOObjectRelease(iterator);
    const char *status = !iterator_valid ? "iterator-invalid" :
                         (limit_reached ? "limit-reached" :
                          (!metadata_valid ? "metadata-incomplete" : "complete"));
    printf("Peer inventory metadata: Observed=true IteratorPresent=true IteratorValid=%s MetadataValid=%s Exhausted=%s ClientCount=%u SelfCount=%u UnexpectedCount=%u LimitReached=%s Status=%s\n",
           iterator_valid ? "true" : "false", metadata_valid ? "true" : "false",
           exhausted ? "true" : "false", count, self_count, unexpected_count,
           limit_reached ? "true" : "false", status);
    return iterator_valid && exhausted && metadata_valid && !limit_reached ? 0 : 1;
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
    int inspect_only = argc == 2 && strcmp(argv[1], "--inspect-peers") == 0;
    if (argc != 2 || (!inspect_only && strcmp(argv[1], "--run-mode1-reset") != 0)) {
        usage(stderr, argv[0]);
        fprintf(stderr,
                "refusal: an exact explicit --run-mode1-reset argument is required.\n");
        return 2;
    }

    if (!inspect_only) puts("WARNING: Mode 1 reset may blank the display. Use test-software-reset.sh --run for automatic capture and reboot.");
    if (!inspect_only && geteuid() != 0) {
        fprintf(stderr, "refusal: run this explicit test as root (for example, with sudo).\n");
        return 3;
    }

    io_service_t service = IO_OBJECT_NULL;
    int lookup_result = find_unique_survey_service(&service);
    if (lookup_result != 0) return 10 + lookup_result;

    int inventory_result = inspect_parent_children(service);
    if (inspect_only) {
        IOObjectRelease(service);
        return inventory_result == 0 ? 0 : 5;
    }

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
        puts("driver request returned error; inspect Mode1ResetReason and peer census metadata to diagnose the result.");
    }

    puts("Post-request service properties:");
    print_property(service, "CobaltSurvey,Mode1ResetStatus");
    print_property(service, "CobaltSurvey,Mode1ResetRecoveryObserved");
    print_property(service, "CobaltSurvey,Mode1ResetResetTransitionObserved");
    print_property(service, "CobaltSurvey,Mode1ResetReason");
    print_property(service, "CobaltSurvey,Mode1ResetPhase");
    print_property(service, "CobaltSurvey,Mode1ResetStoresIssued");
    print_property(service, "CobaltSurvey,Mode1ResetPciMutationAttempted");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusObserved");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusIteratorPresent");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusIteratorValid");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusExhausted");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusClientCount");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusSelfCount");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusUnexpectedCount");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusFirstUnexpectedClass");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusFirstUnexpectedClassTruncated");
    print_property(service, "CobaltSurvey,Mode1ResetPeerCensusStatus");
    IOObjectRelease(service);
    return kr == KERN_SUCCESS ? 0 : 5;
}
