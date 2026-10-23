# Independent survey with separately armed transport and one-command KDB tests.
.DEFAULT_GOAL := all
PRODUCT := CobaltNavi44Survey
BUILD ?= build
MKSDK ?= ../../build/ci-deps/MacKernelSDK
SDK := $(shell xcrun --sdk macosx --show-sdk-path)
ARCH := x86_64
DEPLOY := 11.0
CXX := clang++
CC := clang
PYTHON ?= python3
KEXT := $(BUILD)/$(PRODUCT).kext
EXEC := $(KEXT)/Contents/MacOS/$(PRODUCT)
SHARED := ../navi48-bringup/src
PSP_FIRMWARE := $(BUILD)/psp_firmware.generated.cpp
PSP_INPUT := ../navi48-bringup/firmware/psp_14_0_2_sos.bin
OBJS := $(BUILD)/CobaltNavi44Survey.o $(BUILD)/ipdiscovery.o $(BUILD)/psp.o \
  $(BUILD)/psp_firmware.generated.o $(BUILD)/kmod_info.o
COMMON := -arch $(ARCH) -target $(ARCH)-apple-macos$(DEPLOY) -isysroot $(SDK) \
  -I$(MKSDK)/Headers -Isrc -I$(SHARED) -mmacosx-version-min=$(DEPLOY) \
  -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT \
  -D_FORTIFY_SOURCE=0 -nostdinc -fno-builtin -fno-common -fno-stack-protector \
  -mkernel -Wall -Wextra -Werror -Os -g
CXXFLAGS := $(COMMON) -fapple-kext -std=c++17 -fno-exceptions -fno-rtti -fcheck-new -fno-c++-static-destructors
CFLAGS := $(COMMON)
LDFLAGS := -arch $(ARCH) -target $(ARCH)-apple-macos$(DEPLOY) -isysroot $(SDK) \
  -nostdlib -Xlinker -kext -L$(MKSDK)/Library/x86_64 -lkmodc++ -lkmod -Wl,-no_deduplicate

all: $(KEXT)
$(BUILD)/CobaltNavi44Survey.o: src/CobaltNavi44Survey.cpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/ipdiscovery.o: $(SHARED)/ipdiscovery.cpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/psp.o: $(SHARED)/psp.cpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@
$(PSP_FIRMWARE): $(PSP_INPUT) ../../tools/navi44-survey/embed_psp.py
	@mkdir -p $(BUILD)
	$(PYTHON) ../../tools/navi44-survey/embed_psp.py --input $(PSP_INPUT) --output $@
$(BUILD)/psp_firmware.generated.o: $(PSP_FIRMWARE)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/kmod_info.o: src/kmod_info.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@
-include $(OBJS:.o=.d)
$(KEXT): $(OBJS) Info.plist
	@mkdir -p $(KEXT)/Contents/MacOS
	$(CXX) $(LDFLAGS) $(OBJS) -o $(EXEC)
	@bad=$$(nm -u -arch $(ARCH) $(EXEC) | c++filt | grep -E 'CobaltNavi44Survey|IpDiscovery|PspLoader|psp1402Firmware|cobalt::|n48::' || true); \
	  if [ -n "$$bad" ]; then echo "Undefined survey symbols: $$bad"; exit 1; fi
	cp Info.plist $(KEXT)/Contents/Info.plist
	-xattr -d com.apple.FinderInfo $(KEXT) 2>/dev/null
	xattr -cr $(KEXT)
	codesign --force --sign - $(KEXT)
	codesign --verify --strict --verbose=2 $(KEXT)
	@test -f $(KEXT)/Contents/_CodeSignature/CodeResources
	@echo "Built $(KEXT) for $(ARCH), minimum macOS $(DEPLOY)"
clean:
	rm -rf $(BUILD)
.PHONY: all clean
