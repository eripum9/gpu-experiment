# Independent survey. Optional bounded indexed discovery; no GPU activation objects.
.DEFAULT_GOAL := all
PRODUCT := CobaltNavi44Survey
BUILD ?= build
MKSDK ?= ../../build/ci-deps/MacKernelSDK
SDK := $(shell xcrun --sdk macosx --show-sdk-path)
ARCH := x86_64
DEPLOY := 11.0
CXX := clang++
CC := clang
KEXT := $(BUILD)/$(PRODUCT).kext
EXEC := $(KEXT)/Contents/MacOS/$(PRODUCT)
SHARED := ../navi48-bringup/src
OBJS := $(BUILD)/CobaltNavi44Survey.o $(BUILD)/ipdiscovery.o $(BUILD)/kmod_info.o
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
$(BUILD)/kmod_info.o: src/kmod_info.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@
-include $(OBJS:.o=.d)
$(KEXT): $(OBJS) Info.plist
	@mkdir -p $(KEXT)/Contents/MacOS
	$(CXX) $(LDFLAGS) $(OBJS) -o $(EXEC)
	@bad=$$(nm -u -arch $(ARCH) $(EXEC) | c++filt | grep -E 'CobaltNavi44Survey|IpDiscovery|cobalt::' || true); \
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
