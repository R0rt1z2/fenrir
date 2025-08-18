CC := aarch64-none-elf-gcc
AS := aarch64-none-elf-as
LD := aarch64-none-elf-gcc
OBJCOPY := aarch64-none-elf-objcopy

BUILD_DIR := build
COMMON_DIR := common
DEVICES_DIR := devices
LINKER_SCRIPT := $(COMMON_DIR)/linker.x

CFLAGS := -Os -march=armv9-a -ffreestanding -fno-stack-protector
CFLAGS += -fno-pic -fno-pie -mcmodel=large -I$(COMMON_DIR) -I$(DEVICES_DIR)
ASFLAGS := -march=armv9-a

DEVICE ?= pacman
DEVICE_LOWER := $(shell echo $(DEVICE) | tr '[:upper:]' '[:lower:]')

DEVICE_HEADER := $(DEVICES_DIR)/$(DEVICE_LOWER).h
ifeq ($(wildcard $(DEVICE_HEADER)),)
$(error Device $(DEVICE) not supported. Create $(DEVICE_HEADER) first)
endif

CFLAGS += -DDEVICE_$(DEVICE_LOWER)

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG
endif

debug-flags:
	@echo "DEVICE: $(DEVICE)"
	@echo "DEVICE_LOWER: $(DEVICE_LOWER)"
	@echo "DEVICE_HEADER: $(DEVICE_HEADER)"
	@echo "CFLAGS: $(CFLAGS)"

STAGE1_BASE := $(shell grep "^#define STAGE1_BASE" $(DEVICE_HEADER) | awk '{print $$3}')
STAGE2_BASE := $(shell grep "^#define STAGE2_BASE" $(DEVICE_HEADER) | awk '{print $$3}')
STAGE3_BASE := $(shell grep "^#define STAGE3_BASE" $(DEVICE_HEADER) | awk '{print $$3}')

# ============================================================================
# STAGE DEFINITIONS
# ============================================================================
STAGES := stage1:$(STAGE1_BASE) \
          stage2:$(STAGE2_BASE) \
          stage3:$(STAGE3_BASE)

COMMON_SOURCES := $(wildcard $(COMMON_DIR)/*.c)
STAGE_NAMES := $(foreach stage,$(STAGES),$(word 1,$(subst :, ,$(stage))))
STAGE_TARGETS := $(foreach name,$(STAGE_NAMES),$(name))

get_base = $(word 2,$(subst :, ,$(filter $(1):%,$(STAGES))))

define STAGE_template
$(1)_DIR := $(1)
$(1)_BASE := $(call get_base,$(1))
$(1)_TARGET := $(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/payload
$(1)_SOURCES := $$(wildcard $$($(1)_DIR)/*.c)
$(1)_OBJECTS := $$(patsubst $$($(1)_DIR)/%.c,$$(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/%.o,$$($(1)_SOURCES))
$(1)_COMMON_OBJECTS := $$(patsubst $(COMMON_DIR)/%.c,$$(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/common_%.o,$$(COMMON_SOURCES))
$(1)_ALL_OBJECTS := $$($(1)_OBJECTS) $$($(1)_COMMON_OBJECTS)

.PHONY: $(1)
$(1): $$($(1)_TARGET).bin

$$($(1)_TARGET).bin: $$($(1)_ALL_OBJECTS)
	@mkdir -p $$(@D)
	sed 's/BASE_ADDRESS/$$($(1)_BASE)/g' $(LINKER_SCRIPT) > $$(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/linker_resolved.x
	$(LD) -T $$(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/linker_resolved.x -nostdlib -static -no-pie -o $$($(1)_TARGET).elf $$($(1)_ALL_OBJECTS)
	$(OBJCOPY) -O binary $$($(1)_TARGET).elf $$($(1)_TARGET).bin
	@echo "$(1) payload size: $$$$(wc -c < $$($(1)_TARGET).bin) bytes ($(DEVICE))"

$$(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/%.o: $$($(1)_DIR)/%.c $(DEVICE_HEADER)
	@mkdir -p $$(@D)
	$(CC) $(CFLAGS) -DSTAGE=$(subst stage,,$(1)) -c $$< -o $$@

$$(BUILD_DIR)/$(DEVICE_LOWER)/$(1)/common_%.o: $(COMMON_DIR)/%.c $(DEVICE_HEADER)
	@mkdir -p $$(@D)
	$(CC) $(CFLAGS) -DSTAGE=$(subst stage,,$(1)) -c $$< -o $$@

debug-$(1):
	@echo "$(1) base: $$($(1)_BASE)"
	@echo "$(1) objects: $$($(1)_ALL_OBJECTS)"
endef

$(foreach stage,$(STAGE_NAMES),$(eval $(call STAGE_template,$(stage))))

.PHONY: all clean list-devices list-stages $(STAGE_TARGETS)

all: $(STAGE_TARGETS)

list-devices:
	@echo "Supported devices:"
	@for device in $(DEVICES_DIR)/*.h; do \
		if [ -f "$$device" ]; then \
			basename "$$device" .h | sed 's/^/  /'; \
		fi \
	done

list-stages:
	@echo "Configured stages for device $(DEVICE):"
	@$(foreach stage,$(STAGE_NAMES),echo "  $(stage): $(call get_base,$(stage))";)

device-info:
	@echo "Current device: $(DEVICE)"
	@echo "Device header: $(DEVICE_HEADER)"
	@echo "Stage addresses:"
	@echo "  stage1: $(STAGE1_BASE)"
	@echo "  stage2: $(STAGE2_BASE)"
	@echo "  stage3: $(STAGE3_BASE)"

clean:
	rm -rf $(BUILD_DIR)