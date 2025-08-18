#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

MAX_WAIT_TIME=60
BOOTLOADER_FILE="${1:-lk.patched}"

if ! command -v fastboot &> /dev/null; then
    echo -e "${RED}Error: fastboot could not be found, please install it first.${NC}"
    exit 1
fi

wait_for_fastboot_device() {
    echo -e "${WHITE}Waiting for device in fastboot mode (timeout: ${MAX_WAIT_TIME}s)...${NC}"
    
    local start_time=$(date +%s)
    local current_time=0
    local elapsed=0
    
    while true; do
        if fastboot devices | grep -q "fastboot"; then
            echo -e "${GREEN}Device detected in fastboot mode!${NC}"
            return 0
        fi
        
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        
        if [ $elapsed -ge $MAX_WAIT_TIME ]; then
            echo -e "${RED}Timeout: No device found after ${MAX_WAIT_TIME} seconds.${NC}"
            return 1
        fi
        
        sleep 1
    done
}

wait_for_fastboot_device || {
    echo -e "${RED}Error: Device not found in fastboot mode. Please connect a device and reboot it into fastboot mode.${NC}"
    exit 1
}

echo -e "${WHITE}Detecting active slot...${NC}"
CURRENT_SLOT=$(fastboot getvar current-slot 2>&1 | grep "current-slot" | awk '{print $2}')

if [[ "$CURRENT_SLOT" == "a" || "$CURRENT_SLOT" == "b" ]]; then
    echo -e "${GREEN}Detected active slot: ${BOLD}${CURRENT_SLOT}${NC}"
    LK_PARTITION="lk_${CURRENT_SLOT}"
    echo -e "${WHITE}Will flash to partition: ${BOLD}${LK_PARTITION}${NC}"
else
    echo -e "${YELLOW}No A/B slot system detected or couldn't determine slot. Using default 'lk' partition.${NC}"
    LK_PARTITION="lk"
fi

# This is mainly done for debugging purposes. Clearing expdb isn't required for the exploit
# to work. This is just to make my life easier when debugging bootloader crashes since MTK
# coded the log store system in such a way that old logs are never overwritten under certain
# conditions.
echo -e "${WHITE}Creating temporary expdb.bin...${NC}"
dd if=/dev/zero of=expdb.bin bs=1M count=1 status=none || {
    echo -e "${RED}Error: Failed to create expdb.bin. Please check your permissions.${NC}"
    exit 1
}

echo -e "${WHITE}Flashing expdb partition...${NC}"
fastboot flash expdb expdb.bin || {
    echo -e "${RED}Error: Failed to flash expdb.bin. Please check the file and try again.${NC}"
    rm -f expdb.bin
    exit 1
}

echo -e "${WHITE}Erasing expdb partition...${NC}"
fastboot erase expdb || {
    echo -e "${RED}Error: Failed to erase expdb partition.${NC}"
    exit 1
}

rm -f expdb.bin || {
    echo -e "${YELLOW}Warning: Failed to remove expdb.bin. Continuing anyway.${NC}"
}

echo -e "${WHITE}Flashing ${BOLD}${BOOTLOADER_FILE}${NC} to ${BOLD}${LK_PARTITION}${NC}..."
if [[ -f "$BOOTLOADER_FILE" ]]; then
    fastboot flash ${LK_PARTITION} ${BOOTLOADER_FILE} || {
        echo -e "${RED}Error: Failed to flash ${BOOTLOADER_FILE} to ${LK_PARTITION}. Please check the file and try again.${NC}"
        exit 1
    }
    echo -e "${GREEN}Successfully flashed ${BOOTLOADER_FILE} to ${BOLD}${LK_PARTITION}${NC}"
else
    echo -e "${RED}Error: ${BOOTLOADER_FILE} file not found.${NC}"
    exit 1
fi

echo -e "${GREEN}All operations completed successfully!${NC}"