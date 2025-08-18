#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

DEVICE="${1:-pacman}"
DEVICE_LOWER=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]')

if [ -n "$2" ]; then
    BOOTLOADER="$2"
else
    BOOTLOADER="bin/${DEVICE_LOWER}.bin"
fi

TOOLCHAIN_URL="https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz"
TOOLCHAIN_ARCHIVE="arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz"
TOOLCHAIN_DIR="arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf"
TOOLCHAIN_PATH="$(pwd)/$TOOLCHAIN_DIR/bin"

if [ ! -d "$TOOLCHAIN_PATH" ]; then
   echo -e "${YELLOW}Downloading toolchain...${NC}"
   
   if command -v wget &> /dev/null; then
       wget -O "$TOOLCHAIN_ARCHIVE" "$TOOLCHAIN_URL"
   elif command -v curl &> /dev/null; then
       curl -L -o "$TOOLCHAIN_ARCHIVE" "$TOOLCHAIN_URL"
   else
       echo -e "${RED}Error: Need wget or curl to download toolchain${NC}"
       exit 1
   fi
   
   echo -e "${YELLOW}Extracting toolchain...${NC}"
   tar -xf "$TOOLCHAIN_ARCHIVE"
   rm -f "$TOOLCHAIN_ARCHIVE"
fi

export PATH="$TOOLCHAIN_PATH:$PATH"

if [ ! -f "$BOOTLOADER" ]; then
   echo -e "${RED}Error: Bootloader file '$BOOTLOADER' not found${NC}"
   exit 1
fi

echo
echo -e "${BOLD}Building for device: ${BLUE}$DEVICE${NC}"
echo -e "${BOLD}Bootloader: ${BLUE}$BOOTLOADER${NC}"
echo

rm -f *.patched
rm -rf payload/build

echo -e "${YELLOW}Building payload...${NC}"
(cd payload && make clean && make DEVICE="$DEVICE" all -j$(nproc))

if [ $? -ne 0 ]; then
   echo -e "${RED}Build failed${NC}"
   exit 1
fi

echo
echo -e "${YELLOW}Injecting payload...${NC}"
./inject.sh "$DEVICE" "$BOOTLOADER"

echo

if [ -f "lk.patched" ]; then
   echo -e "${GREEN}Successfully injected payload into bootloader: ${BLUE}$BOOTLOADER${NC}"
else
    echo -e "${RED}Injection failed or output file not found!${NC}"
    exit 1
fi