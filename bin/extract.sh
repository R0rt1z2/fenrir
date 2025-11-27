#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for bootloader in *.bin
do
    CODENAME="${bootloader%.bin}"
    echo "Processing $CODENAME..."
    python3 -m lkpatcher "$bootloader" -d lk > /dev/null 2>&1
done

for patched in *_lk.bin
do
    mv "$patched" "${patched%.bin}.raw"
done
