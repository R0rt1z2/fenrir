#!/usr/bin/env python3
"""MediaTek DA (Download Agent) binary parser."""

import struct
import sys


def detect_arm_arch(data: bytes, offset: int) -> str:
    """Detect ARM32 or ARM64 from raw binary code (no ELF header).

    Strategy:
    1. (Preferred) Use capstone to disassemble the first 4 instructions
       with both ARM32 and ARM64 decoders; pick the one whose mnemonic
       sequence looks more plausible for a function entry.
    2. (Fallback) Scan the first 4 words for bit-patterns that are
       unambiguous in one architecture but not the other (e.g., ADRP,
       STMFD, conditional branches, SVC/HVC/BRK).
    """
    if offset + 16 > len(data):
        return "Unknown (too small)"

    words = [struct.unpack_from("<I", data, offset + i * 4)[0] for i in range(4)]

    # ── Capstone path ──────────────────────────────────────────────
    try:
        import capstone as _cs

        md32 = _cs.Cs(_cs.CS_ARCH_ARM, _cs.CS_MODE_ARM)
        md64 = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM)

        snippet = data[offset:offset + 16]
        mnemonics32 = [i.mnemonic for i in md32.disasm(snippet, offset)]
        mnemonics64 = [i.mnemonic for i in md64.disasm(snippet, offset)]

        # Score by how "normal" a function entry looks
        arm64_good = {"sub", "add", "stp", "mov", "b", "adrp", "ldr", "mrs"}
        arm32_good = {"b", "bl", "ldr", "mov", "stmfd", "stmdb", "push", "sub", "add"}

        s32 = sum(1 for m in mnemonics32 if m in arm32_good)
        s64 = sum(1 for m in mnemonics64 if m in arm64_good)
        # print(s32)
        # print(s64)
        if s64 > s32:
            return "ARM64"
        if s32 > s64:
            return "ARM32"
        
        # Tie-break: ARM32 conditional branch in first instruction
        w0 = words[0]
        if (w0 & 0x0E000000) == 0x0A000000 and (w0 & 0xF0000000) != 0xF0000000:
            return "ARM32"
        # ARM64 SUB SP pattern
        if (w0 & 0xFF800000) == 0xD1000000:
            return "ARM64"

        return "ARM64" if s64 > 0 else "ARM32"
    except ImportError:
        pass
    print("Fallback to No Capstone Method.Maybe Wrong!")
    # ── Heuristic path (no capstone) ──────────────────────────────
    arm64_score = 0
    arm32_score = 0

    for w in words:
        # --- ARM64-only patterns ---
        # print(hex(w))
        # ADRP: 1xx10000 xxxxxxxxxxxxxxx xxxxx  (Rd = 0x1F XZR = uncommon in ARM32)
        if (w & 0x9F000000) == 0x90000000 and (w & 0x0000001F) == 0x0000001F:
            arm64_score += 3
            continue

        # ADRP with any Rd (very common in ARM64, rare in ARM32 as TEQ/TEQP)
        if (w & 0x9F000000) == 0x90000000:
            arm64_score += 2
            continue

        # SVC / HVC / SMC: 11010100 000 xxxxxxxxx xxx 0000x 1
        if (w & 0xFF000000) == 0xD4000000:
            arm64_score += 3
            continue

        # BRK: 11010100 001 xxxxxxxxx xxx 00000
        if (w & 0xFFE00000) == 0xD4200000:
            arm64_score += 3
            continue

        # ARM64 STP/LDP (pre-index): 101010010x (STP), 101010011x (LDP)
        if (w & 0xFFC00000) in (0xA9800000, 0xA9C00000):
            arm64_score += 2
            continue

        # ARM64 LDR (immediate, unsigned): 1x11100101 xxxxxxxxxxxx xxxxx xxxxx
        if (w & 0xBFBF0000) == 0xB9400000:
            arm64_score += 1
            continue

        # ARM64 ADD/SUB immediate (shifted): 1001000100 or 1101000100
        if (w & 0xFF000000) in (0x91000000, 0xD1000000):
            arm64_score += 2
            continue

        # ARM64 MOV immediate (wide): 100100101x or 110100101x
        if (w & 0xFF800000) in (0x92800000, 0xD2800000):
            arm64_score += 1
            continue

        # --- ARM32-only patterns ---

        # STMFD (pre-indexed, decrement): cond 100 1 S 1101 Rn register_list
        # S=1 is typical for STMFD SP! (STMDB with writeback)
        if (w & 0x0FE00000) == 0x09200000 and (w & 0xF0000000) != 0xF0000000:
            arm32_score += 3
            continue

        # STMDB with writeback: cond 100 1 0 1101 Rn register_list
        if (w & 0x0FE00000) == 0x09000000 and (w & 0xF0000000) != 0xF0000000:
            arm32_score += 3
            continue

        # ARM32 conditional branch: cond 101L offset, L=0 (B) or L=1 (BL)
        if (w & 0x0E000000) == 0x0A000000 and (w & 0xF0000000) != 0xF0000000:
            arm32_score += 2
            continue

        # ARM32 LDR PC-relative: cond 01 I P U 0 W 1 Rn Rd imm12
        # With Rn=PC (R15): common for constant pools
        if (w & 0x0F7F0000) == 0x051F0000 and (w & 0xF0000000) != 0xF0000000:
            arm32_score += 2
            continue

        # ARM32 PUSH/STMDB SP!: cond 100 1 0 1001 1101 register_list
        if (w & 0x0FFF0000) == 0x092D0000 and (w & 0xF0000000) != 0xF0000000:
            arm32_score += 3
            continue

        # ARM32 data processing with immediate (common for function entry)
        if (w & 0x0E000000) == 0x02000000 and (w & 0xF0000000) != 0xF0000000:
            op = (w >> 21) & 0xF
            if op in (0x0, 0x2, 0x3, 0x4, 0xD):  # AND, SUB, RSB, ADD, MOV
                arm32_score += 1
                continue

        # ARM32 unconditional branch (NV condition = unconditional extension)
        if (w & 0xF0000000) == 0xF0000000 and (w & 0x0E000000) == 0x0A000000:
            arm32_score += 1
            continue
    # print(arm64_score)
    # print(arm32_score)
    if arm64_score > arm32_score:
        return "ARM64"
    if arm32_score > arm64_score:
        return "ARM32"

    # Last resort: if most words have "always" condition (0xE), likely ARM32
    always_cond = sum(1 for w in words if (w & 0xF0000000) == 0xE0000000)
    return "ARM32" if always_cond >= 3 else "ARM64"


def parse_da(filepath: str) -> None:
    with open(filepath, "rb") as f:
        data = f.read()

    # --- Version and build time at 0x20 (32 bytes) ---
    ver_raw = data[0x20:0x20 + 32]
    ver_str = ver_raw.split(b"\x00")[0].decode("ascii", errors="replace")

    if "V6" in ver_str.upper():
        version = "V6"
    elif "V5" in ver_str.upper():
        version = "V5"
    else:
        version = "Unknown"

    print(f"DA Version      : {version}")
    print(f"Version String  : {ver_str}")

    # Extract build time from version string (format: MTK_DA_v6_2025-08-15 02:19:59)
    parts = ver_str.split("_", 3)
    build_time = parts[3] if len(parts) >= 4 else (parts[2] if len(parts) >= 3 else ver_str)
    print(f"Build Time      : {build_time}")

    # --- DA count at 0x68 (4 bytes, little-endian) ---
    da_count = struct.unpack_from("<I", data, 0x68)[0]
    print(f"DA Count        : {da_count}")

    # --- Parts count for the first DA ---
    # 18 bytes after 0x68, then 2 bytes LE - 1 = number of parts
    parts_offset = 0x68 + 22
    parts_count = struct.unpack_from("<H", data, parts_offset)[0] - 1
    print(f"DA Parts Count  : {parts_count}")

    # --- Part entries start after another 20 bytes ---
    entries_start = parts_offset + 22
    print(f"\n{'='*60}")
    print(f"DA Part Details:")
    print(f"{'='*60}")

    for i in range(parts_count):
        entry_off = entries_start + i * 20
        part_offset = struct.unpack_from("<I", data, entry_off)[0]
        part_size = struct.unpack_from("<I", data, entry_off + 4)[0]
        part_load_addr = struct.unpack_from("<I", data, entry_off + 8)[0]

        arch = detect_arm_arch(data, part_offset)

        print(f"\n  DA{i+1}:")
        print(f"    Offset     : 0x{part_offset:08X}")
        print(f"    Size       : 0x{part_size:08X}")
        print(f"    Load Addr  : 0x{part_load_addr:08X}")
        print(f"    Arch       : {arch}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <da_file>")
        sys.exit(1)
    parse_da(sys.argv[1])


if __name__ == "__main__":
    main()
