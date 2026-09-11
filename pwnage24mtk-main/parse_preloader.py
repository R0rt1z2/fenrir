
"""
MTK Preloader Image Parser
----------------------------
Parse MTK preloader image, extract and display key header information,
support ARM64/ARM32 detection and policy_part_map table parsing.

Supports two image formats:
1. Image with magic string: "EMMC_BOOT" or "UFS_BOOT" (magic at header offset 0x1000)
2. Image starting directly with preloader header

Address space notes:
  load_addr      : Preloader load address (read directly from header at 0x1C)
  ida_offset     : IDA offset (read from header at 0x30)
  ida_load_addr  : Data block load address = load_addr + ida_offset
  → All pointers in data block point to address space with ida_load_addr as base

Preloader header fields (little-endian):
  0x1C - 0x20: Preloader load address
  0x20 - 0x24: Preloader size (including header)
  0x28 - 0x2C: Header size
  0x30 - 0x34: IDA offset (preloader load address + this value = IDA load address)

Architecture detection:
  Determine ARM64 or ARM32 by analyzing preloader entry point instructions

policy_part_map parsing:
  1. Search for "default\x00" string in preloader data block
  2. Determine "default\x00" address based on architecture (in ida_load_addr address space)
  3. ARM64: address - 8 = pointer location in policy_part_map pointing to "default\0"
  4. ARM32: address - 4 = pointer location in policy_part_map pointing to "default\0"
  5. Read pointer value at that location (8 bytes ARM64 / 4 bytes ARM32),
     this value is the policy_part_map start address
  6. Parse each entry in struct format until all part_name are empty
"""

import sys
import struct
import os


# ═══════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════

MAGIC_EMMC_BOOT = b"EMMC_BOOT"
MAGIC_UFS_BOOT = b"UFS_BOOT"
MAGIC_COMBO_BOOT=b"COMBO_BOOT"
HEADER_OFFSET_WITH_MAGIC = 0x1000

# Header field offsets
HDR_OFFSET_LOAD_ADDR = 0x1C
HDR_OFFSET_SIZE = 0x20
HDR_OFFSET_HDR_SIZE = 0x28
HDR_OFFSET_IDA_OFFSET = 0x30

# Structure sizes
ARM64_ENTRY_SIZE = 0x38
ARM32_ENTRY_SIZE = 0x1C


# ═══════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════

def read_u32(data, offset):
    """Read 4-byte unsigned integer from little-endian"""
    return struct.unpack_from("<I", data, offset)[0]


def read_u64(data, offset):
    """Read 8-byte unsigned integer from little-endian"""
    return struct.unpack_from("<Q", data, offset)[0]


def read_address(data, offset, is_arm64):
    """Read address according to architecture (ARM64=8 bytes, ARM32=4 bytes)"""
    if is_arm64:
        return read_u64(data, offset)
    return read_u32(data, offset)


def addr_to_file_offset(mem_addr, data_block_load_addr, data_block_file_start):
    """
    Convert a data block memory address to a file offset.
    
    All pointers in the data block are within the ida_load_addr address space.
    Data block memory address = data_block_load_addr + relative offset
    File offset                = data_block_file_start + relative offset
                               = data_block_file_start + (mem_addr - data_block_load_addr)
    
    Args:
        mem_addr:              Memory address within the data block (in ida_load_addr address space)
        data_block_load_addr:  Data block load address (= load_addr + ida_offset, i.e., IDA load address)
        data_block_file_start: Starting file offset of the data block
    """
    if mem_addr < data_block_load_addr:
        return None
    data_offset = mem_addr - data_block_load_addr
    return data_block_file_start + data_offset


def extract_string(data, addr, data_block_load_addr, data_block_file_start, max_len=128):
    """
    Extract a null-terminated string from raw data given a data block memory address.
    Returns (string, success)
    
    addr must be in the data_block_load_addr address space.
    """
    file_offset = addr_to_file_offset(addr, data_block_load_addr, data_block_file_start)
    if file_offset is None or file_offset >= len(data):
        return None, False
    
    end = min(file_offset + max_len, len(data))
    chunk = data[file_offset:end]
    null_pos = chunk.find(b'\x00')
    if null_pos == -1:
        return chunk.decode('ascii', errors='replace'), True
    return chunk[:null_pos].decode('ascii', errors='replace'), True


# ═══════════════════════════════════════════════
# Image type detection
# ═══════════════════════════════════════════════

def detect_image_type(data):
    """
    Detect image type.
    Returns (image_type, header_offset, header_data)
    image_type: "EMMC_BOOT", "UFS_BOOT", or "DIRECT"
    """
    # if len(data) < 0x1000 + len(MAGIC_EMMC_BOOT):
    #     return "DIRECT", 0, data

    magic_check = data[0x0:len(MAGIC_COMBO_BOOT)]
    # print(magic_check)
    if  MAGIC_EMMC_BOOT in magic_check:
        return "EMMC_BOOT", HEADER_OFFSET_WITH_MAGIC, data[HEADER_OFFSET_WITH_MAGIC:]
    elif MAGIC_UFS_BOOT in magic_check:
        return "UFS_BOOT", HEADER_OFFSET_WITH_MAGIC, data[HEADER_OFFSET_WITH_MAGIC:]
    elif MAGIC_COMBO_BOOT in magic_check:
        return "COMBO_BOOT", HEADER_OFFSET_WITH_MAGIC, data[HEADER_OFFSET_WITH_MAGIC:]
    else:
        return "DIRECT", 0, data


# ═══════════════════════════════════════════════
# Architecture detection (ARM64 vs ARM32)
# ═══════════════════════════════════════════════

def detect_architecture(data_section):
    """
    Detect ARM64 or ARM32 by analyzing the first instruction at the preloader entry point.

    Both ARM64 and ARM32 preloader entry points typically start with `b resethandler`,
    but the encoding differs:
      - ARM64 `B` : 0b0_001010_imm26  → first byte 0x14
      - ARM32 `B` : 0b1110_1010_imm24 → first byte 0xEA
      - Thumb `B` : 0b11100_imm8      → first byte 0xE0

    Detection priority:
      1. ARM32 `B` / Thumb `B` (0xEA / 0xE0) — most common ARM32 entry
      2. ARM64 `B` / `BL` (0x14 / 0x94) — most common ARM64 entry
      3. ARM64 `NOP` / system (0xD5 / 0xD6)
      4. GFH jump_offset heuristic
      5. Default: ARM32
    """
    if len(data_section) < 4:
        return False  # data too short, default to ARM32

    first_instr = struct.unpack_from("<I", data_section, 0)[0]
    first_byte = first_instr & 0xFF

    # --- ARM32 detection (higher priority: ARM32 `B` is very distinctive) ---
    if first_byte == 0xEA:  # ARM `B` (unconditional branch): 0b1110_1010_imm24
        return False
    if first_byte == 0xE0:  # Thumb `B` (unconditional branch): 0b11100_imm8
        return False

    # --- ARM64 detection ---
    # ARM64 `B`/`BL` instruction: bits [31:26] = 0b0_00101 (B) or 0b1_00101 (BL)
    # Mask 0xFC000000 isolates bits [31:26], result 0x14000000 matches both B and BL
    if (first_instr & 0xFC000000) == 0x14000000:  # ARM64 `B` or `BL`
        return True
    if first_byte == 0xD5:  # ARM64 system instruction (NOP = 0xD503201F)
        return True 
    if first_byte == 0xD6:  # ARM64 system instruction (RET = 0xD65F03C0)
        return True

    return True  # default ARM64


# ═══════════════════════════════════════════════
# Preloader header parsing
# ═══════════════════════════════════════════════

def parse_preloader_header(header_data, image_type, header_offset):
    """
    Parse the preloader header.
    Returns a dict with parsed values, or None on failure.
    
    Return value description:
        load_addr:      Preloader load address (read directly from header at 0x1C)
        ida_offset:     IDA offset (read from header at 0x30)
        ida_load_addr:  Data block load address = load_addr + ida_offset
                        (all data block pointers reference this address space)
    """
    if len(header_data) < 0x34:
        print(f"Error: header data too short ({len(header_data)} bytes), need at least {0x34} bytes")
        return None

    load_addr = read_u32(header_data, HDR_OFFSET_LOAD_ADDR)
    preloader_size = read_u32(header_data, HDR_OFFSET_SIZE)
    hdr_size = read_u32(header_data, HDR_OFFSET_HDR_SIZE)
    ida_offset = read_u32(header_data, HDR_OFFSET_IDA_OFFSET)

    data_size = preloader_size - hdr_size  # actual data block size
    ida_load_addr = load_addr + ida_offset  # data block load address (IDA load address)

    # Print results
    print("=" * 60)
    print("  MTK Preloader Image Analysis")
    print("=" * 60)
    print()

    print(f"Image Type        : {image_type}")
    print(f"Header Offset     : 0x{header_offset:X}")
    print()

    print("-" * 60)
    print("  Preloader Header Fields")
    print("-" * 60)
    print(f"Load Address      : 0x{load_addr:08X}  (offset 0x{HDR_OFFSET_LOAD_ADDR:X} - 0x{HDR_OFFSET_LOAD_ADDR + 4:X})")
    print(f"Preloader Size    : 0x{preloader_size:X} ({preloader_size} bytes)  (offset 0x{HDR_OFFSET_SIZE:X} - 0x{HDR_OFFSET_SIZE + 4:X})")
    print(f"Header Size       : 0x{hdr_size:X} ({hdr_size} bytes)  (offset 0x{HDR_OFFSET_HDR_SIZE:X} - 0x{HDR_OFFSET_HDR_SIZE + 4:X})")
    print(f"IDA Offset        : 0x{ida_offset:08X}  (offset 0x{HDR_OFFSET_IDA_OFFSET:X} - 0x{HDR_OFFSET_IDA_OFFSET + 4:X})")
    print()

    print("-" * 60)
    print("  Computed Values")
    print("-" * 60)
    print(f"Data Block Size   : 0x{data_size:X} ({data_size} bytes)  [Preloader Size - Header Size]")
    print(f"IDA Load Address  : 0x{ida_load_addr:08X}  [Preloader Load Address + IDA Offset]")
    print(f"                  :  (0x{load_addr:08X} + 0x{ida_offset:08X})")
    print()

    data_block_file_offset = header_offset + hdr_size

    print("-" * 60)
    print("  Block Offsets in Image")
    print("-" * 60)
    print(f"Header File Offset: 0x{header_offset:X}")
    print(f"Data Block File Offset: 0x{data_block_file_offset:X}")
    print()
    print("=" * 60)

    return {
        'load_addr': load_addr,
        'preloader_size': preloader_size,
        'hdr_size': hdr_size,
        'ida_offset': ida_offset,
        'ida_load_addr': ida_load_addr,  # data block load address (all data block pointers in this address space)
    }


# ═══════════════════════════════════════════════
# "default\0" string search
# ═══════════════════════════════════════════════

def find_default_string(data_section, raw_data, data_block_file_start):
    """
    Search for the "default\0" string in the data section.
    Returns its file offset in the raw data, or None if not found.
    """
    target = b'default\x00'
    idx = data_section.find(target)
    if idx == -1:
        return None
    
    file_offset = data_block_file_start + idx

    if file_offset >= len(raw_data):
        return None

    return file_offset


# ═══════════════════════════════════════════════
# policy_part_map parsing
# ═══════════════════════════════════════════════

def resolve_policy_part_map(raw_data, data_block_load_addr,
                            default_file_offset, data_block_file_start,
                            data_block_file_end, is_arm64):
    """
    Parse the policy_part_map based on the location of "default\0".
    
    Key: all addresses are in the data_block_load_addr (IDA load address) address space.
    
    Process:
      1. Compute the data block relative offset of "default\0"
      2. Compute the memory address of "default\0" (in data_block_load_addr address space)
      3. Search for this address value itself in the preloader image
      4. After finding its location in the file, go back ptr_size (4/8) bytes;
         that location holds the policy_part_map memory address
      5. Convert policy_part_map memory address to a file offset
      6. Start parsing entries
    
    Args:
        raw_data:             Raw file data
        data_block_load_addr: Data block load address (= load_addr + ida_offset, IDA load address)
                              All data block pointers are in this address space
        default_file_offset:  File offset of "default\0"
        data_block_file_start:Start file offset of the data block
        data_block_file_end:  End file offset of the data block
        is_arm64:             Whether it's ARM64
    
    Returns list of parsed entries, empty list on failure.
    """
    ptr_size = 8 if is_arm64 else 4

    # Calculate the data segment offset of "default\0"
    default_data_offset = default_file_offset - data_block_file_start

    # Memory address of "default\0" (in data_block_load_addr address space)
    default_mem_addr = data_block_load_addr + default_data_offset

    # Core logic: search for the default_mem_addr address value as data in the file.
    # Once found, the preceding ptr_size (4/8) bytes hold the policy_part_map structure's file start.
    default_mem_addr_bytes = struct.pack('<Q' if is_arm64 else '<I', default_mem_addr)

    # Search for this address value in the preloader image
    mem_addr_found_in_file = raw_data.find(default_mem_addr_bytes)

    if mem_addr_found_in_file == -1:
        print(f"Error: address value 0x{default_mem_addr:08X} not found in preloader image")
        print(f"  Searched bytes   : {ptr_size}")
        print(f"  Address bytes (little-endian): {default_mem_addr_bytes.hex()}")
        return []

    # Directly obtain the policy_part_map structure's file start (file offset)
    pmap_file_offset = mem_addr_found_in_file - ptr_size

    # Check if the position is within a reasonable range
    if pmap_file_offset < 0 or pmap_file_offset + ARM64_ENTRY_SIZE > len(raw_data):
        print(f"Error: policy_part_map position out of file range")
        print(f"  Address value file position: 0x{mem_addr_found_in_file:X}")
        print(f"  pmap start position : 0x{pmap_file_offset:X}")
        return []

    print("-" * 60)
    print("  Policy Part Map Analysis")
    print("-" * 60)
    print()
    print(f"Address Space     : All pointers in data block use "
          f"IDA Load Address 0x{data_block_load_addr:08X} as base")
    print()
    print(f"'default\\0' String Analysis:")
    print(f"  File Offset      : 0x{default_file_offset:X}")
    print(f"  Data Offset      : 0x{default_data_offset:X}")
    print(f"  Memory Address   : 0x{default_mem_addr:08X} "
          f"(data_block_load_addr + 0x{default_data_offset:X})")
    print()
    print(f"'default_mem_addr' Found in Image:")
    print(f"  File Offset      : 0x{mem_addr_found_in_file:X}")
    print(f"  Searched Bytes   : {default_mem_addr_bytes.hex()}")
    print()
    print(f"Policy Part Map:")
    print(f"  File Offset      : 0x{pmap_file_offset:X}")
    print(f"  Entry Size       : 0x{ARM64_ENTRY_SIZE if is_arm64 else ARM32_ENTRY_SIZE:X} "
          f"bytes ({ARM64_ENTRY_SIZE if is_arm64 else ARM32_ENTRY_SIZE} bytes)")
    print()

    # Parse entries
    offset = pmap_file_offset
    entry_index = 0
    entry_size = ARM64_ENTRY_SIZE if is_arm64 else ARM32_ENTRY_SIZE
    parsed_entries=[]
    while offset + entry_size <= len(raw_data):
        entry_file = offset

        # Read fields according to architecture
        if is_arm64:
            sw_id = read_u32(raw_data, entry_file)
            part_name1_addr = read_u64(raw_data, entry_file + 8)
            part_name2_addr = read_u64(raw_data, entry_file + 16)
            part_name3_addr = read_u64(raw_data, entry_file + 24)
            part_name4_addr = read_u64(raw_data, entry_file + 32)
            sec_sbcdis_lock = raw_data[entry_file + 40]
            sec_sbcdis_unlock = raw_data[entry_file + 41]
            sec_sbcen_lock = raw_data[entry_file + 42]
            sec_sbcen_unlock = raw_data[entry_file + 43]
            hash_addr = read_u64(raw_data, entry_file + 48)

        else:
            sw_id = read_u32(raw_data, entry_file)
            part_name1_addr = read_u32(raw_data, entry_file + 4)
            part_name2_addr = read_u32(raw_data, entry_file + 8)
            part_name3_addr = read_u32(raw_data, entry_file + 12)
            part_name4_addr = read_u32(raw_data, entry_file + 16)
            sec_sbcdis_lock = raw_data[entry_file + 20]
            sec_sbcdis_unlock = raw_data[entry_file + 21]
            sec_sbcen_lock = raw_data[entry_file + 22]
            sec_sbcen_unlock = raw_data[entry_file + 23]
            hash_addr = read_u32(raw_data, entry_file + 24)

        # Termination condition: all part_name pointers are 0
        if (part_name1_addr == 0 and part_name2_addr == 0 and
                part_name3_addr == 0 and part_name4_addr == 0):
            break
        
        # Extract part_name strings
        # part_name addresses are in the data_block_load_addr address space
        def get_part_name(addr):
            if addr == 0:
                return None,None
            return extract_string(raw_data, addr, data_block_load_addr, data_block_file_start)

        name1, ok1 = get_part_name(part_name1_addr)
        

        if(name1 is not None and "NULL" in name1):
            break
        # print(part_name2_addr)
        name2, ok2 = get_part_name(part_name2_addr)
        name3, ok3 = get_part_name(part_name3_addr)
        name4, ok4 = get_part_name(part_name4_addr)
        
        entry = {
            'sw_id': sw_id,
            'name1': name1, 'addr1': part_name1_addr, 'ok1': ok1,
            'name2': name2, 'addr2': part_name2_addr, 'ok2': ok2,
            'name3': name3, 'addr3': part_name3_addr, 'ok3': ok3,
            'name4': name4, 'addr4': part_name4_addr, 'ok4': ok4,
            'sec_sbcdis_lock': sec_sbcdis_lock,
            'sec_sbcdis_unlock': sec_sbcdis_unlock,
            'sec_sbcen_lock': sec_sbcen_lock,
            'sec_sbcen_unlock': sec_sbcen_unlock,
            'hash': hash_addr,
        }
        parsed_entries.append(entry)

        offset += entry_size
        entry_index += 1

    return parsed_entries


def print_policy_entries(entries, is_arm64):
    """Formatted print of policy_part_map entries"""
    if not entries:
        print("  No policy_part_map entries found")
        print()
        return

    print("-" * 60)
    print("  Policy Part Map Entries")
    print("-" * 60)
    print()

    header = (f"  {'#':<4} | {'SW ID':<10} | {'part_name1':<24} | "
              f"{'part_name2':<24} | {'part_name3':<24} | {'part_name4':<24} | "
              f"{'sec_sbcdis_lock':<16} | {'sec_sbcdis_unlock':<18} | "
              f"{'sec_sbcen_lock':<15} | {'sec_sbcen_unlock':<17}")
    sep = (f"  {'---':<4}-|-{'---':<10}-|-{'---':<24}-|-{'---':<24}-|"
           f"{'---':<24}-|-{'---':<24}-|-{'---':<16}-|-{'---':<18}-|"
           f"{'---':<15}-|-{'---':<17}")

    print(header)
    print(sep)

    for i, entry in enumerate(entries):
        def fmt(name, addr, ok):
            if name is not None:
                return name
            elif addr == 0:
                return "(null)"
            else:
                return f"(0x{addr:08X})"

        n1 = fmt(entry['name1'], entry['addr1'], entry['ok1'])
        n2 = fmt(entry['name2'], entry['addr2'], entry['ok2'])
        n3 = fmt(entry['name3'], entry['addr3'], entry['ok3'])
        n4 = fmt(entry['name4'], entry['addr4'], entry['ok4'])

        sbl =  entry['sec_sbcdis_lock'] 
        sbu =  entry['sec_sbcdis_unlock'] 
        sel =   entry['sec_sbcen_lock'] 
        seu =   entry['sec_sbcen_unlock'] 

        print(f"  {i:<4} | {entry['sw_id']:<10} | {n1:<24} | "
              f"{n2:<24} | {n3:<24} | {n4:<24} | {sbl:<16} | "
              f"{sbu:<18} | {sel:<15} | {seu:<17}")

    print("-" * 60)
    print(f"  Total entries: {len(entries)}")
    print()


# ═══════════════════════════════════════════════
# res_mem_info parsing (ARM64)
# ═══════════════════════════════════════════════

RES_MEM_INFO_STRUCT_SIZE = 0x28


def find_res_mem_info(data_block, data_block_load_addr,
                      data_block_file_start, raw_data, is_arm64):
    """
    Locate the res_mem_info structure array by searching for the "BL33-reserved\0"
    string pointer within the data block.

    Algorithm:
      1. Find "BL33-reserved\0" string in the data block
      2. Calculate its memory address: data_block_load_addr + offset_in_data_block
      3. Convert the address to a byte stream (little-endian, 8 bytes for ARM64)
      4. Search for that byte stream in the data block — this finds the location
         where a res_mem_info entry's name pointer points to "BL33-reserved"
      5. From that hit, search backward to find the start of the res_mem_info array
         and forward to find the end
      6. Return (array_file_offset, count) or (None, 0) on failure

    Args:
        data_block:            The data block bytes
        data_block_load_addr:  Data block load address (IDA load address)
        data_block_file_start: Start file offset of the data block
        raw_data:              Full raw file data
        is_arm64:              Whether it's ARM64

    Returns:
        (array_file_offset, entry_count) or (None, 0)
    """
    if not is_arm64:
        return None, 0

    # Step 1: Find "BL33-reserved\0" in the data block
    target_str = b'BL33-reserved\x00'
    str_idx = data_block.find(target_str)
    if str_idx == -1:
        return None, 0

    # Step 2: Calculate the memory address of the string
    str_mem_addr = data_block_load_addr + str_idx

    # Step 3: Convert address to byte stream (little-endian, 8 bytes for ARM64)
    addr_bytes = struct.pack('<Q', str_mem_addr)

    # Step 4: Search for the address byte stream in the data block
    # This finds where a res_mem_info entry stores its name pointer to "BL33-reserved"
    # Start searching from the beginning of the data block up to the string location
    search_end = str_idx  # no need to search past the string itself
    ptr_idx = data_block.find(addr_bytes, 0, search_end)

    if ptr_idx == -1:
        # Try searching in the full data block in case the pointer is after the string
        ptr_idx = data_block.find(addr_bytes)
        if ptr_idx == -1:
            return None, 0

    # ptr_idx is within the data block, at the "name" field of some res_mem_info entry.
    # The name field is at offset 0 within each 0x28-byte entry.
    # So the entry start = ptr_idx (aligned to struct boundary — name is the first field).

    # Step 5: Search backward to find the start of the res_mem_info array.
    # Walk back in 0x28-byte steps. At each position, check if the name pointer
    # resolves to a valid string. Keep going until we find an invalid one.
    entry_size = RES_MEM_INFO_STRUCT_SIZE

    # The hit is at some entry — we know it's valid (it points to "BL33-reserved").
    # Walk backward from the hit to find the first entry.
    array_start = ptr_idx  # relative to data block

    probe = ptr_idx - entry_size
    while probe >= 0:
        probe_file = data_block_file_start + probe
        if probe_file + 8 > len(raw_data):
            break
        name_ptr = read_u64(raw_data, probe_file)
        name_str, name_ok = extract_string(
            raw_data, name_ptr, data_block_load_addr, data_block_file_start, max_len=64)
        if not name_ok or name_str is None or name_str == "":
            break
        array_start = probe
        probe -= entry_size

    # Step 6: Search forward from the hit to find the end of the array.
    # Walk forward in 0x28-byte steps. At each position, check if the name pointer
    # resolves to a valid string. Stop at the first invalid entry.
    probe = array_start
    count = 0
    while probe + entry_size <= len(data_block):
        probe_file = data_block_file_start + probe
        if probe_file + 8 > len(raw_data):
            break
        name_ptr = read_u64(raw_data, probe_file)
        name_str, name_ok = extract_string(
            raw_data, name_ptr, data_block_load_addr, data_block_file_start, max_len=64)
        if not name_ok or name_str is None or name_str == "":
            break
        count += 1
        probe += entry_size

    if count == 0:
        return None, 0

    array_file_offset = data_block_file_start + array_start
    return array_file_offset, count


def parse_res_mem_info(raw_data, data_block_load_addr,
                       data_block_file_start, data_block_file_end,
                       is_arm64):
    """
    Parse the res_mem_info structure array.
    Valid only for ARM64.

    Uses the "BL33-reserved\0" string pointer search method to locate the array,
    then parses entries of size 0x28 bytes each:
      - name:     8 bytes (char*, address in ida_load_addr address space)
      - start:    8 bytes (unsigned __int64)
      - size:     8 bytes (unsigned __int64)
      - align:    8 bytes (unsigned __int64)
      - mapping:  4 bytes (unsigned int)
      - padding:  4 bytes
    """
    if not is_arm64:
        print("Info: res_mem_info is only parsed for ARM64")
        return

    data_block = raw_data[data_block_file_start:data_block_file_end]

    array_file_offset, entry_count = find_res_mem_info(
        data_block, data_block_load_addr,
        data_block_file_start, raw_data, is_arm64
    )

    if array_file_offset is None:
        print("Info: res_mem_info not found (BL33-reserved string or pointer not found)")
        print()
        return

    # Print header information
    print("-" * 60)
    print("  res_mem_info (Memory Region Information)")
    print("-" * 60)
    print()
    print(f"  Found via        : BL33-reserved string pointer search")
    print(f"  Array Offset     : 0x{array_file_offset:X}")
    print(f"  Entry Count      : {entry_count}")
    print()

    # Table header
    header = (f"  {'#':<4} | {'name':<20} | {'start':<16} | "
              f"{'size':<16} | {'align':<16} | {'mapping':<8}")
    sep = (f"  {'---':<4}-|-{'---':<20}-|-{'---':<16}-|"
           f"{'---':<16}-|-{'---':<16}-|-{'---':<8}")
    print(header)
    print(sep)

    entries = []
    offset = array_file_offset

    for _ in range(entry_count):
        if offset + RES_MEM_INFO_STRUCT_SIZE > data_block_file_end:
            break

        # Read name pointer (8 bytes)
        name_ptr = read_u64(raw_data, offset)

        # Try to resolve the name string from the pointer
        name_str, name_ok = extract_string(
            raw_data, name_ptr, data_block_load_addr, data_block_file_start, max_len=64)

        if not name_ok or name_str is None or name_str == "":
            break

        # Read other fields
        start = read_u64(raw_data, offset + 0x08)
        size = read_u64(raw_data, offset + 0x10)
        align = read_u64(raw_data, offset + 0x18)
        mapping = read_u32(raw_data, offset + 0x20)

        entries.append({
            'name': name_str,
            'start': start,
            'size': size,
            'align': align,
            'mapping': mapping,
        })

        offset += RES_MEM_INFO_STRUCT_SIZE

    # Print entries
    for i, entry in enumerate(entries):
        print(f"  {i:<4} | {entry['name']:<20} | "
              f"0x{entry['start']:016X} | 0x{entry['size']:016X} | "
              f"0x{entry['align']:016X} | 0x{entry['mapping']:08X}")

    print(sep)
    if entries:
        print(f"  Total entries: {len(entries)}")
    else:
        print("  No valid res_mem_info entries found")
    print()

    # Extract key address information
    bl2_ext_addr = None
    lk_addr = None
    for entry in entries:
        if entry['name'] == 'system_bl2-ext':
            bl2_ext_addr = entry['start'] + 0xFFFF000000000000
        elif entry['name'] == 'BL33-reserved':
            lk_addr = entry['start'] + 0xFFFF000000000000

    if bl2_ext_addr or lk_addr:
        print("-" * 60)
        print("  Derived Load Addresses")
        print("-" * 60)
        print()
        if bl2_ext_addr:
            print(f"  BL2_EXT Load Address (from system_bl2-ext): 0x{bl2_ext_addr:016X}")
        if lk_addr:
            print(f"  LK   Load Address (from BL33-reserved    ): 0x{lk_addr:016X}")
        print()


# ═══════════════════════════════════════════════
# Main function
# ═══════════════════════════════════════════════

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <preloader_image>")
        print()
        print("Parse MTK preloader image and display header information.")
        print("Supports ARM64/ARM32 architecture detection and policy_part_map parsing.")
        sys.exit(1)

    image_path = sys.argv[1]

    if not os.path.isfile(image_path):
        print(f"Error: file not found: {image_path}")
        sys.exit(1)

    file_size = os.path.getsize(image_path)
    if file_size == 0:
        print("Error: file is empty")
        sys.exit(1)

    print(f"Loading image: {image_path}")
    print(f"File size     : 0x{file_size:X} ({file_size} bytes)")
    print()

    with open(image_path, "rb") as f:
        data = f.read()

    # 1. Detect image type
    image_type, header_offset, header_data = detect_image_type(data)

    # 2. Parse preloader header
    hdr_info = parse_preloader_header(header_data, image_type, header_offset)
    if hdr_info is None:
        sys.exit(1)

    load_addr = hdr_info['load_addr']
    preloader_size = hdr_info['preloader_size']
    hdr_size = hdr_info['hdr_size']
    ida_offset = hdr_info['ida_offset']
    ida_load_addr = hdr_info['ida_load_addr']  # data block load address

    print(f"Preloader Load Addr  : 0x{load_addr:08X}  (from header)")
    print(f"Data Block Load Addr : 0x{ida_load_addr:08X}  (IDA Load Address)")
    print()

    # 3. Calculate data block range
    data_block_file_start = header_offset + hdr_size
    data_block_size = preloader_size - hdr_size
    data_block_file_end = data_block_file_start + data_block_size

    if data_block_file_end > len(data):
        print(f"Error: data block exceeds file range")
        print(f"  Data block end: 0x{data_block_file_end:X}")
        print(f"  File size     : 0x{len(data):X}")
        sys.exit(1)

    # Extract data section
    data_section = data[data_block_file_start:data_block_file_end]

    # 4. Detect architecture
    is_arm64 = detect_architecture(data_section)

    print("Architecture    : ARM64 (64-bit)" if is_arm64 else "Architecture    : ARM32 (32-bit)")
    print()

    # 5. Search for "default\0" string
    default_file_offset = find_default_string(data_section, data, data_block_file_start)
    # print(hex(default_file_offset))
    if default_file_offset is None:
        print("Info: 'default\\0' string not found")
        print("      Skipping policy_part_map parsing")
        print()
    else:
        # 6. Parse policy_part_map
        # Key: pass ida_load_addr as data_block_load_addr
        # All pointers in the data block are in the ida_load_addr address space
        parsed_entries = resolve_policy_part_map(
            data, ida_load_addr,       # ← data block load address (IDA load address)
            default_file_offset,
            data_block_file_start,
            data_block_file_end,
            is_arm64
        )

        # 7. Print parsed results
        print_policy_entries(parsed_entries, is_arm64)

    # 8. Parse res_mem_info (ARM64 only)
    # Uses "BL33-reserved\0" string pointer search to locate the structure
    parse_res_mem_info(
        data, ida_load_addr,
        data_block_file_start,
        data_block_file_end,
        is_arm64
    )

    print("=" * 60)
    print("  Analysis Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
'''
就是解析oem命令
试图解析LK  BL2_EXT加载地址
解析bl2_ext的安全策略

荣耀lk修补
bl2_ext修补 关闭lk验证

rominfo搜索漏洞 好东西...但是只有oppo
oppo宽容
'''
