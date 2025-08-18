import struct
from typing import Tuple

HDR_SIZE: int = 0x200
MAGIC: int = 0x58881688
BOOTLOADER_BASE: int = 0xFFFF000050F00000 # default base, can be overridden


def encode_bl(src: int, dst: int) -> bytes:
    off: int = (dst - src) >> 2
    return struct.pack('<I', 0x94000000 | (off & 0x3FFFFFF))


def inject_payload(data: bytearray, payload: bytes, target_vaddr: int, 
                   bootloader_base: int = BOOTLOADER_BASE) -> Tuple[bytearray, int]:
    file_offset: int = target_vaddr - bootloader_base + HDR_SIZE

    if file_offset < 0 or file_offset + len(payload) > len(data):
        raise ValueError("Target address 0x%X is outside bootloader bounds" % target_vaddr)

    data[file_offset:file_offset + len(payload)] = payload
    return data, target_vaddr