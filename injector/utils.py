import struct


def encode_bl(src: int, dst: int) -> bytes:
    off: int = (dst - src) >> 2
    return struct.pack('<I', 0x94000000 | (off & 0x3FFFFFF))


def pad_payload(payload: bytes) -> bytes:
    return payload.ljust((len(payload) + 15) & ~15, b'\x00')
