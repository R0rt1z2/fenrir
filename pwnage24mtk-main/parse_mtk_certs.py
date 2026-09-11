#!/usr/bin/env python3
"""
Parse MediaTek MKIMG containing CERT1/CERT2, extract ASN.1 blobs and print
each ASN.1 DER TLV entry with its absolute offset (hex) in the source image.

Usage: python parse_mtk_certs.py <image_file>

This implementation does not call external `openssl` and parses DER TLV in pure Python.
"""
import sys
import struct
import math
from pathlib import Path

MKIMG_MAGIC = 0x58881688
MKIMG_EXT_MAGIC = 0x58891689
MKIMG_HDR_SZ = 0x200

IMG_TYPE_GROUP_CERT = 0x02 << 24
IMG_TYPE_CERT1 = IMG_TYPE_GROUP_CERT | 0x00
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02

def le32(b, off):
    return struct.unpack_from('<I', b, off)[0]


def find_headers(data):
    headers = []
    i = 0
    datalen = len(data)
    pattern = struct.pack('<I', MKIMG_MAGIC)
    while True:
        idx = data.find(pattern, i)
        if idx == -1:
            break
        # Ensure we have at least MKIMG_HDR_SZ bytes available
        if idx + 0x40 <= datalen:
            ext_magic = le32(data, idx + 48)
            if ext_magic == MKIMG_EXT_MAGIC:
                dsz = le32(data, idx + 4)
                hdr_sz = le32(data, idx + 52)
                img_type = le32(data, idx + 60)
                img_id = img_type & 0xff
                headers.append((idx, dsz, hdr_sz, img_type))
        i = idx + 4
    return headers




# -- Pure-Python ASN.1 DER TLV parser -------------------------------------------------

TAG_CLASS = ('Universal', 'Application', 'Context-specific', 'Private')

UNIVERSAL_TAGS = {
    0x01: 'BOOLEAN',
    0x02: 'INTEGER',
    0x03: 'BIT STRING',
    0x04: 'OCTET STRING',
    0x05: 'NULL',
    0x06: 'OBJECT IDENTIFIER',
    0x0c: 'UTF8String',
    0x10: 'SEQUENCE',
    0x11: 'SET',
    0x13: 'PrintableString',
    0x14: 'TeletexString',
    0x16: 'IA5String',
    0x17: 'UTCTime',
    0x18: 'GeneralizedTime',
}


def read_tag(data, off):
    b0 = data[off]
    tag_class = (b0 & 0xC0) >> 6
    constructed = bool(b0 & 0x20)
    tagnum = b0 & 0x1F
    tag_bytes = bytes([b0])
    i = off + 1
    if tagnum == 0x1F:
        # long-form tag number
        tagnum = 0
        while True:
            if i >= len(data):
                raise ValueError('Truncated long-form tag')
            b = data[i]
            tag_bytes += bytes([b])
            tagnum = (tagnum << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
    return tag_class, constructed, tagnum, tag_bytes, i - off


def read_length(data, off):
    if off >= len(data):
        raise ValueError('Truncated length')
    b = data[off]
    if not (b & 0x80):
        return b, 1
    num = b & 0x7F
    if num == 0:
        # indefinite length (BER) - not expected in DER
        return None, 1
    if off + 1 + num > len(data):
        raise ValueError('Truncated length bytes')
    val = 0
    for i in range(num):
        val = (val << 8) | data[off + 1 + i]
    return val, 1 + num


def decode_oid(oid_bytes):
    if not oid_bytes:
        return ''
    first = oid_bytes[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return '.'.join(parts)


def hexdump_prefix(b, n=None):
    # Print full byte sequence as hex (no ellipsis), n kept for compatibility
    return ' '.join(f'{x:02x}' for x in b)


def parse_der(data, base_offset=0, max_len=None, depth=0):
    out_lines = []
    off = 0
    end = len(data) if max_len is None else min(len(data), max_len)
    while off < end:
        try:
            tag_class, constructed, tagnum, tag_bytes, tag_len = read_tag(data, off)
        except Exception as e:
            out_lines.append((base_offset + off, depth, f'<TAG ERR: {e}>'))
            break
        try:
            length, len_len = read_length(data, off + tag_len)
        except Exception as e:
            out_lines.append((base_offset + off, depth, f'<LEN ERR: {e}>'))
            break
        hdr_len = tag_len + len_len
        if length is None:
            # indefinite length - try to find EOC (0x00 0x00)
            # Not expected for DER; stop parsing
            out_lines.append((base_offset + off, depth, '<INDEF LEN - unsupported>'))
            break
        val_off = off + hdr_len
        val_end = val_off + length
        if val_end > end:
            out_lines.append((base_offset + off, depth, '<TRUNCATED VALUE>'))
            break
        val = data[val_off:val_end]
        tagclass_name = TAG_CLASS[tag_class]
        utag = UNIVERSAL_TAGS.get(tagnum, f'tag[{tagnum}]' if tag_class == 0 else f'tag[{tagnum}]')
        kind = 'cons' if constructed else 'prim'
        if tag_class == 0:
            desc = utag
        else:
            desc = f'{tagclass_name} {tagnum}'
        summary = f'{desc} ({kind}) hdr={hdr_len} len={length}'
        # add value preview for primitives
        if not constructed:
            if tag_class == 0 and tagnum == 6:
                # OID
                try:
                    summary += ' OID=' + decode_oid(val)
                except Exception:
                    summary += ' OID=<err>'
            elif tag_class == 0 and tagnum == 2:
                # INTEGER
                summary += ' INT=0x' + val.hex()
            elif tag_class == 0 and tagnum in (4, 12, 19, 20, 22, 26):
                # string like / octet
                try:
                    txt = val.decode('utf-8')
                    summary += ' TXT=' + txt
                except Exception:
                    summary += ' RAW=' + hexdump_prefix(val, 24)
            else:
                summary += ' RAW=' + hexdump_prefix(val, 24)
        out_lines.append((base_offset + off, depth, summary))
        # recurse into constructed
        if constructed:
            sub = parse_der(val, base_offset=base_offset + val_off, max_len=length, depth=depth + 1)
            out_lines.extend(sub)
        off = val_end
    return out_lines

# ------------------------------------------------------------------------------------


def process_image(path: Path):
    data = path.read_bytes()
    headers = find_headers(data)
    if not headers:
        print('No MKIMG headers found in file')
        return
    for idx, dsz, hdr_sz, img_type in headers:
        img_id = img_type & 0xff
        kind = 'CERT?'
        if img_type & (0xff << 24) != IMG_TYPE_GROUP_CERT:
            kind = f'IMG_TYPE=0x{img_type:08x}'
        elif img_id == 0:
            kind = 'CERT1'
        elif img_id == 2:
            kind = 'CERT2'
        else:
            kind = f'CERT(id={img_id})'
        print(f'Found header at 0x{idx:08x}: kind={kind} dsz={dsz} hdr_sz={hdr_sz} img_type=0x{img_type:08x}')
        blob_off = idx + hdr_sz
        # try to get blob size from dsz; if zero or too large, use up to file end
        if dsz and dsz <= len(data) - idx - hdr_sz:
            blob_size = dsz
        else:
            blob_size = len(data) - blob_off
        if blob_size <= 0:
            print('  No data after header; skipping')
            continue
        der = data[blob_off:blob_off+blob_size]
        print(f'  Extracted ASN.1 blob at 0x{blob_off:08x} size={blob_size} bytes')
        # Pure-Python parse
        print('  ASN.1 parse (absolute offsets are hex in source image):')
        try:
            lines = parse_der(der, base_offset=blob_off)
            for off_abs, depth, summary in lines:
                indent = '  ' * depth
                print(f'    0x{off_abs:08x} {indent}{summary}')
        except Exception as e:
            print('    <ASN.1 parse error> ', e)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python parse_mtk_certs.py <image_file>')
        sys.exit(2)
    p = Path(sys.argv[1])
    if not p.exists():
        print('File not found:', p)
        sys.exit(2)
    process_image(p)
