#!/usr/bin/env python3
"""
Helper script to extract and optionally update MTK CERT2 hashes.

Usage examples:
    python sign_mtk_cert.py image.bin            # print information only
    python sign_mtk_cert.py -w image.bin -o out.bin  # write updated image
    python sign_mtk_cert.py -w --legacy image.bin -o out.bin  # old libsec layout

Summary:
 - Parse MKIMG (part_hdr_t) list and locate the CERT2 blob
 - In CERT2 ASN.1, find OID 2.16.886.2454.2.4 (Image Header Hash)
     and OID 2.16.886.2454.2.1 (Image Hash) and print the original bitstrings (hex)
 - Choose SHA-256 or SHA-384 according to bitstring length and compute
     hashes for the image header and image data, printing results in hex
 - Optionally (-w) prepend a 0xA0 TLV before the CERT2 DER blob (as a sibling),
     containing OID 2.16.886.2454.2.4 + BITSTRING(header hash) and
     OID 2.16.886.2454.2.1 + BITSTRING(image hash), update the CERT2 header
     `dsize` field and write the modified image to disk.
 - With --legacy, also prepend BITSTRING(original CERT2 DER) before the hash
     override block so old libsec code using bypass_mode=1 can step into the
     BIT STRING payload and find the original 0x30 SEQUENCE.

Implementation note: this script re-uses DER parsing helpers from
`parse_mtk_certs.py` in this repository.
"""

from pathlib import Path
import argparse
import struct
import hashlib
import sys

PART_MAGIC = 0x58881688
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"
IMG_TYPE_GROUP_CERT = (0x02 << 24)
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02
OID_IMAGE_HASH = '2.16.886.2454.2.1'
OID_IMAGE_HEADER_HASH = '2.16.886.2454.2.4'


def roundup(value, align):
    if align is None or align <= 0:
        return value
    return ((value + align - 1) // align) * align


class PartHdr:
    def __init__(self, values):
        self.magic = values[0]
        self.dsize = values[1]
        self.name = values[2].split(b"\0", 1)[0].decode('latin-1')
        self.maddr = values[3]
        self.mode = values[4]
        self.ext_magic = values[5]
        self.hdr_sz = values[6]
        self.hdr_ver = values[7]
        self.img_type = values[8]
        self.img_list_end = values[9]
        self.align_sz = values[10]
        self.dsize_extend = values[11]
        self.maddr_extend = values[12]

    @classmethod
    def parse_from_bytes(cls, data, off):
        vals = struct.unpack_from(PART_HDR_FORMAT, data, off)
        return cls(vals)

    def padded_data_size(self):
        return roundup(self.dsize, self.align_sz)


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(s)]) + s


def encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split('.')]
    if len(parts) < 2:
        raise ValueError('bad oid')
    first = 40 * parts[0] + parts[1]
    out = bytearray([first])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        parts_b = []
        while p > 0:
            parts_b.insert(0, p & 0x7F)
            p >>= 7
        for i, v in enumerate(parts_b):
            if i != len(parts_b) - 1:
                out.append(0x80 | v)
            else:
                out.append(v)
    return bytes(out)


def build_oid_tlv(oid: str) -> bytes:
    b = encode_oid(oid)
    return b'\x06' + encode_length(len(b)) + b


def build_bitstring_tlv(payload: bytes) -> bytes:
    # BIT STRING with 0 unused bits prefix
    val = b'\x00' + payload
    return b'\x03' + encode_length(len(val)) + val


def parse_part_headers(data: bytes):
    out = []
    off = 0
    file_size = len(data)
    idx = 0
    while off + PART_HDR_SIZE <= file_size:
        try:
            hdr = PartHdr.parse_from_bytes(data, off)
        except struct.error:
            break
        if hdr.magic != PART_MAGIC:
            break
        data_offset = off + PART_HDR_SIZE
        next_offset = off + PART_HDR_SIZE + hdr.padded_data_size()
        if data_offset + hdr.dsize > file_size:
            break
        out.append((idx, off, data_offset, next_offset, hdr))
        idx += 1
        off = next_offset
        if hdr.img_list_end:
            break
    return out


def scan_cert_headers(data: bytes):
    """Scan for cert1/cert2 part_hdr_t anywhere in the file (for headerless images)."""
    magic_bytes = struct.pack('<I', PART_MAGIC)
    results = []
    pos = 0
    while pos + PART_HDR_SIZE <= len(data):
        idx = data.find(magic_bytes, pos)
        if idx < 0:
            break
        if idx + PART_HDR_SIZE > len(data):
            break
        try:
            hdr = PartHdr.parse_from_bytes(data, idx)
        except struct.error:
            pos = idx + 4
            continue
        if hdr.magic == PART_MAGIC:
            name = hdr.name.lower()
            if name.startswith('cert'):
                data_off = idx + PART_HDR_SIZE
                next_off = idx + PART_HDR_SIZE + hdr.padded_data_size()
                results.append((len(results), idx, data_off, next_off, hdr))
        pos = idx + PART_HDR_SIZE + hdr.padded_data_size()
    return results


def parse_tlv_tree(data: bytes, base_off: int = 0):
    """递归解析 DER 数据，返回本层节点列表。每个节点为 dict:
       {off, tag_class, constructed, tagnum, hdr_len, length, val, children, tag_bytes}
       off 为相对于整个 der 的绝对偏移（base_off + local_off）。
    """
    import parse_mtk_certs as pmc

    nodes = []
    off = 0
    L = len(data)
    while off < L:
        try:
            tag_class, constructed, tagnum, tag_bytes, tag_len = pmc.read_tag(data, off)
            length, len_len = pmc.read_length(data, off + tag_len)
        except Exception:
            break
        hdr_len = tag_len + len_len
        val_off = off + hdr_len
        val_end = val_off + length
        if val_end > L:
            break
        val = data[val_off:val_end]
        node = {
            'off': base_off + off,
            'tag_class': tag_class,
            'constructed': constructed,
            'tagnum': tagnum,
            'hdr_len': hdr_len,
            'length': length,
            'val': None if constructed else val,
            'children': None,
            'tag_bytes': tag_bytes,
        }
        if constructed:
            # recurse into content
            node['children'] = parse_tlv_tree(val, base_off + val_off)
        nodes.append(node)
        off = val_end
    return nodes


def _find_bitstring_in_node(node):
    # return bitstring bytes (including unused-bits prefix) or None
    if node is None:
        return None
    if node['tag_class'] == 0 and node['tagnum'] == 3 and node['val'] is not None:
        return node['val']
    if node.get('children'):
        for ch in node['children']:
            res = _find_bitstring_in_node(ch)
            if res is not None:
                return res
    return None


def find_oid_bitstring(der: bytes, oid_str: str):
    """在 DER 的任意嵌套结构中查找给定 OID，并返回其后继的 BIT STRING（包含unused prefix）和 OID 的偏移。
       返回 (bitstring_bytes_with_prefix, oid_abs_offset) 或 (None, None)
    """
    import parse_mtk_certs as pmc

    root_nodes = parse_tlv_tree(der, base_off=0)

    # traverse with parent context to find sibling
    def walk(nodes):
        for i, node in enumerate(nodes):
            # check OID primitive
            if node['tag_class'] == 0 and node['tagnum'] == 6 and node['val'] is not None:
                try:
                    name = pmc.decode_oid(node['val'])
                except Exception:
                    name = ''
                if name == oid_str:
                    # look for next sibling in same nodes list
                    if i + 1 < len(nodes):
                        sibling = nodes[i + 1]
                        bs = _find_bitstring_in_node(sibling)
                        if bs is not None:
                            return bs, node['off']
                    # maybe sibling not direct; try children of following constructed nodes further
                    if i + 1 < len(nodes):
                        # search DFS inside following nodes
                        for j in range(i + 1, len(nodes)):
                            bs = _find_bitstring_in_node(nodes[j])
                            if bs is not None:
                                return bs, node['off']
                    # not found at this level
                    return None, node['off']
            # recurse into children
            if node.get('children'):
                res = walk(node['children'])
                if res[0] is not None:
                    return res
        return (None, None)

    return walk(root_nodes)


def iter_top_level_tlvs(data: bytes):
    import parse_mtk_certs as pmc

    off = 0
    while off < len(data):
        tag_class, constructed, tagnum, tag_bytes, tag_len = pmc.read_tag(data, off)
        length, len_len = pmc.read_length(data, off + tag_len)
        if length is None:
            raise ValueError(f'indefinite length at relative offset 0x{off:x}')
        hdr_len = tag_len + len_len
        end = off + hdr_len + length
        if end > len(data):
            raise ValueError(f'truncated TLV at relative offset 0x{off:x}')
        yield {
            'off': off,
            'end': end,
            'tag_class': tag_class,
            'constructed': constructed,
            'tagnum': tagnum,
            'tag_bytes': tag_bytes,
            'hdr_len': hdr_len,
            'length': length,
            'val_off': off + hdr_len,
        }
        off = end


def find_original_cert2_der(cert2_blob: bytes):
    for node in iter_top_level_tlvs(cert2_blob):
        if node['tag_class'] == 0 and node['constructed'] and node['tagnum'] == 0x10:
            return cert2_blob[node['off']:node['end']], node['off']

    raise ValueError('original CERT2 DER SEQUENCE (0x30) not found')


def build_hash_override_block(header_digest, image_digest) -> bytes:
    parts_to_insert = []
    if header_digest is not None:
        parts_to_insert.append(build_oid_tlv(OID_IMAGE_HEADER_HASH))
        parts_to_insert.append(build_bitstring_tlv(header_digest))
    if image_digest is not None:
        parts_to_insert.append(build_oid_tlv(OID_IMAGE_HASH))
        parts_to_insert.append(build_bitstring_tlv(image_digest))

    if not parts_to_insert:
        return b''

    insert_content = b''.join(parts_to_insert)
    return b'\xa0' + encode_length(len(insert_content)) + insert_content


def replace_cert2_blob(data: bytes, c_blob_off: int, c_off: int, c_hdr: PartHdr, new_blob: bytes) -> bytes:
    new_dsz = len(new_blob)
    old_padded = c_hdr.padded_data_size()
    new_padded = roundup(new_dsz, c_hdr.align_sz)
    new_blob_padded = new_blob + b'\x00' * (new_padded - len(new_blob))

    out_bytes = bytearray(data)
    out_bytes[c_blob_off:c_blob_off + old_padded] = new_blob_padded
    struct.pack_into('<I', out_bytes, c_off + 4, new_dsz)
    return bytes(out_bytes)


def encode_der_root_with_insertion(der: bytes, insert_block: bytes):
    # Parse root tag & length then insert insert_block at root content start
    import parse_mtk_certs as pmc

    tag_class, constructed, tagnum, tag_bytes, tag_len = pmc.read_tag(der, 0)
    length_old, len_len = pmc.read_length(der, tag_len)
    hdr_len = tag_len + len_len
    rest = der[hdr_len:]
    new_len = length_old + len(insert_block)
    new_len_enc = encode_length(new_len)
    new_der = tag_bytes + new_len_enc + insert_block + rest
    return new_der


def sign_normal_image(data, args, path):
    """Sign an image that starts with part_hdr_t (normal MKIMG format)."""
    parts = parse_part_headers(data)

    cert2_entry = None
    for idx, off, data_off, next_off, hdr in parts:
        if hdr.img_type == IMG_TYPE_CERT2:
            cert2_entry = (idx, off, data_off, next_off, hdr)
            break

    if not cert2_entry:
        print('No CERT2 partition header found, exiting')
        sys.exit(1)

    c_idx, c_off, c_blob_off, c_next_off, c_hdr = cert2_entry
    c_dsz = c_hdr.dsize
    der = data[c_blob_off:c_blob_off + c_dsz]
    print(f'Found CERT2 at offset 0x{c_off:08x}, blob_off=0x{c_blob_off:08x}, dsz={c_dsz}')
    if args.legacy:
        try:
            original_cert2_der, original_cert2_rel = find_original_cert2_der(der)
        except ValueError as e:
            print(f'Legacy mode cannot locate original CERT2 DER: {e}')
            sys.exit(1)
        print(f'Legacy source CERT2 DER at rel=0x{original_cert2_rel:x}, size={len(original_cert2_der)}')

    hdr_bit, hdr_oid_rel = find_oid_bitstring(der, OID_IMAGE_HEADER_HASH)
    old_hdr_digest = None
    if hdr_bit is None:
        print('OID 2.16.886.2454.2.4 or its following BIT STRING not found in CERT2')
    else:
        if len(hdr_bit) < 1:
            print('Invalid bitstring for img header')
        else:
            old_hdr_digest = hdr_bit[1:]
            print('Image Header Hash (orig):', old_hdr_digest.hex())
            print('Detected header hash algorithm:',
                  'sha256' if len(old_hdr_digest) == 32 else 'sha384')

    img_bit, img_oid_rel = find_oid_bitstring(der, OID_IMAGE_HASH)
    old_img_digest = None
    if img_bit is None:
        print('OID 2.16.886.2454.2.1 or its following BIT STRING not found in CERT2')
    else:
        if len(img_bit) < 1:
            print('Invalid bitstring for image')
        else:
            old_img_digest = img_bit[1:]
            print('Image Hash (orig):', old_img_digest.hex())
            print('Detected image hash algorithm:',
                  'sha256' if len(old_img_digest) == 32 else 'sha384')

    target_part = None
    for idx, off, data_off, next_off, hdr in parts:
        if off < c_off:
            group = hdr.img_type & 0xff000000
            if group != IMG_TYPE_GROUP_CERT:
                target_part = (idx, off, data_off, next_off, hdr)
    if not target_part:
        print('No target image partition found before CERT2; cannot compute hashes')
        if not args.write:
            return
        else:
            sys.exit(1)

    t_idx, t_off, t_data_off, t_next_off, t_hdr = target_part
    img_hdr_sz = t_hdr.hdr_sz if t_hdr.hdr_sz else PART_HDR_SIZE
    header_bytes = data[t_off:t_off + img_hdr_sz]
    padded_size = t_hdr.padded_data_size()
    data_bytes = data[t_data_off:t_data_off + padded_size]

    new_hdr_digest = None
    if old_hdr_digest is not None:
        hfn = hashlib.sha256 if len(old_hdr_digest) == 32 else hashlib.sha384
        new_hdr_digest = hfn(header_bytes).digest()
        print('Image Header Hash (calc):', new_hdr_digest.hex())

    new_img_digest = None
    if old_img_digest is not None:
        hfn2 = hashlib.sha256 if len(old_img_digest) == 32 else hashlib.sha384
        new_img_digest = hfn2(data_bytes).digest()
        print('Image Hash (calc):', new_img_digest.hex())

    if not args.write:
        print('No -w specified; finished printing, not writing.')
        return

    insert_block = build_hash_override_block(new_hdr_digest, new_img_digest)
    if not insert_block:
        print('No hashes to insert; skipping write.')
        return

    prefix_blocks = []
    if args.legacy:
        legacy_block = build_bitstring_tlv(original_cert2_der)
        prefix_blocks.append(legacy_block)
        print(f'Legacy BIT STRING wrapper size: {len(legacy_block)}')
    prefix_blocks.append(insert_block)

    new_blob = b''.join(prefix_blocks) + der
    out_bytes = replace_cert2_blob(data, c_blob_off, c_off, c_hdr, new_blob)
    new_padded = roundup(len(new_blob), c_hdr.align_sz)
    print(f'CERT2 new dsize={len(new_blob)}, padded={new_padded}, align={c_hdr.align_sz}')

    if len(out_bytes) > len(data):
        growth = len(out_bytes) - len(data)
        overflow = out_bytes[len(data):]
        if all(b == 0 for b in overflow):
            out_bytes = out_bytes[:len(data)]
            print(f'Trimmed {growth} bytes trailing zero padding to keep original size')
        else:
            print(f'WARNING: output is {growth} bytes larger than input, '
                  f'trailing bytes are NOT zero — not truncating')

    out_path = Path(args.out) if args.out else path.with_suffix(path.suffix + '.signed')
    out_path.write_bytes(out_bytes)
    print('Write complete:', out_path)


def sign_headerless_image(data, args, path):
    """Sign a headerless image (e.g. lk_second_dtb) where cert1/cert2 are embedded
    after the raw data without a preceding part_hdr_t."""
    cert_parts = scan_cert_headers(data)
    if not cert_parts:
        print('No cert headers found in file, exiting')
        sys.exit(1)

    cert2_entry = None
    cert1_entry = None
    for idx, off, data_off, next_off, hdr in cert_parts:
        if hdr.img_type == IMG_TYPE_CERT2:
            cert2_entry = (idx, off, data_off, next_off, hdr)
        elif cert1_entry is None:
            cert1_entry = (idx, off, data_off, next_off, hdr)

    if not cert2_entry:
        print('No CERT2 found in headerless image, exiting')
        sys.exit(1)

    c_idx, c_off, c_blob_off, c_next_off, c_hdr = cert2_entry
    c_dsz = c_hdr.dsize
    der = data[c_blob_off:c_blob_off + c_dsz]
    print(f'Found CERT2 at offset 0x{c_off:08x}, blob_off=0x{c_blob_off:08x}, dsz={c_dsz}')

    # Determine data region: from file start to first cert header
    first_cert_off = cert_parts[0][1]
    image_data_region = data[:first_cert_off]
    print(f'Headerless mode: data region = [0x0 : 0x{first_cert_off:x}] ({first_cert_off} bytes)')

    hdr_bit, _ = find_oid_bitstring(der, OID_IMAGE_HEADER_HASH)
    old_hdr_digest = None
    if hdr_bit and len(hdr_bit) > 1:
        old_hdr_digest = hdr_bit[1:]
        print('Image Header Hash (orig):', old_hdr_digest.hex())

    img_bit, _ = find_oid_bitstring(der, OID_IMAGE_HASH)
    old_img_digest = None
    if img_bit and len(img_bit) > 1:
        old_img_digest = img_bit[1:]
        print('Image Hash (orig):', old_img_digest.hex())

    hash_len = 32
    if old_img_digest and len(old_img_digest) == 48:
        hash_len = 48
    elif old_hdr_digest and len(old_hdr_digest) == 48:
        hash_len = 48
    hfn = hashlib.sha256 if hash_len == 32 else hashlib.sha384
    alg_name = 'sha256' if hash_len == 32 else 'sha384'
    print(f'Using algorithm: {alg_name}')

    # For headerless images: "header" = first 512 bytes, "data" = entire region before certs
    header_bytes = image_data_region[:PART_HDR_SIZE]
    new_hdr_digest = hfn(header_bytes).digest() if old_hdr_digest is not None else None
    new_img_digest = hfn(image_data_region).digest()

    if new_hdr_digest:
        print('Image Header Hash (calc):', new_hdr_digest.hex())
    print('Image Hash (calc):', new_img_digest.hex())

    if not args.write:
        print('No -w specified; finished printing, not writing.')
        return

    insert_block = build_hash_override_block(new_hdr_digest, new_img_digest)
    if not insert_block:
        print('No hashes to insert; skipping write.')
        return

    prefix_blocks = [insert_block]
    new_blob = b''.join(prefix_blocks) + der
    out_bytes = replace_cert2_blob(data, c_blob_off, c_off, c_hdr, new_blob)
    new_padded = roundup(len(new_blob), c_hdr.align_sz)
    print(f'CERT2 new dsize={len(new_blob)}, padded={new_padded}, align={c_hdr.align_sz}')

    if len(out_bytes) > len(data):
        growth = len(out_bytes) - len(data)
        overflow = out_bytes[len(data):]
        if all(b == 0 for b in overflow):
            out_bytes = out_bytes[:len(data)]
            print(f'Trimmed {growth} bytes trailing zero padding to keep original size')
        else:
            print(f'WARNING: output is {growth} bytes larger than input, '
                  f'trailing bytes are NOT zero — not truncating')

    out_path = Path(args.out) if args.out else path.with_suffix(path.suffix + '.signed')
    out_path.write_bytes(out_bytes)
    print('Write complete:', out_path)


def _sign_one_cert2(out_data, t_off, t_data_off, t_hdr, c_off, c_blob_off, c_hdr, legacy=False):
    """Sign a single image+cert2 pair in-place within out_data (bytearray).
    Returns the size delta (new_padded - old_padded)."""
    c_dsz = c_hdr.dsize
    der = bytes(out_data[c_blob_off:c_blob_off + c_dsz])

    hdr_bit, _ = find_oid_bitstring(der, OID_IMAGE_HEADER_HASH)
    img_bit, _ = find_oid_bitstring(der, OID_IMAGE_HASH)

    old_hdr_digest = hdr_bit[1:] if hdr_bit and len(hdr_bit) > 1 else None
    old_img_digest = img_bit[1:] if img_bit and len(img_bit) > 1 else None

    if old_hdr_digest is None and old_img_digest is None:
        return 0

    img_hdr_sz = t_hdr.hdr_sz if t_hdr.hdr_sz else PART_HDR_SIZE
    header_bytes = bytes(out_data[t_off:t_off + img_hdr_sz])
    padded_size = t_hdr.padded_data_size()
    data_bytes = bytes(out_data[t_data_off:t_data_off + padded_size])

    new_hdr_digest = None
    if old_hdr_digest is not None:
        hfn = hashlib.sha256 if len(old_hdr_digest) == 32 else hashlib.sha384
        new_hdr_digest = hfn(header_bytes).digest()

    new_img_digest = None
    if old_img_digest is not None:
        hfn2 = hashlib.sha256 if len(old_img_digest) == 32 else hashlib.sha384
        new_img_digest = hfn2(data_bytes).digest()

    insert_block = build_hash_override_block(new_hdr_digest, new_img_digest)
    if not insert_block:
        return 0

    prefix_blocks = []
    if legacy:
        original_cert2_der, _ = find_original_cert2_der(der)
        legacy_block = build_bitstring_tlv(original_cert2_der)
        prefix_blocks.append(legacy_block)
    prefix_blocks.append(insert_block)

    new_blob = b''.join(prefix_blocks) + der
    old_padded = c_hdr.padded_data_size()
    new_padded = roundup(len(new_blob), c_hdr.align_sz)
    new_blob_padded = new_blob + b'\x00' * (new_padded - len(new_blob))

    out_data[c_blob_off:c_blob_off + old_padded] = new_blob_padded
    struct.pack_into('<I', out_data, c_off + 4, len(new_blob))
    return new_padded - old_padded


def _sign_headerless_tail(out_data, list_end_offset, legacy=False):
    """Sign a headerless tail region (e.g. lk_second_dtb) after the main image list.
    Returns size delta."""
    tail_data = bytes(out_data[list_end_offset:])

    first_nonzero = None
    for i in range(len(tail_data)):
        if tail_data[i] != 0:
            first_nonzero = i
            break
    if first_nonzero is None:
        return 0

    magic_bytes = struct.pack('<I', PART_MAGIC)
    cert_parts = []
    pos = first_nonzero
    while pos + PART_HDR_SIZE <= len(tail_data):
        idx = tail_data.find(magic_bytes, pos)
        if idx < 0:
            break
        if idx + PART_HDR_SIZE > len(tail_data):
            break
        try:
            hdr = PartHdr.parse_from_bytes(tail_data, idx)
        except struct.error:
            pos = idx + 4
            continue
        if hdr.magic == PART_MAGIC and hdr.name.lower().startswith('cert'):
            abs_off = list_end_offset + idx
            cert_parts.append((len(cert_parts), abs_off, abs_off + PART_HDR_SIZE,
                              abs_off + PART_HDR_SIZE + hdr.padded_data_size(), hdr))
            pos = idx + PART_HDR_SIZE + hdr.padded_data_size()
        else:
            break

    if not cert_parts:
        return 0

    cert2_entry = None
    for entry in cert_parts:
        if entry[4].img_type == IMG_TYPE_CERT2:
            cert2_entry = entry
            break
    if not cert2_entry:
        return 0

    first_cert_abs = cert_parts[0][1]
    data_start = list_end_offset + first_nonzero
    image_region = bytes(out_data[data_start:first_cert_abs])

    c_idx, c_off, c_blob_off, c_next_off, c_hdr = cert2_entry
    c_dsz = c_hdr.dsize
    der = bytes(out_data[c_blob_off:c_blob_off + c_dsz])

    hdr_bit, _ = find_oid_bitstring(der, OID_IMAGE_HEADER_HASH)
    img_bit, _ = find_oid_bitstring(der, OID_IMAGE_HASH)
    old_hdr_digest = hdr_bit[1:] if hdr_bit and len(hdr_bit) > 1 else None
    old_img_digest = img_bit[1:] if img_bit and len(img_bit) > 1 else None

    hash_len = 32
    if old_img_digest and len(old_img_digest) == 48:
        hash_len = 48
    elif old_hdr_digest and len(old_hdr_digest) == 48:
        hash_len = 48
    hfn = hashlib.sha256 if hash_len == 32 else hashlib.sha384

    new_hdr_digest = hfn(image_region[:PART_HDR_SIZE]).digest() if old_hdr_digest is not None else None
    new_img_digest = hfn(image_region).digest()

    insert_block = build_hash_override_block(new_hdr_digest, new_img_digest)
    if not insert_block:
        return 0

    prefix_blocks = []
    if legacy:
        original_cert2_der, _ = find_original_cert2_der(der)
        legacy_block = build_bitstring_tlv(original_cert2_der)
        prefix_blocks.append(legacy_block)
    prefix_blocks.append(insert_block)

    new_blob = b''.join(prefix_blocks) + der
    old_padded = c_hdr.padded_data_size()
    new_padded = roundup(len(new_blob), c_hdr.align_sz)
    new_blob_padded = new_blob + b'\x00' * (new_padded - len(new_blob))

    out_data[c_blob_off:c_blob_off + old_padded] = new_blob_padded
    struct.pack_into('<I', out_data, c_off + 4, len(new_blob))
    return new_padded - old_padded


def sign_composite_image(data, args, path):
    """Sign ALL sub-images in a composite MKIMG image (lk.img, tee.img, etc.)."""
    parts = parse_part_headers(data)
    if not parts:
        print('No part_hdr_t headers found')
        sys.exit(1)

    groups = []
    i = 0
    while i < len(parts):
        idx, off, data_off, next_off, hdr = parts[i]
        group = hdr.img_type & 0xff000000
        if group == IMG_TYPE_GROUP_CERT:
            i += 1
            continue
        img_entry = parts[i]
        cert2_entry = None
        j = i + 1
        while j < len(parts):
            _, _, _, _, h = parts[j]
            g = h.img_type & 0xff000000
            if g != IMG_TYPE_GROUP_CERT:
                break
            if h.img_type == IMG_TYPE_CERT2:
                cert2_entry = parts[j]
            j += 1
        groups.append((img_entry, cert2_entry))
        i = j

    list_end_offset = parts[-1][3]

    if not groups:
        print('No image groups found')
        sys.exit(1)

    print(f'Found {len(groups)} sub-image(s) in composite image')
    for img_entry, cert2_entry in groups:
        has_cert = 'yes' if cert2_entry else 'no'
        print(f'  {img_entry[4].name}: cert2={has_cert}')

    if not args.write:
        print('No -w specified; use -w --all to write.')
        return

    out_data = bytearray(data)
    signed_count = 0

    has_tail = False
    tail_check = bytes(out_data[list_end_offset:])
    for b in tail_check:
        if b != 0:
            has_tail = True
            break

    if has_tail:
        delta = _sign_headerless_tail(out_data, list_end_offset, legacy=args.legacy)
        if delta != 0 or True:
            magic_bytes = struct.pack('<I', PART_MAGIC)
            if tail_check.find(magic_bytes, next(i for i, b in enumerate(tail_check) if b != 0)) >= 0:
                signed_count += 1
                print(f'  [signed] tail (headerless)')

    for img_entry, cert2_entry in reversed(groups):
        if cert2_entry is None:
            continue
        t_idx, t_off, t_data_off, t_next_off, t_hdr = img_entry
        c_idx, c_off, c_blob_off, c_next_off, c_hdr = cert2_entry
        _sign_one_cert2(out_data, t_off, t_data_off, t_hdr,
                        c_off, c_blob_off, c_hdr, legacy=args.legacy)
        signed_count += 1
        print(f'  [signed] {t_hdr.name}')

    original_size = len(data)
    if len(out_data) > original_size:
        overflow = out_data[original_size:]
        if all(b == 0 for b in overflow):
            out_data = out_data[:original_size]
            print(f'Trimmed to original size ({original_size} bytes)')
        else:
            print(f'WARNING: output is {len(out_data) - original_size} bytes larger than input')

    out_path = Path(args.out) if args.out else path.with_suffix(path.suffix + '.signed')
    Path(out_path).write_bytes(bytes(out_data))
    print(f'Signed {signed_count} sub-image(s), wrote: {out_path}')


def main():
    p = argparse.ArgumentParser(description='MTK CERT2 hash extractor and updater')
    p.add_argument('image', help='input image file')
    p.add_argument('-w', '--write', action='store_true', help='write updated image')
    p.add_argument('-o', '--out', help='output file (default: <input>.signed)')
    p.add_argument('--legacy', action='store_true',
                   help='prepend BITSTRING(original CERT2 DER) for old libsec bypass_mode=1')
    p.add_argument('--all', action='store_true',
                   help='sign ALL sub-images in a composite image (lk.img, tee.img)')
    args = p.parse_args()

    path = Path(args.image)
    if not path.exists():
        print('File not found:', path)
        sys.exit(2)
    data = path.read_bytes()
    print(f"Name: {path.name}  Size: {len(data)}")

    parts = parse_part_headers(data)
    if parts:
        if args.all:
            sign_composite_image(data, args, path)
        else:
            sign_normal_image(data, args, path)
    else:
        print('No part_hdr_t at file start, trying headerless mode...')
        sign_headerless_image(data, args, path)


if __name__ == '__main__':
    main()
