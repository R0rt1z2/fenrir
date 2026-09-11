#!/usr/bin/env python3
"""
Tool to rebuild or concatenate MTK part_hdr_t multi-image files.

Features:
- replace: replace a single sub-image (by name) in an existing multi-image file
  with a provided single-image file (header+data) or raw data file.

- concat: concatenate single-image files from a directory in a specified order
  (or default order: lk bl2_ext aee lk_main_dtb lk_dtbo) to create a new
  multi-image file.

- rebuild: read manifest.json from a split directory, re-sign all sub-images
  that have CERT2, concatenate in order, and pad to original partition size.
  One-command workflow: split → modify → rebuild.
"""
from __future__ import print_function

import argparse
import json
import os
import re
import struct
import sys

PART_MAGIC = 0x58881688
PART_HEADER_DEFAULT_ADDR = 0xFFFFFFFF
PART_HDR_SIZE = 512
CHUNK_SIZE = 1024 * 1024
PART_HDR_FORMAT = "<II32sIIIIIIIIII"


class ParseError(Exception):
    pass


def roundup(value, align):
    if align <= 0:
        raise ParseError("invalid align_sz: %d" % align)
    return (value + align - 1) & ~(align - 1)


def decode_name(raw_name):
    name = raw_name.split(b"\0", 1)[0]
    try:
        return name.decode("ascii")
    except UnicodeDecodeError:
        return name.decode("latin-1")


def sanitize_filename(name):
    name = name.strip()
    if not name:
        name = "unnamed"
    name = re.sub(r'[<>:\\"/\\|?*\x00-\x1f]', "_", name)
    name = name.rstrip(" .")
    return name or "unnamed"


class PartHdr(object):
    def __init__(self, values, raw=None):
        self.magic = values[0]
        self.dsize = values[1]
        self.name = decode_name(values[2])
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
        self._raw = raw

    @classmethod
    def parse(cls, data):
        if len(data) < PART_HDR_SIZE:
            raise ParseError("short part_hdr_t: got %d bytes" % len(data))
        values = struct.unpack_from(PART_HDR_FORMAT, data, 0)
        return cls(values, raw=data[:PART_HDR_SIZE])

    def data_size(self):
        return self.dsize

    def align_size(self):
        return self.align_sz

    def padded_data_size(self):
        return roundup(self.data_size(), self.align_size())

    def next_offset(self, offset):
        return offset + PART_HDR_SIZE + self.padded_data_size()


def read_hdr_with_raw(fp, offset, file_size):
    if file_size - offset < PART_HDR_SIZE:
        raise ParseError(
            "offset 0x%x has only %d bytes left, smaller than part_hdr_t"
            % (offset, file_size - offset)
        )
    fp.seek(offset)
    data = fp.read(PART_HDR_SIZE)
    if len(data) != PART_HDR_SIZE:
        raise ParseError("failed to read part_hdr_t at offset 0x%x" % offset)
    hdr = PartHdr.parse(data)
    return hdr, data


def iter_images_with_raw(fp, file_size):
    offset = 0
    index = 0
    while offset < file_size:
        hdr, raw = read_hdr_with_raw(fp, offset, file_size)
        if hdr.magic != PART_MAGIC:
            raise ParseError(
                "header magic error at offset 0x%x: 0x%08x != 0x%08x"
                % (offset, hdr.magic, PART_MAGIC)
            )
        data_offset = offset + PART_HDR_SIZE
        padded = hdr.padded_data_size()
        next_offset = offset + PART_HDR_SIZE + padded
        if data_offset + hdr.data_size() > file_size:
            raise ParseError("%s data exceeds file size" % hdr.name)
        yield index, offset, data_offset, hdr, raw, padded
        index += 1
        offset = next_offset
        if hdr.img_list_end:
            break


def copy_stream(src_fp, dst_fp, offset, size):
    src_fp.seek(offset)
    remaining = size
    while remaining:
        chunk = src_fp.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise ParseError("unexpected EOF while copying stream")
        dst_fp.write(chunk)
        remaining -= len(chunk)


def replace_mode(input_path, target_name, new_file, out_path=None, verbose=False):
    """Replace the target sub-image region (header + image + cert1/cert2 if present)
    with the entire contents of `new_file` (copied as-is).
    """
    if out_path is None:
        out_path = input_path + ".new"
    file_size = os.path.getsize(input_path)
    replaced = False
    with open(input_path, "rb") as src_fp, open(out_path, "wb") as out_fp:
        offset = 0
        index = 0
        while offset < file_size:
            hdr, raw_hdr = read_hdr_with_raw(src_fp, offset, file_size)
            name = hdr.name
            data_offset = offset + PART_HDR_SIZE
            padded = hdr.padded_data_size()
            if verbose:
                print("processing image %d: %s" % (index, name))

            if name == target_name:
                replaced = True
                # determine original region including potential following cert headers
                orig_end = offset + PART_HDR_SIZE + padded
                cur_check_off = orig_end

                def is_cert(hdr_obj):
                    if not hdr_obj:
                        return False
                    return (hdr_obj.name or "").lower().startswith('cert')

                # peek cert1
                try:
                    next_hdr, _ = read_hdr_with_raw(src_fp, cur_check_off, file_size)
                except ParseError:
                    next_hdr = None

                if is_cert(next_hdr):
                    cert1_end = next_hdr.next_offset(cur_check_off)
                    orig_end = cert1_end
                    cur_check_off = cert1_end
                    try:
                        next2_hdr, _ = read_hdr_with_raw(src_fp, cur_check_off, file_size)
                    except ParseError:
                        next2_hdr = None
                    if is_cert(next2_hdr):
                        cert2_end = next2_hdr.next_offset(cur_check_off)
                        orig_end = cert2_end

                # copy replacement file bytes into output (replace entire region)
                if verbose:
                    print("replacing region 0x%x..0x%x with %s" % (offset, orig_end, new_file))
                with open(new_file, 'rb') as nf:
                    copy_stream(nf, out_fp, 0, os.path.getsize(new_file))

                # skip past the original full region (main + certs)
                offset = orig_end
                index += 1
                # continue reading from new offset (do not copy the original certs)
                continue
            else:
                # copy original header + padded data as-is (preserve original padding)
                out_fp.write(raw_hdr)
                copy_stream(src_fp, out_fp, data_offset, padded)
                offset = offset + PART_HDR_SIZE + padded
                index += 1
                if hdr.img_list_end:
                    break
    if not replaced:
        raise ParseError("image not found: %s" % target_name)
    print("wrote rebuilt image to %s" % out_path)


def concat_mode(dir_path, order_names=None, out_path=None, verbose=False):
    if order_names is None or len(order_names) == 0:
        order_names = ["lk", "bl2_ext", "aee", "lk_main_dtb", "lk_dtbo"]
    if out_path is None:
        out_path = os.path.basename(os.path.normpath(dir_path)) + ".new"

    files_to_concat = []
    for name in order_names:
        fname = sanitize_filename(name) + ".bin"
        fpath = os.path.join(dir_path, fname)
        if os.path.exists(fpath):
            files_to_concat.append((name, fpath))
            if verbose:
                print("will include: %s" % fpath)

    if not files_to_concat:
        raise ParseError("no files found to concat in %s" % dir_path)

    with open(out_path, "wb") as out_fp:
        for name, fpath in files_to_concat:
            if verbose:
                print("adding %s" % fpath)
            with open(fpath, "rb") as f:
                f.seek(0)
                remaining = os.path.getsize(fpath)
                while remaining:
                    chunk = f.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ParseError("unexpected EOF while reading %s" % fpath)
                    out_fp.write(chunk)
                    remaining -= len(chunk)

        # Append lk_second_dtb if exists (post-list dtb data without part_hdr_t)
        tail_path = os.path.join(dir_path, "lk_second_dtb.bin")
        if os.path.exists(tail_path):
            tail_size = os.path.getsize(tail_path)
            if tail_size > 0:
                if verbose:
                    print("appending lk_second_dtb: %s (%d bytes)" % (tail_path, tail_size))
                with open(tail_path, "rb") as f:
                    remaining = tail_size
                    while remaining:
                        chunk = f.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise ParseError("unexpected EOF while reading %s" % tail_path)
                        out_fp.write(chunk)
                        remaining -= len(chunk)
                print("appended lk_second_dtb (%d bytes)" % tail_size)

    print("wrote concatenated image to %s" % out_path)


def resign_file(file_path, legacy=False, verbose=False):
    """Re-sign a single sub-image file by updating its CERT2 hash override."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sign_mtk_cert

    data = open(file_path, 'rb').read()
    parts = sign_mtk_cert.parse_part_headers(data)

    if parts:
        # Normal image with part_hdr_t
        cert2_entry = None
        for idx, off, data_off, next_off, hdr in parts:
            if hdr.img_type == sign_mtk_cert.IMG_TYPE_CERT2:
                cert2_entry = (idx, off, data_off, next_off, hdr)
                break
        if not cert2_entry:
            if verbose:
                print("  [skip] %s: no CERT2 found" % os.path.basename(file_path))
            return False

        c_idx, c_off, c_blob_off, c_next_off, c_hdr = cert2_entry
        der = data[c_blob_off:c_blob_off + c_hdr.dsize]

        # Find target image (last non-cert before cert2)
        target_part = None
        for idx, off, data_off, next_off, hdr in parts:
            if off < c_off:
                group = hdr.img_type & 0xff000000
                if group != sign_mtk_cert.IMG_TYPE_GROUP_CERT:
                    target_part = (idx, off, data_off, next_off, hdr)
        if not target_part:
            return False

        t_idx, t_off, t_data_off, t_next_off, t_hdr = target_part
        img_hdr_sz = t_hdr.hdr_sz if t_hdr.hdr_sz else PART_HDR_SIZE
        header_bytes = data[t_off:t_off + img_hdr_sz]
        padded_size = t_hdr.padded_data_size()
        data_bytes = data[t_data_off:t_data_off + padded_size]
    else:
        # Headerless image (e.g. lk_second_dtb)
        cert_parts = sign_mtk_cert.scan_cert_headers(data)
        if not cert_parts:
            if verbose:
                print("  [skip] %s: no cert headers" % os.path.basename(file_path))
            return False

        cert2_entry = None
        for idx, off, data_off, next_off, hdr in cert_parts:
            if hdr.img_type == sign_mtk_cert.IMG_TYPE_CERT2:
                cert2_entry = (idx, off, data_off, next_off, hdr)
        if not cert2_entry:
            return False

        c_idx, c_off, c_blob_off, c_next_off, c_hdr = cert2_entry
        der = data[c_blob_off:c_blob_off + c_hdr.dsize]

        first_cert_off = cert_parts[0][1]
        header_bytes = data[:PART_HDR_SIZE]
        data_bytes = data[:first_cert_off]

    # Detect hash algorithm from existing cert2
    import hashlib
    hdr_bit, _ = sign_mtk_cert.find_oid_bitstring(der, sign_mtk_cert.OID_IMAGE_HEADER_HASH)
    img_bit, _ = sign_mtk_cert.find_oid_bitstring(der, sign_mtk_cert.OID_IMAGE_HASH)

    hash_len = 32
    if hdr_bit and len(hdr_bit) > 1 and len(hdr_bit[1:]) == 48:
        hash_len = 48
    elif img_bit and len(img_bit) > 1 and len(img_bit[1:]) == 48:
        hash_len = 48
    hfn = hashlib.sha256 if hash_len == 32 else hashlib.sha384

    new_hdr_digest = hfn(header_bytes).digest() if hdr_bit else None
    new_img_digest = hfn(data_bytes).digest() if img_bit else None

    insert_block = sign_mtk_cert.build_hash_override_block(new_hdr_digest, new_img_digest)
    if not insert_block:
        return False

    prefix_blocks = []
    if legacy and parts:
        try:
            original_cert2_der, _ = sign_mtk_cert.find_original_cert2_der(der)
            prefix_blocks.append(sign_mtk_cert.build_bitstring_tlv(original_cert2_der))
        except ValueError:
            pass
    prefix_blocks.append(insert_block)

    new_blob = b''.join(prefix_blocks) + der
    out_bytes = sign_mtk_cert.replace_cert2_blob(data, c_blob_off, c_off, c_hdr, new_blob)

    if len(out_bytes) > len(data):
        growth = len(out_bytes) - len(data)
        overflow = out_bytes[len(data):]
        if all(b == 0 for b in overflow):
            out_bytes = out_bytes[:len(data)]

    with open(file_path, 'wb') as f:
        f.write(out_bytes)
    return True


def rebuild_mode(dir_path, out_path=None, legacy=False, verbose=False):
    """Read manifest.json, re-sign all sub-images, concat and pad to original size."""
    manifest_path = os.path.join(dir_path, "manifest.json")
    if not os.path.exists(manifest_path):
        raise ParseError("manifest.json not found in %s (run parse-part-img.py --split first)" % dir_path)

    with open(manifest_path, 'r') as f:
        manifest = json.load(f)

    source_size = manifest.get("source_size", 0)
    images = manifest.get("images", [])
    tail = manifest.get("tail")

    if out_path is None:
        out_path = manifest.get("source", "rebuilt") + ".signed"

    print("[*] Rebuild from %s (%d images%s)" % (
        dir_path, len(images), " + tail" if tail else ""))
    print("[*] Target size: %d bytes (0x%x)" % (source_size, source_size))
    print()

    # Re-sign all sub-images with CERT2
    print("── Re-signing ──")
    for img in images:
        fpath = os.path.join(dir_path, img["file"])
        if not os.path.exists(fpath):
            print("  [!] missing: %s" % img["file"])
            continue
        if not img.get("has_cert"):
            print("  [skip] %s (no cert)" % img["name"])
            continue
        ok = resign_file(fpath, legacy=legacy, verbose=verbose)
        if ok:
            print("  [signed] %s" % img["name"])
        else:
            print("  [skip] %s (sign failed or no cert2)" % img["name"])

    if tail and tail.get("has_cert"):
        tail_path = os.path.join(dir_path, tail["file"])
        if os.path.exists(tail_path):
            ok = resign_file(tail_path, legacy=legacy, verbose=verbose)
            if ok:
                print("  [signed] %s (headerless)" % tail["file"])
            else:
                print("  [skip] %s" % tail["file"])

    # Concatenate
    print()
    print("── Concatenating ──")
    with open(out_path, "wb") as out_fp:
        for img in images:
            fpath = os.path.join(dir_path, img["file"])
            if not os.path.exists(fpath):
                raise ParseError("file missing: %s" % fpath)
            fsize = os.path.getsize(fpath)
            with open(fpath, "rb") as f:
                remaining = fsize
                while remaining:
                    chunk = f.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ParseError("unexpected EOF: %s" % fpath)
                    out_fp.write(chunk)
                    remaining -= len(chunk)
            if verbose:
                print("  + %s (%d bytes)" % (img["name"], fsize))

        # Append tail
        if tail:
            tail_path = os.path.join(dir_path, tail["file"])
            if os.path.exists(tail_path):
                tsize = os.path.getsize(tail_path)
                with open(tail_path, "rb") as f:
                    remaining = tsize
                    while remaining:
                        chunk = f.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise ParseError("unexpected EOF: %s" % tail_path)
                        out_fp.write(chunk)
                        remaining -= len(chunk)
                if verbose:
                    print("  + %s (%d bytes, tail)" % (tail["file"], tsize))

        # Pad to original size
        current_size = out_fp.tell()
        if source_size > 0 and current_size < source_size:
            pad = source_size - current_size
            out_fp.write(b'\x00' * pad)
            print("  padded %d bytes to reach %d (0x%x)" % (pad, source_size, source_size))
        elif current_size > source_size > 0:
            print("  [!] WARNING: output %d bytes > original %d bytes" % (current_size, source_size))

    print()
    print("[*] wrote: %s (%d bytes)" % (out_path, os.path.getsize(out_path)))


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Build/modify MTK part_hdr_t multi-image files")
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_replace = sub.add_parser('replace', help='replace a single sub-image in an existing multi-image')
    p_replace.add_argument('image', help='input multi-image file')
    p_replace.add_argument('--name', required=True, help='sub-image name to replace')
    p_replace.add_argument('--file', required=True, help='replacement single-image file (header+data, may include certs)')
    p_replace.add_argument('-o', '--out', help='output file path, default: <image>.new')
    p_replace.add_argument('-v', '--verbose', action='store_true')

    p_concat = sub.add_parser('concat', help='concatenate single-image files from a directory')
    p_concat.add_argument('dir', help='directory containing single-image files (name.bin)')
    p_concat.add_argument('--order', help='comma-separated image names in desired order')
    p_concat.add_argument('-o', '--out', help='output file path, default: <dir>.new')
    p_concat.add_argument('-v', '--verbose', action='store_true')

    p_rebuild = sub.add_parser('rebuild',
        help='re-sign all sub-images and rebuild (reads manifest.json from split dir)')
    p_rebuild.add_argument('dir', help='split directory containing manifest.json')
    p_rebuild.add_argument('-o', '--out', help='output file path')
    p_rebuild.add_argument('--legacy', action='store_true', help='use legacy cert bypass mode')
    p_rebuild.add_argument('-v', '--verbose', action='store_true')

    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv[1:])
    try:
        if args.cmd == 'replace':
            replace_mode(args.image, args.name, args.file, out_path=args.out, verbose=args.verbose)
        elif args.cmd == 'concat':
            order = None
            if args.order:
                order = [s.strip() for s in args.order.split(',') if s.strip()]
            concat_mode(args.dir, order_names=order, out_path=args.out, verbose=args.verbose)
        elif args.cmd == 'rebuild':
            rebuild_mode(args.dir, out_path=args.out, legacy=args.legacy, verbose=args.verbose)
    except (IOError, OSError, ParseError) as err:
        print("error: %s" % err, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
