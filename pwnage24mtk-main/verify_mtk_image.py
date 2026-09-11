#!/usr/bin/env python3
"""
Verify an MTK part_hdr_t image with CERT1/CERT2.


  * parse part_hdr_t image, CERT1, CERT2
  * verify CERT1 and CERT2 RSA-PSS signatures
  * compare CERT2 image-header hash and image hash
  * skip the device efuse public-key comparison by design and print the key
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PART_MAGIC = 0x58881688
EXT_MAGIC = 0x58891689
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"

IMG_TYPE_GROUP_CERT = 0x02 << 24
IMG_TYPE_CERT1 = IMG_TYPE_GROUP_CERT | 0x00
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_ROOT_KEY = "2.16.886.2454.1.1"
OID_IMG_PUBK = "2.16.886.2454.1.2"
OID_IMG_HASH = "2.16.886.2454.2.1"
OID_IMG_VER = "2.16.886.2454.2.2"
OID_SW_ID = "2.16.886.2454.2.3"
OID_IMG_HDR_HASH = "2.16.886.2454.2.4"
OID_IMG_GROUP = "2.16.886.2454.2.5"
OID_SEC_LEVEL = "2.16.886.2454.2.9"
OID_ROOT_KEY_VER = "2.16.886.2454.2.10"
OID_APPLY_SIG = "2.16.886.2454.3.2"


class VerifyError(Exception):
    pass


@dataclass
class PartHdr:
    magic: int
    dsize: int
    name: str
    maddr: int
    mode: int
    ext_magic: int
    hdr_sz: int
    hdr_ver: int
    img_type: int
    img_list_end: int
    align_sz: int
    dsize_extend: int
    maddr_extend: int

    @classmethod
    def parse(cls, data: bytes, off: int) -> "PartHdr":
        values = struct.unpack_from(PART_HDR_FORMAT, data, off)
        name = values[2].split(b"\0", 1)[0].decode("latin-1")
        return cls(
            magic=values[0],
            dsize=values[1],
            name=name,
            maddr=values[3],
            mode=values[4],
            ext_magic=values[5],
            hdr_sz=values[6] or PART_HDR_SIZE,
            hdr_ver=values[7],
            img_type=values[8],
            img_list_end=values[9],
            align_sz=values[10] or 1,
            dsize_extend=values[11],
            maddr_extend=values[12],
        )

    def padded_data_size(self) -> int:
        return roundup(self.dsize, self.align_sz)


@dataclass
class PartEntry:
    index: int
    off: int
    data_off: int
    next_off: int
    hdr: PartHdr

    @property
    def is_cert(self) -> bool:
        return (self.hdr.img_type & 0xFF000000) == IMG_TYPE_GROUP_CERT


@dataclass
class DerNode:
    data: bytes
    off: int
    tag: int
    tag_class: int
    constructed: bool
    tagnum: int
    hdr_len: int
    length: int
    value_off: int
    end: int
    parent: "DerNode | None" = None
    children: list["DerNode"] | None = None

    @property
    def value(self) -> bytes:
        return self.data[self.value_off : self.end]

    @property
    def full(self) -> bytes:
        return self.data[self.off : self.end]


@dataclass
class RsaPubKey:
    n: bytes
    e: bytes

    @property
    def bits(self) -> int:
        return len(self.n) * 8

    @property
    def exponent(self) -> int:
        return int.from_bytes(self.e, "big")

    @property
    def modulus_int(self) -> int:
        return int.from_bytes(self.n, "big")

    def same_as(self, other: "RsaPubKey") -> bool:
        return self.n == other.n and self.e == other.e


@dataclass
class CertInfo:
    root: DerNode
    tbs: DerNode
    signature: bytes
    public_key: RsaPubKey
    sec_level: int

    @property
    def hash_name(self) -> str:
        return hash_name_for_sec_level(self.sec_level)

    @property
    def hash_size(self) -> int:
        return hashlib.new(self.hash_name).digest_size


def roundup(value: int, align: int) -> int:
    if align <= 0:
        return value
    return (value + align - 1) & ~(align - 1)


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def read_len(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise VerifyError("truncated DER length")
    first = data[off]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if count == 0:
        raise VerifyError("indefinite DER length is not supported")
    if off + 1 + count > len(data):
        raise VerifyError("truncated DER long length")
    value = int.from_bytes(data[off + 1 : off + 1 + count], "big")
    return value, 1 + count


def read_tag(data: bytes, off: int) -> tuple[int, int, bool, int, int]:
    if off >= len(data):
        raise VerifyError("truncated DER tag")
    first = data[off]
    tag_class = (first & 0xC0) >> 6
    constructed = bool(first & 0x20)
    tagnum = first & 0x1F
    pos = off + 1
    if tagnum == 0x1F:
        tagnum = 0
        while True:
            if pos >= len(data):
                raise VerifyError("truncated DER long tag")
            byte = data[pos]
            tagnum = (tagnum << 7) | (byte & 0x7F)
            pos += 1
            if not (byte & 0x80):
                break
    return first, tag_class, constructed, tagnum, pos - off


def parse_der_nodes(data: bytes, start: int = 0, end: int | None = None, parent: DerNode | None = None) -> list[DerNode]:
    end = len(data) if end is None else end
    out: list[DerNode] = []
    off = start
    while off < end:
        tag, tag_class, constructed, tagnum, tag_len = read_tag(data, off)
        length, len_len = read_len(data, off + tag_len)
        hdr_len = tag_len + len_len
        value_off = off + hdr_len
        node_end = value_off + length
        if node_end > end:
            raise VerifyError(f"truncated DER value at 0x{off:x}")
        node = DerNode(
            data=data,
            off=off,
            tag=tag,
            tag_class=tag_class,
            constructed=constructed,
            tagnum=tagnum,
            hdr_len=hdr_len,
            length=length,
            value_off=value_off,
            end=node_end,
            parent=parent,
            children=[] if constructed else None,
        )
        if constructed:
            node.children = parse_der_nodes(data, value_off, node_end, node)
        out.append(node)
        off = node_end
    return out


def walk(nodes: Iterable[DerNode]) -> Iterable[DerNode]:
    for node in nodes:
        yield node
        if node.children:
            yield from walk(node.children)


def node_oid(node: DerNode) -> str | None:
    if node.tag_class == 0 and node.tagnum == 6 and not node.constructed:
        return decode_oid(node.value)
    return None


def first_top_sequence(nodes: list[DerNode]) -> DerNode:
    for node in nodes:
        if node.tag == 0x30:
            return node
    raise VerifyError("no X.509 certificate SEQUENCE found")


def find_oid_nodes(nodes: list[DerNode], oid: str) -> list[DerNode]:
    return [node for node in walk(nodes) if node_oid(node) == oid]


def next_sibling(node: DerNode) -> DerNode | None:
    if node.parent is None or not node.parent.children:
        return None
    siblings = node.parent.children
    for idx, sibling in enumerate(siblings):
        if sibling is node:
            if idx + 1 < len(siblings):
                return siblings[idx + 1]
            return None
    return None


def find_oid_sibling(nodes: list[DerNode], oid: str, tag: int | None = None) -> DerNode | None:
    for oid_node in find_oid_nodes(nodes, oid):
        sibling = next_sibling(oid_node)
        if sibling is None:
            continue
        if tag is None or sibling.tag == tag:
            return sibling
    return None


def der_int_value(node: DerNode) -> bytes:
    if node.tag != 0x02:
        raise VerifyError(f"expected INTEGER, got tag 0x{node.tag:02x}")
    value = node.value
    if len(value) >= 2 and value[0] == 0 and value[1] & 0x80:
        value = value[1:]
    return value


def der_int_u32(node: DerNode) -> int:
    value = der_int_value(node)
    if len(value) > 4:
        raise VerifyError("INTEGER is too large for u32")
    return int.from_bytes(value, "big")


def bit_string_value(node: DerNode) -> bytes:
    if node.tag != 0x03:
        raise VerifyError(f"expected BIT STRING, got tag 0x{node.tag:02x}")
    value = node.value
    if not value:
        raise VerifyError("empty BIT STRING")
    if value[0] != 0:
        raise VerifyError("BIT STRING with unused bits is not supported")
    return value[1:]


def parse_rsa_public_key_from_spki(spki: DerNode) -> RsaPubKey:
    if spki.tag != 0x30 or not spki.children:
        raise VerifyError("public key is not a SEQUENCE")
    bit_node = None
    for child in spki.children:
        if child.tag == 0x03:
            bit_node = child
            break
    if bit_node is None:
        raise VerifyError("SPKI BIT STRING not found")
    rsa_der = bit_string_value(bit_node)
    rsa_root = first_top_sequence(parse_der_nodes(rsa_der))
    if not rsa_root.children or len(rsa_root.children) < 2:
        raise VerifyError("RSA public key SEQUENCE is incomplete")
    n = der_int_value(rsa_root.children[0])
    e = der_int_value(rsa_root.children[1])
    if len(n) not in (256, 384, 512):
        raise VerifyError(f"unsupported RSA modulus size: {len(n)}")
    return RsaPubKey(n=n, e=e)


def find_first_rsa_public_key(nodes: list[DerNode]) -> RsaPubKey:
    for oid_node in find_oid_nodes(nodes, OID_RSA_ENCRYPTION):
        alg_seq = oid_node.parent
        if alg_seq is None:
            continue
        spki = alg_seq.parent
        if spki is None or spki.tag != 0x30 or not spki.children:
            continue
        if any(child.tag == 0x03 for child in spki.children):
            return parse_rsa_public_key_from_spki(spki)
    raise VerifyError("RSA public key not found")


def find_image_public_key(nodes: list[DerNode]) -> RsaPubKey:
    spki = find_oid_sibling(nodes, OID_IMG_PUBK, 0x30)
    if spki is None:
        raise VerifyError("CERT1 image public key OID not found")
    return parse_rsa_public_key_from_spki(spki)


def find_int_by_oid(nodes: list[DerNode], oid: str, default: int | None = None) -> int:
    node = find_oid_sibling(nodes, oid, 0x02)
    if node is None:
        if default is not None:
            return default
        raise VerifyError(f"OID {oid} INTEGER not found")
    return der_int_u32(node)


def find_bit_string_by_oid(nodes: list[DerNode], oid: str) -> bytes:
    node = find_oid_sibling(nodes, oid, 0x03)
    if node is None:
        raise VerifyError(f"OID {oid} BIT STRING not found")
    return bit_string_value(node)


def hash_name_for_sec_level(sec_level: int) -> str:
    if sec_level == 0:
        return "sha256"
    if sec_level in (1, 2):
        return "sha384"
    raise VerifyError(f"unsupported sec_level: {sec_level}")


def hash_data(data: bytes, sec_level: int) -> bytes:
    h = hashlib.new(hash_name_for_sec_level(sec_level))
    h.update(data)
    return h.digest()


def mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        h = hashlib.new(hash_name)
        h.update(seed)
        h.update(counter.to_bytes(4, "big"))
        out.extend(h.digest())
        counter += 1
    return bytes(out[:length])


def pss_verify_digest(digest: bytes, encoded: bytes, hash_name: str, em_bits: int, salt_len: int | None = None) -> bool:
    h_len = hashlib.new(hash_name).digest_size
    salt_len = h_len if salt_len is None else salt_len
    em_len = (em_bits + 7) // 8
    if len(encoded) != em_len or em_len < h_len + salt_len + 2:
        return False
    if encoded[-1] != 0xBC:
        return False

    masked_db = encoded[: em_len - h_len - 1]
    h_val = encoded[em_len - h_len - 1 : em_len - 1]
    unused = 8 * em_len - em_bits
    if unused and masked_db[0] & (0xFF << (8 - unused)):
        return False

    db_mask = mgf1(h_val, len(masked_db), hash_name)
    db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))
    if unused:
        db[0] &= 0xFF >> unused

    ps_len = em_len - h_len - salt_len - 2
    if bytes(db[:ps_len]) != b"\0" * ps_len:
        return False
    if db[ps_len] != 1:
        return False

    salt = bytes(db[-salt_len:]) if salt_len else b""
    h2 = hashlib.new(hash_name)
    h2.update(b"\0" * 8)
    h2.update(digest)
    h2.update(salt)
    return h2.digest() == h_val


def rsa_pss_verify(data: bytes, signature: bytes, pub: RsaPubKey, hash_name: str) -> bool:
    if len(signature) != len(pub.n):
        return False
    digest = hashlib.new(hash_name, data).digest()
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= pub.modulus_int:
        return False
    encoded = pow(sig_int, pub.exponent, pub.modulus_int).to_bytes(len(pub.n), "big")

    candidates = []
    for bits in (pub.modulus_int.bit_length() - 1, len(pub.n) * 8 - 1, len(pub.n) * 8):
        if bits > 0 and bits not in candidates:
            candidates.append(bits)
    return any(pss_verify_digest(digest, encoded, hash_name, bits) for bits in candidates)


def parse_cert(cert_blob: bytes) -> CertInfo:
    nodes = parse_der_nodes(cert_blob)
    root = first_top_sequence(nodes)
    if not root.children or len(root.children) < 3:
        raise VerifyError("certificate SEQUENCE is incomplete")
    tbs = root.children[0]
    sig_node = root.children[2]
    signature = bit_string_value(sig_node)
    sec_level = find_int_by_oid(nodes, OID_SEC_LEVEL, default=0) & 0xF
    public_key = find_first_rsa_public_key(nodes)
    return CertInfo(root=root, tbs=tbs, signature=signature, public_key=public_key, sec_level=sec_level)


def parse_part_entries(data: bytes) -> list[PartEntry]:
    entries: list[PartEntry] = []
    off = 0
    idx = 0
    while off + PART_HDR_SIZE <= len(data):
        hdr = PartHdr.parse(data, off)
        if hdr.magic != PART_MAGIC:
            break
        data_off = off + hdr.hdr_sz
        next_off = off + hdr.hdr_sz + hdr.padded_data_size()
        if data_off + hdr.dsize > len(data):
            raise VerifyError(f"{hdr.name or idx} data exceeds file size")
        if next_off > len(data):
            raise VerifyError(f"{hdr.name or idx} padded data exceeds file size")
        entries.append(PartEntry(idx, off, data_off, next_off, hdr))
        idx += 1
        off = next_off
        if hdr.img_list_end:
            break
    if not entries:
        raise VerifyError("no part_hdr_t entries found")
    return entries


def is_cert1(entry: PartEntry) -> bool:
    return entry.hdr.img_type == IMG_TYPE_CERT1 or entry.hdr.name.lower().startswith("cert1")


def is_cert2(entry: PartEntry) -> bool:
    return entry.hdr.img_type == IMG_TYPE_CERT2 or entry.hdr.name.lower().startswith("cert2")


def find_targets(entries: list[PartEntry], name: str | None) -> list[tuple[PartEntry, PartEntry, PartEntry]]:
    targets: list[tuple[PartEntry, PartEntry, PartEntry]] = []
    i = 0
    while i + 2 < len(entries):
        target, cert1, cert2 = entries[i], entries[i + 1], entries[i + 2]
        if not target.is_cert and is_cert1(cert1) and is_cert2(cert2):
            if name is None or target.hdr.name == name:
                targets.append((target, cert1, cert2))
            i += 3
            continue
        i += 1
    return targets


def entry_blob(data: bytes, entry: PartEntry, include_header: bool = False) -> bytes:
    start = entry.off if include_header else entry.data_off
    end = entry.data_off + entry.hdr.dsize
    return data[start:end]


def padded_image_data(data: bytes, entry: PartEntry) -> bytes:
    start = entry.data_off
    blob = bytearray(data[start : start + entry.hdr.dsize])
    pad_len = entry.hdr.padded_data_size() - entry.hdr.dsize
    if pad_len < 0:
        raise VerifyError("padded image size is smaller than dsize")
    blob.extend(b"\0" * pad_len)
    return bytes(blob)


def hex_block(data: bytes, width: int = 32) -> str:
    lines = []
    for off in range(0, len(data), width):
        lines.append(data[off : off + width].hex())
    return "\n".join(lines)


def print_pubkey(label: str, pub: RsaPubKey) -> None:
    print(f"{label}:")
    print(f"  bits     : {pub.bits}")
    print(f"  exponent : 0x{pub.exponent:x}")
    print("  modulus  :")
    for line in hex_block(pub.n).splitlines():
        print(f"    {line}")


def compare_digest(label: str, expected: bytes, actual: bytes) -> bool:
    ok = expected == actual
    print(f"{label}: {'OK' if ok else 'FAIL'}")
    print(f"  cert : {expected.hex()}")
    print(f"  calc : {actual.hex()}")
    return ok


def verify_one(data: bytes, target: PartEntry, cert1_entry: PartEntry, cert2_entry: PartEntry) -> bool:
    print(f"Image: {target.hdr.name} @ 0x{target.off:x}")
    print(f"  image size : {target.hdr.dsize} (padded {target.hdr.padded_data_size()})")
    print(f"  cert1      : 0x{cert1_entry.off:x}, size {cert1_entry.hdr.dsize}")
    print(f"  cert2      : 0x{cert2_entry.off:x}, size {cert2_entry.hdr.dsize}")

    if cert1_entry.hdr.magic != PART_MAGIC or cert1_entry.hdr.ext_magic != EXT_MAGIC:
        raise VerifyError("CERT1 part header magic is invalid")
    if cert2_entry.hdr.magic != PART_MAGIC or cert2_entry.hdr.ext_magic != EXT_MAGIC:
        raise VerifyError("CERT2 part header magic is invalid")
    if cert1_entry.hdr.img_type != IMG_TYPE_CERT1:
        raise VerifyError(f"CERT1 img_type is 0x{cert1_entry.hdr.img_type:08x}, expected 0x{IMG_TYPE_CERT1:08x}")
    if cert2_entry.hdr.img_type != IMG_TYPE_CERT2:
        raise VerifyError(f"CERT2 img_type is 0x{cert2_entry.hdr.img_type:08x}, expected 0x{IMG_TYPE_CERT2:08x}")

    cert1_blob = entry_blob(data, cert1_entry)
    cert2_blob = entry_blob(data, cert2_entry)
    cert1_nodes = parse_der_nodes(cert1_blob)
    cert2_nodes = parse_der_nodes(cert2_blob)
    cert1 = parse_cert(cert1_blob)
    cert2 = parse_cert(cert2_blob)

    print(f"sec_level: {cert1.sec_level} ({cert1.hash_name})")
    if cert2.sec_level != cert1.sec_level:
        raise VerifyError(f"CERT2 sec_level {cert2.sec_level} does not match CERT1 {cert1.sec_level}")

    print_pubkey("CERT1 root public key (efuse compare skipped)", cert1.public_key)
    cert1_sig_ok = rsa_pss_verify(cert1.tbs.full, cert1.signature, cert1.public_key, cert1.hash_name)
    print(f"CERT1 signature: {'OK' if cert1_sig_ok else 'FAIL'}")

    image_pub = find_image_public_key(cert1_nodes)
    print_pubkey("CERT1 image public key", image_pub)
    print_pubkey("CERT2 public key", cert2.public_key)
    pub_match_ok = cert2.public_key.same_as(image_pub)
    print(f"CERT2 public key matches CERT1 image key: {'OK' if pub_match_ok else 'FAIL'}")

    cert2_sig_ok = rsa_pss_verify(cert2.tbs.full, cert2.signature, cert2.public_key, cert2.hash_name)
    print(f"CERT2 signature: {'OK' if cert2_sig_ok else 'FAIL'}")

    hdr_hash = find_bit_string_by_oid(cert2_nodes, OID_IMG_HDR_HASH)
    img_hash = find_bit_string_by_oid(cert2_nodes, OID_IMG_HASH)
    hash_len = cert1.hash_size
    if len(hdr_hash) != hash_len:
        raise VerifyError(f"CERT2 header hash length {len(hdr_hash)} does not match {hash_len}")
    if len(img_hash) != hash_len:
        raise VerifyError(f"CERT2 image hash length {len(img_hash)} does not match {hash_len}")

    target_header = data[target.off : target.off + target.hdr.hdr_sz]
    calc_hdr_hash = hash_data(target_header, cert1.sec_level)
    header_hash_ok = compare_digest("Image header hash", hdr_hash, calc_hdr_hash)

    calc_img_hash = hash_data(padded_image_data(data, target), cert1.sec_level)
    image_hash_ok = compare_digest("Image data hash", img_hash, calc_img_hash)

    sw_id = find_int_by_oid(cert1_nodes, OID_SW_ID, default=0)
    img_ver = find_int_by_oid(cert2_nodes, OID_IMG_VER, default=0)
    apply_sig = find_int_by_oid(cert2_nodes, OID_APPLY_SIG, default=0)
    print(f"CERT1 sw_id: 0x{sw_id:x}")
    print(f"CERT2 img_ver: {img_ver}")
    print(f"CERT2 apply_sig: {apply_sig}")
    print("Trusted root check: skipped (requested: print public key only, no efuse comparison)")

    ok = cert1_sig_ok and pub_match_ok and cert2_sig_ok and header_hash_ok and image_hash_ok
    print(f"Result: {'VALID' if ok else 'INVALID'}")
    return ok


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify MTK CERT1/CERT2 signed image")
    parser.add_argument("image", help="signed image/blob containing part_hdr_t + CERT1 + CERT2")
    parser.add_argument("-n", "--name", help="verify only this sub-image name")
    parser.add_argument("--all", action="store_true", help="verify all sub-images with CERT1/CERT2")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    path = Path(args.image)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    try:
        data = path.read_bytes()
        entries = parse_part_entries(data)
        targets = find_targets(entries, args.name)
        if not targets:
            wanted = f" named {args.name!r}" if args.name else ""
            raise VerifyError(f"no signed target{wanted} with following CERT1/CERT2 found")
        selected = targets if args.all else targets[:1]
        all_ok = True
        for idx, triple in enumerate(selected):
            if idx:
                print()
            all_ok = verify_one(data, *triple) and all_ok
        return 0 if all_ok else 1
    except (OSError, struct.error, VerifyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
