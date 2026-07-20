# https://github.com/R0rt1z2/lkpatcher/blob/master/lkpatcher/cert_bypass.py
from __future__ import annotations

from enum import Enum
from typing import Callable, Dict, List, Union

from liblk.image import LkImage
from liblk.structures.certificate import Certificate
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import BitString


class CertBypass(Enum):
    OVERRIDE = "override"
    WRAP = "wrap"


def build_bypass_cert2_wrap(
    original_cert2: bytes, header_hash: bytes, image_hash: bytes
) -> bytes:
    cert = Certificate.from_bytes(original_cert2)

    verified_copy = der_encode(BitString(hexValue=bytes(original_cert2).hex()))
    forged_copy = cert.encode_with_hashes(header_hash, image_hash)

    return verified_copy + forged_copy


def build_bypass_cert2_override(
    original_cert2: bytes, header_hash: bytes, image_hash: bytes
) -> bytes:
    cert = Certificate.from_bytes(original_cert2)
    override = cert.build_hash_override_block(header_hash, image_hash)
    return override + bytes(original_cert2)


_BUILDERS: Dict[CertBypass, Callable[[bytes, bytes, bytes], bytes]] = {
    CertBypass.OVERRIDE: build_bypass_cert2_override,
    CertBypass.WRAP: build_bypass_cert2_wrap,
}


def apply_cert_bypass(
    image: LkImage,
    trailing: Union[bytes, bytearray] = b'',
    mode: CertBypass = CertBypass.OVERRIDE,
) -> List[str]:
    signed: List[str] = []
    build = _BUILDERS[mode]

    for name, partition in image.partitions.items():
        if partition.cert2 is None:
            continue

        status = partition.matches_cert2()

        if status is None:
            print(
                "Warning: partition '%s' has an unparseable cert2 "
                '(already bypassed?), skipping' % name
            )
            continue

        if status:
            continue

        header_hash, image_hash = partition.compute_hashes()
        original = bytes(partition.cert2.data)
        partition.cert2.data = build(original, header_hash, image_hash)

        print("Re-signed modified partition '%s'" % name)
        signed.append(name)

    if signed:
        image._rebuild_contents()
        image.contents = bytearray(image.contents) + bytearray(trailing)

    return signed
