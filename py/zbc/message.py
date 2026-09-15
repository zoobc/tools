# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""ZBC-MSG-v1 message signing (spec/signing.md section 5)."""
import hashlib
from typing import Optional

from . import ed25519
from .address import decode_zbc_address, is_hex
from .keys import key_pair

SCHEME = "ZBC-MSG-v1"
_TAG = b"ZBC-MSG"


def message_digest(message: bytes) -> bytes:
    return hashlib.sha3_256(_TAG + message).digest()


def sign_message(seed, message: bytes) -> dict:
    kp = key_pair(seed)
    digest = message_digest(message)
    return {"scheme": SCHEME, "address": kp.address, "public_key": kp.public_key.hex(), "message_hex": message.hex(),
            "digest": digest.hex(), "signature": ed25519.sign(digest, kp.seed).hex()}


def public_key_of_address(address: str) -> Optional[bytes]:
    """The public key behind a ZBC_ address or 64 hex, or None."""
    if is_hex(address, 64):
        return bytes.fromhex(address)
    d = decode_zbc_address(address)
    return d[1] if d is not None and d[0] == "ZBC" else None


def verify_message(address: str, message: bytes, signature) -> bool:
    """False for anything that does not verify; never raises."""
    pub = public_key_of_address(address)
    if pub is None:
        return False
    if isinstance(signature, str):
        if not is_hex(signature, 128):
            return False
        signature = bytes.fromhex(signature)
    return len(signature) == 64 and ed25519.verify(message_digest(message), signature, pub)
