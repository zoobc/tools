# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""ZBC-MSG-v2 message signing (spec/signing.md section 5a); v1 verifies until the sunset (section 5)."""
import hashlib
import time
from typing import Optional, Union

from . import ed25519
from .address import decode_zbc_address, is_hex
from .keys import key_pair

SCHEME = "ZBC-MSG-v2"
SCHEME_V1 = "ZBC-MSG-v1"
_TAG = b"ZBC-MSG-v2"
_TAG_V1 = b"ZBC-MSG"
# v1 signatures verify until 2026-12-01T00:00:00Z and are refused after (owner decision 2026-10-19).
V1_SUNSET = 1796083200
SCHEME_V1_ACCEPTED = SCHEME_V1 + " (accepted until 2026-12-01)"


def _genesis_bytes(genesis_hash: Union[str, bytes]) -> bytes:
    if isinstance(genesis_hash, str):
        if not is_hex(genesis_hash, 64):
            raise ValueError("genesis hash must be 32 bytes (64 hex)")
        genesis_hash = bytes.fromhex(genesis_hash)
    if len(genesis_hash) != 32:
        raise ValueError("genesis hash must be 32 bytes")
    return genesis_hash


def message_digest(message: bytes, genesis_hash: Union[str, bytes]) -> bytes:
    """SHA3-256('ZBC-MSG-v2' || genesis_hash || message): the chain-bound digest."""
    return hashlib.sha3_256(_TAG + _genesis_bytes(genesis_hash) + message).digest()


def message_digest_v1(message: bytes) -> bytes:
    """SHA3-256('ZBC-MSG' || message): the legacy unbound digest, verified only until V1_SUNSET."""
    return hashlib.sha3_256(_TAG_V1 + message).digest()


def sign_message(seed, message: bytes, genesis_hash: Union[str, bytes]) -> dict:
    """Always ZBC-MSG-v2: the signature is bound to the chain whose genesis hash is given."""
    kp = key_pair(seed)
    genesis = _genesis_bytes(genesis_hash)
    digest = message_digest(message, genesis)
    return {"scheme": SCHEME, "genesis_hash": genesis.hex(), "address": kp.address, "public_key": kp.public_key.hex(),
            "message_hex": message.hex(), "digest": digest.hex(), "signature": ed25519.sign(digest, kp.seed).hex()}


def public_key_of_address(address: str) -> Optional[bytes]:
    """The public key behind a ZBC_ address or 64 hex, or None."""
    if is_hex(address, 64):
        return bytes.fromhex(address)
    d = decode_zbc_address(address)
    return d[1] if d is not None and d[0] == "ZBC" else None


def verify_message_scheme(address: str, message: bytes, signature, genesis_hash: Union[str, bytes, None] = None,
                          now: Optional[int] = None) -> Optional[str]:
    """The scheme the signature verifies under (SCHEME or SCHEME_V1_ACCEPTED), or None. Never raises.

    v2 is tried first and needs the chain's genesis; without one only the v1 fallback runs, and v1 is
    accepted only while `now` (default: the clock) is before V1_SUNSET."""
    pub = public_key_of_address(address)
    if pub is None:
        return None
    if isinstance(signature, str):
        if not is_hex(signature, 128):
            return None
        signature = bytes.fromhex(signature)
    if len(signature) != 64:
        return None
    if genesis_hash is not None:
        try:
            genesis = _genesis_bytes(genesis_hash)
        except ValueError:
            genesis = None
        if genesis is not None and ed25519.verify(message_digest(message, genesis), signature, pub):
            return SCHEME
    if (int(time.time()) if now is None else now) < V1_SUNSET and ed25519.verify(message_digest_v1(message), signature, pub):
        return SCHEME_V1_ACCEPTED
    return None


def verify_message(address: str, message: bytes, signature, genesis_hash: Union[str, bytes, None] = None,
                   now: Optional[int] = None) -> bool:
    """False for anything that does not verify; never raises."""
    return verify_message_scheme(address, message, signature, genesis_hash, now) is not None
