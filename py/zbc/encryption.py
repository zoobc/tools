# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Sealed transaction messages (spec/signing.md section 8): 'ZBE1' || libsodium sealed box to the recipient's converted key.
X25519, HSalsa20, XSalsa20 and Poly1305 on the standard library (integers and hashlib), so the package keeps its no-dependency promise."""
import hashlib
import os
import struct
from typing import Optional

P = 2 ** 255 - 19

def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 X25519(scalar bytes, u-coordinate bytes) -> 32 bytes."""
    kk = bytearray(k); kk[0] &= 248; kk[31] &= 127; kk[31] |= 64
    s = int.from_bytes(kk, "little"); x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (s >> t) & 1
        swap ^= kt
        if swap: x2, x3 = x3, x2; z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P; aa = a * a % P; b = (x2 - z2) % P; bb = b * b % P; e = (aa - bb) % P
        c = (x3 + z3) % P; d = (x3 - z3) % P; da = d * a % P; cb = c * b % P
        x3 = pow((da + cb) % P, 2, P); z3 = x1 * pow((da - cb) % P, 2, P) % P
        x2 = aa * bb % P; z2 = e * ((aa + 121665 * e) % P) % P
    if swap: x2, x3 = x3, x2; z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")

def x25519_base(k: bytes) -> bytes: return x25519(k, (9).to_bytes(32, "little"))

def ed25519_pk_to_x25519(pk: bytes) -> bytes:
    """u = (1 + y) / (1 - y) mod p."""
    y = int.from_bytes(pk, "little") & ((1 << 255) - 1)
    return ((1 + y) * pow(1 - y, P - 2, P) % P).to_bytes(32, "little")

def ed25519_seed_to_x25519(seed: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed).digest()[:32]); h[0] &= 248; h[31] &= 127; h[31] |= 64
    return bytes(h)

_SIGMA = b"expand 32-byte k"
def _rotl(v, c): return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))
def _salsa_rounds(x):
    for _ in range(10):
        for (a, b, c, d) in ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11), (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)):
            x[b] ^= _rotl((x[a] + x[d]) & 0xFFFFFFFF, 7); x[c] ^= _rotl((x[b] + x[a]) & 0xFFFFFFFF, 9)
            x[d] ^= _rotl((x[c] + x[b]) & 0xFFFFFFFF, 13); x[a] ^= _rotl((x[d] + x[c]) & 0xFFFFFFFF, 18)
    return x

def hsalsa20(key: bytes, inp: bytes) -> bytes:
    """HSalsa20(key 32, input 16) -> 32 bytes (no feed-forward; words 0,5,10,15,6,7,8,9)."""
    c = struct.unpack("<4I", _SIGMA); k = struct.unpack("<8I", key); n = struct.unpack("<4I", inp)
    x = [c[0], k[0], k[1], k[2], k[3], c[1], n[0], n[1], n[2], n[3], c[2], k[4], k[5], k[6], k[7], c[3]]
    x = _salsa_rounds(x)
    return struct.pack("<8I", x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9])

def salsa20_block(key: bytes, nonce8: bytes, counter: int) -> bytes:
    c = struct.unpack("<4I", _SIGMA); k = struct.unpack("<8I", key); n = struct.unpack("<2I", nonce8)
    x0 = [c[0], k[0], k[1], k[2], k[3], c[1], n[0], n[1], counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF, c[2], k[4], k[5], k[6], k[7], c[3]]
    x = _salsa_rounds(list(x0))
    return struct.pack("<16I", *[(x[i] + x0[i]) & 0xFFFFFFFF for i in range(16)])

def xsalsa20_stream(key: bytes, nonce24: bytes, length: int) -> bytes:
    sub = hsalsa20(key, nonce24[:16]); out = b""; i = 0
    while len(out) < length: out += salsa20_block(sub, nonce24[16:], i); i += 1
    return out[:length]

def poly1305(key32: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key32[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff; s = int.from_bytes(key32[16:], "little")
    p = (1 << 130) - 5; acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]; n = int.from_bytes(blk, "little") + (1 << (8 * len(blk)))
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")

def secretbox(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """crypto_secretbox_easy: tag (16) || ciphertext."""
    stream = xsalsa20_stream(key, nonce, 32 + len(plaintext))
    c = bytes(a ^ b for a, b in zip(plaintext, stream[32:]))
    return poly1305(stream[:32], c) + c

def secretbox_open(key: bytes, nonce: bytes, boxed: bytes):
    if len(boxed) < 16: return None
    stream = xsalsa20_stream(key, nonce, 32 + len(boxed) - 16)
    if poly1305(stream[:32], boxed[16:]) != boxed[:16]: return None
    return bytes(a ^ b for a, b in zip(boxed[16:], stream[32:]))

def box_key(sk: bytes, pk: bytes) -> bytes: return hsalsa20(x25519(sk, pk), bytes(16))

def blake2b_24(data: bytes) -> bytes: return hashlib.blake2b(data, digest_size=24).digest()

SEALED_MAGIC = b"ZBE1"       # the 4-byte marker in front of a sealed message field
SEALED_OVERHEAD = 52         # marker 4 + ephemeral key 32 + tag 16


def is_sealed(field: bytes) -> bool:
    """True when the field starts with the marker (it may still fail to open)."""
    return len(field) >= 4 and field[:4] == SEALED_MAGIC


def seal(plaintext: bytes, recipient_public_key: bytes, ephemeral_secret_key: Optional[bytes] = None) -> bytes:
    """Seal `plaintext` to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is random unless given (tests)."""
    if len(recipient_public_key) != 32:
        raise ValueError("recipient public key must be 32 bytes")
    esk = ephemeral_secret_key if ephemeral_secret_key is not None else os.urandom(32)
    if len(esk) != 32:
        raise ValueError("ephemeral secret key must be 32 bytes")
    rpk = ed25519_pk_to_x25519(recipient_public_key); epk = x25519_base(esk)
    return SEALED_MAGIC + epk + secretbox(box_key(esk, rpk), blake2b_24(epk + rpk), plaintext)


def open_sealed(field: bytes, recipient_seed: bytes) -> Optional[bytes]:
    """The plaintext of a sealed field opened with the recipient's 32-byte seed, or None when it is not a sealed message or the key does not open it."""
    if not is_sealed(field) or len(field) < SEALED_OVERHEAD or len(recipient_seed) != 32:
        return None
    sk = ed25519_seed_to_x25519(recipient_seed); pk = x25519_base(sk); epk = field[4:36]
    return secretbox_open(box_key(sk, epk), blake2b_24(epk + pk), field[36:])

