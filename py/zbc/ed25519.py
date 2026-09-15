# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Ed25519 (RFC 8032): public key from a 32-byte seed, detached signatures, verification.

Pure Python integers. The scalar multiplication takes the same path for every scalar at the
Python level; Python's big integers are not constant time, so keep seeds on machines you trust,
as with any pure-Python signer.
"""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, sign: int) -> int:
    y2 = y * y % P
    u, v = (y2 - 1) % P, (D * y2 + 1) % P
    x = pow(u * pow(v, P - 2, P), (P + 3) // 8, P)
    if (v * x * x - u) % P != 0:
        x = x * I % P
    if (v * x * x - u) % P != 0:
        raise ValueError("not a point on the curve")
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % P)
_ZERO = (0, 1, 1, 0)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(p, s: int):
    r, q = _ZERO, p
    for i in range(256):
        total = _add(r, q)
        r = total if (s >> i) & 1 else r
        q = _add(q, q)
    return r


def _encode(p) -> bytes:
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(b: bytes):
    if len(b) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        raise ValueError("non-canonical point")
    x = _recover_x(y, sign)
    if x == 0 and sign == 1:
        raise ValueError("non-canonical point")
    return (x, y, 1, x * y % P)


def _clamp(h: bytes) -> int:
    k = bytearray(h[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key of a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _encode(_mul(_G, _clamp(hashlib.sha512(seed).digest())))


def sign(message: bytes, seed: bytes) -> bytes:
    """Detached 64-byte signature of `message` with the 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a, prefix = _clamp(h), h[32:]
    pub = _encode(_mul(_G, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = _encode(_mul(_G, r))
    k = int.from_bytes(hashlib.sha512(big_r + pub + message).digest(), "little") % L
    return big_r + ((r + k * a) % L).to_bytes(32, "little")


def verify(message: bytes, signature: bytes, pub: bytes) -> bool:
    """True when `signature` is a valid signature of `message` by `pub`. Never raises."""
    try:
        if len(signature) != 64 or len(pub) != 32:
            return False
        a = _decode(pub)
        big_r = _decode(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        k = int.from_bytes(hashlib.sha512(signature[:32] + pub + message).digest(), "little") % L
        return _encode(_mul(_G, s)) == _encode(_add(big_r, _mul(a, k)))
    except (ValueError, ArithmeticError):
        return False
