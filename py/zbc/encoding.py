# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Base32 (no padding), base58 and base58check (Bitcoin and Ripple alphabets), bech32/bech32m, SS58."""
import base64
import hashlib
from typing import Optional, Tuple, List

BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def base32_encode(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=")


def base32_decode(text: str) -> bytes:
    pad = (-len(text)) % 8
    return base64.b32decode(text + "=" * pad, casefold=False)


def base58_decode(text: str, alphabet: str = BITCOIN_ALPHABET) -> Optional[bytes]:
    n = 0
    for c in text:
        v = alphabet.find(c)
        if v < 0:
            return None
        n = n * 58 + v
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = len(text) - len(text.lstrip(alphabet[0]))
    return b"\x00" * zeros + body


def base58_encode(data: bytes, alphabet: str = BITCOIN_ALPHABET) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * zeros + out


def base58check_decode(text: str, alphabet: str = BITCOIN_ALPHABET) -> Optional[bytes]:
    raw = base58_decode(text, alphabet)
    if raw is None or len(raw) < 5:
        return None
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        return None
    return body


_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


def _polymod(values) -> int:
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode_raw(text: str) -> Optional[Tuple[str, List[int], str]]:
    """(hrp, 5-bit data without checksum, 'bech32' | 'bech32m'), or None."""
    if len(text) > 1023 or (text.lower() != text and text.upper() != text):
        return None
    low = text.lower()
    pos = low.rfind("1")
    if pos < 1 or pos + 7 > len(low):
        return None
    hrp, data = low[:pos], []
    for c in low[pos + 1:]:
        v = _CHARSET.find(c)
        if v < 0:
            return None
        data.append(v)
    pm = _polymod(_hrp_expand(hrp) + data)
    enc = "bech32" if pm == 1 else "bech32m" if pm == 0x2BC830A3 else None
    if enc is None:
        return None
    return hrp, data[:-6], enc


def convert_bits(data, frombits: int, tobits: int, pad: bool) -> Optional[List[int]]:
    acc = bits = 0
    out: List[int] = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or v >> frombits:
            return None
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def segwit_decode(text: str) -> Optional[Tuple[str, int, bytes]]:
    """(hrp, witness version, program), or None."""
    d = bech32_decode_raw(text)
    if d is None or not d[1]:
        return None
    hrp, data, enc = d
    version = data[0]
    prog = convert_bits(data[1:], 5, 8, False)
    if prog is None or len(prog) < 2 or len(prog) > 40 or version > 16:
        return None
    if version == 0 and len(prog) not in (20, 32):
        return None
    if (version == 0) != (enc == "bech32"):
        return None
    return hrp, version, bytes(prog)


def bech32_decode_plain(text: str) -> Optional[Tuple[str, bytes]]:
    """Plain bech32 with an 8-bit payload (Cardano addresses)."""
    d = bech32_decode_raw(text)
    if d is None or d[2] != "bech32":
        return None
    b = convert_bits(d[1], 5, 8, False)
    return None if b is None else (d[0], bytes(b))


def bech32_encode_plain(hrp: str, data: bytes) -> str:
    d = convert_bits(list(data), 8, 5, True) or []
    pm = _polymod(_hrp_expand(hrp) + d + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CHARSET[x] for x in d) + "".join(_CHARSET[(pm >> 5 * (5 - i)) & 31] for i in range(6))


def ss58_decode(text: str) -> Optional[Tuple[int, bytes]]:
    """(prefix, 32-byte account id), or None. Checksum = BLAKE2b-512('SS58PRE' || prefix || id)[:2]."""
    raw = base58_decode(text)
    if raw is None:
        return None
    if len(raw) >= 35 and raw[0] < 64:
        plen, prefix = 1, raw[0]
    elif len(raw) >= 36 and 64 <= raw[0] < 128:
        plen, prefix = 2, ((raw[0] & 0x3F) << 2) | (raw[1] >> 6) | ((raw[1] & 0x3F) << 8)
    else:
        return None
    body = raw[:-2]
    if len(body) - plen != 32:
        return None
    if hashlib.blake2b(b"SS58PRE" + body).digest()[:2] != raw[-2:]:
        return None
    return prefix, body[plen:]
