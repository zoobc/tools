# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Account addresses: the ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md."""
import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from .encoding import (RIPPLE_ALPHABET, base32_decode, base32_encode, base58_decode, base58check_decode,
                       bech32_decode_plain, segwit_decode, ss58_decode)

ZOOBC, BITCOIN, EMPTY, ESTONIA_EID, ETHEREUM = 0, 1, 2, 3, 4
BITCOIN_P2PKH, BITCOIN_P2SH, BITCOIN_P2WPKH, BITCOIN_P2WSH, BITCOIN_TAPROOT = 5, 6, 7, 8, 9
DATASET, SOLANA, POLKADOT, CARDANO, RIPPLE, TRON, TEZOS = 10, 11, 12, 13, 14, 15, 16

TYPE_NAMES = {0: "ZooBC", 1: "Bitcoin", 3: "Estonia eID", 4: "Ethereum", 5: "Bitcoin P2PKH", 6: "Bitcoin P2SH",
              7: "Bitcoin P2WPKH", 8: "Bitcoin P2WSH", 9: "Bitcoin Taproot", 10: "DataSet", 11: "Solana",
              12: "Polkadot", 13: "Cardano", 14: "Ripple", 15: "Tron", 16: "Tezos"}
CHAINS = {"zbc": "zbc", "zoobc": "zbc", "btc": "btc", "bitcoin": "btc", "eth": "eth", "ethereum": "eth", "evm": "eth",
          "sol": "sol", "solana": "sol", "dot": "dot", "polkadot": "dot", "substrate": "dot", "ada": "ada", "cardano": "ada",
          "xrp": "xrp", "ripple": "xrp", "trx": "trx", "tron": "trx", "xtz": "xtz", "tezos": "xtz", "zbs": "zbs", "dataset": "zbs"}
_HEX = re.compile(r"^[0-9a-fA-F]*$")


def is_hex(s: str, length: Optional[int] = None) -> bool:
    return bool(_HEX.match(s)) and len(s) % 2 == 0 and (length is None or len(s) == length)


def account_type_name(t: int) -> str:
    return TYPE_NAMES.get(t, "type %d" % t)


def payload_length(t: int) -> int:
    """Payload length by account type, as the node parses an envelope."""
    if t in (1, 4, 5, 6, 7, 14, 15, 16):
        return 20
    return 28 if t == 13 else 32


def typed_address(t: int, payload: bytes) -> bytes:
    return struct.pack("<i", t) + payload


def encode_zbc_address(payload: bytes, prefix: str = "ZBC") -> str:
    """PREFIX_ + base32(payload || SHA3-256(payload || prefix)[:3]) in seven groups of eight."""
    if len(payload) != 32 or len(prefix) != 3:
        raise ValueError("address payload must be 32 bytes and the prefix 3 characters")
    check = hashlib.sha3_256(payload + prefix.encode()).digest()[:3]
    b32 = base32_encode(payload + check)
    return prefix + "".join("_" + b32[8 * i:8 * i + 8] for i in range(7))


def decode_zbc_address(text: str) -> Optional[Tuple[str, bytes]]:
    """(upper-case prefix, 32-byte payload) of PREFIX_... (separators _ or -, any case), or None."""
    norm = text.upper()
    if len(norm) < 4 or norm[3] not in "_-":
        return None
    prefix, body = norm[:3], norm[4:].replace("_", "").replace("-", "")
    if len(body) != 56:
        return None
    try:
        raw = base32_decode(body)
    except (ValueError, TypeError):
        return None
    if len(raw) != 35:
        return None
    payload = raw[:32]
    if hashlib.sha3_256(payload + prefix.encode()).digest()[:3] != raw[32:]:
        return None
    return prefix, payload


@dataclass
class ParsedAddress:
    type: int
    payload: bytes
    display: str

    @property
    def bytes(self) -> bytes:
        return typed_address(self.type, self.payload)

    @property
    def type_name(self) -> str:
        return account_type_name(self.type)


def _zbc_form(a: str) -> ParsedAddress:
    d = decode_zbc_address(a)
    if d is None:
        raise ValueError("invalid ZooBC address checksum")
    return ParsedAddress(DATASET if d[0] == "ZBS" else ZOOBC, d[1], a)


def _hinted(a: str, hint: str) -> ParsedAddress:
    if hint == "eth":
        h = a[2:] if a[:2] in ("0x", "0X") else a
        if not is_hex(h, 40):
            raise ValueError("not a 20-byte Ethereum address")
        return ParsedAddress(ETHEREUM, bytes.fromhex(h), a)
    if hint == "sol":
        d = base58_decode(a)
        if d is None or len(d) != 32:
            raise ValueError("not a 32-byte Solana address")
        return ParsedAddress(SOLANA, d, a)
    if hint == "dot":
        ss = ss58_decode(a)
        if ss is None:
            raise ValueError("not a valid SS58 address")
        return ParsedAddress(POLKADOT, ss[1], a)
    if hint in ("zbc", "zbs"):
        return _zbc_form(a)
    return _auto(a)


def _auto(a: str) -> ParsedAddress:
    if len(a) == 42 and a[:2] in ("0x", "0X") and is_hex(a[2:], 40):
        return ParsedAddress(ETHEREUM, bytes.fromhex(a[2:]), a)
    if len(a) > 4 and a[3] in "_-":
        return _zbc_form(a)
    low5 = a[:5].lower()
    if low5.startswith(("bc1", "tb1", "bcrt1")):
        d = segwit_decode(a)
        if d is None:
            raise ValueError("invalid Bitcoin bech32 address")
        _, version, prog = d
        if version == 0 and len(prog) == 20:
            return ParsedAddress(BITCOIN_P2WPKH, prog, a)
        if version == 0 and len(prog) == 32:
            return ParsedAddress(BITCOIN_P2WSH, prog, a)
        if version == 1 and len(prog) == 32:
            return ParsedAddress(BITCOIN_TAPROOT, prog, a)
        raise ValueError("unsupported Bitcoin witness program")
    if a[0] in "13" and 26 <= len(a) <= 35:
        raw = base58_decode(a)
        if raw is not None and len(raw) == 25:
            body = base58check_decode(a)
            if body is not None and len(body) == 21:
                if body[0] == 0x00:
                    return ParsedAddress(BITCOIN_P2PKH, body[1:], a)
                if body[0] == 0x05:
                    return ParsedAddress(BITCOIN_P2SH, body[1:], a)
    if len(a) > 5 and a[:5].lower() == "addr1":
        d = bech32_decode_plain(a)
        if d is not None and d[0] == "addr" and len(d[1]) == 29 and d[1][0] == 0x61:
            return ParsedAddress(CARDANO, d[1][1:], a)
        raise ValueError("invalid Cardano address (expected a mainnet enterprise addr1… address)")
    if a[0] == "T" and len(a) == 34:
        body = base58check_decode(a)
        if body is not None and len(body) == 21 and body[0] == 0x41:
            return ParsedAddress(TRON, body[1:], a)
        raise ValueError("invalid Tron address")
    if a[0] == "r" and 25 <= len(a) <= 35:
        body = base58check_decode(a, RIPPLE_ALPHABET)
        if body is not None and len(body) == 21 and body[0] == 0x00:
            return ParsedAddress(RIPPLE, body[1:], a)
        raise ValueError("invalid Ripple address")
    if a.startswith("tz1"):
        body = base58check_decode(a)
        if body is not None and len(body) == 23 and body[:3] == b"\x06\xa1\x9f":
            return ParsedAddress(TEZOS, body[3:], a)
        raise ValueError("invalid Tezos address")
    ss = ss58_decode(a)
    if ss is not None and len(ss[1]) == 32:
        return ParsedAddress(POLKADOT, ss[1], a)
    if 32 <= len(a) <= 44:
        d = base58_decode(a)
        if d is not None and len(d) == 32:
            return ParsedAddress(SOLANA, d, a)
    if is_hex(a, 64):
        key = bytes.fromhex(a)
        return ParsedAddress(ZOOBC, key, encode_zbc_address(key, "ZBC"))
    raise ValueError("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos")


def parse_address(text: str, chain: str = "") -> ParsedAddress:
    """Read a recipient in the order of spec/addresses.md section 3; `chain` forces one reading (--chain)."""
    a = text.strip()
    if not a:
        raise ValueError("empty address")
    if chain:
        hint = CHAINS.get(chain.lower())
        if hint is None:
            raise ValueError("unknown chain %s" % chain)
        try:
            return _hinted(a, hint)
        except ValueError:
            up = a.upper()
            plain = ((len(a) == 42 and a[:2] in ("0x", "0X")) or up.startswith(("ZBC", "ZNK", "ZBS")) or a[0] in "13"
                     or a[:5].lower().startswith(("bc1", "tb1", "bcrt1")) or len(a) == 64)
            if not plain:
                raise
            return _auto(a)
    return _auto(a)


def parse_key32(text: str) -> bytes:
    """A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address; 32 bytes."""
    if len(text) == 66 and text[3] == "_":
        d = decode_zbc_address(text)
        if d is None:
            raise ValueError("invalid address checksum")
        return d[1]
    h = text[2:] if text[:2] in ("0x", "0X") else text
    if not is_hex(h, 64):
        raise ValueError("key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address")
    return bytes.fromhex(h)
