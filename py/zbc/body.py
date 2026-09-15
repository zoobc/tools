# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Parameter validation and the generic body serialiser driven by spec/transactions (encodings of index.json)."""
import re
import struct
from typing import Dict, List, Optional

from .address import is_hex, parse_address, parse_key32
from .errors import usage
from .keys import KeyPair, key_pair
from .transaction import u64

_LIMITS = {"int64": (-(1 << 63), (1 << 63) - 1), "uint64": (0, (1 << 64) - 1), "uint32": (0, (1 << 32) - 1), "uint8": (0, 255)}


def parse_integer(value: str, kind: str, name: str) -> int:
    if not re.match(r"^-?\d+$", value.strip()):
        raise usage('%s must be a whole number, got "%s"' % (name, value))
    v = int(value)
    lo, hi = _LIMITS.get(kind, _LIMITS["int64"])
    if v < lo or v > hi:
        raise usage("%s is out of range for %s" % (name, kind))
    return v


def split_list(s: str) -> List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def validate_param(p: dict, value: str) -> str:
    kind, name = p["kind"], p["name"]
    if kind == "privkey":
        if not is_hex(value, 64):
            raise usage("%s must be 64 hex characters (a 32-byte private key)" % name)
    elif kind == "address":
        try:
            parse_address(value)
        except ValueError as e:
            raise usage("invalid %s: %s" % (name, e))
    elif kind == "address_list":
        for a in split_list(value):
            try:
                parse_address(a)
            except ValueError as e:
                raise usage("invalid %s entry %s: %s" % (name, a, e))
    elif kind == "key":
        try:
            parse_key32(value)
        except ValueError as e:
            raise usage("invalid %s: %s" % (name, e))
    elif kind in _LIMITS:
        n = parse_integer(value, kind, name)
        if ("min" in p and n < p["min"]) or ("max" in p and n > p["max"]):
            raise usage("%s must be between %s and %s" % (name, p.get("min", "-inf"), p.get("max", "inf")))
        return value.strip()
    elif kind == "hex32":
        if not is_hex(value, 64):
            raise usage("%s must be 64 hex characters (32 bytes)" % name)
    elif kind == "hexbytes":
        if not is_hex(value):
            raise usage("%s must be hex" % name)
    return value


def _holds(when: str, params: Dict[str, str]) -> bool:
    m = re.match(r"^(\w+) != (0|'')$", when)
    if not m:
        raise ValueError("unsupported condition " + when)
    v = params.get(m.group(1), "")
    return int(v or "0") != 0 if m.group(2) == "0" else v != ""


def encode_field(f: dict, params: Dict[str, str], sender: KeyPair, files: Optional[Dict[str, bytes]] = None,
                 computed: Optional[Dict[str, bytes]] = None) -> bytes:
    if computed and f["name"] in computed:
        return computed[f["name"]]
    enc, src = f["encoding"], f["from"]
    value = params.get(src, "")
    if f.get("when_zero") and (value == "" or int(value) <= 0):
        value = params.get(f["when_zero"], "0")
    if enc == "u8":
        return bytes([parse_integer(value, "uint8", f["name"])])
    if enc == "u16le":
        return struct.pack("<H", parse_integer(value, "uint32", f["name"]))
    if enc == "u32le":
        return struct.pack("<I", parse_integer(value, "uint32", f["name"]))
    if enc == "u64le":
        return u64(parse_integer(value, "int64", f["name"]))
    if enc == "hex":
        b = bytes.fromhex(value)
        if "size" in f and len(b) != f["size"]:
            raise usage("%s must be %d bytes (%d hex)" % (src, f["size"], 2 * f["size"]))
        return b
    if enc == "hex16":
        b = bytes.fromhex(value)
        return struct.pack("<H", len(b)) + b
    if enc == "bytes32":
        b = files[src] if files and src in files else bytes.fromhex(value)
        return struct.pack("<I", len(b)) + b
    if enc == "str16":
        b = value.encode()
        return struct.pack("<H", len(b)) + b
    if enc == "str32":
        b = value.encode()
        return struct.pack("<I", len(b)) + b
    if enc == "address":
        return parse_address(value).bytes
    if enc == "address_list":
        return b"".join(parse_address(a).bytes for a in split_list(value))
    if enc == "address_list8":
        items = split_list(value)
        if len(items) > 255:
            raise usage("%s: at most 255 entries" % src)
        return bytes([len(items)]) + b"".join(parse_address(a).bytes for a in items)
    if enc == "sender_address":
        return sender.account_bytes
    if enc == "pubkey_of_key":
        if not is_hex(value, 64):
            raise usage("%s must be 64 hex characters (a 32-byte private key)" % src)
        return key_pair(value).public_key
    if enc == "key32":
        return parse_key32(value)
    if enc == "literal":
        return bytes.fromhex(f.get("value", ""))
    if enc == "custom":
        raise ValueError("field %s needs a custom hook" % f["name"])
    raise ValueError("unknown encoding " + enc)


def build_body(spec: dict, params: Dict[str, str], sender: KeyPair, files: Optional[Dict[str, bytes]] = None,
               computed: Optional[Dict[str, bytes]] = None) -> bytes:
    """The whole body of a non-custom transaction; `computed` carries what custom hooks produced."""
    out = b""
    for f in spec["body"]:
        if f.get("when") and not _holds(f["when"], params):
            continue
        out += encode_field(f, params, sender, files, computed)
    return out
