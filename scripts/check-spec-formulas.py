#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Check that the formulas and byte layouts written in spec/*.md and spec/transactions/*.json
reproduce what the C++ tools printed into spec/vectors. Python standard library only, except the
Ed25519 checks, which run when the `cryptography` package is installed and are skipped otherwise.

    python3 scripts/check-spec-formulas.py
"""
import base64, hashlib, hmac, json, pathlib, struct, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
V = ROOT / "spec" / "vectors"
keys = json.load(open(V / "keys.json")); msgs = json.load(open(V / "messages.json"))
txs = json.load(open(V / "transactions.json"))["vectors"]; alls = json.load(open(V / "transactions-all.json"))["vectors"]
addrs = json.load(open(V / "addresses.json"))["vectors"]
SPECS = {f.stem: json.loads(f.read_text()) for f in (ROOT / "spec" / "transactions").glob("*.json") if f.stem != "index"}
ok = True
def check(name, cond, detail=""):
    global ok
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else "  " + detail)); ok = ok and bool(cond)

# addresses.md 2: the ZBC_/ZNK_ text form
def zbc_encode(pub, prefix):
    c = hashlib.sha3_256(bytes.fromhex(pub) + prefix.encode()).digest()[:3]
    b32 = base64.b32encode(bytes.fromhex(pub) + c).decode().rstrip("=")
    return prefix + "_" + "_".join(b32[i:i + 8] for i in range(0, 56, 8))
check("addresses.md 2: ZBC_/ZNK_ = prefix + base32(pubkey || SHA3-256(pubkey||prefix)[0..3]) in 7 groups",
      all(zbc_encode(s["public_key"], "ZBC") == s["address"] and zbc_encode(s["public_key"], "ZNK") == s["node_address"] for s in keys["seeds"]))
check("addresses.md 1: a ZooBC recipient's typed bytes are 00000000 || key",
      all(a["address_bytes"] == "00000000" + a["address_bytes"][8:] and len(a["address_bytes"]) == 72 for a in addrs if a["valid"] and a["account_type"] == 0))

# signing.md 1: keys and HD wallets
def slip10(mnemonic, passphrase, index):
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048, 64)
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest(); k, c = I[:32], I[32:]
    for i in (44, 883, index):
        I = hmac.new(c, b"\x00" + k + struct.pack(">I", i + 0x80000000), hashlib.sha512).digest(); k, c = I[:32], I[32:]
    return k.hex()
check("signing.md 1: BIP-39 (PBKDF2 2048, 'mnemonic'+passphrase) -> SLIP-10 ed25519 m/44'/883'/i'",
      all(slip10(w["mnemonic"], w["passphrase"], a["index"]) == a["seed"] for w in keys["wallets"] for a in w["accounts"]))
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    def pub(seed):
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    def sign(seed, digest):
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(digest).hex()
    check("signing.md 1: public key = Ed25519 public key of the seed", all(pub(s["seed"]) == s["public_key"] for s in keys["seeds"]))
    check("signing.md 5: message signature = Ed25519(seed, digest)", all(sign(m["seed"], bytes.fromhex(m["digest"])) == m["signature"] for m in msgs["vectors"]))
    check("signing.md 4: transaction signature = Ed25519(seed, digest)", all(sign(v["key"], bytes.fromhex(v["expected"]["digest"])) == v["expected"]["signature"] for v in txs + alls))
except ImportError:
    print("skip  Ed25519 checks: pip install cryptography to run them")

# signing.md 5: ZBC-MSG-v1
check("signing.md 5: digest = SHA3-256('ZBC-MSG' || message)", all(hashlib.sha3_256(b"ZBC-MSG" + bytes.fromhex(m["message_hex"])).hexdigest() == m["digest"] for m in msgs["vectors"]))
check("messages.json: message_hex is the UTF-8 of message", all(m["hex_input"] or bytes.fromhex(m["message_hex"]).decode() == m["message"] for m in msgs["vectors"]))

# signing.md 2-4: envelope, escrow block, digest, hash
def digest(v):
    u = bytes.fromhex(v["expected"]["unsigned_bytes"])
    return hashlib.sha3_256(u if v["genesis"] == "v1" else b"ZBC-TX" + bytes.fromhex(v["genesis"]) + u).hexdigest()
check("signing.md 4: digest = SHA3-256('ZBC-TX' || genesis || unsigned), or SHA3-256(unsigned) for v1", all(digest(v) == v["expected"]["digest"] for v in txs + alls))
check("signing.md 2: transaction_bytes = unsigned || signature, transaction_hash = SHA3-256(transaction_bytes)",
      all(v["expected"]["transaction_bytes"] == v["expected"]["unsigned_bytes"] + v["expected"]["signature"]
          and hashlib.sha3_256(bytes.fromhex(v["expected"]["transaction_bytes"])).hexdigest() == v["expected"]["transaction_hash"] for v in txs + alls))
def envelope(v):
    p = v["expected"]["payload"]
    b = struct.pack("<I", p["transaction_type"]) + b"\x01" + struct.pack("<q", p["timestamp"]) + b"\0\0\0\0" + bytes.fromhex(p["sender_account_address"])
    r = p["recipient_account_address"]
    b += b"\x02\0\0\0" if r == "" else (b"\0\0\0\0" + bytes.fromhex(r) if len(r) == 64 else bytes.fromhex(r))
    b += struct.pack("<q", p["fee"]) + struct.pack("<I", len(p["transaction_body_bytes"]) // 2) + bytes.fromhex(p["transaction_body_bytes"])
    if "escrow" in p:
        e = p["escrow"]; ins = e.get("instruction", "").encode()
        b += bytes.fromhex(e["approver_address"]) + struct.pack("<qq", e["commission"], e["timeout"]) + struct.pack("<I", len(ins)) + ins + b"\x00"
    else:
        b += b"\x02\0\0\0"
    m = bytes.fromhex(p.get("message_hex", "")); b += struct.pack("<I", len(m)) + m
    return b.hex()
check("signing.md 2-3 and api.md 2: the envelope rebuilt from the submit payload is unsigned_bytes, for every vector",
      all(envelope(v) == v["expected"]["unsigned_bytes"] for v in txs + alls))

# spec/transactions: every generic body layout rebuilds the C++ body from the example parameters
KEYS = {s["seed"]: s for s in keys["seeds"]}
ADDR = {a["input"]: a for a in addrs if a["valid"] and "chain" not in a}
def typed_addr(text):
    if text in ADDR: return bytes.fromhex(ADDR[text]["address_bytes"])
    if len(text) == 64: return b"\0\0\0\0" + bytes.fromhex(text)
    raise KeyError("no address vector for " + text)
def body_of(spec, v, files):
    P = v["params"]; out = b""
    for f in spec["body"]:
        if f.get("computed") and f["encoding"] not in ("sender_address", "pubkey_of_key", "bytes32"): continue
        enc, val = f["encoding"], P.get(f["from"], "")
        if f.get("when"):
            name, _, rhs = f["when"].partition(" != "); rv = P.get(name, "")
            if (rhs == "0" and int(rv or 0) == 0) or (rhs == "''" and rv == ""): continue
        if f.get("when_zero") and int(val or 0) <= 0: val = P[f["when_zero"]]
        if enc == "u8": out += bytes([int(val)])
        elif enc == "u16le": out += struct.pack("<H", int(val))
        elif enc == "u32le": out += struct.pack("<I", int(val))
        elif enc == "u64le": out += struct.pack("<q", int(val))
        elif enc == "hex": out += bytes.fromhex(val)
        elif enc == "hex16": out += struct.pack("<H", len(val) // 2) + bytes.fromhex(val)
        elif enc == "str32": out += struct.pack("<I", len(val.encode())) + val.encode()
        elif enc == "str16": out += struct.pack("<H", len(val.encode())) + val.encode()
        elif enc == "bytes32":
            raw = bytes.fromhex(files[f["from"]]); out += struct.pack("<I", len(raw)) + raw
        elif enc == "address": out += typed_addr(val)
        elif enc == "address_list8":
            items = [x for x in val.split(",") if x]; out += bytes([len(items)]) + b"".join(typed_addr(x) for x in items)
        elif enc == "sender_address": out += b"\0\0\0\0" + bytes.fromhex(KEYS[v["key"]]["public_key"])
        elif enc == "pubkey_of_key": out += bytes.fromhex(KEYS[val]["public_key"])
        elif enc == "key32": out += bytes.fromhex(val)
        elif enc == "literal": out += bytes.fromhex(f["value"])
        else: raise ValueError(enc)
    return out.hex()
bad = []
for v in alls:
    spec = SPECS[v["command"]]
    if spec["custom"]: continue
    try:
        b = body_of(spec, v, v.get("files", {}))
    except Exception as e:
        bad.append("%s: %s" % (v["name"], e)); continue
    exp = v["expected"]["body"]
    if spec["command"] == "store-file":   # piece_count is computed: check around it
        n = len(v["params"]["piece_ids"]) // 64; exp_no_count = exp[:2 * 52] + exp[2 * 56:]
        if b != exp_no_count or struct.unpack("<I", bytes.fromhex(exp[2 * 52:2 * 56]))[0] != n: bad.append(v["name"])
    elif b != exp: bad.append("%s: %s != %s" % (v["name"], b[:80], exp[:80]))
n_generic = sum(1 for v in alls if not SPECS[v["command"]]["custom"])
check("spec/transactions: the generic layouts rebuild the C++ body for all %d non-custom vectors" % n_generic, not bad, "; ".join(bad))
print("ALL FORMULAS MATCH THE C++ OUTPUT" if ok else "SOME CHECKS FAILED"); sys.exit(0 if ok else 1)
