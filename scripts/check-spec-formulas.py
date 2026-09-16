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

# signing.md 8: sealed messages. A standard-library rendering of the formulas (X25519 ladder, HSalsa20, XSalsa20,
# Poly1305, the Ed25519 -> X25519 conversions) applied to encryption.json.
enc = json.load(open(V / "encryption.json"))
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

MAGIC = b"ZBE1"
def seal(plaintext: bytes, recipient_ed25519_pk: bytes, ephemeral_sk: bytes) -> bytes:
    rpk = ed25519_pk_to_x25519(recipient_ed25519_pk); epk = x25519_base(ephemeral_sk)
    nonce = blake2b_24(epk + rpk)
    return MAGIC + epk + secretbox(box_key(ephemeral_sk, rpk), nonce, plaintext)

def open_sealed(field: bytes, recipient_seed: bytes):
    if len(field) < 4 + 48 or field[:4] != MAGIC: return None
    sk = ed25519_seed_to_x25519(recipient_seed); pk = x25519_base(sk); epk = field[4:36]
    return secretbox_open(box_key(sk, epk), blake2b_24(epk + pk), field[36:])


check("signing.md 8: recipient_pk_x = (1 + y) / (1 - y) mod p, recipient_sk_x = clamp(SHA-512(seed)[0..32]), X25519(sk, 9) = pk",
      all(ed25519_pk_to_x25519(bytes.fromhex(k["public_key"])).hex() == k["x25519_public_key"] and ed25519_seed_to_x25519(bytes.fromhex(k["seed"])).hex() == k["x25519_secret_key"]
          and x25519_base(bytes.fromhex(k["x25519_secret_key"])).hex() == k["x25519_public_key"] for k in enc["keys"]))
check("signing.md 8: e_pk = X25519(e_sk, 9), nonce = BLAKE2b-24(e_pk || recipient_pk_x)",
      all(x25519_base(bytes.fromhex(s["ephemeral_secret_key"])).hex() == s["ephemeral_public_key"]
          and blake2b_24(bytes.fromhex(s["ephemeral_public_key"]) + ed25519_pk_to_x25519(bytes.fromhex(s["recipient_public_key"]))).hex() == s["nonce"] for s in enc["sealed"]))
check("signing.md 8: message_field = 'ZBE1' || e_pk || XSalsa20-Poly1305(HSalsa20(X25519(e_sk, recipient_pk_x)), nonce, plaintext)",
      all(seal(bytes.fromhex(s["plaintext_hex"]), bytes.fromhex(s["recipient_public_key"]), bytes.fromhex(s["ephemeral_secret_key"])).hex() == s["message_field"] for s in enc["sealed"]))
check("signing.md 8: the recipient's converted key opens every sealed vector and every field the C++ tool sealed",
      all(open_sealed(bytes.fromhex(s["message_field"]), bytes.fromhex(s["recipient_seed"])) == bytes.fromhex(s["plaintext_hex"]) for s in enc["sealed"] + enc["samples"]))
check("encryption.json: every invalid case fails to open", all(open_sealed(bytes.fromhex(i["message_field"]), bytes.fromhex(i["recipient_seed"])) is None
                                                             for i in enc["invalid"] if all(c in "0123456789abcdef" for c in i["message_field"])))

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
