#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Generate spec/vectors/*.json by running the C++ reference tools.

    python3 scripts/make-vectors.py [--bin cpp/build] [--out spec/vectors] [--check]

Every value in the vectors is what the C++ tools printed; nothing is computed here. --check
regenerates into a temporary directory and fails if any file differs from the committed one,
which is what CI runs. A tiny local HTTP server stands in for a node during the three
node-registration commands, whose proof of ownership needs a reference block.
"""
import argparse, json, os, pathlib, shutil, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
GENESIS = "cf30b4a8c165da3bc004b3a397b18c68986271b0395f9df0e984552fb455cf1d"   # devnet, signing v2
GENESIS_B = "090ab3c7e0ce0630f9b6a3d9694dc4d2d5e1ccd018352ef27de6cd8de0a61878" # reference chain R
FEE = 5000000
T0 = 1700000000
SEED_V = "51bae95d58f32304a5c9d894819989a4fb04da6115d9a43612a026e7a5dd5d96"   # vector wallet account 0
SEED_1 = "11" * 32
SEED_2 = "22" * 32
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
A_V = "ZBC_L2HLFDOM_VKKKTEXX_C2P2M6LG_EB6ZNKSV_356SJUWW_5QPVHDE7_EFJA3PEX"
A_1 = "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I"
V_SIG_1 = "4cdf8cafca5d06dd6c81c5460c9affec7eada96a63943e485b673ae33da6330570885a8b3f5dd752cbbe2b4404ae9402cdd2f6c36a09941e5d8546dbdd4ef10b"  # sign-message(SEED_1, "hello zoobc")
REF_BLOCK = {"block_hash": "5a" * 32, "height": 1000}

BIN = None
def run(args, stdin=None):
    env = dict(os.environ)
    for k in ("ZBC_KEY", "ZBC_API", "ZBC_TIMEOUT", "ZOOBC_GENESIS_HASH"): env.pop(k, None)
    p = subprocess.run(args, input=stdin, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr
def cli(*args, stdin=None):
    return run([str(BIN / "zbc-cli"), *args], stdin=stdin)
def must_json(rc, out, err, what):
    if rc != 0:
        sys.exit("%s: exit %d\n%s\n%s" % (what, rc, out, err))
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        sys.exit("%s: not JSON:\n%s" % (what, out))

# ---------------------------------------------------------------- keys ----------------------
def keys_vectors():
    seeds = [SEED_V, SEED_1, SEED_2, "00" * 31 + "01", "ff" * 32,
             "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"]  # RFC 8032 test 1 seed
    out = []
    for s in seeds:
        a = must_json(*run([str(BIN / "zbc-account-from-key"), s]), "account-from-key")
        n = must_json(*run([str(BIN / "zbc-node-from-key"), s]), "node-from-key")
        assert a["public_key"] == n["public_key"]
        out.append({"seed": s, "public_key": a["public_key"], "address": a["account_address"], "node_address": n["node_address"]})
    wallets = []
    for passphrase in ("", "TREZOR"):
        args = [str(BIN / "zbc-wallet-gen"), "--mnemonic", MNEMONIC, "--count", "3"]
        if passphrase: args += ["--password", passphrase]
        w = must_json(*run(args), "wallet-gen")
        wn = must_json(*run(args + ["--node"]), "wallet-gen --node")
        accts = []
        for a, n in zip(w["accounts"], wn["accounts"]):
            assert a["private_key"] == n["private_key"]
            accts.append({"index": a["account"], "path": a["path"], "seed": a["private_key"], "public_key": a["public_key"],
                          "address": a["address"], "node_address": n["address"]})
        wallets.append({"mnemonic": MNEMONIC, "passphrase": passphrase, "accounts": accts})
    return {"description": "Ed25519 seed -> public key -> ZBC_ account address and ZNK_ node address (signing.md 1, addresses.md 2); "
                           "BIP-39 mnemonic + passphrase -> SLIP-10 m/44'/883'/<index>' accounts.",
            "seeds": out, "wallets": wallets}

# ---------------------------------------------------------------- addresses -----------------
def bech32_encode(hrp, data):
    """Plain bech32 (BIP 173) of raw bytes, used only to build one Cardano input string."""
    CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    bits = "".join(f"{b:08b}" for b in data); bits += "0" * (-len(bits) % 5)
    d = [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]
    G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    def polymod(v):
        c = 1
        for x in v:
            b = c >> 25; c = ((c & 0x1ffffff) << 5) ^ x
            for k in range(5):
                if (b >> k) & 1: c ^= G[k]
        return c
    hrpx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = polymod(hrpx + d + [0] * 6) ^ 1
    return hrp + "1" + "".join(CS[x] for x in d) + "".join(CS[(pm >> 5 * (5 - i)) & 31] for i in range(6))

ADDRESS_INPUTS = [
    A_V, A_1, A_1.lower(), A_1.replace("_", "-"), "ZBC-2BFLEMTU_FO2KWOQT-NC6UMFPE_43ICESVX-DIAWXL4F_ECRTFSLX-Q43UIV2I",
    "ZNK_" + A_1[4:],                       # ZBC_ body behind a ZNK_ prefix: bad checksum (the prefix is hashed)
    "ZNK_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43WTXZ7",   # genuine ZNK_ form of seed 11..11: same key, type 0
    "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2J",   # last char changed: bad checksum
    "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX",            # too short
    "5e8eb28dccaa94a992f7169fa67966207d96aa55df7d24d2d6ec1f538c9f2152",     # 64 hex = raw ZooBC key
    "5E8EB28DCCAA94A992F7169FA67966207D96AA55DF7D24D2D6EC1F538C9F2152",
    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "0xd8da6bf26964af9d7eed9e03e53415d37aa96045", "d8da6bf26964af9d7eed9e03e53415d37aa96045",
    "0x1234",                                                              # not an address
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    "11111111111111111111111111111111", "So11111111111111111111111111111111111111112",
    "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8", "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH", "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
    "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps",       # not a valid enterprise address
    bech32_encode("addr", bytes([0x61]) + bytes(range(1, 29))),            # a valid one: header 0x61 + 28-byte key hash
    "", "hello", "ZBC_",
    # the 59-character rule (addresses.md 2): separators and whitespace are cosmetic, case is free
    A_V.replace("_", ""), A_1.replace("_", "").lower(), "ZBS" + A_V[3:].replace("_", ""),
    A_V[:28] + " " + A_V[28:], A_V.replace("_", "\t"), "  " + A_V.replace("_", "-") + "\n",
    "ZNK" + A_V[3:].replace("_", ""),                                       # bare form is ZooBC only behind ZBC/ZBS: bad checksum anyway
    "zbc" + A_V[3:].replace("_", "").lower()[:55] + "8",                   # bare form with a character outside base32
    A_V.replace("_", "")[:58],                                             # 58 significant characters
]
def decode_recipient(unsigned_hex):
    """Recipient field of the envelope: offset 4+1+8+36 = 49; type int32 LE then the payload."""
    b = bytes.fromhex(unsigned_hex)
    t = int.from_bytes(b[49:53], "little", signed=True)
    sizes = {0: 32, 1: 20, 4: 20, 5: 20, 6: 20, 7: 20, 8: 32, 9: 32, 10: 32, 11: 32, 12: 32, 13: 28, 14: 20, 15: 20, 16: 20}
    n = sizes[t]
    return t, b[49:53 + n].hex()
def addresses_vectors():
    out = []
    for a in ADDRESS_INPUTS:
        rc, o, e = cli("send-zbc", SEED_V, a, "1", "--fee", "1", "--timestamp", "1", "--genesis", "v1", "--offline")
        if rc == 0:
            j = json.loads(o); t, typed = decode_recipient(j["unsigned_bytes"])
            # zbc-send (the standalone) also names the type; same decoder, so the bytes must agree
            k = must_json(*run([str(BIN / "zbc-send"), SEED_V, a, "1", "--fee", "1", "--timestamp", "1", "--genesis", "v1", "--offline"]), "zbc-send " + a)
            assert k["unsigned_bytes"] == j["unsigned_bytes"], a
            out.append({"input": a, "valid": True, "account_type": t, "address_bytes": typed, "type_label": k["recipient_type"], "display": k["recipient"]})
        else:
            j = json.loads(o) if o.strip().startswith("{") else {}
            out.append({"input": a, "valid": False, "exit_code": rc, "error_class": j.get("error_class")})
    for chain, a in [("eth", "d8da6bf26964af9d7eed9e03e53415d37aa96045"), ("zbc", "5e8eb28dccaa94a992f7169fa67966207d96aa55df7d24d2d6ec1f538c9f2152"),
                     ("sol", "11111111111111111111111111111111"), ("btc", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")]:
        rc, o, e = cli("send-zbc", SEED_V, a, "1", "--chain", chain, "--fee", "1", "--timestamp", "1", "--genesis", "v1", "--offline")
        if rc == 0:
            j = json.loads(o); t, typed = decode_recipient(j["unsigned_bytes"])
            k = must_json(*run([str(BIN / "zbc-send"), SEED_V, a, "1", "--chain", chain, "--fee", "1", "--timestamp", "1", "--genesis", "v1", "--offline"]), "zbc-send --chain " + a)
            assert k["unsigned_bytes"] == j["unsigned_bytes"], a
            out.append({"input": a, "chain": chain, "valid": True, "account_type": t, "address_bytes": typed, "type_label": k["recipient_type"], "display": k["recipient"]})
        else:
            j = json.loads(o) if o.strip().startswith("{") else {}
            out.append({"input": a, "chain": chain, "valid": False, "exit_code": rc, "error_class": j.get("error_class")})
    return {"description": "What parse_address (addresses.md 3) makes of each input as a send-zbc recipient: valid or not, the account type and "
                           "the full typed address bytes (4-byte type LE + payload). `chain` = the --chain option. Produced by zbc-cli send-zbc --offline.",
            "vectors": out}

# ---------------------------------------------------------------- messages ------------------
def messages_vectors():
    cases = [(SEED_1, "hello zoobc", False), (SEED_V, "", False), (SEED_V, "héllo ✓ zoobc", False), (SEED_2, "00ff10", True), (SEED_2, "", True),
             (SEED_V, "The quick brown fox jumps over the lazy dog", False)]
    out = []
    for seed, msg, hexin in cases:
        args = ["sign-message", seed, msg] + (["--hex"] if hexin else [])
        j = must_json(*cli(*args), "sign-message")
        v = must_json(*cli("verify-message", j["address"], msg, j["signature"], *(["--hex"] if hexin else [])), "verify-message")
        assert v["valid"] is True and v["exit_code"] == 0
        out.append({"seed": seed, "message": None if hexin else msg, "message_hex": j["message_hex"], "hex_input": hexin,
                    "address": j["address"], "public_key": j["public_key"], "digest": j["digest"], "signature": j["signature"], "scheme": j["scheme"]})
    v0 = out[0]
    neg = []
    for name, addr, msg, sig in [("tampered message", v0["address"], "hello zoobd", v0["signature"]),
                                 ("other signer", out[1]["address"], "hello zoobc", v0["signature"]),
                                 ("corrupted signature", v0["address"], "hello zoobc", "00" + v0["signature"][2:])]:
        rc, o, e = cli("verify-message", addr, msg, sig)
        j = json.loads(o)
        neg.append({"case": name, "address": addr, "message": msg, "signature": sig, "valid": j["valid"], "exit_code": rc, "error_class": j["error_class"]})
    for name, addr, msg, sig, code in [("signature not hex", v0["address"], "hello zoobc", "zz" * 64, 2),
                                       ("signature wrong length", v0["address"], "hello zoobc", "00" * 63, 2),
                                       ("address not ZBC", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "hello zoobc", v0["signature"], 2)]:
        rc, o, e = cli("verify-message", addr, msg, sig)
        neg.append({"case": name, "address": addr, "message": msg, "signature": sig, "valid": False, "exit_code": rc, "error_class": json.loads(o)["error_class"]})
    return {"description": "ZBC-MSG-v1 (signing.md 5): digest = SHA3-256('ZBC-MSG' || message), signature = Ed25519(seed, digest). "
                           "`hex_input` = the message was given as hex bytes. `invalid` lists verify-message outcomes that must fail.",
            "vectors": out, "invalid": neg}

# ---------------------------------------------------------------- encryption ----------------
# The sealed-message construction (signing.md 9) is libsodium's crypto_box_seal, which draws a random
# ephemeral key, so the tools' own output cannot be compared byte for byte. The `sealed` vectors are
# therefore built by libsodium itself (the library the tools link) with a FIXED ephemeral key, opened
# back by libsodium and by the C++ tool; the `samples` are the tools' own random-key output, which every
# implementation must open. --check ignores the samples (they differ on every run) and re-checks the rest.
def _sodium():
    import ctypes, ctypes.util
    lib = ctypes.CDLL(ctypes.util.find_library("sodium") or "libsodium.so.23")
    assert lib.sodium_init() >= 0
    return lib

def encryption_vectors():
    import ctypes
    lib = _sodium()
    def buf(n): return ctypes.create_string_buffer(max(n, 1))
    def convert(seed_hex):
        edpk, edsk, xpk, xsk = buf(32), buf(64), buf(32), buf(32)
        assert lib.crypto_sign_seed_keypair(edpk, edsk, bytes.fromhex(seed_hex)) == 0
        assert lib.crypto_sign_ed25519_pk_to_curve25519(xpk, edpk) == 0 and lib.crypto_sign_ed25519_sk_to_curve25519(xsk, edsk) == 0
        return edpk.raw, xpk.raw, xsk.raw
    keys = []
    for seed in (SEED_V, SEED_1, SEED_2):
        edpk, xpk, xsk = convert(seed)
        keys.append({"seed": seed, "public_key": edpk.hex(), "x25519_public_key": xpk.hex(), "x25519_secret_key": xsk.hex()})
    sealed = []
    for name, seed, pt, esk_hex in [("text", SEED_1, b"hello sealed", "22" * 32), ("empty", SEED_1, b"", "33" * 32),
                                    ("utf8", SEED_V, "h\u00e9llo \u2713 sealed".encode(), "44" * 32), ("binary-64", SEED_2, bytes(range(64)), "55" * 32),
                                    ("plain-256", SEED_V, bytes([0x5a]) * 256, "66" * 32)]:
        edpk, xpk, xsk = convert(seed)
        esk = bytes.fromhex(esk_hex); epk, nonce, c = buf(32), buf(24), buf(len(pt) + 16)
        assert lib.crypto_scalarmult_base(epk, esk) == 0
        assert lib.crypto_generichash(nonce, 24, epk.raw + xpk, 64, None, 0) == 0
        assert lib.crypto_box_easy(c, pt, len(pt), nonce, xpk, esk) == 0
        field = b"ZBE1" + epk.raw + c.raw[:len(pt) + 16]
        out = buf(len(pt))
        assert lib.crypto_box_seal_open(out, field[4:], len(field) - 4, xpk, xsk) == 0 and out.raw[:len(pt)] == pt   # libsodium opens its own construction
        j = must_json(*cli("decrypt-message", seed, field.hex()), "decrypt-message " + name)                            # and so does the C++ tool
        assert j["message_hex"] == pt.hex(), name
        sealed.append({"name": name, "recipient_seed": seed, "recipient_public_key": edpk.hex(), "plaintext_hex": pt.hex(),
                       "ephemeral_secret_key": esk_hex, "ephemeral_public_key": epk.raw.hex(), "nonce": nonce.raw.hex(), "message_field": field.hex()})
    samples = []
    for name, seed, addr, text in [("send-zbc", SEED_1, A_1, "hello sealed"), ("send-zbc-utf8", SEED_V, A_V, "h\u00e9llo \u2713 sealed")]:
        j = must_json(*cli("send-zbc", SEED_V, addr, "1", "--message", text, "--encrypt", "--genesis", GENESIS, "--timestamp", str(T0), "--offline"), "send-zbc --encrypt")
        field = j["payload"]["message_hex"]
        assert field.startswith("5a424531") and j["message"] == text and len(bytes.fromhex(field)) == len(text.encode()) + 52, name
        assert must_json(*cli("decrypt-message", seed, field), "decrypt-message " + name)["message"] == text
        samples.append({"name": name, "recipient_seed": seed, "recipient_address": addr, "plaintext": text, "plaintext_hex": text.encode().hex(),
                        "message_field": field, "unsigned_bytes": j["unsigned_bytes"], "transaction_hash": j["transaction_hash"]})
    f0 = sealed[0]["message_field"]
    def flip(h, i): return h[:i] + ("00" if h[i:i + 2] != "00" else "01") + h[i + 2:]
    invalid = []
    for name, seed, field, code in [("wrong key", SEED_V, f0, 10), ("tag altered", SEED_1, flip(f0, 8 + 64), 10), ("ciphertext altered", SEED_1, flip(f0, len(f0) - 2), 10),
                                    ("ephemeral key altered", SEED_1, flip(f0, 8), 10), ("box too short", SEED_1, f0[:8 + 64 + 30], 10),
                                    ("not encrypted", SEED_1, b"hello".hex(), 2), ("prefix only", SEED_1, "5a424531", 10), ("not hex", SEED_1, "5a4245zz", 2)]:
        rc, o, e = cli("decrypt-message", seed, field)
        assert rc == code, (name, rc, o, e)
        invalid.append({"case": name, "recipient_seed": seed, "message_field": field, "exit_code": rc, "error_class": json.loads(o)["error_class"]})
    return {"description": "Sealed messages (signing.md 9): 'ZBE1' || crypto_box_seal to the recipient's Curve25519 key converted from the Ed25519 account key. "
                           "`keys`: the conversion. `sealed`: built by libsodium with the given ephemeral secret key, so the field is reproducible; opened by libsodium "
                           "and by zbc-cli decrypt-message. `samples`: fields produced by zbc-cli send-zbc --encrypt --offline (random ephemeral key) that every "
                           "implementation must open. `invalid`: decrypt-message outcomes that must fail with the given exit code.",
            "keys": keys, "sealed": sealed, "samples": samples, "invalid": invalid}

# ---------------------------------------------------------------- transactions --------------
class FakeNode(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = None
        if self.path.endswith("/api/v1/blocks/latest"): body = REF_BLOCK
        elif self.path.endswith("/api/v1/node/info"): body = {"signing_version": 2, "genesis_hash": GENESIS}
        if body is None:
            self.send_response(404); self.end_headers(); return
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)

def transaction_vector(name, spec, params, *, key=SEED_V, fee=FEE, ts=T0, genesis=GENESIS, message=None, escrow=None, extra_args=(), api=None, files=None):
    cmd = spec["command"]
    if spec["binary"] and not spec.get("_cli", True):
        argv = [str(BIN / spec["binary"])]
    else:
        argv = [str(BIN / "zbc-cli"), cmd]
    argv.append(key)
    option_args = []
    for p in spec["params"][1:]:
        v = params.get(p["name"], p.get("default", ""))
        if p["kind"] == "file": v = files[p["name"]]
        if cmd == "liquid-payment" and p["name"] == "token_id":
            # zbc-liquid-pay takes the token as --token; zbc-cli liquid-payment has no token at all
            if int(v or 0) != 0: option_args += ["--token", str(v)]
            continue
        argv.append(str(v))
    argv += option_args
    argv += ["--fee", str(fee), "--timestamp", str(ts), "--genesis", genesis, "--offline"]
    if message is not None: argv += ["--message", message]
    if escrow:
        argv += ["--escrow-approver", escrow["approver"], "--escrow-commission", str(escrow["commission"]), "--escrow-timeout", str(escrow["timeout"])]
        if escrow.get("instruction"): argv += ["--escrow-instruction", escrow["instruction"]]
    if api: argv += ["--api", api]
    argv += list(extra_args)
    j = must_json(*run(argv), name)
    assert j["transaction_type"] == spec["type"], (name, j["transaction_type"], spec["type"])
    rec = {"name": name, "command": cmd, "type": spec["type"], "key": key,
           "params": {p["name"]: str(params.get(p["name"], p.get("default", ""))) for p in spec["params"][1:]},
           "fee": fee, "timestamp": ts, "genesis": genesis, "message": message, "escrow": escrow, "reference_block": REF_BLOCK if api else None,
           "expected": {"body": j["payload"]["transaction_body_bytes"], "unsigned_bytes": j["unsigned_bytes"], "digest": j["digest"],
                        "signature": j["signature"], "transaction_bytes": j["transaction_bytes"], "transaction_hash": j["transaction_hash"],
                        "signing_version": j["signing_version"], "payload": j["payload"]}}
    if files:
        rec["files"] = {k: pathlib.Path(v).read_bytes().hex() for k, v in files.items()}
    return rec

def transactions_vectors():
    rc, listing, _ = cli("list"); assert rc == 0
    cli_commands = {line.split()[0] for line in listing.splitlines() if line.startswith("  ") and line.strip()}
    specs = {}
    for f in sorted((ROOT / "spec" / "transactions").glob("*.json")):
        if f.name == "index.json": continue
        s = json.loads(f.read_text()); s["_cli"] = s["command"] in cli_commands; specs[s["command"]] = s
    core, every = [], []
    send = specs["send-zbc"]; appr = specs["approve-escrow"]
    core.append(transaction_vector("send-zbc/plain", send, {"recipient": A_V, "amount": "100000000"}))
    core.append(transaction_vector("send-zbc/message", send, {"recipient": A_V, "amount": "100000000"}, ts=T0 + 1, message="hello zoobc"))
    core.append(transaction_vector("send-zbc/escrow", send, {"recipient": A_V, "amount": "100000000"}, ts=T0 + 2,
                                   escrow={"approver": A_V, "commission": 1000, "timeout": 720, "instruction": "release on delivery"}))
    core.append(transaction_vector("send-zbc/escrow-no-instruction", send, {"recipient": A_1, "amount": "250000000"}, ts=T0 + 3,
                                   escrow={"approver": A_V, "commission": 0, "timeout": 1800000000, "instruction": ""}))
    core.append(transaction_vector("send-zbc/escrow-and-message", send, {"recipient": A_1, "amount": "250000000"}, ts=T0 + 4, message="invoice 42",
                                   escrow={"approver": A_V, "commission": 5000, "timeout": 1800000000, "instruction": "ship first"}))
    core.append(transaction_vector("send-zbc/other-sender", send, {"recipient": A_V, "amount": "1"}, key=SEED_1, ts=T0 + 5))
    core.append(transaction_vector("send-zbc/large-fee-above-2^53", send, {"recipient": A_V, "amount": "100000000"}, ts=T0 + 6, fee=9007199254740995))
    core.append(transaction_vector("send-zbc/hex-recipient", send, {"recipient": "5e8eb28dccaa94a992f7169fa67966207d96aa55df7d24d2d6ec1f538c9f2152", "amount": "7"}, ts=T0 + 7))
    core.append(transaction_vector("send-zbc/eth-recipient", send, {"recipient": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "amount": "100000000"}, ts=T0 + 8))
    core.append(transaction_vector("send-zbc/signing-v1", send, {"recipient": A_V, "amount": "100000000"}, ts=T0, genesis="v1"))
    core.append(transaction_vector("send-zbc/other-genesis", send, {"recipient": A_V, "amount": "100000000"}, ts=T0, genesis=GENESIS_B))
    core.append(transaction_vector("send-zbc/utf8-message", send, {"recipient": A_V, "amount": "100000000"}, ts=T0 + 9, message="héllo ✓ zoobc"))
    core.append(transaction_vector("approve-escrow/approve", appr, {"approval": "0", "transaction_hash": core[2]["expected"]["transaction_hash"]}, ts=T0 + 10))
    core.append(transaction_vector("approve-escrow/reject", appr, {"approval": "1", "transaction_hash": core[2]["expected"]["transaction_hash"]}, key=SEED_1, ts=T0 + 11))
    core.append(transaction_vector("approve-escrow/expire", appr, {"approval": "2", "transaction_hash": "ab" * 32}, ts=T0 + 12, fee=1000000))

    srv = HTTPServer(("127.0.0.1", 0), FakeNode); port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp()
    try:
        content = pathlib.Path(tmp) / "hello.txt"; content.write_bytes(b"hello zoobc\n")
        for i, (cmd, s) in enumerate(sorted(specs.items())):
            ex = s["example"]
            kw = {"ts": T0 + 100 + i}
            if s["needs_node"]: kw["api"] = "http://127.0.0.1:%d" % port
            if any(p["kind"] == "file" for p in s["params"]): kw["files"] = {"content_file": str(content)}
            if s["command"] == "liquid-payment": kw["extra_args"] = ()
            every.append(transaction_vector("%s/example" % cmd, s, ex, **kw))
        lp = specs["liquid-payment"]; lp2 = dict(lp); lp2["_cli"] = False
        every.append(transaction_vector("liquid-payment/token", lp2, {"recipient": A_1, "amount": "500000000", "complete_minutes": "60", "token_id": "123456789"}, ts=T0 + 200))
    finally:
        srv.shutdown(); shutil.rmtree(tmp)
    desc = ("Transactions built by the C++ tools with --offline --timestamp (signing.md). `params` are the command-line strings in "
            "spec/transactions order after the key; `expected` is what the tools printed: body, unsigned envelope, digest, signature, "
            "transaction_bytes = unsigned || signature, transaction_hash = SHA3-256(transaction_bytes), and the submit payload. "
            "`genesis` = the chain signed for ('v1' = legacy bare digest). `reference_block` is the block a proof of ownership used.")
    return ({"description": desc + " Core set: SendZBC and ApprovalEscrow.", "vectors": core},
            {"description": desc + " One vector per transaction type, from each spec/transactions example.", "vectors": every})

# ---------------------------------------------------------------- cli behaviour -------------
def cli_vectors():
    cases = []
    def case(name, args, expect_code, stdin=None):
        rc, o, e = cli(*args, stdin=stdin)
        j = json.loads(o) if o.strip().startswith("{") else None
        cases.append({"case": name, "args": list(args), "stdin": stdin, "exit_code": rc, "error_class": (j or {}).get("error_class"), "success": (j or {}).get("success")})
        assert rc == expect_code, (name, rc, o, e)
    case("missing amount", ["send-zbc", SEED_V, A_V], 2)
    case("bad recipient", ["send-zbc", SEED_V, "not-an-address", "1", "--genesis", "v1", "--offline"], 2)
    case("fee not a number", ["send-zbc", SEED_V, A_V, "1", "--fee", "abc"], 2)
    case("unknown option", ["send-zbc", SEED_V, A_V, "1", "--bogus"], 2)
    case("offline without genesis", ["send-zbc", SEED_V, A_V, "1", "--offline"], 2)
    case("timestamp not a number", ["send-zbc", SEED_V, A_V, "1", "--timestamp", "x", "--genesis", "v1", "--offline"], 2)
    case("escrow without approver", ["send-zbc", SEED_V, A_V, "1", "--escrow-timeout", "1800000000", "--genesis", "v1", "--offline"], 2)
    case("escrow without timeout", ["send-zbc", SEED_V, A_V, "1", "--escrow-approver", A_1, "--genesis", "v1", "--offline"], 2)
    case("key placeholder without ZBC_KEY", ["send-zbc", "-", A_V, "1", "--genesis", "v1", "--offline"], 2)
    case("key wrong length", ["send-zbc", "abcd", A_V, "1", "--genesis", "v1", "--offline"], 2)
    case("approve-escrow bad approval", ["approve-escrow", SEED_V, "3", "11" * 32, "--genesis", "v1", "--offline"], 2)
    case("approve-escrow short hash", ["approve-escrow", SEED_V, "0", "1111", "--genesis", "v1", "--offline"], 2)
    case("unreachable node", ["send-zbc", SEED_V, A_V, "1", "--api", "http://127.0.0.1:9", "--genesis", "v1", "--timeout", "2"], 3)
    case("json-input missing field", ["send-zbc", "--json-input", "--genesis", "v1", "--offline"], 2, stdin=json.dumps({"sender_privkey": SEED_V, "recipient": A_V}))
    case("json-input invalid json", ["send-zbc", "--json-input"], 2, stdin="{not json")
    case("verify-message wrong signature", ["verify-message", A_1, "hello zoobc", "00" * 64], 10)
    case("verify-message dashed address", ["verify-message", A_1.replace("_", "-"), "hello zoobc", V_SIG_1], 0)
    case("verify-message bare address", ["verify-message", A_1.replace("_", "").lower(), "hello zoobc", V_SIG_1], 0)
    case("send-zbc bare recipient", ["send-zbc", SEED_V, A_V.replace("_", ""), "1", "--genesis", "v1", "--offline"], 0)
    case("unknown command", ["no-such-command"], 2)
    case("no arguments", [], 2)
    return {"description": "Exit codes and error_class for command-line mistakes (cli-contract.md 5), as zbc-cli behaves. "
                           "A port's zbc-cli must produce the same exit code and error_class for the same arguments.", "vectors": cases}

def main():
    global BIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=str(ROOT / "cpp" / "build")); ap.add_argument("--out", default=str(ROOT / "spec" / "vectors"))
    ap.add_argument("--check", action="store_true", help="regenerate into a temp dir and diff against --out")
    a = ap.parse_args(); BIN = pathlib.Path(a.bin).resolve()
    if not (BIN / "zbc-cli").exists(): sys.exit("no zbc-cli in %s (build cpp/ first)" % BIN)
    out = pathlib.Path(tempfile.mkdtemp()) if a.check else pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    core, every = transactions_vectors()
    files = {"keys.json": keys_vectors(), "addresses.json": addresses_vectors(), "messages.json": messages_vectors(),
             "transactions.json": core, "transactions-all.json": every, "cli.json": cli_vectors(), "encryption.json": encryption_vectors()}
    for name, data in files.items():
        data = {"license": "MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci", **data}
        (out / name).write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    if a.check:
        def stable(path):   # encryption.json: the tool-made samples carry a random ephemeral key and differ on every run
            d = json.loads(path.read_text()); d.pop("samples", None); return json.dumps(d, sort_keys=True)
        bad = [n for n in files if stable(out / n) != stable(pathlib.Path(a.out) / n)]
        shutil.rmtree(out)
        if bad: sys.exit("vectors differ from the C++ tools' output: " + ", ".join(bad))
        print("vectors match the C++ tools' output (%d files)" % len(files))
    else:
        for name, data in files.items():
            n = len(data.get("vectors", data.get("seeds", data.get("sealed", [])))); print("%-22s %d vectors" % (name, n))

if __name__ == "__main__":
    main()
