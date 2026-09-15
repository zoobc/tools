// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/bitcoin_transaction.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/bitcoin_signature.h"

namespace zoobc {
namespace crypto {

namespace {

// Bounds-checked little-endian reader with Bitcoin CompactSize ("varint") support.
struct Reader {
    const std::vector<uint8_t>& b;
    size_t o = 0;
    bool bad = false;
    explicit Reader(const std::vector<uint8_t>& d) : b(d) {}
    bool need(size_t n) { if (o + n > b.size()) { bad = true; return false; } return true; }
    uint8_t  u8()  { if (!need(1)) return 0; return b[o++]; }
    uint32_t u32() { if (!need(4)) return 0; uint32_t v = 0; for (int i = 0; i < 4; i++) v |= (uint32_t)b[o++] << (8 * i); return v; }
    uint64_t u64() { if (!need(8)) return 0; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)b[o++] << (8 * i); return v; }
    uint64_t varint() {
        uint8_t p = u8(); if (bad) return 0;
        if (p < 0xfd) return p;
        if (p == 0xfd) { if (!need(2)) return 0; uint64_t v = b[o] | ((uint64_t)b[o + 1] << 8); o += 2; return v; }
        if (p == 0xfe) return u32();
        return u64();
    }
    std::vector<uint8_t> take(uint64_t n) {
        if (n > b.size() || !need((size_t)n)) { bad = true; return {}; }
        std::vector<uint8_t> r(b.begin() + o, b.begin() + o + (size_t)n); o += (size_t)n; return r;
    }
};

void putU32(std::vector<uint8_t>& v, uint32_t x) { for (int i = 0; i < 4; i++) v.push_back((x >> (8 * i)) & 0xff); }
void putU64(std::vector<uint8_t>& v, uint64_t x) { for (int i = 0; i < 8; i++) v.push_back((x >> (8 * i)) & 0xff); }
void putVar(std::vector<uint8_t>& v, uint64_t n) {
    if (n < 0xfd) v.push_back((uint8_t)n);
    else if (n <= 0xffff) { v.push_back(0xfd); v.push_back(n & 0xff); v.push_back((n >> 8) & 0xff); }
    else if (n <= 0xffffffffULL) { v.push_back(0xfe); putU32(v, (uint32_t)n); }
    else { v.push_back(0xff); putU64(v, n); }
}
std::vector<uint8_t> dsha(const std::vector<uint8_t>& d) { auto r = Hash::DoubleSHA256(d); return r.IsOk() ? r.Value() : std::vector<uint8_t>(); }

// Low-s check (BIP-146 anti-malleability): the DER signature's s value must be <= n/2, where n is the
// secp256k1 group order. Without this, (r, n-s) is an equally valid signature → the carried BTC tx
// (and thus the ZooBC tx hash) could be malleated into a distinct-but-equivalent transaction.
bool DerSigIsLowS(const std::vector<uint8_t>& der) {
    // DER: 0x30 len 0x02 rlen <r> 0x02 slen <s>
    if (der.size() < 8 || der[0] != 0x30 || der[2] != 0x02) return false;
    size_t rlen = der[3];
    size_t i = 4 + rlen;
    if (i + 2 > der.size() || der[i] != 0x02) return false;
    size_t slen = der[i + 1];
    i += 2;
    if (i + slen > der.size()) return false;
    std::vector<uint8_t> s(der.begin() + i, der.begin() + i + slen);
    while (s.size() > 1 && s[0] == 0x00) s.erase(s.begin());     // strip DER leading-zero padding
    if (s.size() > 32) return false;                            // > 32 bytes ⇒ > n/2
    std::vector<uint8_t> s32(32 - s.size(), 0);
    s32.insert(s32.end(), s.begin(), s.end());
    static const uint8_t HALF_N[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D, 0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };
    for (int k = 0; k < 32; k++) { if (s32[k] < HALF_N[k]) return true; if (s32[k] > HALF_N[k]) return false; }
    return true;                                                // s == n/2 is allowed
}

}  // namespace

std::vector<uint8_t> BitcoinOutputHash160(const std::vector<uint8_t>& s) {
    if (s.size() == 22 && s[0] == 0x00 && s[1] == 0x14) return {s.begin() + 2, s.end()};          // P2WPKH
    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac)
        return {s.begin() + 3, s.begin() + 23};                                                   // P2PKH
    return {};
}

BitcoinTx ParseBitcoinTx(const std::vector<uint8_t>& raw) {
    BitcoinTx tx;
    Reader r(raw);
    tx.version = r.u32();
    // SegWit marker (0x00) + flag (0x01). A real legacy tx always has >=1 input, so the byte after
    // version is a non-zero CompactSize input count — never 0x00 — so this is unambiguous.
    if (r.o + 2 <= raw.size() && raw[r.o] == 0x00 && raw[r.o + 1] == 0x01) { tx.segwit = true; r.o += 2; }

    uint64_t vinCount = r.varint();
    if (r.bad || vinCount == 0 || vinCount > 100000) { tx.error = "bad vin count"; return tx; }
    for (uint64_t i = 0; i < vinCount; i++) {
        BitcoinTxInput in;
        in.outpoint = r.take(36);
        in.script_sig = r.take(r.varint());
        in.sequence = r.u32();
        if (r.bad) { tx.error = "truncated vin"; return tx; }
        tx.vin.push_back(std::move(in));
    }

    uint64_t voutCount = r.varint();
    if (r.bad || voutCount > 100000) { tx.error = "bad vout count"; return tx; }
    for (uint64_t i = 0; i < voutCount; i++) {
        BitcoinTxOutput out;
        out.value = r.u64();
        out.script = r.take(r.varint());
        if (r.bad) { tx.error = "truncated vout"; return tx; }
        tx.vout.push_back(std::move(out));
    }

    if (tx.segwit) {
        for (uint64_t i = 0; i < vinCount; i++) {
            uint64_t items = r.varint();
            if (r.bad || items > 100000) { tx.error = "bad witness count"; return tx; }
            for (uint64_t k = 0; k < items; k++) {
                auto item = r.take(r.varint());
                if (r.bad) { tx.error = "truncated witness"; return tx; }
                tx.vin[i].witness.push_back(std::move(item));
            }
        }
    }

    tx.locktime = r.u32();
    if (r.bad) { tx.error = "truncated (locktime)"; return tx; }
    // Reject trailing garbage so the bytes the signer committed to == the bytes we parsed.
    if (r.o != raw.size()) { tx.error = "trailing bytes after tx"; return tx; }
    tx.ok = true;
    return tx;
}

std::vector<uint8_t> BIP143Preimage(const BitcoinTx& tx, size_t idx,
        const std::vector<uint8_t>& script_code, uint64_t amount, uint32_t hash_type) {
    // SIGHASH_ALL: hashPrevouts/hashSequence over ALL inputs, hashOutputs over ALL outputs.
    std::vector<uint8_t> prevouts, sequences, outputs;
    for (const auto& in : tx.vin) prevouts.insert(prevouts.end(), in.outpoint.begin(), in.outpoint.end());
    for (const auto& in : tx.vin) putU32(sequences, in.sequence);
    for (const auto& o : tx.vout) { putU64(outputs, o.value); putVar(outputs, o.script.size()); outputs.insert(outputs.end(), o.script.begin(), o.script.end()); }
    auto hashPrevouts = dsha(prevouts);
    auto hashSequence = dsha(sequences);
    auto hashOutputs  = dsha(outputs);

    std::vector<uint8_t> p;
    putU32(p, tx.version);
    p.insert(p.end(), hashPrevouts.begin(), hashPrevouts.end());
    p.insert(p.end(), hashSequence.begin(), hashSequence.end());
    p.insert(p.end(), tx.vin[idx].outpoint.begin(), tx.vin[idx].outpoint.end());
    putVar(p, script_code.size());
    p.insert(p.end(), script_code.begin(), script_code.end());
    putU64(p, amount);
    putU32(p, tx.vin[idx].sequence);
    p.insert(p.end(), hashOutputs.begin(), hashOutputs.end());
    putU32(p, tx.locktime);
    putU32(p, hash_type);
    return p;
}

bool VerifyP2WPKHInput(const BitcoinTx& tx, size_t idx, uint64_t amount, std::string* err) {
    auto fail = [&](const char* m) { if (err) *err = m; return false; };
    if (idx >= tx.vin.size()) return fail("input index out of range");
    const auto& in = tx.vin[idx];
    if (in.witness.size() != 2) return fail("expected 2 witness items (sig, pubkey)");
    const auto& sigWithType = in.witness[0];
    const auto& pubkey = in.witness[1];
    if (sigWithType.size() < 2) return fail("malformed signature");
    if (pubkey.size() != 33) return fail("expected 33-byte compressed pubkey");

    uint32_t hashType = sigWithType.back();
    if (hashType != 0x01) return fail("only SIGHASH_ALL supported (phase 1)");
    std::vector<uint8_t> derSig(sigWithType.begin(), sigWithType.end() - 1);   // strip the hashtype byte
    if (!DerSigIsLowS(derSig)) return fail("high-s signature (malleable)");

    // scriptCode for P2WPKH = OP_DUP OP_HASH160 <20 HASH160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
    auto h160 = BitcoinSignature::Hash160(pubkey);
    if (h160.IsErr() || h160.Value().size() != 20) return fail("hash160 failed");
    std::vector<uint8_t> scriptCode = {0x76, 0xa9, 0x14};
    scriptCode.insert(scriptCode.end(), h160.Value().begin(), h160.Value().end());
    scriptCode.push_back(0x88); scriptCode.push_back(0xac);

    auto preimage = BIP143Preimage(tx, idx, scriptCode, amount, hashType);
    // VerifyDER double-SHA256s its payload internally, so we pass the preimage (sighash = dSHA256(preimage)).
    BitcoinSignature btc;
    auto v = btc.VerifyDER(pubkey, preimage, derSig);
    if (v.IsErr()) return fail("verify error");
    if (!v.Value()) return fail("signature does not verify");
    return true;
}

std::vector<uint8_t> LegacySighashPreimage(const BitcoinTx& tx, size_t idx,
        const std::vector<uint8_t>& script_code, uint32_t hash_type) {
    // Re-serialize the tx as LEGACY (no segwit marker/witness): input[idx] gets script_code as its
    // scriptSig, every other input gets an empty scriptSig; outputs and locktime are unchanged.
    std::vector<uint8_t> p;
    putU32(p, tx.version);
    putVar(p, tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const auto& in = tx.vin[i];
        p.insert(p.end(), in.outpoint.begin(), in.outpoint.end());
        if (i == idx) { putVar(p, script_code.size()); p.insert(p.end(), script_code.begin(), script_code.end()); }
        else { putVar(p, 0); }
        putU32(p, in.sequence);
    }
    putVar(p, tx.vout.size());
    for (const auto& o : tx.vout) { putU64(p, o.value); putVar(p, o.script.size()); p.insert(p.end(), o.script.begin(), o.script.end()); }
    putU32(p, tx.locktime);
    putU32(p, hash_type);
    return p;
}

std::vector<uint8_t> P2PKHScriptSigPubkey(const std::vector<uint8_t>& ss) {
    // Standard P2PKH scriptSig is exactly two canonical data pushes: <sig+hashtype> <pubkey>.
    // Data-push opcodes 0x01..0x4b push that many bytes (sig ≤ ~73, pubkey 33 or 65 ⇒ always direct push).
    Reader r(ss);
    uint8_t l1 = r.u8(); if (r.bad || l1 < 1 || l1 > 0x4b) return {};
    r.take(l1);                                   // skip the signature
    uint8_t l2 = r.u8(); if (r.bad || l2 < 1 || l2 > 0x4b) return {};
    auto pub = r.take(l2);
    if (r.bad || r.o != ss.size()) return {};     // reject trailing bytes / non-standard scriptSig
    if (pub.size() != 33 && pub.size() != 65) return {};
    return pub;
}

bool VerifyP2PKHInput(const BitcoinTx& tx, size_t idx, std::string* err) {
    auto fail = [&](const char* m) { if (err) *err = m; return false; };
    if (idx >= tx.vin.size()) return fail("input index out of range");
    const auto& ss = tx.vin[idx].script_sig;
    // Re-parse the two pushes to get BOTH sig and pubkey (P2PKHScriptSigPubkey only returns the pubkey).
    Reader r(ss);
    uint8_t l1 = r.u8(); if (r.bad || l1 < 1 || l1 > 0x4b) return fail("malformed scriptSig (sig push)");
    auto sigWithType = r.take(l1);
    uint8_t l2 = r.u8(); if (r.bad || l2 < 1 || l2 > 0x4b) return fail("malformed scriptSig (pubkey push)");
    auto pubkey = r.take(l2);
    if (r.bad || r.o != ss.size()) return fail("non-standard P2PKH scriptSig");
    if (pubkey.size() != 33 && pubkey.size() != 65) return fail("bad pubkey length");
    if (sigWithType.size() < 2) return fail("malformed signature");

    uint32_t hashType = sigWithType.back();
    if (hashType != 0x01) return fail("only SIGHASH_ALL supported");
    std::vector<uint8_t> derSig(sigWithType.begin(), sigWithType.end() - 1);
    if (!DerSigIsLowS(derSig)) return fail("high-s signature (malleable)");

    // scriptCode = the spent P2PKH scriptPubKey = OP_DUP OP_HASH160 <HASH160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
    auto h160 = BitcoinSignature::Hash160(pubkey);
    if (h160.IsErr() || h160.Value().size() != 20) return fail("hash160 failed");
    std::vector<uint8_t> scriptCode = {0x76, 0xa9, 0x14};
    scriptCode.insert(scriptCode.end(), h160.Value().begin(), h160.Value().end());
    scriptCode.push_back(0x88); scriptCode.push_back(0xac);

    auto preimage = LegacySighashPreimage(tx, idx, scriptCode, hashType);
    BitcoinSignature btc;
    auto v = btc.VerifyDER(pubkey, preimage, derSig);   // VerifyDER double-SHA256s its payload internally
    if (v.IsErr()) return fail("verify error");
    if (!v.Value()) return fail("signature does not verify");
    return true;
}

BitcoinTransfer ParseAndVerifyP2PKHTransfer(const std::vector<uint8_t>& raw) {
    BitcoinTransfer t;
    auto tx = ParseBitcoinTx(raw);
    if (!tx.ok) { t.error = "parse: " + tx.error; return t; }
    if (tx.vin.size() != 1) { t.error = "only single-input P2PKH supported"; return t; }
    if (tx.vout.empty()) { t.error = "no outputs"; return t; }

    std::string verr;
    if (!VerifyP2PKHInput(tx, 0, &verr)) { t.error = "verify: " + verr; return t; }

    const auto& o0 = tx.vout[0];
    auto h = BitcoinOutputHash160(o0.script);
    if (h.empty()) { t.error = "output[0] is not P2WPKH/P2PKH"; return t; }

    t.from_pubkey = P2PKHScriptSigPubkey(tx.vin[0].script_sig);
    auto fh = BitcoinSignature::Hash160(t.from_pubkey);
    if (fh.IsOk()) t.from_hash160 = fh.Value();
    t.to_hash160 = h;
    t.satoshis = o0.value;
    t.ok = true;
    return t;
}

BitcoinTransfer ParseAndVerifyP2WPKHTransfer(const std::vector<uint8_t>& raw, uint64_t input_amount) {
    BitcoinTransfer t;
    auto tx = ParseBitcoinTx(raw);
    if (!tx.ok) { t.error = "parse: " + tx.error; return t; }
    if (tx.vin.size() != 1) { t.error = "only single-input P2WPKH supported (phase 1)"; return t; }
    if (tx.vout.empty()) { t.error = "no outputs"; return t; }

    std::string verr;
    if (!VerifyP2WPKHInput(tx, 0, input_amount, &verr)) { t.error = "verify: " + verr; return t; }

    // Recipient = output[0]; must be a hash form we can mirror to a ZooBC BTC account.
    const auto& o0 = tx.vout[0];
    auto h = BitcoinOutputHash160(o0.script);
    if (h.empty()) { t.error = "output[0] is not P2WPKH/P2PKH"; return t; }

    t.from_pubkey = tx.vin[0].witness[1];
    auto fh = BitcoinSignature::Hash160(t.from_pubkey);
    if (fh.IsOk()) t.from_hash160 = fh.Value();
    t.to_hash160 = h;
    t.satoshis = o0.value;
    t.ok = true;
    return t;
}

}  // namespace crypto
}  // namespace zoobc
