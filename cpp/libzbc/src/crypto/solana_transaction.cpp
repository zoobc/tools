// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/solana_transaction.h"
#include "zoobc/crypto/signature.h"

namespace zoobc {
namespace crypto {
namespace {
// Solana compact-u16 ("shortvec"): up to 3 bytes, 7 bits each, little-endian groups.
bool ShortVec(const std::vector<uint8_t>& b, size_t& off, uint32_t& out) {
    uint32_t v = 0; int shift = 0;
    for (int i = 0; i < 3; i++) {
        if (off >= b.size()) return false;
        uint8_t c = b[off++];
        v |= static_cast<uint32_t>(c & 0x7f) << shift;
        if (!(c & 0x80)) { out = v; return true; }
        shift += 7;
    }
    return false;  // too long
}
bool Take(const std::vector<uint8_t>& b, size_t& off, size_t n, std::vector<uint8_t>& out) {
    if (off + n > b.size()) return false;
    out.assign(b.begin() + off, b.begin() + off + n); off += n; return true;
}
}  // namespace

SolanaTransfer ParseAndVerifySolanaTransfer(const std::vector<uint8_t>& raw) {
    SolanaTransfer r;
    auto fail = [&](const char* m){ r.ok = false; r.error = m; return r; };
    size_t off = 0;
    uint32_t nsig = 0;
    if (!ShortVec(raw, off, nsig) || nsig == 0 || nsig > 8) return fail("bad signature count");
    std::vector<std::vector<uint8_t>> sigs;
    for (uint32_t i = 0; i < nsig; i++) { std::vector<uint8_t> s; if (!Take(raw, off, 64, s)) return fail("truncated signatures"); sigs.push_back(std::move(s)); }

    const size_t msg_start = off;                       // the signed message is everything after the sigs
    if (off + 3 > raw.size()) return fail("truncated header");
    off += 3;                                           // header: numReqSig, numRoSigned, numRoUnsigned
    uint32_t nkey = 0;
    if (!ShortVec(raw, off, nkey) || nkey == 0 || nkey > 64) return fail("bad account count");
    std::vector<std::vector<uint8_t>> keys;
    for (uint32_t i = 0; i < nkey; i++) { std::vector<uint8_t> k; if (!Take(raw, off, 32, k)) return fail("truncated account keys"); keys.push_back(std::move(k)); }
    std::vector<uint8_t> blockhash; if (!Take(raw, off, 32, blockhash)) return fail("truncated blockhash");

    uint32_t nix = 0;
    if (!ShortVec(raw, off, nix)) return fail("bad instruction count");
    bool found = false;
    for (uint32_t i = 0; i < nix; i++) {
        if (off >= raw.size()) return fail("truncated instruction");
        uint8_t prog_idx = raw[off++];
        uint32_t nacct = 0; if (!ShortVec(raw, off, nacct)) return fail("bad ix account count");
        std::vector<uint8_t> acc_idx; if (!Take(raw, off, nacct, acc_idx)) return fail("truncated ix accounts");
        uint32_t ndata = 0; if (!ShortVec(raw, off, ndata)) return fail("bad ix data len");
        std::vector<uint8_t> data; if (!Take(raw, off, ndata, data)) return fail("truncated ix data");
        if (prog_idx >= keys.size()) return fail("program index out of range");
        const auto& prog = keys[prog_idx];
        bool is_system = true; for (uint8_t bb : prog) if (bb != 0) { is_system = false; break; }
        // System transfer: data = u32 LE index(2) + u64 LE lamports; accounts = [from, to]
        if (is_system && data.size() >= 12 &&
            (data[0]|(data[1]<<8)|(data[2]<<16)|((uint32_t)data[3]<<24)) == 2 &&
            acc_idx.size() >= 2 && acc_idx[0] < keys.size() && acc_idx[1] < keys.size()) {
            uint64_t lamports = 0; for (int k = 0; k < 8; k++) lamports |= static_cast<uint64_t>(data[4 + k]) << (8 * k);
            r.from = keys[acc_idx[0]]; r.to = keys[acc_idx[1]]; r.lamports = lamports; found = true;
        }
    }
    if (!found) return fail("no System transfer instruction");

    // Verify signature[0] (ed25519) over the message bytes against account_keys[0] (fee payer).
    std::vector<uint8_t> message(raw.begin() + msg_start, raw.end());
    auto v = Signature::Verify(message, sigs[0], keys[0]);
    if (v.IsErr() || !v.Value()) return fail("ed25519 signature verification failed");
    // The fee payer (keys[0]) must be the transfer source.
    if (keys[0] != r.from) return fail("signer is not the transfer source");

    r.ok = true; return r;
}

}  // namespace crypto
}  // namespace zoobc
