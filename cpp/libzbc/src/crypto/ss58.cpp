// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/ss58.h"
#include <sodium.h>

namespace zoobc {
namespace crypto {

namespace {

static const char* B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58Encode(const std::vector<uint8_t>& data) {
    size_t zeros = 0;
    for (auto b : data) { if (b == 0) zeros++; else break; }
    std::vector<uint8_t> digits;             // base-58, little-endian
    for (auto byte : data) {
        uint32_t carry = byte;
        for (auto& d : digits) { carry += (uint32_t)d << 8; d = carry % 58; carry /= 58; }
        while (carry) { digits.push_back(carry % 58); carry /= 58; }
    }
    std::string out(zeros, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) out += B58[*it];
    return out;
}

bool base58Decode(const std::string& s, std::vector<uint8_t>& out) {
    size_t ones = 0;
    for (char c : s) { if (c == '1') ones++; else break; }
    std::vector<uint8_t> bytes;              // big-endian byte accumulation
    for (char c : s) {
        const char* p = nullptr;
        for (const char* q = B58; *q; ++q) if (*q == c) { p = q; break; }
        if (!p) return false;
        uint32_t carry = (uint32_t)(p - B58);
        for (auto& b : bytes) { carry += (uint32_t)b * 58; b = carry & 0xff; carry >>= 8; }
        while (carry) { bytes.push_back(carry & 0xff); carry >>= 8; }
    }
    out.assign(ones, 0);
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) out.push_back(*it);
    return true;
}

// blake2b-512(in) via libsodium (crypto_generichash IS blake2b); returns 64 bytes.
std::vector<uint8_t> blake2b512(const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out(64);
    crypto_generichash_blake2b(out.data(), out.size(), in.data(), in.size(), nullptr, 0);
    return out;
}

// SS58 checksum: first 2 bytes of blake2b-512("SS58PRE" || prefix_bytes || payload).
std::vector<uint8_t> ss58Checksum(const std::vector<uint8_t>& prefix_and_payload) {
    static const uint8_t PRE[7] = {'S','S','5','8','P','R','E'};
    std::vector<uint8_t> buf(PRE, PRE + 7);
    buf.insert(buf.end(), prefix_and_payload.begin(), prefix_and_payload.end());
    auto h = blake2b512(buf);
    return {h.begin(), h.begin() + 2};
}

}  // namespace

// Public wrappers over the base58 implementation above. Exposed rather than copied: a second
// base58 in another file is how two parsers for one format drift apart, and this codebase has
// already paid for that lesson twice (the CreateApp bodies, and a whole duplicate gateway).
std::vector<uint8_t> Base58Decode(const std::string& s, bool& ok) {
    std::vector<uint8_t> out;
    ok = base58Decode(s, out);
    return out;
}
std::string Base58Encode(const std::vector<uint8_t>& data) { return base58Encode(data); }

std::string Ss58Encode(const std::vector<uint8_t>& account_id, uint16_t prefix) {
    if (account_id.size() != 32 || prefix > 63) return "";   // single-byte-prefix AccountId form only
    std::vector<uint8_t> body;
    body.push_back((uint8_t)prefix);
    body.insert(body.end(), account_id.begin(), account_id.end());
    auto ck = ss58Checksum(body);
    body.insert(body.end(), ck.begin(), ck.end());
    return base58Encode(body);
}

Ss58Decoded Ss58Decode(const std::string& address) {
    Ss58Decoded r;
    std::vector<uint8_t> raw;
    if (!base58Decode(address, raw)) { r.error = "invalid base58"; return r; }
    // single-byte prefix + 32-byte AccountId + 2-byte checksum
    if (raw.size() != 1 + 32 + 2) { r.error = "unexpected SS58 length (expect 35-byte AccountId form)"; return r; }
    if (raw[0] & 0x40) { r.error = "two-byte SS58 prefix not supported"; return r; }
    std::vector<uint8_t> prefix_and_payload(raw.begin(), raw.begin() + 1 + 32);
    auto want = ss58Checksum(prefix_and_payload);
    if (raw[33] != want[0] || raw[34] != want[1]) { r.error = "bad SS58 checksum"; return r; }
    r.prefix = raw[0];
    r.account_id.assign(raw.begin() + 1, raw.begin() + 1 + 32);
    r.ok = true;
    return r;
}

}  // namespace crypto
}  // namespace zoobc
