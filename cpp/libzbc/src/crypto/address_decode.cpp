// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/address_decode.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "zoobc/crypto/bitcoin_transaction.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/slip10.h"
#include "zoobc/crypto/ss58.h"
#include "zoobc/util/transaction_util.h"

namespace zoobc {
namespace crypto {

namespace {

using AT = util::TransactionUtil;

std::vector<uint8_t> withType(int32_t type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    out.reserve(4 + payload.size());
    out.push_back(static_cast<uint8_t>(type & 0xFF));
    out.push_back(static_cast<uint8_t>((type >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((type >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((type >> 24) & 0xFF));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool isHex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (char c : s) if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

std::vector<uint8_t> hexBytes(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return out;
}

// base58check: payload followed by the first 4 bytes of double-SHA256. Returns the payload without
// the checksum, or empty on a checksum failure — which is the whole point: it is what stops a
// Solana key from being read as a Bitcoin address.
std::vector<uint8_t> b58check(const std::string& s) {
    bool ok = false;
    auto raw = Base58Decode(s, ok);
    if (!ok || raw.size() < 5) return {};
    std::vector<uint8_t> body(raw.begin(), raw.end() - 4);
    auto h = Hash::DoubleSHA256(body);
    if (h.IsErr()) return {};
    const auto& d = h.Value();
    for (int i = 0; i < 4; i++)
        if (d[static_cast<size_t>(i)] != raw[raw.size() - 4 + static_cast<size_t>(i)]) return {};
    return body;
}

// Ripple uses its own base58 alphabet, not Bitcoin's — the same 58 symbols in a different order.
// Transliterating into the Bitcoin alphabet lets the shared decoder do the arithmetic, rather than
// carrying a second base58 implementation that could drift from the first.
std::string rippleToBitcoinAlphabet(const std::string& s) {
    static const char* kRipple  = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    static const char* kBitcoin = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        const char* p = std::strchr(kRipple, c);
        if (!p || !c) return {};          // not a ripple-base58 character
        out.push_back(kBitcoin[p - kRipple]);
    }
    return out;
}

// A ZooBC identifier is 59 significant characters — a 3-letter prefix and 56 of base32 — and
// everything else in the written form is cosmetic: '_' and '-' (interchangeably, mixed) and
// whitespace from a line-wrapped paste; a form with no separator at all is the same identifier.
// That is the wallet's rule and ZoobcAddress::Decode's, and detection has to agree with it, or a
// spelling the wallet accepts is refused as "unrecognised" here while the same string decodes one
// call deeper — and a ZBS address typed as a ZBC account because only its prefix check looked at
// the separator.
bool zbcSeparator(char c) { return c == '_' || c == '-'; }

std::string zbcSignificant(const std::string& a) {
    std::string n;
    for (char c : a) {
        if (zbcSeparator(c) || std::isspace(static_cast<unsigned char>(c))) continue;
        n.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return n;
}

bool zbcPrefixIs(const std::string& a, const char* p) {
    const std::string n = zbcSignificant(a);   // the prefix is the first three significant characters
    return n.size() >= 3 && n[0] == p[0] && n[1] == p[1] && n[2] == p[2];
}

// Shape only (Decode verifies): PREFIX then a separator, or — with no separator at all — 59
// significant characters that are all base32 after an account prefix. The bare form is gated on
// ZBC/ZBS because without a separator nothing else marks the string as ZooBC; the checksum decides.
bool looksZbc(const std::string& a) {
    if (a.size() > 4 && zbcSeparator(a[3])) return true;
    const std::string n = zbcSignificant(a);
    if (n.size() != 59 || !(n.compare(0, 3, "ZBC") == 0 || n.compare(0, 3, "ZBS") == 0)) return false;
    static const char* kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (size_t i = 3; i < n.size(); i++)
        if (n[i] == '\0' || std::strchr(kAlphabet, n[i]) == nullptr) return false;
    return true;
}

Result<DecodedAddress> zbcForm(const std::string& a) {
    auto dec = ZoobcAddress::Decode(a);
    if (dec.IsErr()) return Error{ErrorCode::ValidationError, "invalid ZooBC address checksum"};
    // ZBS_ is a DataSet object's own fundable address: type 10, so a transfer credits the dataset's
    // storage balance rather than a same-bytes ordinary account.
    const int32_t type = zbcPrefixIs(a, "ZBS") ? AT::ACCOUNT_TYPE_DATASET : AT::ACCOUNT_TYPE_ZBC;
    return DecodedAddress{withType(type, dec.Value()), type, type == AT::ACCOUNT_TYPE_DATASET ? "dataset" : "zoobc"};
}

}  // namespace

AddressChain ParseAddressChain(const std::string& name) {
    std::string n;
    for (char c : name) n.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (n == "zbc" || n == "zoobc")                    return AddressChain::ZooBC;
    if (n == "btc" || n == "bitcoin")                  return AddressChain::Bitcoin;
    if (n == "eth" || n == "ethereum" || n == "evm")   return AddressChain::Ethereum;
    if (n == "sol" || n == "solana")                   return AddressChain::Solana;
    if (n == "dot" || n == "polkadot" || n == "substrate") return AddressChain::Polkadot;
    if (n == "ada" || n == "cardano")                  return AddressChain::Cardano;
    if (n == "xrp" || n == "ripple")                   return AddressChain::Ripple;
    if (n == "trx" || n == "tron")                     return AddressChain::Tron;
    if (n == "xtz" || n == "tezos")                    return AddressChain::Tezos;
    if (n == "zbs" || n == "dataset")                  return AddressChain::DataSet;
    return AddressChain::Auto;
}

std::string AccountTypeName(int32_t t) {
    switch (t) {
        case AT::ACCOUNT_TYPE_ZBC:         return "ZooBC";
        case AT::ACCOUNT_TYPE_BTC:         return "Bitcoin";
        case AT::ACCOUNT_TYPE_ETH:         return "Ethereum";
        case AT::ACCOUNT_TYPE_ESTONIA_EID: return "Estonia eID";
        case AT::ACCOUNT_TYPE_BTC_P2PKH:   return "Bitcoin P2PKH";
        case AT::ACCOUNT_TYPE_BTC_P2SH:    return "Bitcoin P2SH";
        case AT::ACCOUNT_TYPE_BTC_P2WPKH:  return "Bitcoin P2WPKH";
        case AT::ACCOUNT_TYPE_BTC_P2WSH:   return "Bitcoin P2WSH";
        case AT::ACCOUNT_TYPE_BTC_P2TR:    return "Bitcoin Taproot";
        case AT::ACCOUNT_TYPE_DATASET:     return "DataSet";
        case AT::ACCOUNT_TYPE_SOLANA:      return "Solana";
        case AT::ACCOUNT_TYPE_POLKADOT:    return "Polkadot";
        case AT::ACCOUNT_TYPE_CARDANO:     return "Cardano";
        case AT::ACCOUNT_TYPE_RIPPLE:      return "Ripple";
        case AT::ACCOUNT_TYPE_TRON:        return "Tron";
        case AT::ACCOUNT_TYPE_TEZOS:       return "Tezos";
        default:                           return "type " + std::to_string(t);
    }
}


// Plain bech32 (BIP-173 checksum, no witness-version semantics): hrp + 8-bit payload. Cardano
// addresses are bech32 with hrp "addr" and a byte payload whose first byte is the header; reading
// them with the segwit decoder made the header's high bits a "witness version" and then demanded
// the bech32m checksum that version implies, so every Cardano address was refused.
static bool bech32_plain_decode(const std::string& in, std::string& hrp_out, std::vector<uint8_t>& bytes_out) {
    static const char* CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    std::string s; s.reserve(in.size());
    bool lower = false, upper = false;
    for (char c : in) { if (c >= 'a' && c <= 'z') lower = true; if (c >= 'A' && c <= 'Z') upper = true; s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c)))); }
    if (lower && upper) return false;
    const auto pos = s.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > s.size() || s.size() > 1023) return false;
    hrp_out = s.substr(0, pos);
    std::vector<uint8_t> data;
    for (size_t i = pos + 1; i < s.size(); ++i) { const char* f = std::strchr(CS, s[i]); if (!f || !s[i]) return false; data.push_back(static_cast<uint8_t>(f - CS)); }
    // checksum
    std::vector<uint8_t> v; for (char c : hrp_out) v.push_back(static_cast<uint8_t>(c) >> 5); v.push_back(0); for (char c : hrp_out) v.push_back(static_cast<uint8_t>(c) & 31);
    v.insert(v.end(), data.begin(), data.end());
    uint32_t chk = 1; static const uint32_t G[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    for (uint8_t x : v) { uint8_t b = static_cast<uint8_t>(chk >> 25); chk = ((chk & 0x1ffffff) << 5) ^ x; for (int k = 0; k < 5; ++k) if ((b >> k) & 1) chk ^= G[k]; }
    if (chk != 1) return false;                                   // bech32 (not bech32m)
    data.resize(data.size() - 6);
    uint32_t acc = 0; int bits = 0; bytes_out.clear();
    for (uint8_t d : data) { acc = (acc << 5) | d; bits += 5; if (bits >= 8) { bits -= 8; bytes_out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff)); } }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) return false;   // bad padding
    return true;
}

Result<DecodedAddress> DecodeAddress(const std::string& input, AddressChain hint) {
    std::string a = input;
    a.erase(0, a.find_first_not_of(" \t\r\n"));
    if (auto e = a.find_last_not_of(" \t\r\n"); e != std::string::npos) a.erase(e + 1);
    if (a.empty()) return Error{ErrorCode::ValidationError, "empty address"};

    // ---- explicit chain wins, so an operator can always override detection ---------------------
    if (hint == AddressChain::Ethereum) {
        std::string h = (a.size() > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) ? a.substr(2) : a;
        if (!isHex(h, 40)) return Error{ErrorCode::ValidationError, "not a 20-byte Ethereum address"};
        return DecodedAddress{withType(AT::ACCOUNT_TYPE_ETH, hexBytes(h)), AT::ACCOUNT_TYPE_ETH, "ethereum"};
    }
    if (hint == AddressChain::Solana) {
        bool ok = false; auto d = Base58Decode(a, ok);
        if (!ok || d.size() != 32) return Error{ErrorCode::ValidationError, "not a 32-byte Solana address"};
        return DecodedAddress{withType(AT::ACCOUNT_TYPE_SOLANA, d), AT::ACCOUNT_TYPE_SOLANA, "solana"};
    }
    if (hint == AddressChain::Polkadot) {
        auto ss = Ss58Decode(a);
        if (!ss.ok) return Error{ErrorCode::ValidationError, "not a valid SS58 address"};
        return DecodedAddress{withType(AT::ACCOUNT_TYPE_POLKADOT, ss.account_id), AT::ACCOUNT_TYPE_POLKADOT, "polkadot"};
    }
    if (hint == AddressChain::ZooBC || hint == AddressChain::DataSet) return zbcForm(a);

    // ---- Ethereum: 0x + 40 hex ---------------------------------------------------------------
    if (a.size() == 42 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X') && isHex(a.substr(2), 40))
        return DecodedAddress{withType(AT::ACCOUNT_TYPE_ETH, hexBytes(a.substr(2))), AT::ACCOUNT_TYPE_ETH, "ethereum"};

    // ---- ZooBC family: PREFIX then '_' or '-' then base32, or the bare 59-character form -------
    if (looksZbc(a)) return zbcForm(a);

    // ---- Bitcoin bech32 / bech32m: version+program decide the script type ---------------------
    {
        std::string low;
        for (size_t i = 0; i < std::min<size_t>(5, a.size()); i++)
            low.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(a[i]))));
        if (low.rfind("bc1", 0) == 0 || low.rfind("tb1", 0) == 0 || low.rfind("bcrt1", 0) == 0) {
            auto d = Bech32SegwitDecode(a);
            if (d.IsErr()) return Error{ErrorCode::ValidationError, "invalid Bitcoin bech32 address"};
            const auto& v = d.Value();
            if (v.witness_version == 0 && v.program.size() == 20)
                return DecodedAddress{withType(AT::ACCOUNT_TYPE_BTC_P2WPKH, v.program), AT::ACCOUNT_TYPE_BTC_P2WPKH, "bitcoin-p2wpkh"};
            if (v.witness_version == 0 && v.program.size() == 32)
                return DecodedAddress{withType(AT::ACCOUNT_TYPE_BTC_P2WSH, v.program), AT::ACCOUNT_TYPE_BTC_P2WSH, "bitcoin-p2wsh"};
            if (v.witness_version == 1 && v.program.size() == 32)
                return DecodedAddress{withType(AT::ACCOUNT_TYPE_BTC_P2TR, v.program), AT::ACCOUNT_TYPE_BTC_P2TR, "bitcoin-taproot"};
            return Error{ErrorCode::ValidationError, "unsupported Bitcoin witness program"};
        }
    }

    // ---- Bitcoin base58check: 25 bytes, version byte picks P2PKH vs P2SH ----------------------
    if ((a[0] == '1' || a[0] == '3') && a.size() >= 26 && a.size() <= 35) {
        bool ok = false; auto raw = Base58Decode(a, ok);
        if (ok && raw.size() == 25) {
            auto body = b58check(a);
            if (!body.empty() && body.size() == 21) {
                if (body[0] == 0x00)
                    return DecodedAddress{withType(AT::ACCOUNT_TYPE_BTC_P2PKH, {body.begin()+1, body.end()}), AT::ACCOUNT_TYPE_BTC_P2PKH, "bitcoin-p2pkh"};
                if (body[0] == 0x05)
                    return DecodedAddress{withType(AT::ACCOUNT_TYPE_BTC_P2SH, {body.begin()+1, body.end()}), AT::ACCOUNT_TYPE_BTC_P2SH, "bitcoin-p2sh"};
            }
        }
        // Not a valid Bitcoin address — fall through. A 32-byte Solana key can start with 1 or 3.
    }

    // ---- Cardano: plain bech32 "addr", 0x61 enterprise header + 28-byte blake2b-224 key hash ---
    if (a.size() > 5 && (a.compare(0, 5, "addr1") == 0 || a.compare(0, 5, "ADDR1") == 0)) {
        // A REAL Cardano enterprise address: 0x61 header + blake2b-224(key). The 28-byte hash IS the
        // account payload, so a Cardano user's own address is their ZooBC account.
        std::string hrp; std::vector<uint8_t> bytes;
        if (bech32_plain_decode(a, hrp, bytes) && hrp == "addr" && bytes.size() == 29 && bytes[0] == 0x61)
            return DecodedAddress{withType(AT::ACCOUNT_TYPE_CARDANO, {bytes.begin() + 1, bytes.end()}), AT::ACCOUNT_TYPE_CARDANO, "cardano"};
        return Error{ErrorCode::ValidationError, "invalid Cardano address (expected a mainnet enterprise addr1… address)"};
    }

    // ---- Tron: base58check, 0x41 + 20-byte Keccak address ------------------------------------
    if (a[0] == 'T' && a.size() == 34) {
        auto body = b58check(a);
        if (body.size() == 21 && body[0] == 0x41)
            return DecodedAddress{withType(AT::ACCOUNT_TYPE_TRON, {body.begin()+1, body.end()}), AT::ACCOUNT_TYPE_TRON, "tron"};
        return Error{ErrorCode::ValidationError, "invalid Tron address"};
    }

    // ---- Ripple: base58check (ripple alphabet upstream), 0x00 + 20-byte HASH160 ---------------
    if (a[0] == 'r' && a.size() >= 25 && a.size() <= 35) {
        auto body = b58check(rippleToBitcoinAlphabet(a));
        if (body.size() == 21 && body[0] == 0x00)
            return DecodedAddress{withType(AT::ACCOUNT_TYPE_RIPPLE, {body.begin()+1, body.end()}), AT::ACCOUNT_TYPE_RIPPLE, "ripple"};
        return Error{ErrorCode::ValidationError, "invalid Ripple address"};
    }

    // ---- Tezos: base58check tz1 + 20-byte blake2b-160 key hash --------------------------------
    if (a.compare(0, 3, "tz1") == 0) {
        // tz1 = base58check(0x06a19f || blake2b-160(pubkey)): a 20-byte HASH, which is what the
        // Tezos verifier checks the signing key against. 35 (a 32-byte key) matched no real tz1.
        auto body = b58check(a);
        if (body.size() == 23 && body[0] == 0x06 && body[1] == 0xa1 && body[2] == 0x9f)
            return DecodedAddress{withType(AT::ACCOUNT_TYPE_TEZOS, {body.begin()+3, body.end()}), AT::ACCOUNT_TYPE_TEZOS, "tezos"};
        return Error{ErrorCode::ValidationError, "invalid Tezos address"};
    }

    // ---- Polkadot SS58: checked BEFORE bare Solana, because it carries a checksum -------------
    {
        auto ss = Ss58Decode(a);
        if (ss.ok && ss.account_id.size() == 32)
            return DecodedAddress{withType(AT::ACCOUNT_TYPE_POLKADOT, ss.account_id), AT::ACCOUNT_TYPE_POLKADOT, "polkadot"};
    }

    // ---- Solana: plain base58 of a 32-byte ed25519 key, no checksum ---------------------------
    if (a.size() >= 32 && a.size() <= 44) {
        bool ok = false; auto d = Base58Decode(a, ok);
        if (ok && d.size() == 32)
            return DecodedAddress{withType(AT::ACCOUNT_TYPE_SOLANA, d), AT::ACCOUNT_TYPE_SOLANA, "solana"};
    }

    // ---- Raw 64-hex public key → an ordinary ZooBC account -----------------------------------
    if (isHex(a, 64))
        return DecodedAddress{withType(AT::ACCOUNT_TYPE_ZBC, hexBytes(a)), AT::ACCOUNT_TYPE_ZBC, "zoobc"};

    return Error{ErrorCode::ValidationError,
                 "unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, "
                 "Polkadot, Cardano, Ripple, Tron, Tezos. Use --chain to force one."};
}

}  // namespace crypto
}  // namespace zoobc
