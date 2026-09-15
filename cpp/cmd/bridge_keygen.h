// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// bridge_keygen.h — deterministic derivation of a node's per-chain bridge signer keys.
// Shared by zbc-bridge-keygen and its test so the "same seed always regenerates the same
// keys" recovery guarantee is verifiable. Pure functions of the node seed (SHA3 domain
// separation per chain); no wall-clock, no randomness.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <sodium.h>
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/slip10.h"
#include "zoobc/crypto/ethereum_signature.h"
#include "zoobc/crypto/bitcoin_signature.h"
#include "zoobc/crypto/ss58.h"

namespace bkg {

// blake2b with a chosen output length (Cardano=28, Tezos=20) — libsodium's generichash IS blake2b.
inline std::vector<uint8_t> blake2b(const std::vector<uint8_t>& in, size_t outlen){
    std::vector<uint8_t> out(outlen);
    crypto_generichash_blake2b(out.data(), out.size(), in.data(), in.size(), nullptr, 0);
    return out;
}
inline std::vector<uint8_t> sha256(const std::vector<uint8_t>& in){ return zoobc::crypto::Hash::SHA256(in).Value(); }

// Generic Base58 with a supplied alphabet (Bitcoin default; Ripple uses its own).
inline const char* BTC_B58  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
inline const char* XRP_B58  = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
inline std::string base58alpha(const std::vector<uint8_t>& data, const char* A){
    size_t zeros=0; while(zeros<data.size() && data[zeros]==0) zeros++;
    std::vector<uint8_t> digits;
    for(size_t i=zeros;i<data.size();i++){ int carry=data[i];
        for(size_t k=0;k<digits.size();k++){ int x=digits[k]*256+carry; digits[k]=x%58; carry=x/58; }
        while(carry){ digits.push_back(carry%58); carry/=58; } }
    std::string out(zeros, A[0]);
    for(auto it=digits.rbegin(); it!=digits.rend(); ++it) out+=A[*it];
    return out.empty()? std::string(1,A[0]) : out;
}
// Base58Check(payload) = base58alpha(payload || sha256(sha256(payload))[:4]) — Bitcoin/Tron/Tezos/Ripple.
inline std::string base58check(std::vector<uint8_t> payload, const char* A){
    auto c = sha256(sha256(payload));
    payload.insert(payload.end(), c.begin(), c.begin()+4);
    return base58alpha(payload, A);
}

// --- Bech32 (Cardano Shelley addresses) ---
inline uint32_t bech32_polymod(const std::vector<uint8_t>& v){
    static const uint32_t G[5]={0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3};
    uint32_t chk=1;
    for(uint8_t x:v){ uint8_t top=chk>>25; chk=((chk&0x1ffffff)<<5)^x; for(int i=0;i<5;i++) if((top>>i)&1) chk^=G[i]; }
    return chk;
}
inline std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp){
    std::vector<uint8_t> o;
    for(char c:hrp) o.push_back((uint8_t)c >> 5);
    o.push_back(0);
    for(char c:hrp) o.push_back((uint8_t)c & 31);
    return o;
}
inline std::vector<uint8_t> convertbits(const std::vector<uint8_t>& data){  // 8-bit -> 5-bit, pad
    std::vector<uint8_t> out; int acc=0, bits=0;
    for(uint8_t b:data){ acc=(acc<<8)|b; bits+=8; while(bits>=5){ bits-=5; out.push_back((acc>>bits)&31); } }
    if(bits>0) out.push_back((acc<<(5-bits))&31);
    return out;
}
inline std::string bech32_encode(const std::string& hrp, const std::vector<uint8_t>& data5){
    std::vector<uint8_t> vals = bech32_hrp_expand(hrp);
    vals.insert(vals.end(), data5.begin(), data5.end());
    vals.insert(vals.end(), 6, 0);
    uint32_t mod = bech32_polymod(vals) ^ 1;
    static const char* C="qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    std::string out = hrp + "1";
    for(uint8_t d:data5) out += C[d];
    for(int i=0;i<6;i++) out += C[(mod>>(5*(5-i)))&31];
    return out;
}

inline std::string toHex(const std::vector<uint8_t>& v){
    static const char* h="0123456789abcdef"; std::string o; o.reserve(v.size()*2);
    for(uint8_t b:v){o+=h[b>>4];o+=h[b&0xf];} return o;
}
// SHA3-256(seed || tag) — chain-specific key material.
inline std::vector<uint8_t> derive(const std::vector<uint8_t>& seed, const std::string& tag){
    std::vector<uint8_t> in=seed; in.insert(in.end(), tag.begin(), tag.end());
    return zoobc::crypto::Hash::SHA3_256(in).Value();
}
// Plain Base58 (no checksum) — Solana address encoding of a 32-byte ed25519 pubkey.
inline std::string base58(const std::vector<uint8_t>& data){
    static const char* A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t zeros=0; while(zeros<data.size() && data[zeros]==0) zeros++;
    std::vector<uint8_t> digits;
    for(size_t i=zeros;i<data.size();i++){
        int carry=data[i];
        for(size_t k=0;k<digits.size();k++){ int x=digits[k]*256+carry; digits[k]=x%58; carry=x/58; }
        while(carry){ digits.push_back(carry%58); carry/=58; }
    }
    std::string out(zeros,'1');
    for(auto it=digits.rbegin(); it!=digits.rend(); ++it) out+=A[*it];
    return out.empty()? std::string("1") : out;
}

struct ChainKey { std::string chain, address, privkey_hex; std::vector<uint8_t> pubkey{}; };
struct NodeSigners { std::string zbc_owner, backup_seed; std::vector<ChainKey> chains; };

// ==================== Derivable k-of-n custody multisig addresses ====================
// These chains let the multisig address be computed as a pure function of the participant
// public keys + threshold — no on-chain deployment needed. (Ethereum Safe, Solana, Ripple,
// Tezos, Tron do NOT — they require an on-chain contract/permission/signer-list step.)
// NOTE: verify each against the chain's reference tool before real custody.

// Bitcoin P2WSH k-of-n: OP_k <sorted compressed pubkeys> OP_n OP_CHECKMULTISIG, witness v0.
inline std::string btc_p2wsh(std::vector<std::vector<uint8_t>> pubs, int k){
    std::sort(pubs.begin(), pubs.end());                    // BIP67 canonical ordering
    std::vector<uint8_t> ws;
    ws.push_back((uint8_t)(0x50 + k));                      // OP_k
    for(auto& p:pubs){ ws.push_back(0x21); ws.insert(ws.end(), p.begin(), p.end()); }  // 0x21=33 + pubkey
    ws.push_back((uint8_t)(0x50 + (int)pubs.size()));       // OP_n
    ws.push_back(0xae);                                     // OP_CHECKMULTISIG
    auto sh = sha256(ws);                                   // 32-byte witness program
    std::vector<uint8_t> data5{0};                          // segwit witness version 0
    auto conv = convertbits(sh); data5.insert(data5.end(), conv.begin(), conv.end());
    return bech32_encode("bc", data5);                      // mainnet HRP (testnet = "tb")
}

// Polkadot/Substrate native multisig: AccountId = blake2b256("modlpy/utilisuba" ||
// compact(len) || sorted 32-byte signatories || u16 threshold), then SS58 (prefix 0).
inline std::string polkadot_multisig(std::vector<std::vector<uint8_t>> ids, int threshold){
    std::sort(ids.begin(), ids.end());
    std::vector<uint8_t> pre;
    const char* tag="modlpy/utilisuba"; pre.insert(pre.end(), tag, tag+16);
    pre.push_back((uint8_t)((int)ids.size() << 2));         // SCALE compact len (n<64)
    for(auto& id:ids) pre.insert(pre.end(), id.begin(), id.end());
    pre.push_back((uint8_t)(threshold & 0xff)); pre.push_back((uint8_t)((threshold>>8)&0xff));  // u16 LE
    return zoobc::crypto::Ss58Encode(blake2b(pre, 32), 0);
}

// Cardano native-script k-of-n: RequireMOf script CBOR [3, k, [ [0, keyHash]… ]] over the
// blake2b-224 key hashes; scriptHash = blake2b224(0x00 || cbor); enterprise script address.
inline std::string cardano_native_multisig(std::vector<std::vector<uint8_t>> pubs, int k){
    std::vector<std::vector<uint8_t>> kh;
    for(auto& p:pubs) kh.push_back(blake2b(p, 28));
    std::sort(kh.begin(), kh.end());
    int n=(int)kh.size();
    std::vector<uint8_t> cbor;
    cbor.push_back(0x83);                                   // array(3)
    cbor.push_back(0x03);                                   // RequireMOf
    if(k<24) cbor.push_back((uint8_t)k); else { cbor.push_back(0x18); cbor.push_back((uint8_t)k); }
    if(n<24) cbor.push_back((uint8_t)(0x80+n)); else { cbor.push_back(0x98); cbor.push_back((uint8_t)n); }
    for(auto& h:kh){ cbor.push_back(0x82); cbor.push_back(0x00);      // [0, keyHash]
        cbor.push_back(0x58); cbor.push_back(0x1c); cbor.insert(cbor.end(), h.begin(), h.end()); }  // bytes(28)
    std::vector<uint8_t> tagged{0x00}; tagged.insert(tagged.end(), cbor.begin(), cbor.end());
    auto sh = blake2b(tagged, 28);
    std::vector<uint8_t> raw{0x71};                         // enterprise, script credential, mainnet
    raw.insert(raw.end(), sh.begin(), sh.end());
    return bech32_encode("addr", convertbits(raw));
}

// Derive one node's signer set (ethereum/bitcoin/solana) + its ZBC owner address, from a
// 32-byte node seed. `eth`/`btc` are reused across calls (each holds a secp256k1 context).
inline NodeSigners deriveNode(const std::vector<uint8_t>& node_seed,
                              zoobc::crypto::EthereumSignature& eth,
                              zoobc::crypto::BitcoinSignature& btc){
    NodeSigners ns; ns.backup_seed = toHex(node_seed);
    {
        std::vector<uint8_t> pk = derive(node_seed, "ethereum");
        auto pub = eth.GetPublicKeyFromPrivateKey(pk);
        if(pub.IsOk()) ns.chains.push_back({"ethereum", eth.GetAddressFromPublicKey("", pub.Value()), toHex(pk)});
    }
    {
        std::vector<uint8_t> pk = derive(node_seed, "bitcoin");
        auto pub = btc.GetPublicKeyFromPrivateKey(pk);
        if(pub.IsOk()) ns.chains.push_back({"bitcoin", btc.GetAddressFromPublicKey("", pub.Value()), toHex(pk), pub.Value()});
    }
    {
        std::vector<uint8_t> seed = derive(node_seed, "solana");
        std::vector<uint8_t> pub(32), sk(64);
        crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(), seed.data());
        ns.chains.push_back({"solana", base58(pub), toHex(seed)});
    }
    // Tron (secp256k1, Ethereum-style): addr = Base58Check(0x41 || keccak256(uncompressed_pubkey)[12:]).
    {
        std::vector<uint8_t> pk = derive(node_seed, "tron");
        auto pub = eth.GetPublicKeyFromPrivateKey(pk);   // 64-byte uncompressed
        if(pub.IsOk()){
            auto k = zoobc::crypto::EthereumSignature::Keccak256(pub.Value());
            if(k.IsOk()){
                std::vector<uint8_t> payload{0x41};
                payload.insert(payload.end(), k.Value().end()-20, k.Value().end());
                ns.chains.push_back({"tron", base58check(payload, BTC_B58), toHex(pk)});
            }
        }
    }
    // Ripple (secp256k1): classic address = Base58Check(0x00 || Hash160(compressed_pubkey)) in the XRP alphabet.
    {
        std::vector<uint8_t> pk = derive(node_seed, "ripple");
        auto pub = btc.GetPublicKeyFromPrivateKey(pk);   // 33-byte compressed
        if(pub.IsOk()){
            auto h = zoobc::crypto::BitcoinSignature::Hash160(pub.Value());
            if(h.IsOk()){
                std::vector<uint8_t> payload{0x00};
                payload.insert(payload.end(), h.Value().begin(), h.Value().end());
                ns.chains.push_back({"ripple", base58check(payload, XRP_B58), toHex(pk)});
            }
        }
    }
    // Tezos (ed25519): tz1 = Base58Check([6,161,159] || blake2b-160(pubkey)).
    {
        std::vector<uint8_t> seed = derive(node_seed, "tezos");
        std::vector<uint8_t> pub(32), sk(64);
        crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(), seed.data());
        std::vector<uint8_t> payload{6,161,159};
        auto pkh = blake2b(pub, 20);
        payload.insert(payload.end(), pkh.begin(), pkh.end());
        ns.chains.push_back({"tezos", base58check(payload, BTC_B58), toHex(seed)});
    }
    // Cardano (ed25519): Shelley enterprise address = bech32("addr", 0x61 || blake2b-224(pubkey)).
    {
        std::vector<uint8_t> seed = derive(node_seed, "cardano");
        std::vector<uint8_t> pub(32), sk(64);
        crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(), seed.data());
        std::vector<uint8_t> raw{0x61};
        auto kh = blake2b(pub, 28);
        raw.insert(raw.end(), kh.begin(), kh.end());
        ns.chains.push_back({"cardano", bech32_encode("addr", convertbits(raw)), toHex(seed), pub});
    }
    // Polkadot (ed25519): SS58 address of the 32-byte pubkey, network prefix 0. Polkadot's default
    // is sr25519, but ed25519 is a fully supported account type (self-consistent: ed25519 key ->
    // ed25519 AccountId -> SS58 address -> ed25519 signing).
    {
        std::vector<uint8_t> seed = derive(node_seed, "polkadot");
        std::vector<uint8_t> pub(32), sk(64);
        crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(), seed.data());
        ns.chains.push_back({"polkadot", zoobc::crypto::Ss58Encode(pub, 0), toHex(seed), pub});
    }
    {
        std::vector<uint8_t> seed = derive(node_seed, "zoobc");
        std::vector<uint8_t> pub(32), sk(64);
        crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(), seed.data());
        ns.zbc_owner = zoobc::crypto::ZoobcAddress::Encode(pub, "ZBC");
    }
    return ns;
}

// node_seed for index i from an optional master seed (deterministic) — else caller passes random.
inline std::vector<uint8_t> nodeSeedFromMaster(const std::vector<uint8_t>& master, int i){
    std::vector<uint8_t> idx{(uint8_t)(i>>24),(uint8_t)(i>>16),(uint8_t)(i>>8),(uint8_t)i};
    return derive(master, std::string(idx.begin(), idx.end()));
}

}  // namespace bkg
