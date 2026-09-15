// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Shared body builders for the on-chain infrastructure registries (gateway / archival / relay).
//
// All three "register" bodies share the same tail — a length-prefixed domain then a length-prefixed
// url — and all three "unregister" bodies are just the 32-byte key. Keeping the layout in one place
// means the six tools cannot drift from each other, and a change to the wire format is one edit.
//
//   RegisterGateway   (36) : gateway_key(32) | u32 domain_len | domain | u32 url_len | url
//   UnregisterGateway (38) : gateway_key(32)
//   RegisterArchival  (46) : node_public_key(32) | u32 domain_len | domain | u32 url_len | url
//   UnregisterArchival(47) : node_public_key(32)
//   RegisterRelay     (48) : relay_key(32) | gateway_key(32) | u32 domain_len | domain | u32 url_len | url
//   UnregisterRelay   (49) : relay_key(32)
//
// Lengths are little-endian uint32, matching the executors' rd_u32 in transaction_executor.cpp.
#ifndef ZOOBC_TOOLS_REGISTRY_COMMON_H
#define ZOOBC_TOOLS_REGISTRY_COMMON_H

#include <string>
#include <vector>
#include <cstdint>

namespace txc {

inline void reg_put_u32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) { b.push_back(static_cast<uint8_t>(v & 0xff)); v >>= 8; }
}

inline void reg_put_lenstr(std::vector<uint8_t>& b, const std::string& s) {
    reg_put_u32(b, static_cast<uint32_t>(s.size()));
    b.insert(b.end(), s.begin(), s.end());
}

// key(32) [| key2(32)] | u32 len | domain | u32 len | url
inline std::vector<uint8_t> reg_body(const std::vector<uint8_t>& key,
                                     const std::string& domain, const std::string& url,
                                     const std::vector<uint8_t>* key2 = nullptr) {
    std::vector<uint8_t> b;
    b.insert(b.end(), key.begin(), key.end());
    if (key2) b.insert(b.end(), key2->begin(), key2->end());
    reg_put_lenstr(b, domain);
    reg_put_lenstr(b, url);
    return b;
}

inline std::vector<uint8_t> unreg_body(const std::vector<uint8_t>& key) {
    return std::vector<uint8_t>(key.begin(), key.end());
}

}  // namespace txc
#endif
