// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;

static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void putU16(std::vector<uint8_t>& b, int v){ b.push_back((uint8_t)(v&0xff)); b.push_back((uint8_t)((v>>8)&0xff)); }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Issue Token Tool";
    config.description = "Issue a native token (colored coin) backed by ZBC.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::IssueToken);
    config.has_recipient = false;
    config.params = {
        {"Sender private key", "sender_privkey", "Issuer private key (64 hex)", "", true, nullptr},
        {"Symbol",   "symbol",   "Token symbol (e.g. GOLD)",                       "", true,  nullptr},
        {"Name",     "name",     "Token name",                                     "", true,  nullptr},
        {"Decimals", "decimals", "Decimals 0-8",                                   "", true,  nullptr},
        {"Supply",   "supply",   "Total supply (atomic, token's smallest unit)",   "", true,  nullptr},
        {"Backing",  "backing",  "ZBC backing locked (atomic; 0 = unbacked)",      "", true,  nullptr},
        {"Flags",    "flags",    "bit0 redeemable, bit1 mintable, bit3 unbacked",  "1", false, nullptr},
    };

    ParsedParams params; auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& m){ emit_error(m); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);
    if (!init_sodium(emit_error)) return 1;

    try {
        auto kp = derive_zbc_keypair(params.values[0]);
        if (!kp.IsOk()) { emit_error(kp.GetError().ToString()); return 1; }
        std::string sym = params.values[1], name = params.values[2];
        int decimals = std::stoi(params.values[3]);
        int64_t supply = std::stoll(params.values[4]);
        int64_t backing = std::stoll(params.values[5]);
        int flags = (params.values.size() > 6 && !params.values[6].empty()) ? std::stoi(params.values[6]) : 1;
        if (decimals < 0 || decimals > 8) { emit_error("decimals must be 0-8"); return 1; }
        if (supply <= 0) { emit_error("supply must be > 0"); return 1; }

        std::vector<uint8_t> body;
        body.push_back((uint8_t)decimals); body.push_back((uint8_t)flags);
        putU64(body, supply); putU64(body, backing);
        putU16(body, (int)sym.size()); body.insert(body.end(), sym.begin(), sym.end());
        putU16(body, (int)name.size()); body.insert(body.end(), name.begin(), name.end());

        std::string sender_addr = zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key, "ZBC");
        json extra = {{"sender_address", sender_addr}, {"symbol", sym}, {"supply", supply},
                      {"backing", backing}, {"decimals", decimals}, {"flags", flags}};
        return run_transaction(params, config.tx_type, kp.Value().public_key, std::vector<uint8_t>{},
                               body, kp.Value(), KeyType::ZBC, extra, emit_error, "SUCCESS: Token issued!");
    } catch (const std::exception& e) { emit_error(e.what()); return 1; }
}
