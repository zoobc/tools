// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Remove Node Registration Tool";
    config.description = "Remove a node from the registry and return locked balance to owner.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::RemoveNodeRegistration);
    config.params = {
        {"Node private key",  "node_privkey",  "Node's private key (64 hex chars)",  "", true, nullptr},
        {"Owner private key", "owner_privkey", "Owner's private key (64 hex chars)", "", true, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);

    if (!init_sodium(emit_error)) return 1;

    try {
        auto node_kp = derive_zbc_keypair(params.values[0]);
        if (!node_kp.IsOk()) { emit_error(node_kp.GetError().ToString()); return 1; }

        auto owner_kp = derive_zbc_keypair(params.values[1]);
        if (!owner_kp.IsOk()) { emit_error(owner_kp.GetError().ToString()); return 1; }

        auto body_bytes = TransactionUtil::GetRemoveNodeRegistrationBodyBytes(node_kp.Value().public_key);

        std::string node_addr = zoobc::crypto::ZoobcAddress::Encode(node_kp.Value().public_key, "ZNK");
        std::string owner_addr = zoobc::crypto::ZoobcAddress::Encode(owner_kp.Value().public_key, "ZBC");

        json extra = {
            {"node_address", node_addr},
            {"owner_address", owner_addr}
        };

        std::vector<uint8_t> empty_recipient;
        return run_transaction(
            params, config.tx_type,
            owner_kp.Value().public_key,
            empty_recipient,
            body_bytes,
            owner_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Node removal transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
