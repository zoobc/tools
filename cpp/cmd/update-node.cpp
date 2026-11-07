// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Update Node Registration Tool";
    config.description = "Raise a node's locked balance (it is never lowered), or rotate the node to a new node key.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::NodeRegistrationUpdate);
    config.needs_poown = true;
    config.params = {
        {"Node private key",     "node_privkey",      "Node's private key (64 hex chars)",  "", true, nullptr},
        {"Owner private key",    "owner_privkey",     "Owner's private key (64 hex chars)", "", true, nullptr},
        {"New locked balance",   "new_locked_balance", "New total locked balance (atomic units); never lower than the current one (a genesis registry node's is 0)", "", true, nullptr},
        {"New node private key", "new_node_privkey",  "Optional: rotate the registered node to this node key (64 hex chars); the proof is signed by it (rule node_key_rotation). It takes effect 120 blocks after the block that includes it: keep the node on the old key until then", "", false, nullptr},
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

        int64_t locked_balance = whole_param(params.values, 2);
        // j62: the node refuses only a lower stake; a genesis seat locks nothing, so its owner rotates the key with a
        // stake of 0. Without a new key the update must name a stake to raise to.
        const bool rotating = params.values.size() > 3 && !params.values[3].empty();
        if (locked_balance < 0) { emit_error("Locked balance must not be negative"); return 1; }
        if (locked_balance == 0 && !rotating) { emit_error("Locked balance must be positive (or give a new node key to rotate the node)"); return 1; }

        // Rule node_key_rotation (20 F4): with a fourth key the seat moves to it; the proof is the
        // NEW key's (the old one may be lost or stolen) and the body names old key + new key.
        std::vector<uint8_t> new_node_key;
        auto proof_kp = node_kp.Value();
        if (params.values.size() > 3 && !params.values[3].empty()) {
            auto new_kp = derive_zbc_keypair(params.values[3]);
            if (!new_kp.IsOk()) { emit_error(new_kp.GetError().ToString()); return 1; }
            new_node_key = new_kp.Value().public_key;
            proof_kp = new_kp.Value();
        }
        auto poown_result = build_proof_of_ownership(owner_kp.Value(), proof_kp, params.api_url);
        if (!poown_result.IsOk()) { emit_error(poown_result.GetError().ToString()); return 1; }

        auto body_bytes = TransactionUtil::GetUpdateNodeRegistrationBodyBytes(
            node_kp.Value().public_key, locked_balance, poown_result.Value(), new_node_key);

        std::string node_addr = zoobc::crypto::ZoobcAddress::Encode(node_kp.Value().public_key, "ZNK");
        std::string owner_addr = zoobc::crypto::ZoobcAddress::Encode(owner_kp.Value().public_key, "ZBC");

        json extra = {
            {"node_address", node_addr},
            {"owner_address", owner_addr},
            {"locked_balance", locked_balance}
        };
        if (!new_node_key.empty()) extra["new_node_address"] = zoobc::crypto::ZoobcAddress::Encode(new_node_key, "ZNK");

        std::vector<uint8_t> empty_recipient;
        return run_transaction(
            params, config.tx_type,
            owner_kp.Value().public_key,
            empty_recipient,
            body_bytes,
            owner_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Node update transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
