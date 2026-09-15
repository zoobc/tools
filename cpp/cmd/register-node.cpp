// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Node Registration Tool";
    config.description = "Register a new node on the ZooBC network.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::NodeRegistration);
    config.needs_poown = true;
    // There used to be a required "Node address" (IP:Port) parameter here. It was never read:
    // GetNodeRegistrationBodyBytes takes the node public key, owner account, locked balance and
    // proof-of-ownership, and no address, so whatever the operator typed was discarded. Worse, the
    // tool then reported a field NAMED node_address holding something else entirely (the node's
    // ZNK-encoded public key), so the value that came back was not the value that went in.
    //
    // A node does not need to be told its own address. It discovers it three ways, none of which
    // involve this transaction: an external service (checkip.amazonaws.com / api.ipify.org), peers
    // reporting the address back to it (discover_public_ip_from_seed_nodes), and UPnP asking the
    // router directly (network.upnp_enabled). Peers then exchange addresses over P2P and store
    // them via SendNodeAddressInfo -> InsertNodeAddressInfo, which is the ONLY writer of
    // node_address_info anywhere in the tree. Verified on a NAT-ed host: it discovered its public
    // IP and advertised it with nothing registered on its behalf.
    //
    // Dropping the parameter changes no transaction format, so it carries no consensus risk.
    config.params = {
        {"Node private key",  "node_privkey",   "Node's private key (64 hex chars)",  "", true, nullptr},
        {"Owner private key", "owner_privkey",  "Owner's private key (64 hex chars)", "", true, nullptr},
        {"Locked balance",    "locked_balance", "Amount to lock (atomic units)",      "", true, nullptr},
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

        int64_t locked_balance = std::stoll(params.values[2]);
        if (locked_balance <= 0) { emit_error("Locked balance must be positive"); return 1; }

        // Build ProofOfOwnership
        auto poown_result = build_proof_of_ownership(owner_kp.Value(), params.api_url);
        if (!poown_result.IsOk()) { emit_error(poown_result.GetError().ToString()); return 1; }

        // Build owner account address
        auto owner_account_address = TransactionUtil::BuildAccountAddress(
            TransactionUtil::ACCOUNT_TYPE_ZBC, owner_kp.Value().public_key);

        auto body_bytes = TransactionUtil::GetNodeRegistrationBodyBytes(
            node_kp.Value().public_key,
            owner_account_address,
            locked_balance,
            poown_result.Value());

        // Named for what it actually is. This is a ZNK-encoded PUBLIC KEY, not a network address;
        // reporting it under "node_address" while the tool also demanded an IP:Port was the whole
        // source of the confusion.
        std::string node_pubkey = zoobc::crypto::ZoobcAddress::Encode(node_kp.Value().public_key, "ZNK");
        std::string owner_addr = zoobc::crypto::ZoobcAddress::Encode(owner_kp.Value().public_key, "ZBC");

        json extra = {
            {"node_public_key", node_pubkey},
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
            "SUCCESS: Node registration transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
