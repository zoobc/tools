// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Escrow Request Tool";
    config.description = "Create a recipient-initiated escrow request.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::EscrowRequest);
    config.params = {
        {"Requester private key", "requester_privkey", "Requester's private key (64 hex chars)", "", true, nullptr},
        {"Proposed sender",       "proposed_sender",   "Proposed sender address",                "", true, nullptr},
        {"Amount",                "amount",            "Proposed amount (atomic units)",          "", true, nullptr},
        {"Approver address",      "approver",          "Third-party approver address",           "", true, nullptr},
        {"Commission",            "commission",        "Approver commission (atomic units)",      "0", false, nullptr},
        {"Timeout",               "timeout",           "Escrow timeout (future Unix timestamp, seconds)", "", true, nullptr},
        {"Instruction",           "instruction",       "Instructions (optional)",                 "", false, nullptr},
        {"Expiry",                "expiry",            "Request expiry (block height gap)",       "0", false, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);

    if (!init_sodium(emit_error)) return 1;

    try {
        auto requester_kp = derive_zbc_keypair(params.values[0]);
        if (!requester_kp.IsOk()) { emit_error(requester_kp.GetError().ToString()); return 1; }

        auto sender_result = parse_address(params.values[1]);
        if (!sender_result.IsOk()) { emit_error("Invalid proposed sender: " + sender_result.GetError().ToString()); return 1; }

        auto approver_result = parse_address(params.values[3]);
        if (!approver_result.IsOk()) { emit_error("Invalid approver: " + approver_result.GetError().ToString()); return 1; }

        zoobc::model::EscrowRequestTransactionBody body;
        body.proposed_sender = sender_result.Value().address;
        body.proposed_amount = std::stoll(params.values[2]);
        body.approver_address = approver_result.Value().address;
        body.commission = std::stoll(params.values[4]);
        body.timeout = std::stoll(params.values[5]);
        body.instruction = params.values[6];
        body.expiry = std::stoll(params.values[7]);
        // The validator requires expiry > 0 (ValidateEscrowRequest). When the
        // caller leaves it unset (default "0"), the request would otherwise be
        // rejected at mempool admission — and silently, because the two-tier
        // staging pool returns success on staging before validation runs.
        // Default it to the timeout window so a request is valid out of the box.
        if (body.expiry <= 0) {
            body.expiry = body.timeout;
        }

        auto body_bytes = TransactionUtil::GetEscrowRequestBodyBytes(body);

        std::string requester_addr = zoobc::crypto::ZoobcAddress::Encode(requester_kp.Value().public_key, "ZBC");

        json extra = {
            {"requester_address", requester_addr},
            {"proposed_sender", sender_result.Value().display},
            {"proposed_amount", body.proposed_amount},
            {"approver", approver_result.Value().display}
        };

        std::vector<uint8_t> empty_recipient;
        return run_transaction(
            params, config.tx_type,
            requester_kp.Value().public_key,
            empty_recipient,
            body_bytes,
            requester_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Escrow request transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
