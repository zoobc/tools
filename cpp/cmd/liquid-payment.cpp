// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Liquid Payment Tool";
    config.description = "Create a time-vested liquid payment to a recipient.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::LiquidPayment);
    config.has_recipient = true;
    config.params = {
        {"Sender private key", "sender_privkey",    "Sender's private key (64 hex chars)",     "", true, nullptr},
        {"Recipient address",  "recipient",         "Recipient address",                        "", true, nullptr},
        {"Amount",             "amount",            "Payment amount (atomic units)",            "", true, nullptr},
        {"Complete minutes",   "complete_minutes",  "Time period for full vesting (minutes)",   "", true, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);

    if (!init_sodium(emit_error)) return 1;

    try {
        auto sender_kp = derive_zbc_keypair(params.values[0]);
        if (!sender_kp.IsOk()) { emit_error(sender_kp.GetError().ToString()); return 1; }

        auto recip_result = parse_address(params.values[1]);
        if (!recip_result.IsOk()) { emit_error("Invalid recipient: " + recip_result.GetError().ToString()); return 1; }

        int64_t amount = std::stoll(params.values[2]);
        if (amount <= 0) { emit_error("Amount must be positive"); return 1; }

        uint64_t complete_minutes = std::stoull(params.values[3]);
        if (complete_minutes == 0) { emit_error("Complete minutes must be positive"); return 1; }

        auto body_bytes = TransactionUtil::GetLiquidPaymentBodyBytes(amount, complete_minutes, params.token_id);

        std::string sender_addr = zoobc::crypto::ZoobcAddress::Encode(sender_kp.Value().public_key, "ZBC");

        json extra = {
            {"sender_address", sender_addr},
            {"recipient", recip_result.Value().display},
            {"amount", amount},
            {"complete_minutes", complete_minutes},
            {"token_id", params.token_id}
        };

        return run_transaction(
            params, config.tx_type,
            sender_kp.Value().public_key,
            recip_result.Value().address,
            body_bytes,
            sender_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Liquid payment transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
