// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Liquid Payment Stop Tool";
    config.description = "Stop/complete a pending liquid payment, distributing funds pro-rata.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::LiquidPaymentStop);
    config.params = {
        {"Sender private key", "sender_privkey",  "Sender's private key (64 hex chars)",             "", true, nullptr},
        {"Transaction ID",     "transaction_id",  "ID of the LiquidPayment transaction to stop",     "", true, nullptr},
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

        int64_t transaction_id = std::stoll(params.values[1]);

        auto body_bytes = TransactionUtil::GetLiquidPaymentStopBodyBytes(transaction_id);

        std::string sender_addr = zoobc::crypto::ZoobcAddress::Encode(sender_kp.Value().public_key, "ZBC");

        json extra = {
            {"sender_address", sender_addr},
            {"stopped_transaction_id", transaction_id}
        };

        std::vector<uint8_t> empty_recipient;
        return run_transaction(
            params, config.tx_type,
            sender_kp.Value().public_key,
            empty_recipient,
            body_bytes,
            sender_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Liquid payment stop transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
