// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Approve Escrow Tool";
    config.description = "Approve or reject an escrow transaction. The escrow is named by the full "
                         "hash of the escrowed transaction (as shown by the explorer and by "
                         "GET /api/v1/accounts/<address>/escrows), not by its numeric id.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::ApprovalEscrow);
    config.params = {
        {"Sender private key", "sender_privkey",    "Sender's private key (64 hex chars)", "", true, nullptr},
        {"Approval decision",  "approval",          "Approval: 0=approve, 1=reject, 2=expire", "", true, nullptr},
        {"Transaction hash",   "transaction_hash",  "Escrowed transaction hash (64 hex chars)", "", true, nullptr},
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

        int32_t approval_int = std::stoi(params.values[1]);
        if (approval_int < 0 || approval_int > 2) {
            emit_error("Approval must be 0 (approve), 1 (reject), or 2 (expire)");
            return 1;
        }
        auto approval = static_cast<zoobc::model::EscrowApproval>(approval_int);

        // The body carries the escrowed transaction's FULL 32-byte hash (since 2026-09-08). A
        // numeric id is not accepted: an approval that names only 8 bytes cannot be checked by a
        // signer against the transaction it is releasing.
        auto tx_hash = hex_to_bytes(params.values[2]);
        if (tx_hash.size() != 32) {
            emit_error("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)");
            return 1;
        }

        auto body_bytes = TransactionUtil::GetApprovalEscrowBodyBytes(approval, tx_hash);

        std::string sender_addr = zoobc::crypto::ZoobcAddress::Encode(sender_kp.Value().public_key, "ZBC");

        json extra = {
            {"sender_address", sender_addr},
            {"approval", approval_int},
            {"escrow_transaction_hash", params.values[2]},
            {"escrow_transaction_id", TransactionUtil::GetTransactionID(tx_hash)}
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
            "SUCCESS: Escrow approval transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
