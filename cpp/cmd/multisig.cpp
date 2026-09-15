// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// zbc-multisig: build and submit a MultiSignature (type 5) transaction.
//
// One-shot flow for testing an N-of-M multisig "send": it computes the
// multisig address from the participants, builds an UNSIGNED inner SendZBC
// transaction from that multisig address, signs the inner-tx hash with each
// provided participant key, packs everything into a MultiSignatureTransactionBody
// (multisig_info + unsigned_transaction_bytes + signature_info) and submits it
// as a type-5 transaction.
//
// The submitter (submitter_privkey) pays the outer multisig fee and is the
// sender of the type-5 tx. The multisig address must be funded for the inner
// SendZBC to succeed when the signatures complete.
//
// JSON params (stdin): submitter_privkey, participants (comma-separated ZBC
// addresses), min_signatures, nonce, signer_privkeys (comma-separated),
// recipient, amount, inner_fee, fee, api_url.

#include "tx_common.h"
#include "zoobc/transaction/multisignature_service.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/signature.h"
#include <sstream>
#include <ctime>

using namespace txc;

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        size_t a = item.find_first_not_of(" \t");
        size_t b = item.find_last_not_of(" \t");
        if (a != std::string::npos) out.push_back(item.substr(a, b - a + 1));
    }
    return out;
}

static std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    for (uint8_t b : v) o << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return o.str();
}

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC MultiSignature Tool";
    config.description = "Build + submit an N-of-M multisig SendZBC transaction.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::MultiSignature);
    config.params = {
        {"Submitter private key", "submitter_privkey", "Key paying the multisig fee / type-5 sender", "", true, nullptr},
        {"Participants",          "participants",      "Comma-separated participant ZBC addresses",    "", true, nullptr},
        {"Minimum signatures",    "min_signatures",    "Required signatures (N of M)",                 "", true, nullptr},
        {"Nonce",                 "nonce",             "Multisig account nonce",                       "0", false, nullptr},
        {"Signer private keys",   "signer_privkeys",   "Comma-separated participant keys that sign",   "", true, nullptr},
        {"Recipient",             "recipient",         "Inner SendZBC recipient address",              "", true, nullptr},
        {"Amount",                "amount",            "Inner SendZBC amount (atomic units)",          "", true, nullptr},
        {"Inner fee",             "inner_fee",         "Inner SendZBC fee (atomic units)",             "10000000", false, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);

    if (!init_sodium(emit_error)) return 1;

    try {
        // Submitter keypair (outer type-5 tx sender, pays the multisig fee).
        auto submitter_kp = derive_zbc_keypair(params.values[0]);
        if (!submitter_kp.IsOk()) { emit_error(submitter_kp.GetError().ToString()); return 1; }

        // Participants -> full address bytes.
        auto participant_strs = split_csv(params.values[1]);
        if (participant_strs.size() < 2) { emit_error("Need at least 2 participants"); return 1; }
        std::vector<std::vector<uint8_t>> participants;
        for (const auto& p : participant_strs) {
            auto pr = parse_address(p);
            if (!pr.IsOk()) { emit_error("Invalid participant address: " + p); return 1; }
            participants.push_back(pr.Value().address);
        }

        uint32_t min_sigs = static_cast<uint32_t>(std::stoul(params.values[2]));
        int64_t nonce = std::stoll(params.values[3]);

        auto signer_key_strs = split_csv(params.values[4]);
        if (signer_key_strs.empty()) { emit_error("Need at least one signer key"); return 1; }

        auto recipient_result = parse_address(params.values[5]);
        if (!recipient_result.IsOk()) { emit_error("Invalid recipient: " + recipient_result.GetError().ToString()); return 1; }
        int64_t amount = std::stoll(params.values[6]);
        int64_t inner_fee = std::stoll(params.values[7]);

        // 1. Compute the multisig address from the participants.
        auto multisig_addr = zoobc::transaction::MultisignatureService::GenerateMultisigAddress(
            participants, nonce, min_sigs);
        if (multisig_addr.empty()) { emit_error("Failed to generate multisig address"); return 1; }

        // 2. Build the UNSIGNED inner SendZBC transaction (sender = multisig addr).
        //    Body for SendZBC is the 8-byte little-endian amount.
        std::vector<uint8_t> inner_body;
        TransactionUtil::WriteUint64LE(inner_body, static_cast<uint64_t>(amount));

        std::vector<uint8_t> empty;
        int64_t inner_ts = transaction_timestamp(params);  // --timestamp fixes it, else now
        // Inner-tx sender = the multisig account as a ZBC-TYPED 36-byte address (4-byte ACCOUNT_TYPE_ZBC
        // prefix + the 32-byte GenerateMultisigAddress hash). The node deserializes the inner sender this
        // way (transaction_executor.cpp:5111); passing the bare 32-byte hash misaligns the parse and the
        // inner tx fails with "Unexpected end of bytes (body)".
        std::vector<uint8_t> inner_sender;
        TransactionUtil::WriteInt32LE(inner_sender, ACCOUNT_TYPE_ZBC);
        inner_sender.insert(inner_sender.end(), multisig_addr.begin(), multisig_addr.end());
        auto inner_unsigned = build_transaction_bytes_multikey(
            1 /*version*/, inner_ts,
            inner_sender,
            recipient_result.Value().address,
            static_cast<uint32_t>(zoobc::TransactionType::SendZBC),
            inner_fee, inner_body, empty, empty);

        // 3. Hash of the unsigned inner tx — this is what participants sign and
        //    what the executor stores as the pending transaction hash.
        auto inner_hash_result = zoobc::crypto::Hash::SHA3_256(inner_unsigned);
        if (inner_hash_result.IsErr()) { emit_error("Failed to hash inner tx"); return 1; }
        auto inner_hash = inner_hash_result.Value();

        // 4. Each provided participant key signs the CHAIN-BOUND digest of the inner bytes
        //    (signing v2: SHA3-256("ZBC-TX" ‖ genesis ‖ inner)); inner_hash stays the key the
        //    chain collects the signatures under.
        if (!ensure_signing_context(params.api_url, params.genesis_hex, emit_error)) return 1;
        auto inner_digest_result = signing_digest(inner_unsigned);
        if (inner_digest_result.IsErr()) { emit_error("Failed to digest inner tx: " + inner_digest_result.GetError().ToString()); return 1; }
        auto inner_digest = inner_digest_result.Value();
        zoobc::model::SignatureInfo sig_info;
        sig_info.transaction_hash = inner_hash;
        for (const auto& sk : signer_key_strs) {
            auto kp = derive_zbc_keypair(sk);
            if (!kp.IsOk()) { emit_error("Invalid signer key"); return 1; }
            auto sig = zoobc::crypto::Signature::Sign(inner_digest, kp.Value().private_key);
            if (sig.IsErr()) { emit_error("Failed to sign inner tx: " + sig.GetError().ToString()); return 1; }
            // Key: hex of the signer's full ZBC account address (4-byte type prefix + pubkey).
            std::vector<uint8_t> signer_addr;
            TransactionUtil::WriteInt32LE(signer_addr, ACCOUNT_TYPE_ZBC);
            signer_addr.insert(signer_addr.end(), kp.Value().public_key.begin(), kp.Value().public_key.end());
            sig_info.signatures[to_hex(signer_addr)] = sig.Value();
        }

        // 5. Assemble the multisig body (info + unsigned inner tx + signatures).
        zoobc::model::MultiSignatureTransactionBody body;
        zoobc::model::MultiSignatureInfo info;
        info.minimum_signatures = min_sigs;
        info.nonce = nonce;
        info.addresses = participants;
        body.multi_signature_info = info;
        body.unsigned_transaction_bytes = inner_unsigned;
        body.signature_info = sig_info;

        auto body_bytes = zoobc::transaction::MultisignatureService::GetBodyBytes(body);

        // The multisig account must hold funds for the inner tx to execute. Expose its fundable ZBC
        // address (send ZBC here first, then submit the multisig) — the raw 32-byte hash is not a
        // valid send-zbc recipient on its own.
        std::string multisig_zbc = zoobc::crypto::ZoobcAddress::Encode(multisig_addr, "ZBC");
        json extra = {
            {"multisig_address", to_hex(multisig_addr)},
            {"multisig_zbc_address", multisig_zbc},
            {"fund_hint", "send ZBC to multisig_zbc_address before submitting, else the inner tx stays in mempool"},
            {"min_signatures", min_sigs},
            {"participants", participant_strs.size()},
            {"signers", signer_key_strs.size()},
            {"inner_recipient", recipient_result.Value().display},
            {"inner_amount", amount},
            {"inner_tx_hash", to_hex(inner_hash)}
        };

        std::vector<uint8_t> empty_recipient;
        return run_transaction(
            params, config.tx_type,
            submitter_kp.Value().public_key,
            empty_recipient,
            body_bytes,
            submitter_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: MultiSignature transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
