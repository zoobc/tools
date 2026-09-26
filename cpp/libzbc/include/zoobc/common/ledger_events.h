// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// Names for every event type the node writes into account_ledger.event_type (gap 4 of wallet prompt
// 12). The numbers come from two places: model::EventType (1-16, 100: the Go-era transaction events)
// and the EVENT_TYPE_* constants in common/constants.h (17-70). The DFS executors write their
// transaction type as the event (8, 264, 520); 8 therefore also names a DFSCreateFile row, which is
// told apart from a block reward by its non-zero transaction_id. ledger_events_test pins that every
// constant has a name here, so a new event cannot reach the API unnamed.
#include <cstdint>

namespace zoobc {
namespace ledger {

inline const char* EventName(int64_t ev) {
    switch (ev) {
        case 1:   return "send_or_fee";                 // SendZBC amount, or the fee row of any type (uniform_fee_refund)
        case 2:   return "node_registration";
        case 3:   return "node_registration_update";
        case 4:   return "node_registration_removed";
        case 5:   return "node_registration_claimed";
        case 6:   return "dataset_setup";
        case 7:   return "dataset_removed";
        case 8:   return "block_reward";                // also DFSCreateFile (transaction_id != 0)
        case 9:   return "escrow_approval";
        case 10:  return "multisig";
        case 11:  return "fee_vote_commit";
        case 12:  return "fee_vote_reveal";
        case 13:  return "liquid_payment";
        case 14:  return "liquid_paid";
        case 15:  return "liquid_payment_stop";
        case 16:  return "escrowed_transaction";
        case 17:  return "dataset_storage_fee";
        case 18:  return "dataset_pruned";
        case 19:  return "storage_rent_reward";
        case 20:  return "token_expired";
        case 21:  return "token_backing_returned";
        case 22:  return "fee_refund";
        case 23:  return "trigger_fired";
        case 24:  return "account_rent_paid";
        case 25:  return "account_pruned";
        case 26:  return "oracle_resolved";
        case 27:  return "bridge_mint";
        case 28:  return "vesting_release";
        case 29:  return "scheduled_payment";
        case 30:  return "scheduled_skipped";
        case 31:  return "gateway_pruned";
        case 32:  return "dataset_deposit_refund";
        case 33:  return "dataset_transferred";
        case 34:  return "schedule_cancelled";
        case 35:  return "consensus_param_changed";
        case 36:  return "bridge_burn";
        case 37:  return "longevity_funded";            // FundLongevity deposit or a transaction's own survival
        case 38:  return "longevity_rent";
        case 39:  return "longevity_payout";
        case 40:  return "longevity_refund";            // CancelLongevity, before survival_field
        case 41:  return "split_out";
        case 42:  return "split_in";
        case 43:  return "escrow_fee_held";             // reserved, not written today
        case 44:  return "escrow_fee_refund";           // reserved, not written today
        case 45:  return "survival_paid";               // escrow rent, token survival: paid into the node pool
        case 46:  return "fee_refund_in_token";
        case 47:  return "fee_not_collected";
        case 48:  return "group_join_out";
        case 49:  return "group_join_in";
        case 50:  return "survival_to_pool";            // leftover rent to the longevity node pool
        case 51:  return "stored_file_funded";          // StoreFile deposit / FundStoredFile top-up
        case 52:  return "token_backing_locked";
        case 53:  return "token_redeemed";
        case 54:  return "swap_offer_locked";
        case 55:  return "swap_offer_released";
        case 56:  return "exchange_trade";
        case 57:  return "market_creation_cost";
        case 58:  return "order_locked";
        case 59:  return "order_released";
        case 60:  return "exchange_taker_fee";
        case 61:  return "trigger_locked";
        case 62:  return "trigger_cancelled";
        case 63:  return "schedule_locked";
        case 64:  return "gateway_stake_locked";
        case 65:  return "gateway_stake_returned";
        case 66:  return "app_stake";
        case 67:  return "app_rake";
        case 68:  return "prepaid_storage_funded";
        case 69:  return "stored_file_rent";
        case 70:  return "multisig_inner_fee";          // rule multisig_inner_fee_path: the inner transaction's fee
        case 100: return "app_payout";
        case 264: return "dfs_file_updated";
        case 520: return "dfs_file_deleted";
        default:  return "movement";
    }
}

}  // namespace ledger
}  // namespace zoobc
