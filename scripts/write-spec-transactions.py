#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Write spec/transactions/<command>.json, one machine-readable description per transaction type.

The table below is transcribed from the C++ reference (cpp/cmd/zoobc-cli.cpp builders and the
standalone tools in cpp/cmd/); scripts/make-vectors.py then runs the C++ tools on each file's
example and records what they produce, so every description is checked against the reference.
Run from the repository root:  python3 scripts/write-spec-transactions.py
"""
import json, pathlib, sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "transactions"
LICENSE = "MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci"

# ---- helpers to keep the table short ---------------------------------------------------------
def P(name, kind, help, required=True, default=None):
    d = {"name": name, "kind": kind, "required": required, "help": help}
    if default is not None: d["default"] = default
    return d
def F(name, encoding, source=None, **kw):
    d = {"name": name, "encoding": encoding, "from": source or name}
    d.update(kw)
    return d
KEY = P("sender_privkey", "privkey", "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY")

def T(command, type_code, name, description, params, body, *, binary=None, recipient="none",
      sender_key="sender_privkey", options=("message", "encrypt"), needs_node=False, custom=None,
      example=None, notes=()):
    """One transaction description. `params` excludes the key, which is always first."""
    key = dict(KEY); key["name"] = sender_key
    if sender_key != "sender_privkey":
        key["help"] = "the signing key (64 hex). Named %s: ZBC_KEY does not apply, pass it explicitly" % sender_key
    return {
        "license": LICENSE,
        "name": name, "type": type_code, "command": command, "binary": binary,
        "description": description, "sender_key": sender_key, "recipient": recipient,
        "options": list(options), "needs_node": needs_node, "custom": custom,
        "params": [key] + params, "body": body, "example": example or {}, "notes": list(notes),
    }

# Example values shared by every file, so the vectors are readable side by side.
A_SELF = "ZBC_L2HLFDOM_VKKKTEXX_C2P2M6LG_EB6ZNKSV_356SJUWW_5QPVHDE7_EFJA3PEX"   # seed 51bae95d…, vector wallet account 0
A_OTHER = "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I"  # seed 11…11
H32 = "1111111111111111111111111111111111111111111111111111111111111111"
H32B = "2222222222222222222222222222222222222222222222222222222222222222"
SEED1 = "1111111111111111111111111111111111111111111111111111111111111111"
SEED2 = "2222222222222222222222222222222222222222222222222222222222222222"
ID8 = F("id", "u64le")

TX = [
T("send-zbc", 1, "SendZBC", "Send ZBC from the sender to a recipient; optionally escrowed.",
  [P("recipient", "address", "recipient address (ZBC_, 64 hex, or another chain's address)"),
   P("amount", "int64", "amount in atomic units (1 ZBC = 100000000)")],
  [F("amount", "u64le")], binary="zbc-send", recipient="required", options=("message", "encrypt", "escrow", "chain"),
  example={"recipient": A_SELF, "amount": "100000000"},
  notes=["zbc-send also accepts --liquid <minutes>, which makes it a LiquidPayment (type 6) instead."]),

T("liquid-payment", 6, "LiquidPayment", "Stream ZBC (or a token) to a recipient, vesting linearly over complete_minutes.",
  [P("recipient", "address", "recipient address"), P("amount", "int64", "amount (atomic units)"),
   P("complete_minutes", "uint64", "minutes until fully vested"),
   P("token_id", "int64", "token to stream instead of ZBC (--token); 0 = ZBC", required=False, default="0")],
  [F("amount", "u64le"), F("complete_minutes", "u64le"), F("token_id", "u64le", when="token_id != 0")],
  binary="zbc-liquid-pay", recipient="required", example={"recipient": A_OTHER, "amount": "500000000", "complete_minutes": "60"},
  notes=["zbc-cli liquid-payment always streams ZBC; the token_id field comes from zbc-liquid-pay --token <id>."]),

T("liquid-payment-stop", 262, "LiquidPaymentStop", "Stop a liquid payment; the vested part goes to the recipient, the rest back.",
  [P("transaction_id", "int64", "the liquid payment's transaction id (first 8 bytes of its hash, int64 LE; often negative)")],
  [F("transaction_id", "u64le")], binary="zbc-liquid-stop", example={"transaction_id": "-1234567890123456789"}),

T("approve-escrow", 4, "ApprovalEscrow", "Approve (0), reject (1) or expire (2) an escrowed transaction, named by its full hash.",
  [P("approval", "uint32", "0 = approve, 1 = reject, 2 = expire"), P("transaction_hash", "hex32", "the escrowed transaction's hash, 64 hex")],
  [F("approval", "u32le"), F("transaction_hash", "hex", size=32)], binary="zbc-escrow-approve",
  example={"approval": "0", "transaction_hash": H32},
  notes=["The tool reports escrowed_transaction_hash and transaction_id (int64 of the escrowed hash) next to its own transaction_hash."]),

T("escrow-request", 260, "EscrowRequest", "Recipient-initiated escrow: ask proposed_sender to pay amount through an approver.",
  [P("proposed_sender", "address", "who is asked to pay"), P("amount", "int64", "proposed amount (atomic units)"),
   P("approver", "address", "third-party approver"), P("commission", "int64", "approver commission (atomic units)", required=False, default="0"),
   P("timeout", "int64", "escrow timeout, future Unix seconds"), P("instruction", "string", "instructions", required=False, default=""),
   P("expiry", "int64", "request expiry; 0 = same as timeout", required=False, default="0")],
  [F("proposed_sender", "address"), F("amount", "u64le"), F("approver", "address"), F("commission", "u64le"),
   F("timeout", "u64le"), F("instruction", "str32"), F("expiry", "u64le", default_from="timeout", when_zero="timeout")],
  binary="zbc-escrow-request", example={"proposed_sender": A_OTHER, "amount": "250000000", "approver": A_SELF, "commission": "1000", "timeout": "1800000000", "instruction": "pay on delivery", "expiry": "0"},
  notes=["zbc-escrow-request names its first field requester_privkey; zbc-cli uses sender_privkey (ZBC_KEY applies there)."]),

T("issue-token", 10, "IssueToken", "Issue a token backed by ZBC.",
  [P("symbol", "string", "2-10 upper-case letters or digits, not a reserved symbol"), P("name", "string", "token name"),
   P("decimals", "uint8", "0-8, display only"), P("supply", "int64", "total supply (atomic, 10^8 per unit)"),
   P("backing", "int64", "ZBC locked as backing (atomic); 0 = unbacked"),
   P("flags", "uint8", "bit0 redeemable, bit1 mintable, bit3 unbacked", required=False, default="1")],
  [F("decimals", "u8"), F("flags", "u8"), F("supply", "u64le"), F("backing", "u64le"), F("symbol", "str16"), F("name", "str16")],
  binary="zbc-token-issue", example={"symbol": "GOLD", "name": "Gold token", "decimals": "2", "supply": "100000000000", "backing": "100000000", "flags": "1"}),
T("transfer-token", 11, "TransferToken", "Transfer a token to a recipient.",
  [P("recipient", "address", "recipient address"), P("token_id", "int64", "token id"), P("amount", "int64", "amount (atomic), > 0")],
  [F("token_id", "u64le"), F("amount", "u64le")], binary="zbc-token-transfer", recipient="required",
  example={"recipient": A_OTHER, "token_id": "-4611686018427387904", "amount": "500"}),
T("mint-token", 12, "MintToken", "Mint more of a mintable token (adds backing).",
  [P("token_id", "int64", "token id"), P("amount", "int64", "amount (atomic)")],
  [F("token_id", "u64le"), F("amount", "u64le")], binary="zbc-token-mint", example={"token_id": "123456789", "amount": "1000"}),
T("burn-token", 13, "BurnToken", "Burn a token; reclaims backing when redeemable.",
  [P("token_id", "int64", "token id"), P("amount", "int64", "amount (atomic)")],
  [F("token_id", "u64le"), F("amount", "u64le")], binary="zbc-token-burn", example={"token_id": "123456789", "amount": "1000"}),
T("finance-token", 14, "FinanceToken", "Top up a token's survival financing; the fee buys persistence.",
  [P("token_id", "int64", "token id")], [F("token_id", "u64le")], binary="zbc-token-finance", example={"token_id": "123456789"}),

T("swap-create", 18, "CreateSwapOffer", "Offer give_amount of give_token for want_amount of want_token; the give side is held.",
  [P("give_token", "int64", "token to give, 0 = ZBC"), P("give_amount", "int64", "atomic"), P("want_token", "int64", "token wanted, 0 = ZBC"),
   P("want_amount", "int64", "atomic"), P("expiry", "int64", "Unix seconds, 0 = good till cancelled", required=False, default="0")],
  [F("give_token", "u64le"), F("give_amount", "u64le"), F("want_token", "u64le"), F("want_amount", "u64le"), F("expiry", "u64le")],
  binary="zbc-swap-create", example={"give_token": "0", "give_amount": "100000000", "want_token": "123456789", "want_amount": "5000", "expiry": "0"}),
T("swap-accept", 19, "AcceptSwapOffer", "Fill an open swap offer.", [P("offer_id", "int64", "offer id")], [F("offer_id", "u64le")], binary="zbc-swap-accept", example={"offer_id": "42"}),
T("swap-cancel", 20, "CancelSwapOffer", "Cancel your open swap offer; the held amount is refunded.", [P("offer_id", "int64", "offer id")], [F("offer_id", "u64le")], binary="zbc-swap-cancel", example={"offer_id": "42"}),
T("market-create", 21, "CreateMarket", "Open a (base, quote) order-book market, paying a rent deposit.",
  [P("base_token", "int64", "base token, 0 = ZBC"), P("quote_token", "int64", "quote token, 0 = ZBC"), P("deposit", "int64", "rent deposit (atomic)", required=False, default="0")],
  [F("base_token", "u64le"), F("quote_token", "u64le"), F("deposit", "u64le")], binary="zbc-market-create", example={"base_token": "123456789", "quote_token": "0", "deposit": "100000000"}),
T("order-place", 22, "PlaceOrder", "Place a limit or market order on a market.",
  [P("market_id", "int64", "market id"), P("side", "uint8", "0 = buy, 1 = sell"), P("price", "int64", "quote per base, scaled by 10^8"),
   P("amount", "int64", "base amount (atomic)"), P("flags", "uint8", "bit0 market order, bit1 post-only", required=False, default="0"),
   P("expiry", "int64", "Unix seconds, 0 = good till cancelled", required=False, default="0")],
  [F("market_id", "u64le"), F("side", "u8"), F("price", "u64le"), F("amount", "u64le"), F("flags", "u8"), F("expiry", "u64le")],
  binary="zbc-order-place", example={"market_id": "7", "side": "0", "price": "150000000", "amount": "1000", "flags": "0", "expiry": "0"}),
T("order-cancel", 23, "CancelOrder", "Cancel a resting order; the held remainder is refunded.", [P("order_id", "int64", "order id")], [F("order_id", "u64le")], binary="zbc-order-cancel", example={"order_id": "99"}),

T("app-create", 24, "CreateApp", "Open an on-chain app (game): type, stake, seats, optional params and opponent.",
  [P("app_type", "uint8", "1 tic-tac-toe, 3 connect-4, 6 gomoku, 16 dice, 17 coin flip"), P("stake_token", "int64", "0 = ZBC"),
   P("stake_amount", "int64", "stake (atomic)"), P("seats", "uint8", "2 = player vs player, 1 = solo", required=False, default="2"),
   P("params_hex", "hexbytes", "app parameters (solo bet, e.g. coin flip choice '00')", required=False, default=""),
   P("opponent_hex", "hexbytes", "36-byte opponent account bytes (open seat if empty); a single byte 01 marks a state-channel app", required=False, default="")],
  [F("app_type", "u8"), F("stake_token", "u64le"), F("stake_amount", "u64le"), F("seats", "u8"), F("params_hex", "hex16"), F("opponent_hex", "hex", when="opponent_hex != ''")],
  binary="zbc-app-create", example={"app_type": "1", "stake_token": "0", "stake_amount": "100000000", "seats": "2", "params_hex": "", "opponent_hex": ""},
  notes=["zbc-app-create takes (app_type, stake_token, stake_amount, seats, channel) and cannot pass params or an opponent."]),
T("app-join", 25, "JoinApp", "Join an open app seat, locking an equal stake.", [P("app_id", "int64", "app id")], [F("app_id", "u64le")], binary="zbc-app-join", example={"app_id": "5"}),
T("app-move", 26, "AppMove", "Submit one move.", [P("app_id", "int64", "app id"), P("move_hex", "hexbytes", "move bytes, e.g. tic-tac-toe cell 4 = '04'")],
  [F("app_id", "u64le"), F("move_hex", "hex16")], binary="zbc-app-move", example={"app_id": "5", "move_hex": "04"}),
T("app-resign", 27, "ResignApp", "Resign; your stake share goes to the opponent(s).", [P("app_id", "int64", "app id")], [F("app_id", "u64le")], binary="zbc-app-resign", example={"app_id": "5"}),
T("app-claim", 28, "ClaimAppTimeout", "Claim the win when an opponent missed the per-move deadline.", [P("app_id", "int64", "app id")], [F("app_id", "u64le")], binary="zbc-app-claim", example={"app_id": "5"}),
T("app-settle", 39, "SettleApp", "Settle a two-seat tic-tac-toe state channel: replay the signed moves on chain.",
  [P("app_id", "int64", "the channel app id"), P("p0_privkey", "privkey", "seat 0 key, signs seat 0 vouchers"), P("p1_privkey", "privkey", "seat 1 key"),
   P("opening_turn", "uint8", "seat that moves first, 0 or 1", required=False, default="0"), P("moves", "string", "cells in play order, comma-separated, e.g. 0,3,1,4,2")],
  [F("app_id", "u64le"), F("count", "u32le", "moves", computed="number of moves"), F("final_seq", "u32le", "moves", computed="number of moves"),
   F("entries", "custom", "moves", computed="per move: seat u8, move_bytes hex16, 64-byte voucher signature = Ed25519(seat key, SHA3-256(app_id u64le ‖ seq u32le ‖ SHA3-256(9-byte board before the move) ‖ move_bytes)); the board marks cells with seat+1")],
  binary="zbc-app-settle", custom="settle", example={"app_id": "5", "p0_privkey": SEED1, "p1_privkey": SEED2, "opening_turn": "0", "moves": "0,3,1,4,2"}),

T("create-trigger", 15, "CreateTrigger", "Lock amount now and send it to recipient at fire_height, or when an oracle event resolves.",
  [P("recipient", "address", "where the scheduled SendZBC pays"), P("fire_height", "int64", "future block height"),
   P("amount", "int64", "atomic ZBC locked now"), P("event_id", "string", "oracle event id; when set the trigger fires on the event", required=False, default="")],
  [F("fire_height", "u64le"), F("amount", "u64le"), F("event_id", "str32", when="event_id != ''")],
  binary="zbc-trigger-create", recipient="required", example={"recipient": A_OTHER, "fire_height": "100000", "amount": "100000000", "event_id": ""}),
T("cancel-trigger", 16, "CancelTrigger", "Cancel a pending trigger you own; the locked amount is refunded.", [P("trigger_id", "int64", "trigger id")], [F("trigger_id", "u64le")], binary="zbc-trigger-cancel", example={"trigger_id": "77"}),
T("attest-event", 17, "AttestEvent", "Oracle attestation of an external (event_id, value) by an authorised node account.",
  [P("event_id", "string", "external event id"), P("value", "string", "attested value")],
  [F("event_id", "str32"), F("value", "str32")], binary="zbc-event-attest", example={"event_id": "match-2026-09-16", "value": "home"}),

T("add-prepaid-storage", 9, "AddPrepaidStorage", "Fund the account's prepaid storage balance (dataset rent).", [P("amount", "int64", "atomic ZBC")], [F("amount", "u64le")], binary="zbc-storage-prepay", example={"amount": "100000000"}),
T("dfs-create-file", 8, "DFSCreateFile", "Create an on-chain file at path with the given content (up to 64 KB).",
  [P("path", "string", "absolute path, e.g. /docs/readme.txt"), P("content_file", "file", "local file whose bytes become the content")],
  [F("path", "str32"), F("content", "bytes32", "content_file", computed="the file's bytes")], binary="zbc-dfs-create-file",
  example={"path": "/docs/hello.txt", "content_file": "<a file containing the 12 bytes 'hello zoobc\\n'>"}),
T("store-file", 40, "StoreFile", "Anchor a decentralised-storage manifest (root and piece ids) with a rent deposit.",
  [P("file_root", "hex32", "manifest root hash"), P("total_size", "int64", "file size in bytes"), P("piece_size", "uint32", "piece size in bytes"),
   P("deposit", "int64", "rent deposit (atomic)"), P("piece_ids", "hexbytes", "piece id hashes concatenated, n x 32 bytes")],
  [F("file_root", "hex", size=32), F("total_size", "u64le"), F("piece_size", "u32le"), F("deposit", "u64le"),
   F("piece_count", "u32le", "piece_ids", computed="len(piece_ids) / 32"), F("piece_ids", "hex")],
  example={"file_root": H32, "total_size": "4096", "piece_size": "2048", "deposit": "100000000", "piece_ids": H32 + H32B}),

T("setup-dataset", 3, "SetupAccountDataset", "Set a key-value property on an account (the recipient is the subject).",
  [P("recipient", "address", "dataset subject address"), P("property", "string", "key"), P("value", "string", "value")],
  [F("property", "str32"), F("value", "str32"), F("setter", "sender_address", computed="the sender's 36-byte account"), F("recipient", "address")],
  binary="zbc-dataset-setup", recipient="required", example={"recipient": A_OTHER, "property": "role", "value": "tester"}),
T("remove-dataset", 259, "RemoveAccountDataset", "Deactivate a key-value property; same body layout as setup-dataset.",
  [P("recipient", "address", "dataset subject address"), P("property", "string", "key"), P("value", "string", "value")],
  [F("property", "str32"), F("value", "str32"), F("setter", "sender_address", computed="the sender's 36-byte account"), F("recipient", "address")],
  binary="zbc-dataset-remove", recipient="required", example={"recipient": A_OTHER, "property": "role", "value": "tester"}),
T("transfer-dataset", 42, "TransferDataset", "Propose transferring a dataset object to a new owner.",
  [P("object_id", "hex32", "dataset object id = the creating transaction hash"), P("new_owner", "address", "new owner")],
  [F("object_id", "hex", size=32), F("new_owner", "address")], example={"object_id": H32, "new_owner": A_OTHER}),
T("accept-dataset", 44, "AcceptDataset", "Accept a pending dataset transfer.", [P("object_id", "hex32", "dataset object id")], [F("object_id", "hex", size=32)], example={"object_id": H32}),
T("delete-dataset", 45, "DeleteDataset", "Delete a dataset object and refund its deposit.", [P("object_id", "hex32", "dataset object id")], [F("object_id", "hex", size=32)], example={"object_id": H32}),
T("set-dataset-policy", 43, "SetDatasetPolicy", "Set a dataset object's manage policy and edit its access lists.",
  [P("object_id", "hex32", "dataset object id"), P("mode", "uint8", "0 owner-only, 1 whitelist, 2 blacklist, 3 open"),
   P("add", "address_list", "comma-separated addresses to add (max 255)", required=False, default=""),
   P("remove", "address_list", "comma-separated addresses to remove (max 255)", required=False, default="")],
  [F("object_id", "hex", size=32), F("mode", "u8"), F("add", "address_list8"), F("remove", "address_list8")],
  example={"object_id": H32, "mode": "1", "add": A_OTHER, "remove": ""}),

T("scheduled-transfer", 29, "ScheduledTransfer", "Recurring or vested transfers to a recipient.",
  [P("recipient", "address", "paid on each fire"), P("token_id", "int64", "0 = ZBC", required=False, default="0"),
   P("per_fire_amount", "int64", "amount per fire (atomic), > 0"), P("interval_seconds", "int64", "seconds between fires", required=False, default="0"),
   P("remaining_fires", "uint32", "number of fires, >= 1"), P("cliff_seconds", "int64", "delay before the first fire", required=False, default="0"),
   P("funding_mode", "uint8", "0 pre-lock now, 1 pull at fire", required=False, default="0"), P("cancel_policy", "uint8", "0 or 1", required=False, default="0"),
   P("end_time", "int64", "Unix-seconds cutoff, 0 = none", required=False, default="0")],
  [F("token_id", "u64le"), F("per_fire_amount", "u64le"), F("interval_seconds", "u64le"), F("remaining_fires", "u32le"), F("cliff_seconds", "u64le"),
   F("funding_mode", "u8"), F("cancel_policy", "u8"), F("end_time", "u64le"), F("reserved", "literal", value="00")],
  recipient="required", example={"recipient": A_OTHER, "token_id": "0", "per_fire_amount": "100000000", "interval_seconds": "86400", "remaining_fires": "3", "cliff_seconds": "0", "funding_mode": "0", "cancel_policy": "0", "end_time": "0"}),
T("cancel-schedule", 30, "CancelSchedule", "Cancel a scheduled transfer (sender) or decline it (recipient).", [P("schedule_id", "int64", "schedule id")], [F("schedule_id", "u64le")], example={"schedule_id": "11"}),
T("reassign-schedule", 31, "ReassignSchedule", "Redirect a schedule's future fires to a new recipient.",
  [P("schedule_id", "int64", "schedule id"), P("new_recipient", "address", "new recipient")],
  [F("schedule_id", "u64le"), F("new_recipient", "address")], example={"schedule_id": "11", "new_recipient": A_OTHER}),

T("fee-vote-commit", 7, "FeeVoteCommitment", "Commit a hashed fee vote during the commit phase.", [P("vote_hash", "hex32", "32-byte vote hash")], [F("vote_hash", "hex", size=32)], binary="zbc-fee-vote-commit", example={"vote_hash": H32}),
T("fee-vote-reveal", 263, "FeeVoteReveal", "Reveal the fee vote during the reveal phase; the body carries the sender's signature over the 44 vote bytes.",
  [P("recent_block_hash", "hex32", "reference block hash"), P("recent_block_height", "uint32", "reference block height"), P("fee_vote", "int64", "proposed fee multiplier")],
  [F("recent_block_hash", "hex", size=32), F("recent_block_height", "u32le"), F("fee_vote", "u64le"),
   F("voter_signature", "bytes32", computed="u32le length (64) then Ed25519(sender seed, the 44 bytes above), no tag")],
  binary="zbc-fee-vote-reveal", custom="voter_signature", example={"recent_block_hash": H32, "recent_block_height": "1000", "fee_vote": "3"}),
T("governance-vote", 51, "SetConsensusParam", "A registry node votes a value for a governable parameter (2/3 of the registry must agree).",
  [P("parameter", "string", "parameter name"), P("value", "int64", "the value voted for, raw units")],
  [F("parameter", "str32"), F("value", "u64le")], binary="zbc-governance-vote", sender_key="node_privkey",
  example={"parameter": "min_fee", "value": "2500000"}, notes=["No zbc-cli subcommand; the node's own key signs."]),

T("fund-longevity", 52, "FundLongevity", "Attach a rent deposit to a transaction so pruning keeps it.",
  [P("target_tx_id", "int64", "the transaction to keep, as its int64 id"), P("amount", "int64", "deposit (atomic), minimum 0.1 ZBC")],
  [F("target_tx_id", "u64le"), F("amount", "u64le")], binary="zbc-fund-longevity", example={"target_tx_id": "-1234567890123456789", "amount": "10000000"},
  notes=["No zbc-cli subcommand."]),
T("cancel-longevity", 53, "CancelLongevity", "Cancel a longevity sponsorship you created; the remainder is refunded.",
  [P("target_tx_id", "int64", "the sponsored transaction's int64 id")], [F("target_tx_id", "u64le")], binary="zbc-cancel-longevity",
  example={"target_tx_id": "-1234567890123456789"}, notes=["No zbc-cli subcommand."]),

T("multisig", 5, "MultiSignature", "N-of-M multisig SendZBC: the inner transaction plus the participant signatures gathered so far.",
  [P("participants", "address_list", "comma-separated participant addresses"), P("min_signatures", "uint32", "signatures required (N of M)"),
   P("nonce", "int64", "multisig account nonce", required=False, default="0"), P("signer_privkeys", "string", "comma-separated participant keys that sign now"),
   P("recipient", "address", "inner SendZBC recipient"), P("amount", "int64", "inner amount (atomic)"), P("inner_fee", "int64", "inner fee (atomic)", required=False, default="10000000")],
  [F("info_present", "literal", value="01000000"), F("min_signatures", "u32le"), F("nonce", "u64le"),
   F("participant_count", "u32le", "participants", computed="number of participants"), F("participants", "address_list", computed="each 36-byte address, in the order given"),
   F("inner", "bytes32", computed="the inner unsigned SendZBC envelope: sender = 36-byte address whose 32-byte key is the multisig address, timestamp = --timestamp or now, fee = inner_fee, body = amount u64le, no escrow, no message"),
   F("signatures_present", "literal", value="01000000"), F("inner_hash", "hex", size=32, computed="SHA3-256(inner) (bare, no tag)"),
   F("signature_count", "u32le", computed="number of signer keys"),
   F("signatures", "custom", computed="sorted by the signer's 36-byte address hex: address (36) ‖ u32le 64 ‖ Ed25519(signer seed, signing digest of the inner bytes per signing.md section 4)")],
  binary="zbc-multisig", custom="multisig",
  example={"participants": A_SELF + "," + A_OTHER, "min_signatures": "1", "nonce": "0", "signer_privkeys": SEED1, "recipient": A_OTHER, "amount": "1000", "inner_fee": "10000000"},
  notes=["multisig address = SHA3-256(min_signatures u32le ‖ nonce u64le ‖ count u32le ‖ the participant addresses sorted bytewise).",
         "The multisig account must be funded (send ZBC to its ZBC_ form) before the inner transaction can execute."]),

T("register-node", 2, "NodeRegistration", "Register a node with a locked stake; the owner proves control of the node key.",
  [P("node_privkey", "privkey", "the node's private key; its public key goes in the body"), P("locked_balance", "int64", "stake to lock (atomic)")],
  [F("node_public_key", "pubkey_of_key", "node_privkey"), F("owner", "sender_address", computed="the owner's 36-byte account"), F("locked_balance", "u64le"),
   F("proof_of_ownership", "custom", computed="136 bytes: owner address (36) ‖ latest block hash (32) ‖ latest block height u32le ‖ Ed25519(owner seed, those 72 bytes); block from GET /api/v1/blocks/latest")],
  binary="zbc-node-register", needs_node=True, custom="proof_of_ownership", example={"node_privkey": SEED2, "locked_balance": "100000000000"},
  notes=["zbc-node-register takes (node_privkey, owner_privkey, locked_balance): node key first, then the owner key that signs."]),
T("update-node", 258, "NodeRegistrationUpdate", "Change a node registration's locked balance.",
  [P("node_privkey", "privkey", "the node's private key"), P("locked_balance", "int64", "new stake (atomic)")],
  [F("node_public_key", "pubkey_of_key", "node_privkey"), F("locked_balance", "u64le"), F("proof_of_ownership", "custom", computed="as register-node")],
  binary="zbc-node-update", needs_node=True, custom="proof_of_ownership", example={"node_privkey": SEED2, "locked_balance": "200000000000"},
  notes=["zbc-node-update takes (node_privkey, owner_privkey, new_locked_balance)."]),
T("claim-node", 770, "ClaimNodeRegistration", "Claim the locked balance of a removed or expired node registration.",
  [P("node_privkey", "privkey", "the node's private key")],
  [F("node_public_key", "pubkey_of_key", "node_privkey"), F("proof_of_ownership", "custom", computed="as register-node")],
  binary="zbc-node-claim", needs_node=True, custom="proof_of_ownership", example={"node_privkey": SEED2},
  notes=["zbc-node-claim takes (node_privkey, owner_privkey)."]),
T("remove-node", 514, "RemoveNodeRegistration", "Remove a node from the registry; the locked balance returns to the owner.",
  [P("node_privkey", "privkey", "the node's private key; its public key is the body")],
  [F("node_public_key", "pubkey_of_key", "node_privkey")], binary="zbc-node-remove", example={"node_privkey": SEED2},
  notes=["zbc-node-remove takes (node_privkey, owner_privkey)."]),

T("register-gateway", 36, "RegisterGateway", "Announce a gateway you run, locking the registration stake.",
  [P("gateway_key", "key", "gateway public key: 64 hex (zbc-cli) or ZBG_ address (zbc-gateway-register)"), P("domain", "string", "public domain, 1-256 chars"), P("url", "string", "base URL")],
  [F("gateway_key", "key32"), F("domain", "str32"), F("url", "str32")], binary="zbc-gateway-register", sender_key="sender_privkey",
  example={"gateway_key": H32B, "domain": "gw.example.org", "url": "https://gw.example.org"},
  notes=["zbc-gateway-register names its first field owner_privkey."]),
T("unregister-gateway", 38, "UnregisterGateway", "Withdraw a gateway you registered; the stake is refunded.",
  [P("gateway_key", "key", "gateway public key")], [F("gateway_key", "key32")], binary="zbc-gateway-unregister", example={"gateway_key": H32B},
  notes=["zbc-gateway-unregister names its first field owner_privkey."]),
T("gateway-heartbeat", 37, "GatewayHeartbeat", "Liveness proof signed by the gateway key over a recent block; any account may relay it.",
  [P("gateway_privkey", "privkey", "the gateway's own private key"), P("reference_height", "uint32", "height of a recent confirmed block"), P("reference_block_hash", "hex32", "that block's hash")],
  [F("gateway_key", "pubkey_of_key", "gateway_privkey"), F("reference_height", "u32le"), F("reference_block_hash", "hex", size=32),
   F("signature", "hex", size=64, computed="Ed25519(gateway seed, the 68 bytes above), no tag")],
  custom="gateway_signature", example={"gateway_privkey": SEED2, "reference_height": "41154", "reference_block_hash": H32}),
T("archival-register", 46, "RegisterArchival", "Announce a registered node as archival: it serves history and the read API.",
  [P("node_public_key", "key", "the node's ZNK_ address or 64 hex"), P("domain", "string", "public domain"), P("url", "string", "public API base URL")],
  [F("node_public_key", "key32"), F("domain", "str32"), F("url", "str32")], binary="zbc-archival-register", sender_key="owner_privkey",
  example={"node_public_key": H32B, "domain": "archive.example.org", "url": "https://archive.example.org"}, notes=["No zbc-cli subcommand."]),
T("archival-unregister", 47, "UnregisterArchival", "Withdraw an archival announcement; the node stays registered.",
  [P("node_public_key", "key", "the node's ZNK_ address or 64 hex")], [F("node_public_key", "key32")], binary="zbc-archival-unregister", sender_key="owner_privkey",
  example={"node_public_key": H32B}, notes=["No zbc-cli subcommand."]),
T("relay-register", 48, "RegisterRelay", "Announce a relay a gateway runs.",
  [P("relay_key", "key", "the relay's ZBR_ address or 64 hex"), P("gateway_key", "key", "the ZBG_ address or 64 hex of the gateway it serves"), P("domain", "string", "public domain"), P("url", "string", "base URL")],
  [F("relay_key", "key32"), F("gateway_key", "key32"), F("domain", "str32"), F("url", "str32")], binary="zbc-relay-register", sender_key="owner_privkey",
  example={"relay_key": H32, "gateway_key": H32B, "domain": "relay.example.org", "url": "https://relay.example.org"}, notes=["No zbc-cli subcommand."]),
T("relay-unregister", 49, "UnregisterRelay", "Withdraw a relay announcement.",
  [P("relay_key", "key", "the relay's ZBR_ address or 64 hex")], [F("relay_key", "key32")], binary="zbc-relay-unregister", sender_key="owner_privkey",
  example={"relay_key": H32}, notes=["No zbc-cli subcommand."]),

T("register-release", 32, "RegisterRelease", "Publish a signed binary release (release authority only).",
  [P("version", "string", "release version, 1-256 chars"), P("manifest_hash", "hex32", "manifest hash"), P("release_address", "address", "the release's on-chain address")],
  [F("version", "str32"), F("manifest_hash", "hex", size=32), F("release_address", "address")],
  example={"version": "0.4.2", "manifest_hash": H32, "release_address": A_OTHER}),
T("revoke-release", 35, "RevokeRelease", "Revoke a published release.", [P("version", "string", "version to revoke")], [F("version", "str32")], example={"version": "0.4.2"}),
T("release-authority-propose", 33, "ReleaseAuthorityPropose", "Propose handing the release authority to another account.",
  [P("new_authority", "address", "proposed new authority")], [F("new_authority", "address")], example={"new_authority": A_OTHER}),
T("release-authority-accept", 34, "ReleaseAuthorityAccept", "Accept a pending release-authority handover. Empty body.", [], [], example={}),
]

ENCODINGS = {
    "u8": "1 byte", "u16le": "2 bytes little-endian", "u32le": "4 bytes little-endian",
    "u64le": "8 bytes little-endian; an int64 is written as its two's-complement uint64",
    "hex": "raw bytes given as hex (fixed `size` when stated)",
    "hex16": "u16le byte length, then the bytes", "bytes32": "u32le byte length, then the bytes",
    "str16": "u16le byte length, then the UTF-8 bytes", "str32": "u32le byte length, then the UTF-8 bytes",
    "address": "the typed account address bytes (addresses.md section 1; 36 bytes for a ZooBC account)",
    "address_list": "the typed address bytes of each entry, concatenated",
    "address_list8": "u8 count, then the typed address bytes of each entry",
    "sender_address": "the signing account's 36-byte typed address (00000000 ‖ public key)",
    "pubkey_of_key": "the 32-byte Ed25519 public key derived from the named private-key parameter",
    "key32": "32 bytes from a `key` parameter: 64 hex, or a ZNK_/ZBG_/ZBR_/ZBC_ text address decoded (addresses.md)",
    "literal": "the fixed bytes in `value` (hex)",
    "custom": "cannot be produced by the generic serialiser; see `computed`",
}
KINDS = {
    "privkey": "64 hex characters, a 32-byte Ed25519 seed",
    "address": "any address form of addresses.md section 3",
    "address_list": "comma-separated addresses; may be empty",
    "key": "64 hex characters (optionally 0x-prefixed) or a ZNK_/ZBG_/ZBR_/ZBC_ text address",
    "int64": "decimal, may be negative", "uint64": "decimal", "uint32": "decimal", "uint8": "decimal 0-255",
    "hex32": "exactly 64 hex characters", "hexbytes": "hex of any even length, may be empty",
    "string": "UTF-8 text", "file": "path of a local file whose bytes are used",
}

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    seen = set()
    for t in TX:
        assert t["command"] not in seen, t["command"]; seen.add(t["command"])
        (OUT / (t["command"] + ".json")).write_text(json.dumps(t, indent=2, ensure_ascii=False) + "\n")
    index = {
        "license": LICENSE,
        "description": "Index of spec/transactions: one file per transaction type. Field meanings in README.md.",
        "encodings": ENCODINGS, "param_kinds": KINDS,
        "transactions": [{"command": t["command"], "type": t["type"], "name": t["name"], "binary": t["binary"],
                          "recipient": t["recipient"], "needs_node": t["needs_node"], "custom": t["custom"]} for t in TX],
    }
    (OUT / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n")
    print("wrote %d transaction files + index.json to %s" % (len(TX), OUT))

if __name__ == "__main__":
    main()
