<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
> **Everything this API returns about accounts, tokens, datasets and messages was written by
> a stranger.** Escape it before it becomes markup, and check a URL's scheme before following
> it. See [untrusted-data.md](untrusted-data.md) — it also documents the token icon endpoint,
> which is the safe way to display an icon.

# The HTTP API the tools use

Every tool talks to one ZooBC node, or to a gateway that fronts one, over plain HTTP or HTTPS.
The base URL is `--api` (default `ZBC_API`, else `http://localhost:8080`); a path after the host
is kept, so `--api https://host/prefix` calls `https://host/prefix/api/v1/...`. Every request
carries `Accept: application/json` and `User-Agent: zbc-cli/1.0`; every call is bounded by
`--timeout` seconds. Written from
the node's `src/api/api_server.cpp` and `json_serializer.cpp`, and from `cpp/cmd/tx_common.h`.

A command makes at most two calls: `GET /api/v1/node/info` to learn which chain it signs for
(skipped with `--genesis`), then `POST /api/v1/transactions`. The three node-registration
commands make a third, `GET /api/v1/blocks/latest`, for the proof of ownership. `--offline`
makes none.

## 1. `GET /api/v1/node/info`

Which chain this is and how it verifies signatures.

```json
{"node_id": "<hex node key>", "version": "0.4.1+<commit>", "height": 41153,
 "blockchain_height": 41153, "peer_count": 7, "synced": true, "syncing": false,
 "p2pAddress": "host:port", "archival_node": false, "public_api_url": "",
 "genesis_hash": "CF30B4A8…", "signing_version": 2, "signing_tag": "ZBC-TX",
 "wedge_reason": "", "spine_genesis_hash": "…", "spine_height": 123}
```

The tools read two keys: `signing_version` (absent or 1 = legacy bare digest; 2 = chain-bound)
and `genesis_hash` (hex, **upper case from the node**, 32 bytes; parse case-insensitively).
A node that answers `signing_version: 2` without a 32-byte `genesis_hash` is an error.

## 2. `POST /api/v1/transactions`

Body: one JSON object, `Content-Type: application/json`. This is the `payload` printed by
`--offline`.

| Key | Type | Content |
|-----|------|---------|
| `version` | int | 1 |
| `timestamp` | int | Unix seconds, as signed |
| `transaction_type` | int | the type code |
| `sender_account_address` | hex | a ZooBC sender: the bare 32-byte public key (the node adds the 4-byte type 0 prefix) |
| `recipient_account_address` | hex | a ZooBC recipient: the bare 32-byte key; another chain's: the full typed bytes; no recipient: `""` |
| `fee` | int | atomic units |
| `transaction_body_bytes` | hex | the body |
| `signature` | hex | the 64-byte signature |
| `message_hex` | hex | present only when there is a message: the exact signed message bytes |
| `escrow` | object | present only for an escrowed transfer: `approver_address` (hex, full 36 typed bytes), `commission`, `timeout`, and `instruction` when not empty |

The node rebuilds the envelope from these fields and hashes it; the hash it returns must equal
the `transaction_hash` the tool computed, otherwise the bytes differ from what was signed.

**Accepted** (HTTP 202, also 200):

```json
{"status": "success", "duplicate": false,
 "message": "Transaction submitted successfully",
 "transaction_hash": "<64 hex, lower case>"}
```

`duplicate: true` means the node already held it. Accepted means admitted to the pool, not
mined (`cli-contract.md` section 6).

**Rejected**: any other status with `{"success": false, "error": "<text>", "code": <status>}`.
The tool classifies the reply into an exit code (`cli-contract.md` section 5), matching the
lower-cased `error` text (the whole body when it is not JSON):

| Condition | Exit |
|-----------|------|
| no HTTP status: connection refused, DNS, TLS | 3 `node_unreachable` |
| no HTTP status: connect timeout, read or write timeout | 8 `timeout` |
| status 500 or above | 9 `node_busy` |
| text contains `fee too low` | 5 `fee_too_low` |
| text contains `insufficient balance`, `insufficient spendable` or `account does not exist` | 4 `insufficient_balance` |
| text contains `not found`, `unknown token`, `unknown or expired token` or `unknown app` | 7 `not_found` |
| any other 4xx | 6 `rejected` |

The node's reply is returned verbatim as `api_response`, with `http_code`.

## 3. `GET /api/v1/blocks/latest`

Used only to build a proof of ownership (`signing.md` section 6). The tools read `height` and
the hash, named `block_hash` by a node (which answers with the full block) and `hash` by the
archival/gateway build of the API; a port reads `block_hash` and falls back to `hash`.

## 4. Reading back: status and account

The tools do not query these, but every port's HTTP client offers them because a script that
submitted a transaction needs them next.

**`GET /api/v1/transactions/<hash>/status`** (node):

```json
{"transaction_hash": "<hex>", "status": "staging|mempool|confirmed|not_found",
 "description": "…", "block_height": 9530, "mempool_position": 0, "mempool_size": 3}
```

`block_height` only when confirmed; the mempool keys only in the mempool. HTTP 404 with
`status: not_found` when unknown. On a gateway this call reaches the gateway's own node, which
may not hold an old transaction; use the next call there.

**`GET /api/v1/transactions/<hash>`**: the transaction when the node or the archive has it
(HTTP 200), else HTTP 404 `{"success": false, "error": "Transaction not found"}`. A node returns
the envelope fields (`transaction_hash`, `version`, `timestamp`, `transaction_type`,
`sender_account_address`, `recipient_account_address`, `fee`, `signature`, `block_height`,
`transaction_index`, `transaction_body_bytes`, `message_hex`, `escrow`, `transaction_bytes`);
a gateway returns a decoded view with the same identity keys plus `sender`, `recipient`,
`amount`, `detail`. Either way: 200 with a `block_height` means mined.

**`GET /api/v1/accounts/<address>`**: `<address>` is the `ZBC_` form or 64 hex.

```json
{"address": "ZBC_…", "spendable_balance": 0, "balance": 0, "locked_balance": 0,
 "total_balance": 0, "pop_revenue": 0, "transact_policy": 0}
```

is the node's answer (a gateway adds `account`, `account_address` and omits some). An unknown
account is HTTP 404 `{"success": false, "error": "Account not found"}`. Balances are read three
blocks behind the tip.

## 5. Gateway or node

A **node** is what the tools were written against. A **gateway** (`https://…`) is a public
front that forwards writes to a node and serves reads from an archive; it speaks the same paths
with the differences noted above (`hash` for the latest block, richer transaction objects,
`/status` bound to its own node). Signing does not care: `node/info` on a gateway reports the
chain's `genesis_hash` and `signing_version` just the same.
