# Command-line contract

What every ZooBC tool promises, in every language. The C++ tools are the reference; a port that
deviates from this document is wrong, not the document. Where this document is silent, the C++
behaviour decides and should be written down here.

## 1. Invocation

```
zbc-cli <command> <params...> [options]         one binary, one subcommand per transaction type
zbc-<tool> <params...> [options]                 the same command as its own binary
printf '%s' '{...}' | zbc-cli <command> --json-input    parameters as JSON on stdin (keeps the key out of `ps`)
zbc-cli <command> --verbose                      prompts for each field, prints human-readable text
zbc-cli list                                     every command with a one-line description
zbc-cli help <command>                           the JSON field names of one command
zbc-cli <command> --help                         options, environment variables, exit codes
```

The first positional parameter is the **signing private key**: 64 hex characters, the 32-byte
Ed25519 seed. When the command's first field is named `sender_privkey` (as `zbc-cli help <command>`
prints it) the key may be omitted, or given as `-`, and `ZBC_KEY` supplies it. Commands whose first
field has another name (`owner_privkey` for gateways, archivals and relays, `node_privkey` for
governance votes, `requester_privkey` for escrow requests) always take the key explicitly.
`verify-message` is the exception: its first parameter is a ZBC address, because verification needs
no key.

Positional parameters and the JSON fields of `--json-input` are the same names, in the same order,
as printed by `zbc-cli help <command>`. The stdin object may also carry the options `fee`,
`timeout_seconds`, `timestamp`, `offline`, `hex` and `verbose` (booleans), `api_url`, `message` and `escrow`
(an object with `approver`, `commission`, `timeout`, `instruction`).

## 2. Options

| Option | Meaning |
|--------|---------|
| `--api <url>` | Node or gateway to talk to. Default `ZBC_API`, else `http://localhost:8080`. `https://` works. |
| `--fee <n>` | Fee in atomic units. Default 5 000 000 (0.05 ZBC). |
| `--timeout <s>`, `--timeout-seconds <s>` | Bound for each HTTP call. Default `ZBC_TIMEOUT`, else 20. A command makes at most two calls. |
| `--genesis <hex>` | Sign for the chain with this genesis block hash without asking the node. Offline signing, or an unreachable node. `--genesis v1` forces the legacy unbound digest. Default: ask `--api`. |
| `--json-input` | Read the parameters as one JSON object from stdin. |
| `--verbose`, `-v` | Interactive prompts and text output instead of JSON. |
| `--message <text>` | Optional transaction message (plain messages are capped at 256 bytes). |
| `--encrypt` | Encrypt `--message` to the recipient (ZBC recipients only). |
| `--chain <name>` | Read the recipient as an address of this chain: `zbc`, `btc`, `eth`, `sol`, `dot`, `ada`, `xrp`, `trx`, `xtz`. Detection is automatic; this only forces a reading. |
| `--escrow-approver <addr>`, `--escrow-commission <n>`, `--escrow-timeout <unix s>`, `--escrow-instruction <s>` | Turn a transfer into an escrow. The timeout is an absolute future Unix time in seconds. |
| `--hex` | `sign-message` and `verify-message` only: the message is given as hex bytes, not text. |
| `--offline` | Build, sign and hash, print every intermediate byte string (section 4) and exit 0 without submitting. Nothing is asked of a node, so `--genesis` (or `ZOOBC_GENESIS_HASH`) is required. |
| `--timestamp <unix seconds>` | The transaction timestamp, instead of the clock. With `--offline` the output is reproducible byte for byte; that is how `spec/vectors` are made. Also fixes a multisig inner transaction's timestamp. |

Options may appear anywhere on the command line. Unknown options are a usage error.

## 3. Environment

| Variable | Used for |
|----------|----------|
| `ZBC_KEY` | The sender private key when the key parameter is omitted or `-` (also inside stdin JSON). |
| `ZBC_API` | Default for `--api`. |
| `ZBC_TIMEOUT` | Default for `--timeout`. |
| `ZOOBC_GENESIS_HASH` | Default for `--genesis`. |

Command-line options always win over environment variables.

## 4. Output

Exactly one JSON object on stdout, nothing else on stdout. Diagnostics go to stderr. Whitespace
and key order are not part of the contract: `zbc-cli` pretty-prints, some single-purpose binaries
print one line. Parse it as JSON.

Every object carries `"success": true|false`.

**A submitted transaction, accepted by the node:**

| Key | Meaning |
|-----|---------|
| `transaction_hash` | Hex. The transaction's identity on the chain. |
| `transaction_type` | Numeric type code. |
| `sender_account_address`, `recipient_account_address` | Hex public keys as sent. |
| `fee`, `timestamp` | As signed. |
| `api_response` | The node's reply, verbatim. |

Some commands add fields of their own; `approve-escrow`, for example, adds
`escrowed_transaction_hash`, the hash of the escrow being decided, while `transaction_hash` stays
the approval's own hash.

**An error, from the tool or from the node:**

| Key | Meaning |
|-----|---------|
| `error` | One sentence for a human. |
| `exit_code` | The process exit code, see section 5. |
| `error_class` | The name of that code. |
| `http_code` | Present when the node answered with an error status. |
| `api_response` | The node's reply, verbatim, when there was one. |

**`--offline`**, instead of submitting, exits 0 with:

| Key | Meaning |
|-----|---------|
| `offline` | `true`. |
| `transaction_hash`, `transaction_type`, `sender_account_address`, `recipient_account_address`, `fee`, `timestamp` | As above. |
| `signing_version` | 1 or 2. `genesis_hash` (hex) is present when it is 2. |
| `unsigned_bytes` | Hex. The serialised transaction without its signature, the bytes the digest is computed over. |
| `digest` | Hex. The 32 bytes actually signed (`signing.md`). |
| `signature` | Hex. 64 bytes for a ZBC sender. |
| `transaction_bytes` | Hex. `unsigned_bytes ‖ signature`; `transaction_hash` is its SHA3-256. |
| `payload` | The JSON object that `POST /api/v1/transactions` would have received (`api.md`). |

plus `message`, `escrow` and the command's own fields when present. Nothing else prints.

**`sign-message`** returns `address`, `public_key`, `message`, `message_hex`, `digest`, `scheme`
(`ZBC-MSG-v1`) and `signature` (hex). **`verify-message`** returns `valid`, `address`, `digest`,
`scheme`, `exit_code` and `error_class`.

## 5. Exit codes

| Code | `error_class` | When |
|------|---------------|------|
| 0 | `ok` | Done. For a transaction: the node accepted it into its pool. |
| 1 | `internal` | Anything not classified below: signing, hashing, a bug. |
| 2 | `usage` | Bad or missing arguments, a malformed address, an unknown option. |
| 3 | `node_unreachable` | Connection refused, DNS, TLS, no route. |
| 4 | `insufficient_balance` | The node says the sender cannot pay (fee, or unknown account). |
| 5 | `fee_too_low` | The node says the declared fee is below its enforced minimum. |
| 6 | `rejected` | Any other validation rejection by the node (HTTP 4xx). |
| 7 | `not_found` | Unknown transaction, escrow or token. |
| 8 | `timeout` | The node did not answer within `--timeout`. |
| 9 | `node_busy` | The node answered 5xx: emergency mode, backpressure. |
| 10 | `signature_invalid` | `verify-message` only: the signature does not verify. |

A script can branch on the exit code alone; the JSON carries the same information for logging.

## 6. What "accepted" means

Exit code 0 on a transaction means the node **accepted it into its pool**, not that it is in a
block. Nodes admit a transaction before checking balances and state in depth. A transaction can
be accepted and then never be mined, for example when the balance is insufficient at execution
time. Confirmation is a separate query, described in `api.md`. A pending transaction that is not
mined within about an hour is dropped.

State reads (balances, holdings, datasets) are served three blocks behind the tip. A transaction
mined at height H is visible in reads from height H+3 onwards.

## 7. Amounts

All amounts are integers in atomic units. 1 ZBC = 100 000 000 atomic units. Token amounts use the
same 10^8 scale regardless of the decimals the token declares; the declared decimals only affect
how wallets display the token.

## 8. Keys, addresses, signing

- Keys are Ed25519. A private key is the 32-byte seed, written as 64 hex characters.
- An account address is the public key encoded with the prefix `ZBC_` followed by seven groups of
  eight characters. A node address uses the prefix `ZNK_`. The exact encoding is in `addresses.md`.
- **Transaction signature** (signing version 2, all live chains): Ed25519 over
  `SHA3-256("ZBC-TX" ‖ genesis_block_hash ‖ unsigned_transaction_bytes)`. A signature is valid on
  one chain only. The tools ask the node which chain they are talking to; `--genesis` states it
  without asking. Signing version 1, `SHA3-256(unsigned_transaction_bytes)`, exists only for
  chains that predate version 2 and is selected with `--genesis v1`.
- **Message signature** (`ZBC-MSG-v1`): Ed25519 over `SHA3-256("ZBC-MSG" ‖ message_bytes)`.
  No node is involved. Verification takes the signer's ZBC address, which is the public key.
  A message signature can never be replayed as a transaction, because the two digests are
  prefixed differently.
