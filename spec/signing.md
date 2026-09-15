<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Signing

What a ZooBC tool signs, how it hashes, and how a signature is verified. Written from the C++
reference (`cpp/libzbc/src/util/transaction_util.cpp`, `cpp/cmd/tx_common.h`) and checked
against `vectors/`.

## 1. Keys

- Ed25519. A **private key** as the tools use it is the 32-byte seed, written as 64 hex characters.
  The 64-byte libsodium secret key is derived from it (`crypto_sign_seed_keypair`) and never shown.
- The **public key** is 32 bytes. It is also the account's identity on the chain: an account
  address is the public key with a 4-byte type prefix (`addresses.md`).
- `zbc-key-gen` prints `public_key` and `private_key` (the seed) as hex. `zbc-account-from-key`
  derives the public key and the `ZBC_` address from a seed; `zbc-node-from-key` the `ZNK_` address.
- HD wallets (`zbc-wallet-gen`): BIP-39 mnemonic → 64-byte seed
  (PBKDF2-HMAC-SHA512, salt `"mnemonic" + passphrase`, 2048 rounds), then SLIP-10 for Ed25519
  (master key from `HMAC-SHA512(key="ed25519 seed", seed)`, hardened children only) along
  `m/44'/883'/<account>'`. The 32-byte SLIP-10 private key of that node is the account's seed.

## 2. The transaction envelope

Every transaction is serialised to one byte string, little-endian throughout:

| # | Field | Size | Content |
|---|-------|------|---------|
| 1 | transaction_type | 4 | uint32 LE, the type code (`transactions/`) |
| 2 | version | 1 | `0x01` |
| 3 | timestamp | 8 | int64 LE, Unix seconds |
| 4 | sender | 4 + n | account type int32 LE, then the key or address bytes (36 bytes for a ZBC account) |
| 5 | recipient | 4 + n | same encoding; `02 00 00 00` alone (type 2, "empty") when the transaction has no recipient |
| 6 | fee | 8 | int64 LE, atomic units |
| 7 | body_length | 4 | uint32 LE |
| 8 | body | body_length | the type's body (`transactions/`) |
| 9 | escrow | var | `02 00 00 00` when there is no escrow, else the escrow block (section 3) |
| 10 | message_length | 4 | uint32 LE, 0 when there is no message |
| 11 | message | message_length | raw bytes; a plain message is the UTF-8 text, an encrypted one the sealed bytes |

Fields 1–11 are the **unsigned bytes** (`unsigned_bytes` in `--offline` output). The
**transaction bytes** are the unsigned bytes followed by the signature; the **transaction hash**,
the transaction's identity everywhere (API, explorer, escrow approvals), is

    transaction_hash = SHA3-256(unsigned_bytes ‖ signature)

The **transaction id** some bodies carry (`LiquidPaymentStop`, `FundLongevity`, `CancelLongevity`)
is the first 8 bytes of the transaction hash read as an int64 LE, so it is often negative.

## 3. The escrow block

Present in the envelope when the transfer is escrowed (`--escrow-*` options):

| Field | Size | Content |
|-------|------|---------|
| approver | 4 + 32 | the approver's account address with type prefix |
| commission | 8 | int64 LE, atomic units paid to the approver |
| timeout | 8 | int64 LE, absolute Unix time in seconds after which the escrow expires |
| instruction_length | 4 | uint32 LE |
| instruction | var | UTF-8 text, may be empty |
| multi_party | 1 | `0x00` from the tools |

(A multi-party escrow, `multi_party = 0x01`, continues with a 4-byte co-signer signature length,
the signature and an 8-byte escrow request id. The tools never produce it.)

## 4. The signing digest

Since node v0.4.0 (**signing version 2**, every live chain) the signer signs

    digest = SHA3-256("ZBC-TX" ‖ genesis_block_hash ‖ unsigned_bytes)

where `"ZBC-TX"` is the 6 ASCII bytes `5a 42 43 2d 54 58` and `genesis_block_hash` is the 32-byte
hash of block 0 of the chain the transaction is for. A signature is therefore valid on exactly one
chain. The tools learn the hash from `GET /api/v1/node/info` (`genesis_hash`, hex, with
`signing_version: 2`), or take it from `--genesis <hex>` / `ZOOBC_GENESIS_HASH` without asking.

**Signing version 1** (chains that predate v0.4.0; a node that reports no `signing_version`) is

    digest = SHA3-256(unsigned_bytes)

and is selected with `--genesis v1`. A tool never guesses: with no `--genesis` and no reachable
node it fails with exit 3 rather than sign an unbound digest.

The signature is `Ed25519(seed, digest)`, 64 bytes, detached. It goes into the envelope as
field 12 and into the submit payload as `signature` (hex).

## 5. Message signing (`ZBC-MSG-v1`)

Off-chain proof of control of an address, no node involved:

    digest    = SHA3-256("ZBC-MSG" ‖ message_bytes)
    signature = Ed25519(seed, digest)

`"ZBC-MSG"` is the 7 ASCII bytes `5a 42 43 2d 4d 53 47`. The message is the UTF-8 text, or raw
bytes with `--hex`. Verification needs only the signer's `ZBC_` address (the public key) and the
64-byte signature; `verify-message` exits 0 when it verifies and 10 when it does not. Because the
prefixes differ, a message signature can never be replayed as a transaction signature, a
proof-of-ownership or a multisig participant signature, and vice versa.

## 6. Proof of ownership (node registration)

`NodeRegistration`, `NodeRegistrationUpdate` and `ClaimNodeRegistration` carry a proof that the
owner account controls the node: the owner signs, with the **owner's** account key, over the
plain bytes (no tag, no genesis)

    message = owner_address (36) ‖ recent_block_hash (32) ‖ recent_block_height (4, uint32 LE)

and the proof is `message ‖ signature` (136 bytes). The reference block is fetched from
`GET /api/v1/blocks/latest`, so these three commands need a node even with `--genesis`.

## 7. Other signatures inside bodies

- **MultiSignature**: each participant signs the signing digest (section 4) of the *inner*
  unsigned transaction; the inner transaction's SHA3-256 (bare, no tag) is the key the chain
  collects signatures under. Participant signatures are keyed by the signer's 36-byte account
  address in hex.
- **FeeVoteReveal**: `voter_signature` is the sender's Ed25519 signature over the 44 FeeVoteInfo
  bytes (`recent_block_hash` 32 ‖ `recent_block_height` 4 ‖ `fee_vote` 8), no tag.
- **GatewayHeartbeat**: the gateway key signs `gateway_key (32) ‖ height (4) ‖ block_hash (32)`.
- **SettleApp**: each move voucher is the seat key's signature over
  `SHA3-256(app_id (8) ‖ seq (4) ‖ SHA3-256(state_before) ‖ move_bytes)`.

## 8. Signature lengths by sender account type

The node reads a fixed signature length after the message, by the sender's account type: 64 for
ZooBC (type 0), Estonia eID (3) and Polkadot (12); 65 for Ethereum (4); 98 for Tezos (16) and
Cardano (13); Bitcoin types (1, 5–9) take the rest of the bytes. The tools sign as a ZooBC account;
the other types exist for wallets that hold a foreign key and are outside this specification.
