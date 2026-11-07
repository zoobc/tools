<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Addresses

How a ZooBC account or node is written, and what bytes it stands for. Written from the C++
reference (`cpp/libzbc/src/crypto/slip10.cpp` for the text form, `address_decode.cpp` and
`cpp/cmd/tx_common.h` for detection) and checked against `vectors/addresses.json`.

## 1. Account address bytes

On the chain an account is a **typed byte string**: a 4-byte little-endian `int32` account type,
then the key or address payload of that type.

| Type | Name | Payload | Text form |
|------|------|---------|-----------|
| 0 | ZooBC | 32-byte Ed25519 public key | `ZBC_…` (section 2) or 64 hex |
| 1 | Bitcoin (legacy) | 20 bytes | `1…`, `3…` (also types 5–9 below) |
| 2 | empty | none | used in the envelope for "no recipient" and "no escrow" |
| 3 | Estonia eID | 32 bytes | not produced by the tools |
| 4 | Ethereum | 20-byte address | `0x` + 40 hex |
| 5 | Bitcoin P2PKH | 20-byte hash160 | base58check, version `0x00` |
| 6 | Bitcoin P2SH | 20-byte hash160 | base58check, version `0x05` |
| 7 | Bitcoin P2WPKH | 20-byte witness program | bech32 `bc1q…` (v0, 20 bytes) |
| 8 | Bitcoin P2WSH | 32-byte witness program | bech32 `bc1q…` (v0, 32 bytes) |
| 9 | Bitcoin Taproot | 32-byte witness program | bech32m `bc1p…` (v1, 32 bytes) |
| 10 | DataSet object | 32-byte object id | `ZBS_…` (section 2, prefix `ZBS`) |
| 11 | Solana | 32-byte Ed25519 key | base58, 32 bytes |
| 12 | Polkadot | 32-byte AccountId | SS58 |
| 13 | Cardano | 28-byte key hash | bech32 `addr1…` enterprise address, header `0x61` |
| 14 | Ripple | 20-byte hash160 | base58check in the Ripple alphabet, version `0x00`, `r…` |
| 15 | Tron | 20-byte Keccak address | base58check, version `0x41`, `T…` |
| 16 | Tezos | 20-byte blake2b-160 key hash | base58check `tz1…`, prefix `06 a1 9f` |

A ZooBC account is therefore 36 bytes: `00 00 00 00` followed by the public key. That is what the
envelope carries for sender, recipient and escrow approver, and what appears in the API as
`sender_account_address` / `recipient_account_address` when 72 hex characters long. The submit
payload sends them the same way, typed (72 hex for a ZooBC account): from node 0.6.0 (rule
typed_accounts_only) a bare 32-byte key is refused as an account (`api.md`).

## 2. The `ZBC_` text form

An account (`ZBC`), a node (`ZNK`) and a dataset object (`ZBS`) are written the same way, with a
different three-letter prefix:

1. Take the 32-byte payload (the public key for `ZBC` and `ZNK`, the object id for `ZBS`).
2. Append the 3 ASCII bytes of the prefix: 35 bytes.
3. `checksum = SHA3-256(those 35 bytes)[0..3]`.
4. Replace the 3 prefix bytes with the 3 checksum bytes: still 35 bytes.
5. Base32-encode (RFC 4648 alphabet `A–Z2–7`, no padding): 35 bytes is exactly 56 characters.
6. Write `PREFIX_` then the 56 characters in seven groups of eight separated by `_`.

    ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I

is 66 characters. Node addresses look the same with `ZNK_`; the checksum differs because the prefix
bytes are hashed, so a key's `ZBC_` and `ZNK_` forms never share their last characters.

**Decoding** looks only at the 59 significant characters — the 3-letter prefix and the 56 of
base32. Everything else in the written form is cosmetic: the separators `_` and `-`
(interchangeably, and mixed), whitespace (a line-wrapped paste, a chat client), and any letter
case; a form with no separators at all is the same address. Strip `_`, `-` and whitespace,
uppercase, then: the prefix is the first three characters, the body must be exactly 56 characters
and decode to 35 bytes, and the checksum must match when recomputed with that prefix. This is the
rule the wallet applies before it decodes, and the node and the C++ tools apply the same one (node
commit 12a716b9). `ZBC_` and `ZNK_` bytes are the same key; which prefix a tool expects is a matter
of role, not of format.

Auto-detection of a recipient's chain (`DecodeAddress` without a chain hint) takes the bare form
as ZooBC only behind a `ZBC`/`ZBS` prefix with a base32 body: without a separator nothing else
marks the string as ZooBC, and no other supported chain writes an address as 59 base32 characters.

The canonical form is upper case with `_`. Tools print that form.

## 3. What the tools accept as a recipient

`parse_address` (`cpp/cmd/tx_common.h`) tries, in order:

1. `--chain <name>` given: read as that chain (`zbc`, `btc`, `eth`, `sol`, `dot`, `ada`,
   `xrp`, `trx`, `xtz`; `zbs` for a dataset object), as the paragraph after this list says.
2. `0x` + 40 hex: Ethereum (type 4). Checksum casing is not enforced.
3. Fourth character `_` (or `-`): ZooBC text form. Prefix `ZBS` gives type 10, anything else type 0.
4. `bc1…` / `tb1…` / `bcrt1…`: Bitcoin bech32 (types 7, 8, 9 by witness version and length).
5. `1…` / `3…`, 26–35 characters, valid base58check: Bitcoin P2PKH (5) or P2SH (6).
6. `addr1…`: Cardano enterprise address (13). Only the mainnet enterprise form is accepted.
7. `T…`, 34 characters: Tron (15).
8. `r…`, 25–35 characters: Ripple (14).
9. `tz1…`: Tezos (16).
10. A valid SS58 string with a 32-byte account id: Polkadot (12).
11. 32–44 characters of base58 decoding to 32 bytes: Solana (11).
12. Exactly 64 hex characters: a raw ZooBC public key (type 0).

With `--chain btc`, `ada`, `xrp`, `trx` or `xtz` the hint is a check, not a reading: the address is
read by the steps above, and one that reads as another chain is refused by this reading. `eth`,
`sol` and `dot` read the string as that chain only (`eth`: 40 hex, `0x` optional); `zbc` and `zbs`
read the ZooBC text form only.

When that reading fails, the tools try a second one, on the string exactly as given (not trimmed);
the first form that applies decides, and when its string is not valid the address is refused:

| The string | Read as | `recipient_type` |
|---|---|---|
| `0x` and 42 characters in all | 40 hex: Ethereum (4) | `ETH (compact)` |
| starts with `1` or `3`, or `bc1` / `tb1` / `bcrt1` (any case) | a Bitcoin address only (5, 6, 7, 8, 9) | `BTC P2PKH`, `BTC P2SH`, `BTC P2WPKH`, `BTC P2WSH`, `BTC P2TR` |
| starts with `ZBC` or `ZNK` (any case) | the ZooBC text form (section 2), type 0 | `ZBC` |
| starts with `ZBS` (any case) | the ZooBC text form, type 10 | `DATASET` |
| 64 hex | a raw ZooBC public key (0) | `ZBC` |

So `--chain btc 0x…` is still an Ethereum account, and a bare `ZNK…` form (which detection does not
read) is a type 0 account. `recipient_type`, which the tools print, is otherwise the account type's
name (`ZooBC`, `Ethereum`, `Bitcoin P2PKH`, …).

Anything else is a usage error (exit 2). A `ZNK_` string decodes like `ZBC_` and yields type 0;
that is how node keys are passed to `zbc-archival-register` and friends. The tools' own sender is
always a ZooBC account derived from the 32-byte seed.

## 4. Vectors

`vectors/addresses.json` lists, for each input string (and `--chain`, when given), whether it is
valid, the account type, the full typed bytes and the `recipient_type` label, produced by running
the C++ tools. `vectors/keys.json` lists seeds with
their public keys and `ZBC_` / `ZNK_` forms, and BIP-39 wallets with their derived accounts
(`signing.md` section 1).
