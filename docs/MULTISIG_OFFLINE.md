# Offline multisig with zbc-multisig-offline

`zbc-multisig-offline` (C++ only for now, `cpp/cmd/multisig-offline.cpp`) runs an N-of-M ZooBC
multisig where every participant keeps their key on their own machine: **prepare / sign offline
per participant / combine / submit**. Each participant signs a file offline, one person combines
the signature files, and anyone submits the result. Only the last step needs a network
connection.

The older `zbc-multisig` needs all the participants' private keys in one process, which works
only when one person holds every key.

## What the chain checks

A multisig spend is a MultiSignature transaction (type 5). Its body carries:

1. **multisig_info**: the participant accounts, the threshold and a nonce. The chain derives the
   multisig address from them,
   `SHA3-256(threshold u32 LE ‖ nonce i64 LE ‖ count u32 LE ‖ sorted participant accounts)`,
   and never takes an address from the caller.
2. **unsigned_transaction_bytes**: the inner transaction, sent from the multisig account.
3. **signature_info**: participant account to signature, under `SHA3-256(inner bytes)`.

A signature counts only when the signer is a listed participant and the signature verifies
against `SHA3-256("ZBC-TX" ‖ genesis_hash ‖ inner bytes)`, the same signing-v2 digest as an
ordinary transaction (see [`../spec/signing.md`](../spec/signing.md)), so it is valid on one chain
only. When the count reaches the threshold, the inner transaction executes in the same block,
from the multisig account. One type-5 transaction carrying all the threshold signatures settles
in one block, so the participants never need to be online together: the signatures are ordinary
data that can travel by USB stick, email or paper.

The outer transaction is an ordinary transaction: its sender signs it with their own key and pays
the outer fee, and need not be a participant.

Inner types that can execute: SendZBC (1), NodeRegistration (2), NodeRegistrationUpdate (258),
RemoveNodeRegistration (514) and ClaimNodeRegistration (770). The tool refuses any other type.

**A multisig is visible on chain.** Every type-5 transaction carries, in the clear, the full
participant list, the threshold and nonce, the unsigned inner transaction, and which participants
signed. The multisig address alone looks like an ordinary `ZBC_` address; its first spend shows
the participants.

## Roles

| Step | Who | Network |
|---|---|---|
| `address` | each participant | none |
| `prepare` | anyone (the coordinator) | reads the genesis hash with `--api`; none with `--genesis-hash` |
| `sign` | each signing participant | none |
| `combine` | anyone with the files, plus a funded ZBC key for the outer fee | none |
| `submit` | anyone | yes |

The submitter cannot change what is spent: the participants' signatures cover the inner
transaction, and any change to it makes them fail. The inner fee is paid by the multisig account.

## Step by step

Each key is a 32-byte seed as 64 hex characters, in a key file (`--key-file`) or in `ZBC_KEY`.

**1. Each participant publishes their address.**

```sh
zbc-multisig-offline address --key-file alice.key                  # ZBC_...
zbc-multisig-offline address --key-file carol.key --key-type eth   # 0x...
zbc-multisig-offline address --key-file dave.key  --key-type btc   # 1... (P2PKH)
```

**2. The coordinator prepares the signing package.**

```sh
zbc-multisig-offline prepare \
  --participants ZBC_AAAA...,ZBC_BBBB...,0xCCCC... \
  --threshold 2 --nonce 0 \
  --to ZBC_RRRR... --amount 300000000 \
  --api https://<gateway or node> \
  --out pkg.json
```

- `--genesis-hash <64 hex>` instead of `--api` binds the package to a chain with no network at all.
- `--type N --body-hex HEX [--recipient ADDR]` instead of `--to/--amount` for another inner type.
- `--inner-fee` sets the most the multisig account pays (default 0.1 ZBC); `--message` adds up to
  256 bytes of text to the inner transaction.
- The same participants, threshold and nonce always give the same multisig address.

The result reports `multisig_address`: fund it with the amount plus the inner fee before you
submit. Send `pkg.json` (format `zbc-multisig-package-v1`) to every participant.

**3. Each participant signs, offline.**

```sh
zbc-multisig-offline sign pkg.json --key-file alice.key \
  --genesis-hash <the chain you expect> --out sig-alice.json
```

`sign` opens no connection. Before signing it re-derives the multisig address, parses the inner
bytes, checks their sender is the multisig account, recomputes the hash and digest, and refuses
the package as tampered if any human-readable detail does not match the bytes. It then shows the
chain, the participants, the type, recipient, amount, inner fee and digest, and asks you to type
`yes` (`--yes` in a script). With `--genesis-hash` it refuses a package for any other chain; it
also refuses a key that is not a participant. The signature file (`zbc-multisig-signature-v1`)
holds no secret: send it back to the coordinator.

**4. Combine, offline.**

```sh
zbc-multisig-offline combine pkg.json sig-alice.json sig-carol.json \
  --submitter-key-file me.key --fee 5000000 --out signed.json
```

`combine` refuses a signature for a different chain or digest, a signer who is not a participant,
a second signature from the same participant, a signature that does not verify, and anything
below the threshold. It builds the type-5 body, parses it back and counts the valid signatures as
the chain does, then signs the outer transaction with the submitter key. `signed.json`
(`zbc-multisig-transaction-v1`) holds the transaction hash, the signed bytes and the payload for
`POST /api/v1/transactions`.

**5. Submit.**

```sh
zbc-multisig-offline submit signed.json --api https://<gateway or node>
```

`submit` refuses a node that serves a different chain from the one in the file. HTTP 202 means the
pool accepted the transaction, not that a block includes it: check
`/api/v1/transactions/<hash>` and the recipient's balance.

## Output and exit codes

stdout carries one JSON object, as for every tool ([`../spec/cli-contract.md`](../spec/cli-contract.md));
`-v` prints text instead, and `sign` writes its summary to stderr in JSON mode. Exit codes: 0 ok,
1 internal, 2 usage (for example `--yes` missing when stdin is not a terminal), 3 node
unreachable, 6 node rejected, 8 timeout, 9 node busy, 10 refused (bad, duplicate or foreign
signature, not a participant, below threshold, tampered package, wrong chain at submit).
`ZBC_API` and `ZBC_TIMEOUT` work as in the other tools.

## Replay of an executed spend

Before the rule `multisig_no_replay`, a later type-5 transaction carrying the public inner bytes
of an already executed multisig spend could make that spend execute again, until the multisig
account was empty. From the rule's activation height an executed inner transaction is final: a
type-5 naming it is refused at admission and, if mined, is a no-op. On a chain where the rule is
not yet active, keep in a multisig account only what is about to be spent.

## Contact

https://zoobc.com · info@zoobc.foundation
