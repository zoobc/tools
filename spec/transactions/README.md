<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Transaction descriptions

One JSON file per transaction type, written from the C++ reference (`cpp/cmd/zoobc-cli.cpp`
builders; the standalone tools in `cpp/cmd/` for the eight types `zbc-cli` does not have).
Ports generate their serialisers and `zbc-cli` subcommands from these files; the vector for
each file's `example` is in `../vectors/transactions-all.json`, produced by running the C++
tools, so a generated serialiser is checked against the reference on every type.
`index.json` lists them all with the encoding and parameter-kind vocabularies.

`scripts/write-spec-transactions.py` writes these files from its table; edit the table, not
the JSON.

## Fields of one description

| Key | Meaning |
|-----|---------|
| `name`, `type` | the node's name and numeric code of the transaction type |
| `command` | the `zbc-cli` subcommand; for the eight standalone-only types, the name a port uses for its subcommand |
| `binary` | the single-purpose C++ program, or `null` when only `zbc-cli` has it |
| `description` | one sentence |
| `sender_key` | the name of the first parameter (the signing key). `ZBC_KEY` applies only when it is `sender_privkey` |
| `recipient` | `required` when the envelope carries a recipient (the `recipient` parameter), else `none` |
| `options` | envelope options that apply: `message`, `encrypt`, `escrow`, `chain` |
| `needs_node` | `true` when building the body needs a node (proof of ownership) even with `--genesis` |
| `custom` | `null` when the generic serialiser can produce the body from `body`; else a label for the hand-written part |
| `params` | the command-line parameters in order, key first: `name`, `kind` (see `index.json`), `required`, `default`, `help`, and `min`/`max` when the reference refuses values outside a range |
| `body` | the body byte layout in order: `name`, `encoding` (see `index.json`), `from` (the parameter it is read from), and any of `size`, `value`, `when`, `computed`, `default_from`, `when_zero` |
| `example` | parameter values (strings, as typed on the command line) that the vectors use |
| `notes` | differences between `zbc-cli` and the standalone binary, and other things a port must know |

### Body field modifiers

- `size`: fixed byte count for `hex`.
- `value`: the bytes of a `literal`.
- `when`: the field is written only when the condition on a parameter holds, e.g. `token_id != 0`,
  `event_id != ''`.
- `default_from` / `when_zero`: `escrow-request.expiry` takes the value of `timeout` when it is 0.
- `computed`: prose for what a generic serialiser cannot derive; such a field, or the whole
  type when `custom` is set, needs a small hand-written function in every port (the proof of
  ownership, the multisig inner transaction and signatures, the settle vouchers, the fee-vote and
  heartbeat signatures). Everything else is data-driven.

## The envelope around the body

`signing.md` section 2. The body is field 8; `send-zbc`'s escrow terms and every type's
`--message` are envelope fields, not body fields, and apply as `options` says.
