<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Test vectors

Every value here was printed by the C++ reference tools (`scripts/make-vectors.py` runs them;
nothing is computed by the script). Every port runs every file in its test suite; CI regenerates
the files from a fresh C++ build and fails if a byte differs (`.github/workflows/spec.yml`).

| File | What a port must reproduce |
|------|----------------------------|
| `keys.json` | seed → public key → `ZBC_` and `ZNK_` address; BIP-39 mnemonic (+ passphrase) → SLIP-10 `m/44'/883'/i'` accounts |
| `addresses.json` | for each input string: accepted or not, account type, full typed address bytes; `chain` entries use `--chain` |
| `messages.json` | `ZBC-MSG-v1` sign and verify, including hex-byte messages, and `invalid` cases that must fail with the given exit code |
| `transactions.json` | the core set: `SendZBC` (plain, message, escrow, foreign recipient, signing v1, another genesis, large fee) and `ApprovalEscrow`; unsigned bytes, digest, signature, transaction bytes, hash and submit payload |
| `transactions-all.json` | one vector per transaction type, from each `../transactions/*.json` example, plus the liquid-payment token variant |
| `cli.json` | exit code and `error_class` of `zbc-cli` for a list of wrong invocations |

Conventions: hex is lower case; `key` is the 32-byte seed; `params` are the command-line strings
in `../transactions` order after the key; `genesis` is the chain the transaction was signed for
(`"v1"` = legacy bare digest); `fee` and `timestamp` are the envelope values. Node-registration
vectors record the `reference_block` their proof of ownership used (a stand-in node served it).
The `send-zbc/plain`, `message`, `escrow` and `large-fee` vectors are the same cases the node
repository recorded against the live devnet (genesis `cf30b4a8…`), so they are known to be
accepted by a chain.

Regenerate: build `cpp/`, then `python3 scripts/make-vectors.py`. Check: add `--check`.
