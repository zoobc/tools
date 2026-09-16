<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Python

One pip package, `zbc-tools` (import name `zbc`), on the standard library only: `hashlib` gives
SHA3-256, SHA-512, BLAKE2b and PBKDF2; Ed25519 is implemented in `zbc/ed25519.py`; HTTP is
`urllib`. It contains the library (keys, addresses, message signing, the transaction envelope
and chain-bound digest, every transaction body, the node client) and `zbc-cli`, the same
command line as the C++ tools, with the same exit codes and JSON. Python 3.9 or newer.

```
cd py
python3 -m unittest -v          # every vector in ../spec/vectors through the library and the CLI
python3 -m zbc.cli list
pip install .                   # puts zbc-cli on the path
```

## Use the command line

```
zbc-cli send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
zbc-cli send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> zbc-cli send-zbc --json-input
zbc-cli approve-escrow - 0 <escrowed tx hash>
zbc-cli sign-message <64 hex key> "text"
zbc-cli verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
zbc-cli help send-zbc                                    # the fields of one command
zbc-cli send-zbc --help                                  # options, environment, exit codes
```

Without installing: `python3 -m zbc.cli ...` from `py/`. The contract every command follows is
[`../spec/cli-contract.md`](../spec/cli-contract.md). All 58 transaction types of
`../spec/transactions` are subcommands; their parameters and body layouts are generated into
`zbc/_commands.py` by `scripts/gen_commands.py`. The seven types the spec marks custom are in
`zbc/custom.py`. `--encrypt` seals `--message` to a ZBC recipient exactly as the C++ tools do
(`../spec/signing.md` 8; X25519, HSalsa20, XSalsa20 and Poly1305 in `zbc/encryption.py`, standard library only) and
`zbc-cli decrypt-message <recipient key> <message_hex>` opens a sealed field; in the library, `seal` and `open_sealed`.

## Use the library

```python
import zbc

kp = zbc.key_pair("<64 hex seed>")                 # kp.address (ZBC_), kp.node_address (ZNK_), kp.account_bytes
acct = zbc.wallet_account("<12 or 24 words>", 0)   # m/44'/883'/0'

s = zbc.sign_message(kp.seed, b"hello")             # ZBC-MSG-v1: dict with address, digest, signature
zbc.verify_message(kp.address, b"hello", s["signature"])   # True

client = zbc.Client("https://<gateway>", timeout_seconds=20)
ctx = client.signing_rule()                         # SigningContext(2, genesis) from /api/v1/node/info
tx = zbc.sign_transaction(zbc.SEND_ZBC, int(time.time()), kp, zbc.parse_address("ZBC_...").bytes,
                          5000000, zbc.send_zbc_body(100000000), ctx,
                          escrow=zbc.Escrow("ZBC_...", commission=0, timeout=1800000000, instruction="on delivery"))
tx.hash.hex()                                       # the transaction hash
client.submit_or_raise(tx.payload)                  # raises zbc.ToolError with the contract's exit code
client.status(tx.hash.hex())                        # staging | mempool | confirmed | not_found
client.account(kp.address)                          # balances
```

Offline signing takes `zbc.SigningContext.of("<genesis hex>")` (or `"v1"`) instead of asking the
node. Every body of `../spec/transactions` is available through `zbc.build_body(spec, params,
sender)` with `zbc.COMMAND_BY_NAME["issue-token"]` and friends; `zbc.custom` has
`multisig_address`, `proof_of_ownership` and the custom builders.

## Layout

```
zbc/ed25519.py      Ed25519 on Python integers
zbc/encoding.py     base32, base58/base58check, bech32/bech32m, SS58
zbc/address.py      account types, ZBC_/ZNK_/ZBS_ text form, parse_address for every supported chain
zbc/keys.py         seed -> key pair; BIP-39 + SLIP-10 wallets (zbc/bip39_words.py)
zbc/message.py      ZBC-MSG-v1
zbc/transaction.py  envelope, escrow block, digest, signature, hash, submit payload
zbc/body.py         the data-driven body serialiser; zbc/custom.py the hand-written parts
zbc/api.py          the node/gateway client
zbc/cli.py          zbc-cli
zbc/_commands.py    the command table, generated from ../spec/transactions
tests/              the vector suite (unittest)
```

Ed25519 here is big-integer arithmetic: the scalar multiplication takes the same path for every
key, but Python integers are not constant time. Keep private keys on machines you trust, as with
any pure-Python signer.
