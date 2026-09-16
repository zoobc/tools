<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Rust

One Cargo workspace: the `zbc` crate is the library (keys, addresses, message signing, the
transaction envelope and chain-bound digest, every transaction body, the node client) and holds
the `zbc-cli` logic; the `zbc-cli` crate builds the combined command and one binary per
transaction, as the C++ tools have; `gen` writes the command table and those binaries' sources
from `../spec/transactions`. Rust 1.75 or newer. Dependencies: `sha3`, `sha2`, `hmac`,
`pbkdf2`, `blake2`, `ed25519-dalek`, `hex`, `serde_json`, `ureq`.

```
cd rust
cargo test                                  # every vector in ../spec/vectors through the library and the CLI
cargo build --release                       # target/release/zbc-cli and the 45 zbc-* programs
cargo install --path zbc-cli                # onto ~/.cargo/bin
```

## Use the command line

```
zbc-cli send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
zbc-send - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> zbc-cli send-zbc --json-input
zbc-cli approve-escrow - 0 <escrowed tx hash>
zbc-cli sign-message <64 hex key> "text"
zbc-cli verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
zbc-cli help send-zbc                                    # the fields of one command
zbc-cli send-zbc --help                                  # options, environment, exit codes
```

The contract every command follows is [`../spec/cli-contract.md`](../spec/cli-contract.md). All
58 transaction types of `../spec/transactions` are subcommands, and the 45 that the C++ tools
also ship as single programs exist as binaries with the same names; `cargo run -p gen`
regenerates `zbc/src/commands_gen.rs` and `zbc-cli/src/bin/*.rs` from the spec. The seven types
the spec marks custom are in `zbc/src/custom.rs`. `--encrypt` seals `--message` to a ZBC recipient exactly as the
C++ tools do (`../spec/signing.md` 8; x25519-dalek, salsa20 and crypto_secretbox in `zbc/src/encryption.rs`) and
`zbc-cli decrypt-message <recipient key> <message_hex>` opens a sealed field; in the crate, `seal` and `open_sealed`.

## Use the library

```rust
use zbc::*;

let kp = KeyPair::from_hex("<64 hex seed>")?;             // kp.address() ZBC_, kp.node_address() ZNK_, kp.account_bytes()
let (acct, path) = wallet_account("<12 or 24 words>", 0, "")?;   // m/44'/883'/0'

let s = sign_message(&kp, b"hello");                       // ZBC-MSG-v1: address, digest, signature
verify_message(&kp.address(), b"hello", &sig_bytes);

let client = Client::new("https://<gateway>", 20);
let ctx = client.signing_rule()?;                          // {2, genesis} from /api/v1/node/info
let tx = sign_transaction(&Unsigned {
    tx_type: transaction::SEND_ZBC, timestamp: now, sender: kp.account_bytes(),
    recipient: parse_address("ZBC_...", "")?.bytes(), fee: 5_000_000, body: send_zbc_body(100_000_000),
    escrow: Some(Escrow { approver: "ZBC_...".into(), commission: 0, timeout: 1_800_000_000, instruction: "on delivery".into() }),
    ..Default::default()
}, &kp, &ctx)?;
hex::encode(tx.hash);                                      // the transaction hash
client.submit_or_fail(&tx.payload)?;                       // ToolError carries the contract's exit code
client.status(&hex::encode(tx.hash))?;                     // staging | mempool | confirmed | not_found
client.account(&kp.address())?;                            // balances
```

Offline: `SigningContext::of("<genesis hex>")` (or `"v1"`) instead of `signing_rule`. Every body
of `../spec/transactions` is available through `body::build_body(def, &params, &ctx)` with
`command("issue-token")` and friends; `multisig_address`, `proof_of_ownership` and the custom
builders are exported.

## Layout

```
zbc/src/        address, keys (bip39_words), message, transaction, body, custom, api, errors,
                encoding (base32, base58, bech32, SS58), spec + commands_gen (generated), cli
zbc/tests/      the vector suite
zbc-cli/src/    main.rs (the combined command) and bin/*.rs (one per transaction, generated)
gen/            writes commands_gen.rs and zbc-cli/src/bin from ../spec/transactions
```
