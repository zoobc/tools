<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Swift (iOS, macOS, Linux)

One Swift package: the `ZBC` library (keys, addresses, message signing, the transaction envelope
and chain-bound digest, every transaction body, the node client) and the `zbc-cli` executable.
SHA-512, HMAC and Ed25519 *verification* come from [swift-crypto](https://github.com/apple/swift-crypto),
which is CryptoKit on Apple platforms. Ed25519 *signing*, SHA3-256 and BLAKE2b are in the package:
CryptoKit has no SHA-3, and its Ed25519 signatures are randomised, so they would never equal the
signature the reference tools and every other port produce for the same bytes; `Ed25519.swift`
signs deterministically per RFC 8032 (about 100 ms per signature in a release build, much slower
in debug). HTTP is `URLSession`. Swift 5.9 or newer; macOS 12 / iOS 15 or newer; Linux with the
swift.org toolchain.

```
cd swift
swift test -c release              # every vector in ../spec/vectors through the library and the CLI (debug builds sign slowly)
swift build -c release             # .build/release/zbc-cli
swift run gen                      # regenerate Sources/ZBC/CommandsGen.swift from ../spec/transactions
```

Add to another package with `.package(url: "https://github.com/zoobc/tools.git", branch: "main")`
and depend on the product `ZBC` (the package manifest is in `swift/`; from a checkout use
`.package(path: "../tools/swift")`).

## Use the command line

```
.build/release/zbc-cli send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
.build/release/zbc-cli send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> .build/release/zbc-cli send-zbc --json-input
.build/release/zbc-cli approve-escrow - 0 <escrowed tx hash>
.build/release/zbc-cli sign-message <64 hex key> "text"
.build/release/zbc-cli verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
.build/release/zbc-cli help send-zbc                                    # the fields of one command
.build/release/zbc-cli send-zbc --help                                  # options, environment, exit codes
```

The contract every command follows is [`../spec/cli-contract.md`](../spec/cli-contract.md). All
58 transaction types of `../spec/transactions` are subcommands; `swift run gen` embeds the spec
into `Sources/ZBC/CommandsGen.swift`, so a new type in the spec is a regeneration, not new code.
The seven types the spec marks custom are in `Custom.swift`. `--encrypt` seals `--message` to a ZBC recipient exactly as the C++ tools do (`../spec/signing.md` 8: X25519 from
CryptoKit / swift-crypto, HSalsa20, XSalsa20 and Poly1305 in `Encryption.swift`) and `zbc-cli decrypt-message <recipient key>
<message_hex>` opens a sealed field; in the library, `Encryption.seal` and `Encryption.openSealed`.

## Use the library

```swift
import ZBC

let kp = try KeyPair(hex: "<64 hex seed>")                  // kp.address ZBC_, kp.nodeAddress ZNK_, kp.accountBytes
let (acct, path) = try Wallet.account("<12 or 24 words>", index: 0)   // m/44'/883'/0'

let s = Message.sign(kp, Array("hello".utf8))               // ZBC-MSG-v1: address, digest, signature
Message.verify(kp.address, Array("hello".utf8), Enc.unhex(s.signature)!)   // true

let client = Client(api: "https://<gateway>", timeoutSeconds: 20)
let ctx = try client.signingRule()                          // version 2 + genesis from /api/v1/node/info
let tx = try Transaction.sign(type: Transaction.sendZBC, timestamp: Int64(Date().timeIntervalSince1970), sender: kp,
    recipient: try Address.parse("ZBC_...").bytes, fee: 5_000_000, body: Transaction.sendZBCBody(100_000_000), ctx: ctx,
    escrow: Escrow(approver: "ZBC_...", commission: 0, timeout: 1_800_000_000, instruction: "on delivery"))
Enc.hex(tx.hash)                                            // the transaction hash
try client.submitOrThrow(tx.payload)                        // ToolError carries the contract's exit code
try client.status(Enc.hex(tx.hash))                         // staging | mempool | confirmed | not_found
try client.account(kp.address)                              // balances
```

Offline: `try SigningContext.of("<genesis hex>")` (or `"v1"`) instead of `signingRule()`. Every
body of `../spec/transactions` is available through `Body.build(def, params, ctx)` with
`Spec.command("issue-token")` and friends; `Custom.multisigAddress`, `Custom.proofOfOwnership` and
the custom builders are public.

## Layout

```
Sources/ZBC/     Sha3, Blake2b, Encoding (hex, base32, base58, bech32, SS58), Bip39Words,
                 Address, Keys, Message, Transaction, Spec + CommandsGen (generated), Body, Custom, Api, Errors, Cli
Sources/zbc-cli/ the command-line program
Sources/gen/     writes CommandsGen.swift from ../spec/transactions
Tests/ZBCTests/  the vector suite (XCTest)
```
