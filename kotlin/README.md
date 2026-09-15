<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Kotlin (JVM and Android)

One Gradle project, group `foundation.zoobc`, artifact `zbc`: a JVM library usable from Kotlin
and Java (every entry point is a plain class or a `@JvmStatic` function) and the `zbc-cli`
command line. Ed25519, BLAKE2b and the address encodings are implemented in the library;
SHA3-256, SHA-512, HMAC and PBKDF2 come from the JDK, HTTP from `java.net.http`. The only
dependency is `kotlinx-serialization-json`. Bytecode targets JVM 17 (Android desugaring not
needed); build with any JDK 17 or newer and Gradle 8.5 or newer (no wrapper is committed:
install Gradle from gradle.org or your package manager).

```
cd kotlin
gradle test                          # every vector in ../spec/vectors through the library and the CLI
gradle installDist                   # build/install/zbc-cli/bin/zbc-cli
gradle jar                           # build/libs/zbc-0.1.0.jar (the library, plus the CLI main class)
```

## Use the command line

```
build/install/zbc-cli/bin/zbc-cli send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
build/install/zbc-cli/bin/zbc-cli send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> build/install/zbc-cli/bin/zbc-cli send-zbc --json-input
build/install/zbc-cli/bin/zbc-cli approve-escrow - 0 <escrowed tx hash>
build/install/zbc-cli/bin/zbc-cli sign-message <64 hex key> "text"
build/install/zbc-cli/bin/zbc-cli verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
build/install/zbc-cli/bin/zbc-cli help send-zbc                                    # the fields of one command
build/install/zbc-cli/bin/zbc-cli send-zbc --help                                  # options, environment, exit codes
```

The contract every command follows is [`../spec/cli-contract.md`](../spec/cli-contract.md). All
58 transaction types of `../spec/transactions` are subcommands: the build copies the spec files
into the jar (`zbc/transactions/*.json`) and the command table is read from them at run time, so
a new type in the spec is a rebuild, not new code. The seven types the spec marks custom are in
`Custom.kt`. Not available yet in this port: `--encrypt`.

## Use the library

```kotlin
import foundation.zoobc.zbc.*

val kp = KeyPair.fromHex("<64 hex seed>")                 // kp.address (ZBC_), kp.nodeAddress (ZNK_), kp.accountBytes
val (acct, path) = Wallet.account("<12 or 24 words>", 0)  // m/44'/883'/0'

val s = Message.sign(kp, "hello".toByteArray())            // ZBC-MSG-v1: address, digest, signature
Message.verify(kp.address, "hello".toByteArray(), Encoding.hexToBytes(s.signature))   // true

val client = Client("https://<gateway>", timeoutSeconds = 20)
val ctx = client.signingRule()                             // SigningContext(2, genesis) from /api/v1/node/info
val tx = Transaction.sign(Transaction.SEND_ZBC, System.currentTimeMillis() / 1000, kp,
    Address.parse("ZBC_...").bytes, 5_000_000, Transaction.sendZbcBody(100_000_000), ctx,
    escrow = Escrow("ZBC_...", commission = 0, timeout = 1_800_000_000, instruction = "on delivery"))
Encoding.bytesToHex(tx.hash)                               // the transaction hash
client.submitOrThrow(tx.payload)                           // ToolError carries the contract's exit code
client.status(Encoding.bytesToHex(tx.hash))                // staging | mempool | confirmed | not_found
client.account(kp.address)                                 // balances
```

From Java: `KeyPair.fromHex(...)`, `Message.sign(kp, bytes)`, `Transaction.sign(...)`,
`Address.parse(...)`, `new Client(url, 20)` are all static or ordinary methods. Offline signing
takes `SigningContext.of("<genesis hex>")` (or `"v1"`) instead of asking the node. Every body of
`../spec/transactions` is available through `Body.build(def, params, ctx)` with
`Spec.command("issue-token")` and friends.

## Layout

```
src/main/kotlin/foundation/zoobc/zbc/
  Ed25519.kt Blake2b.kt Encoding.kt Bip39Words.kt   primitives and encodings
  Address.kt Keys.kt Message.kt Transaction.kt       the core
  Spec.kt Body.kt Custom.kt Api.kt Errors.kt         descriptions, serialiser, custom parts, client, errors
  cli/Main.kt                                        zbc-cli
src/test/kotlin/.../VectorsTest.kt                   the vector suite (kotlin.test)
```

Ed25519 here is `BigInteger` arithmetic: the scalar multiplication takes the same path for every
key, but `BigInteger` is not constant time. Keep private keys on machines you trust.
