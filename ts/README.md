<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# TypeScript / JavaScript

One npm package, `@zoobc/tools`, for Node (20 or newer) and the browser, with no runtime
dependencies: SHA3-256, SHA-512, BLAKE2b and Ed25519 are implemented in TypeScript, and HTTP is
the platform's `fetch`. It contains the library (keys, addresses, message signing, the
transaction envelope and chain-bound digest, every transaction body, the node client) and
`zbc-cli`, the same command line as the C++ tools, with the same exit codes and JSON.
`../js/zbc.js` is this package bundled into one file for a `<script>` tag (see `../js/README.md`).

```
cd ts
npm install          # dev dependencies only: typescript, esbuild, @types/node
npm test             # builds, then runs every vector in ../spec/vectors through the library and the CLI
node dist/cli.js list
```

## Use the command line

```
node dist/cli.js send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
node dist/cli.js send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> node dist/cli.js send-zbc --json-input
node dist/cli.js approve-escrow - 0 <escrowed tx hash>
node dist/cli.js sign-message <64 hex key> "text"
node dist/cli.js verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
node dist/cli.js help send-zbc                                    # the fields of one command
node dist/cli.js send-zbc --help                                  # options, environment, exit codes
```

`npm link` (or a global install of the package) puts `zbc-cli` on the path. The contract every
command follows, exit codes, options and JSON shape, is [`../spec/cli-contract.md`](../spec/cli-contract.md).
All 58 transaction types of `../spec/transactions` are subcommands; their parameters and body
layouts are generated into `src/generated/commands.ts` by `scripts/gen-commands.mjs`, so a new
type in the spec is a regeneration, not new code. The seven types the spec marks custom (proof of
ownership, multisig, settle-app vouchers, fee-vote and heartbeat signatures, store-file piece
count) are in `src/custom.ts`.

`--encrypt` seals `--message` to a ZBC recipient exactly as the C++ tools do (`../spec/signing.md` 8:
X25519, HSalsa20, XSalsa20 and Poly1305 are in `src/crypto`, no dependency), and `zbc-cli decrypt-message
<recipient key> <message_hex>` opens a sealed field. In the library: `seal(plaintext, recipientPublicKey)` and
`openSealed(field, recipientSeed)`.

## Use the library

```ts
import { keyPairFromSeed, walletAccount, signMessage, verifyMessage, signTransaction, signingContext,
         sendZbcBody, approvalEscrowBody, parseAddress, Client, bytesToHex, hexToBytes, utf8 } from "@zoobc/tools";

const kp = keyPairFromSeed("<64 hex seed>");            // kp.address is the ZBC_ form, kp.nodeAddress the ZNK_ form
const acct = walletAccount("<12 or 24 words>", 0);       // m/44'/883'/0'

const s = signMessage(kp.seed, utf8("hello"));           // ZBC-MSG-v1: { address, digest, signature, ... }
verifyMessage(kp.address, utf8("hello"), s.signature);   // true

const client = new Client({ api: "https://<gateway>", timeoutSeconds: 20 });
const ctx = await client.signingRule();                  // { version: 2, genesisHash } from /api/v1/node/info
const tx = signTransaction({
  type: 1, timestamp: Math.floor(Date.now() / 1000), sender: kp.accountBytes,
  recipient: parseAddress("ZBC_...").bytes, fee: 5000000n, body: sendZbcBody(100000000n),
  escrow: { approver: "ZBC_...", commission: 0, timeout: 1800000000, instruction: "on delivery" },   // optional
}, kp, ctx);
bytesToHex(tx.hash);                                     // the transaction hash
await client.submitOrThrow(tx.payload);                  // throws a ToolError with the contract's exit code
await client.status(bytesToHex(tx.hash));                // staging | mempool | confirmed | not_found
await client.account(kp.address);                        // balances
```

Offline signing takes `signingContext("<genesis hex>")` (or `"v1"`) instead of asking the node.
Every body of `../spec/transactions` is available through `buildBody(def, params, ctx)` with
`COMMAND_BY_NAME.get("issue-token")` and friends; `custom.ts` exports `multisigAddress`,
`proofOfOwnership` and the custom builders.

## Layout

```
src/crypto/     sha3, sha2 (sha256, sha512, hmac, pbkdf2), blake2b, ed25519
src/util/       bytes, base32, base58, bech32, ss58, the BIP-39 word list
src/address.ts  account types, ZBC_/ZNK_/ZBS_ text form, parseAddress for every supported chain
src/keys.ts     seed -> key pair; BIP-39 + SLIP-10 wallets
src/message.ts  ZBC-MSG-v1
src/transaction.ts  envelope, escrow block, digest, signature, hash, submit payload
src/body.ts     the data-driven body serialiser; src/custom.ts the hand-written parts
src/api.ts      the node/gateway client
src/cli.ts      zbc-cli
src/generated/  the command table, generated from ../spec/transactions
src/test/       the vector suite (node:test)
```

Ed25519 here is BigInt arithmetic: the scalar multiplication takes the same path for every key,
but BigInt operations are not constant time at the machine level. Keep private keys on machines
you trust, as with any pure-JavaScript signer.
