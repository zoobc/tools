# C++ tools

The reference implementation of the ZooBC command-line tools: 57 small programs and the
library they share. Everything talks to a node or gateway over its public HTTP API; nothing here
is node code.

```
libzbc/       keys, addresses, hashing, transaction serialisation and signing (the core)
cmd/          one source file per tool, plus the shared headers
third_party/  cpp-httplib and nlohmann/json, header-only, unmodified
cmake/        find module for libsodium
tests/        offline smoke test, run by ctest
UPSTREAM.txt  which node commit the core was last synchronised from
```

## Build

Requirements: a C++17 compiler, CMake 3.16 or newer, libsodium, OpenSSL and secp256k1.

Debian or Ubuntu:

```
sudo apt install cmake g++ libsodium-dev libssl-dev libsecp256k1-dev
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build
```

macOS with Homebrew:

```
brew install cmake libsodium openssl@3 secp256k1
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build -j
ctest --test-dir build
```

The binaries land in `build/`. `cmake --install build --prefix ~/.local` copies them to `~/.local/bin`.

Self-contained Linux binaries, with every third-party library linked in and only libc left
dynamic, come from `-DZBC_STATIC=ON`; the static archives of the three libraries must be
installed (on Ubuntu the OpenSSL archive also wants `libjitterentropy-dev`).

## Use

```
build/zbc-cli list                                  every command
build/zbc-cli help send-zbc                         the fields of one command
build/zbc-cli send-zbc --help                       options, environment, exit codes

export ZBC_API=https://<gateway or node>            where to send
export ZBC_KEY=<64 hex>                             the sender key, kept out of the command line
build/zbc-cli send-zbc - ZBC_... 100000000          send 1 ZBC (amounts are atomic units, 10^8 per ZBC)
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | build/zbc-cli send-zbc --json-input

build/zbc-cli sign-message <64 hex> "text"          off-chain signature, no node needed
build/zbc-cli verify-message ZBC_... "text" <sig>   exit 0 valid, exit 10 not

build/zbc-cli send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline
                                                    build, sign and hash without a node: prints
                                                    unsigned_bytes, digest, signature, transaction_bytes,
                                                    transaction_hash and the payload it would have sent
```

Every tool prints one JSON object and exits with a meaningful code. The full contract, shared by
every language, is [`../spec/cli-contract.md`](../spec/cli-contract.md). A success reply means the
node accepted the transaction into its pool, not that it is in a block.

## The tools

**The combined command**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-cli` | `cmd/zoobc-cli.cpp` | All commands below as one binary; also sign-message and verify-message |

**Value**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-send` | `cmd/transfer.cpp` | Send ZBC coins from one account to another |
| `zbc-liquid-pay` | `cmd/liquid-payment.cpp` | Create a time-vested liquid payment to a recipient |
| `zbc-liquid-stop` | `cmd/liquid-payment-stop.cpp` | Stop/complete a pending liquid payment, distributing funds pro-rata |

**Tokens**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-token-issue` | `cmd/issue-token.cpp` | Issue a native token (colored coin) backed by ZBC |
| `zbc-token-transfer` | `cmd/token-transfer.cpp` | Transfer a held token to a recipient |
| `zbc-token-mint` | `cmd/mint-token.cpp` | Mint a token (token_id + amount) |
| `zbc-token-burn` | `cmd/burn-token.cpp` | Burn a token (token_id + amount) |
| `zbc-token-finance` | `cmd/finance-token.cpp` | Top up a token's survival financing (the fee buys persistence). Body = 8-byte token_id |

**Exchange**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-swap-create` | `cmd/swap-create.cpp` | Post an atomic swap offer: GIVE X of a token for WANT Y of another (give is held) |
| `zbc-swap-accept` | `cmd/swap-accept.cpp` | accept a swap offer by id |
| `zbc-swap-cancel` | `cmd/swap-cancel.cpp` | cancel a swap offer by id |
| `zbc-market-create` | `cmd/market-create.cpp` | Open a permissionless (base,quote) order-book market, paying a rent deposit |
| `zbc-order-place` | `cmd/order-place.cpp` | Place a limit/market buy/sell order on a market (price scaled 1e8) |
| `zbc-order-cancel` | `cmd/order-cancel.cpp` | Cancel a resting order by id (refunds the held remainder) |

**Apps**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-app-create` | `cmd/app-create.cpp` | Open an app: type + stake (token,amount) + seats. (params/opponent omitted for v1.) |
| `zbc-app-join` | `cmd/app-join.cpp` | join an app by id |
| `zbc-app-move` | `cmd/app-move.cpp` | Submit a move (app_id + move bytes as hex; e.g. ttt cell 4 = '04') |
| `zbc-app-resign` | `cmd/app-resign.cpp` | resign an app by id |
| `zbc-app-claim` | `cmd/app-claim.cpp` | claim an app by id |
| `zbc-app-settle` | `cmd/app-settle.cpp` | Settle a 1-v-1 tic-tac-toe channel app: replay moves, sign a voucher each, submit SettleApp |

**Storage and account**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-storage-prepay` | `cmd/add-prepaid-storage.cpp` | Fund your account's prepaid storage balance (pays dataset storage rent). Body = 8-byte amount |
| `zbc-dfs-create-file` | `cmd/dfs-create-file.cpp` | Create an on-chain file. Body = u32 path_len | path | u32 content_len | content |
| `zbc-dataset-setup` | `cmd/setup-dataset.cpp` | Create or update a key-value property on an account |
| `zbc-dataset-remove` | `cmd/remove-dataset.cpp` | Deactivate a key-value property on an account |
| `zbc-escrow-approve` | `cmd/approve-escrow.cpp` | Approve or reject an escrow transaction. The escrow is named by the full  |
| `zbc-escrow-request` | `cmd/escrow-request.cpp` | Create a recipient-initiated escrow request |
| `zbc-event-attest` | `cmd/attest-event.cpp` | Oracle attestation (Phase C): an authorized node attests an external (event_id -> value).  |
| `zbc-trigger-create` | `cmd/create-trigger.cpp` | Schedule a SendZBC to fire at a future block height (or on an oracle event).  |
| `zbc-trigger-cancel` | `cmd/cancel-trigger.cpp` | Cancel a pending trigger you own; the locked amount is refunded. Body = 8-byte trigger_id |
| `zbc-fund-longevity` | `cmd/fund-longevity.cpp` | Attach a rent deposit to a transaction so pruning skips it.  |
| `zbc-cancel-longevity` | `cmd/cancel-longevity.cpp` | Cancel a sponsorship you created. Refunds the remainder less the current  |
| `zbc-fee-vote-commit` | `cmd/fee-vote-commit.cpp` | Submit a hashed fee vote during the commit phase |
| `zbc-fee-vote-reveal` | `cmd/fee-vote-reveal.cpp` | Reveal the actual fee vote during the reveal phase |
| `zbc-multisig` | `cmd/multisig.cpp` | N-of-M multisig transfer: inner transaction plus participant signatures |
| `zbc-governance-vote` | `cmd/governance-vote.cpp` | Declare the value this node wants for a governable parameter (2/3 of the registry must agree) |

**Nodes, gateways, archivals, relays**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-node-register` | `cmd/register-node.cpp` | Register a new node on the ZooBC network |
| `zbc-node-update` | `cmd/update-node.cpp` | Update a node registration to change the locked balance |
| `zbc-node-remove` | `cmd/remove-node.cpp` | Remove a node from the registry and return locked balance to owner |
| `zbc-node-claim` | `cmd/claim-node.cpp` | Claim back locked balance from an expired or deleted node registration |
| `zbc-gateway-register` | `cmd/gateway-register.cpp` | Announce a gateway you run: gateway_key + domain + url, locking the registration stake |
| `zbc-gateway-unregister` | `cmd/gateway-unregister.cpp` | Withdraw a gateway you registered, refunding the locked stake |
| `zbc-archival-register` | `cmd/archival-register.cpp` | Announce a registered node as archival (serves history + the read API): node_key + domain + url |
| `zbc-archival-unregister` | `cmd/archival-unregister.cpp` | Withdraw an archival announcement (the node itself stays registered) |
| `zbc-relay-register` | `cmd/relay-register.cpp` | Announce a relay: relay_key + the gateway_key it belongs to + domain + url |
| `zbc-relay-unregister` | `cmd/relay-unregister.cpp` | Withdraw a relay announcement |

**Keys and addresses (offline)**

| Binary | Source | Does |
|--------|--------|------|
| `zbc-key-gen` | `cmd/keygen.cpp` | Generate Ed25519 key pairs |
| `zbc-account-gen` | `cmd/account-gen.cpp` | Generate account addresses (ZBC and, with a chain name, other chains) |
| `zbc-node-gen` | `cmd/bcn-address-gen.cpp` | Generate a node key pair and ZNK address |
| `zbc-wallet-gen` | `cmd/wallet-gen.cpp` | Generate a BIP-39 mnemonic wallet and derive its keys (path m/44'/883') |
| `zbc-account-from-key` | `cmd/zbc-from-privkey.cpp` | ZBC address of a private key |
| `zbc-node-from-key` | `cmd/znk-from-privkey.cpp` | ZNK node address of a node private key |
| `zbc-message-decrypt` | `cmd/decrypt-message.cpp` | Decrypt an encrypted transaction message with the recipient key |
| `zbc-account-eth` | `cmd/account-gen.cpp` | Ethereum address and key |
| `zbc-account-btc` | `cmd/account-gen.cpp` | Bitcoin address and key |
| `zbc-account-solana` | `cmd/account-gen.cpp` | Solana address and key |
| `zbc-account-polkadot` | `cmd/account-gen.cpp` | Polkadot address and key |

## Keeping the core in step with the node

`libzbc` is the node's own crypto, address and serialisation code, copied file by file, so the
bytes the tools sign are exactly the bytes the node verifies. `UPSTREAM.txt` names the node commit
of the last copy. The synchronisation is a script on the node side; the copy is not edited here.
The multisig helpers in `libzbc/src/transaction/` are the two stateless functions the tools need
from the node's multisignature service, extracted verbatim.

## Licence

MIT, see [`../LICENSE`](../LICENSE). The header-only libraries in `third_party/` keep their own
MIT licences.
