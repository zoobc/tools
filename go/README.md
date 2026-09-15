<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Go

One module, `github.com/zoobc/tools/go`, on the standard library only (`crypto/ed25519`,
`crypto/sha3`, `crypto/pbkdf2`; BLAKE2b for SS58 is in the package). Package `zbc` is the
library (keys, addresses, message signing, the transaction envelope and chain-bound digest, every
transaction body, the node client); `cmd/zbc-cli` is the combined command line and `cmd/zbc-*`
one program per transaction, as the C++ tools have. Go 1.24 or newer.

```
cd go
go test ./...                       # every vector in ../spec/vectors through the library and the CLI
go build -o bin/ ./cmd/...          # zbc-cli and the 45 single-purpose programs into bin/
go install ./cmd/zbc-cli            # or just the combined command onto $GOPATH/bin
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
also ship as single programs exist under `cmd/` with the same names; `internal/gen` writes
`zbc/commands_gen.go` and those `cmd/` programs from the spec, so a new type is a regeneration
(`go run ./internal/gen`), not new code. The seven types the spec marks custom are in
`zbc/custom.go`. Not available yet in this port: `--encrypt`.

## Use the library

```go
import "github.com/zoobc/tools/go/zbc"

kp, _ := zbc.KeyPairFromHex("<64 hex seed>")       // kp.Address() ZBC_, kp.NodeAddress() ZNK_, kp.AccountBytes()
acct, path, _ := zbc.WalletAccount("<12 or 24 words>", 0, "")   // m/44'/883'/0'

s := zbc.SignMessage(kp, []byte("hello"))         // ZBC-MSG-v1: Address, Digest, Signature
zbc.VerifyMessage(kp.Address(), []byte("hello"), sig)

c := zbc.NewClient("https://<gateway>", 20)
ctx, _ := c.SigningRule()                          // {2, genesis} from /api/v1/node/info
to, _ := zbc.ParseAddress("ZBC_...", "")
tx, _ := zbc.SignTransaction(zbc.Unsigned{Type: zbc.TypeSendZBC, Timestamp: time.Now().Unix(), Sender: kp.AccountBytes(),
    Recipient: to.Bytes(), Fee: 5000000, Body: zbc.SendZBCBody(100000000),
    Escrow: &zbc.Escrow{Approver: "ZBC_...", Timeout: 1800000000, Instruction: "on delivery"}}, kp, ctx)
hex.EncodeToString(tx.Hash)                        // the transaction hash
c.SubmitOrFail(tx.Payload)                         // *zbc.ToolError carries the contract's exit code
c.Status(hex.EncodeToString(tx.Hash))              // staging | mempool | confirmed | not_found
c.Account(kp.Address())                            // balances
```

Offline: `zbc.SigningContextOf("<genesis hex>")` (or `"v1"`) instead of `SigningRule`. Every body
of `../spec/transactions` is available through `zbc.BuildBody(def, params, ctx)` with
`zbc.CommandByName["issue-token"]` and friends; `MultisigAddress`, `ProofOfOwnership` and the
custom builders are exported.

## Layout

```
zbc/            the library: address, keys (bip39_words), message, transaction, body, custom, api,
                errors, encoding (base58, bech32, SS58), blake2b, spec + commands_gen (generated)
cli/            zbc-cli (Run) and the one-command entry the tool programs use (RunTool)
cmd/zbc-cli/    the combined command;  cmd/zbc-*/  one program per transaction (generated)
internal/gen/   writes commands_gen.go and cmd/zbc-*/ from ../spec/transactions
```
