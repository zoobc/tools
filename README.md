# ZooBC tools

Command-line tools for the ZooBC blockchain: one small program per transaction type, plus
`zbc-cli`, which bundles them all under one command. The same tools are provided in several
languages and kept in step by one shared specification and one set of test vectors.

The tools talk to a ZooBC node or gateway over its public HTTP API only. They are not the node.
The node has its own repository and its own licence (the ZooBC Source License). These tools are
MIT licensed, so you can build them into your own software, commercial or not, without asking.

## Layout

```
spec/       the contract, independent of language: transaction formats, signing, addresses,
            the HTTP calls used, the command-line contract (exit codes, options, JSON output),
            and vectors/ with golden test vectors every implementation must pass
cpp/        C++ implementation: libzbc (keys, addresses, serialisation, signing, HTTP client),
            one program per transaction, and zbc-cli
go/         Go implementation, same shape: a zbc package, cmd/<tool>, cmd/zbc-cli
rust/       Rust implementation, same shape: a zbc crate, one binary per tool, zbc-cli
```

Language first, because each language has its own build system and package registry. What keeps
the implementations identical is `spec/vectors`: every language runs the same vectors in CI, and a
single differing byte fails the build.

## Status

The C++ tools are being moved here from the node repository. Go and Rust follow. The table below
is updated as tools land.

| Tool | C++ | Go | Rust |
|------|-----|----|------|
| zbc-cli (all transactions) | moving | planned | planned |
| one program per transaction | moving | planned | planned |
| key and address generators | moving | planned | planned |

## Command-line contract

Every tool prints one JSON object on stdout and uses the same exit codes, options and
environment variables. The contract is in `spec/cli-contract.md` (to be added with the C++ tools).

## Licence

MIT. See [LICENSE](LICENSE).
