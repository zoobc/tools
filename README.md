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
ts/         TypeScript: one npm package for Node and the browser, no runtime dependencies, with zbc-cli
js/         the TypeScript package bundled into one dependency-free file for a <script> tag
py/         Python: one pip package on the standard library only, with zbc-cli
scripts/    the generators that write spec/transactions and spec/vectors from the C++ tools
go/         Go: one module on the standard library, package zbc, cmd/zbc-cli and cmd/zbc-* (one per transaction)
rust/       Rust: one Cargo workspace, the zbc crate, zbc-cli and one binary per transaction
kotlin/     Kotlin: one Gradle project, a JVM/Android library usable from Java, with zbc-cli
swift/      Swift: one package for iOS, macOS and Linux, the ZBC library and zbc-cli
php/        PHP: one Composer package on PHP's own sodium/hash extensions, with zbc-cli
perl/       Perl: one CPAN-style distribution on core modules only (SHA3, BLAKE2b and Ed25519 in pure Perl), with zbc-cli
```

Language first, because each language has its own build system and package registry. What keeps
the implementations identical is `spec/vectors`: every language runs the same vectors in CI, and a
single differing byte fails the build.

## Status

The C++ tools are here and build on Linux and macOS (see `cpp/README.md`). The TypeScript
package with its drop-in JavaScript build (`ts/README.md`, `js/README.md`), the Python package
(`py/README.md`), the Go module (`go/README.md`), the Rust workspace (`rust/README.md`), the
Kotlin/JVM library (`kotlin/README.md`), the Swift package (`swift/README.md`), the PHP package
(`php/README.md`) and the Perl distribution (`perl/README.md`) are here too, `--encrypt` included.
Every language of [ROADMAP.md](ROADMAP.md) is published.

| Tool | C++ | TypeScript / JS | Python | Go | Rust | Kotlin | Swift | PHP | Perl |
|------|-----|-----------------|--------|----|------|--------|-------|-----|------|
| zbc-cli (all transactions) | done | done (58 types, generated from the spec) | done (58 types) | done (58 types) | done (58 types) | done (58 types) | done (58 types) | done (58 types) | done (58 types) |
| one program per transaction | done (45) | n/a, one command | n/a, one command | done (45, generated) | done (45, generated) | n/a, one command (done) | n/a (done, one command) | n/a, one command (done) | n/a, one command (done) |
| key and address generators | done | done (library and `zbc-cli`; no separate generator programs) | done (library) | done (library) | done (library) | done (library) | done (library) | done (library) | done (library) |
| passes every vector in `spec/vectors` in CI | done | done | done | done | done | done | done | done | done |

## Command-line contract

Every tool prints one JSON object on stdout and uses the same exit codes, options and
environment variables. The contract is in [`spec/cli-contract.md`](spec/cli-contract.md).

## Links

- Project site: https://zoobc.com
- ZooBC Foundation: https://zoobc.foundation
- This repository: https://github.com/zoobc/tools
- Contact: info@zoobc.foundation

## Licence

MIT. See [LICENSE](LICENSE). Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci.
