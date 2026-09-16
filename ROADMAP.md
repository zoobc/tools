# Roadmap

The same tools, in the languages people integrate with. Every implementation passes the same
`spec/vectors`, so a byte produced in one language verifies in every other. The order is the order
of work, chosen by who integrates ZooBC with what.

| # | Language | Shape | Status |
|---|----------|-------|--------|
| 1 | C++ | `libzbc` and 57 programs, the reference | published, `cpp/` |
| 2 | TypeScript | one npm package for browser and Node, typed, with `zbc-cli` | published, `ts/` (all 58 types, `--encrypt`) |
| 3 | JavaScript | one dependency-free file to include with a script tag, built from the TypeScript package and committed so nobody needs npm | published, `js/zbc.js` |
| 4 | Python | one pip package and `zbc-cli` | published, `py/` (all 58 types; `--encrypt` not yet) |
| 5 | Go | one module: `zbc` package, `cmd/<tool>`, `cmd/zbc-cli` | published, `go/` (all 58 types, 45 programs; `--encrypt` not yet) |
| 6 | Rust | one Cargo workspace: `zbc` crate, one binary per tool, `zbc-cli` | published, `rust/` (all 58 types, 45 programs; `--encrypt` not yet) |
| 7 | Kotlin | one JVM/Android library, usable from Java, and `zbc-cli` | published, `kotlin/` (all 58 types; `--encrypt` not yet) |
| 8 | Swift | one Swift package for iOS and macOS | published, `swift/` (all 58 types; `--encrypt` not yet) |
| 9 | PHP | one Composer package and `zbc-cli`; PHP ships SHA3 and Ed25519 built in | published, `php/` (all 58 types; `--encrypt` not yet) |
| 10 | Perl | one CPAN-style distribution | published, `perl/` (all 58 types; `--encrypt` not yet) |

## What every port contains, in this order

1. **Core.** Keys, addresses, message signing (`ZBC-MSG-v1`), the transaction envelope and its
   chain-bound digest, `SendZBC` with escrow terms, `ApprovalEscrow`, the HTTP client (submit,
   status, account) and the exit-code contract of `spec/cli-contract.md`. Passes the core vectors.
2. **Every transaction type**, generated from the machine-readable descriptions in
   `spec/transactions/`, not written by hand seven times.
3. **The command line**, `zbc-cli` with one subcommand per transaction. Compiled languages also
   build one program per transaction; scripting languages ship the library and the one command.

## Spec first

The transaction descriptions in `spec/transactions/` are the source the serializers are generated
from, one file per type with its fields and byte layout. The vectors in `spec/vectors/` are produced
by the C++ tools and checked against a live network. A port is done when it passes them, and it
stays done because CI runs them on every change in every language.
