# Specification

Language-neutral description of what every implementation must do. Files arrive with the C++
tools, which are the reference implementation:

- `transactions/` one file per transaction type: fields, byte layout, fee rule, examples
- `signing.md` transaction digest (ZBC-TX, chain-bound) and message signing (ZBC-MSG-v1)
- `addresses.md` account and node address formats
- `api.md` the node HTTP calls the tools use, and how a gateway differs from a node
- `cli-contract.md` exit codes, options, environment variables, JSON output shape
- `vectors/` golden test vectors in JSON. Every implementation runs all of them in CI.
