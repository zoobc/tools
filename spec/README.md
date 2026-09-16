# Specification

Language-neutral description of what every implementation must do, written from the C++
reference and checked against its output:

- `transactions/` one file per transaction type: fields, byte layout, an example; `index.json`
  lists them with the encoding vocabulary; `README.md` explains the schema
- `signing.md` keys, the transaction envelope, the chain-bound digest (`ZBC-TX`), sealed messages (`ZBE1`), message
  signing (`ZBC-MSG-v1`), proof of ownership and the other in-body signatures
- `addresses.md` account types, the `ZBC_`/`ZNK_`/`ZBS_` text form, what a recipient may be
- `api.md` the node HTTP calls the tools use, the submit payload, replies and error classes,
  and how a gateway differs from a node
- `cli-contract.md` exit codes, options, environment variables, JSON output shape
- `vectors/` test vectors produced by running the C++ tools (`../scripts/make-vectors.py`).
  Every implementation runs all of them in CI; `../scripts/check-spec-formulas.py` checks
  that the documents' formulas reproduce them
