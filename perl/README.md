<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Perl

One CPAN-style distribution, `ZBC`, on Perl 5.16 or newer with 64-bit integers (every stock build
of the last decade) and nothing beyond the core modules: SHA-256, SHA-512 and HMAC come from
`Digest::SHA`, JSON from `JSON::PP`, HTTP from `HTTP::Tiny`, big numbers from `Math::BigInt`.
SHA3-256, BLAKE2b and Ed25519 are not on CPAN's core list, so they are written here in pure Perl
(`ZBC::SHA3`, `ZBC::Blake2b`, `ZBC::Ed25519`). It contains the library (keys, addresses, message
signing, the transaction envelope and chain-bound digest, every transaction body, the node client)
and `bin/zbc-cli`.

```
cd perl
prove -l t                        # every vector in ../spec/vectors through the library and, in-process, the CLI
perl bin/zbc-cli list
perl Makefile.PL && make && make test && make install   # installs ZBC::* and zbc-cli where this perl installs modules
```

`bin/zbc-cli` runs from a checkout without installing anything (it adds `../lib` to `@INC`).
`Math::BigInt::GMP` from CPAN, if present, is picked up automatically and makes signing several
times faster; the core `Math::BigInt::FastCalc` signs a transaction in about half a second.

## Use the command line

```
perl bin/zbc-cli send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
perl bin/zbc-cli send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> perl bin/zbc-cli send-zbc --json-input
perl bin/zbc-cli approve-escrow - 0 <escrowed tx hash>
perl bin/zbc-cli sign-message <64 hex key> "text"
perl bin/zbc-cli verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
perl bin/zbc-cli help send-zbc                                    # the fields of one command
perl bin/zbc-cli send-zbc --help                                  # options, environment, exit codes
```

The contract every command follows is [`../spec/cli-contract.md`](../spec/cli-contract.md). All
58 transaction types of `../spec/transactions` are subcommands; `perl script/gen-commands.pl`
embeds the spec into `lib/ZBC/Commands.pm`, so a new type in the spec is a regeneration, not new
code. The seven types the spec marks custom are in `lib/ZBC/Custom.pm`. Not available yet in this
port: `--encrypt`.

## Use the library

```perl
use ZBC::Keys qw(key_pair wallet_account);
use ZBC::Message qw(sign_message verify_message);
use ZBC::Transaction qw(sign_transaction send_zbc_body SEND_ZBC);
use ZBC::Address qw(parse_address);
use ZBC::Client;

my $kp = key_pair('<64 hex seed>');                     # $kp->address ZBC_, $kp->node_address ZNK_, $kp->account_bytes
my $acct = wallet_account('<12 or 24 words>', 0, '');   # m/44'/883'/0': $acct->seed, $acct->address, $acct->path

my $s = sign_message($kp->seed, 'hello');               # ZBC-MSG-v1: {address, digest, signature, ...} as hex
verify_message($kp->address, 'hello', $s->{signature}); # 1

my $client = ZBC::Client->new('https://<gateway>', 20);
my $ctx = $client->signing_rule;                        # ZBC::SigningContext (2, genesis) from /api/v1/node/info
my $tx = sign_transaction(SEND_ZBC, time, $kp, parse_address('ZBC_...')->bytes, 5000000, send_zbc_body(100000000), $ctx,
                          ZBC::Escrow->new(approver => 'ZBC_...', commission => 0, timeout => 1800000000, instruction => 'on delivery'));
unpack 'H*', $tx->hash;                                 # the transaction hash
$client->submit_or_die($tx->payload);                   # dies with a ZBC::Error carrying the contract's exit code
$client->status(unpack 'H*', $tx->hash);                # staging | mempool | confirmed | not_found
$client->account($kp->address);                         # balances
```

Offline signing takes `ZBC::SigningContext->of('<genesis hex>')` (or `'v1'`) instead of asking the
node. Every body of `../spec/transactions` is available through `ZBC::Body::build_body($def,
\%params, $kp)` with `ZBC::Commands::by_name('issue-token')` and friends; `multisig_address`,
`proof_of_ownership` and the custom builders in `ZBC::Custom` are public. Strings are bytes
throughout: pass UTF-8 encoded text, as the command line does.

## Layout

```
lib/ZBC/        SHA3, Blake2b, Ed25519, Encoding, Bip39Words, Error, ExitCode, Address, Keys, Message, Transaction,
                Commands (generated), Body, Custom, Client, CLI;  lib/ZBC.pm loads them all
bin/zbc-cli     the command line;  script/gen-commands.pl  writes lib/ZBC/Commands.pm from ../spec/transactions
t/vectors.t     the vector suite (prove -l t)
Makefile.PL     ExtUtils::MakeMaker: perl Makefile.PL && make test && make install
```

`ZBC::Ed25519` is a straightforward RFC 8032 implementation on `Math::BigInt`; it is not constant
time. Keep seeds on machines you trust, as with any scripting-language signer.
