<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# PHP

One Composer package, `zoobc/zbc-tools` (namespace `Zoobc\Zbc`), on PHP 8.1 or newer with the
`sodium`, `hash` and `json` extensions that PHP ships: Ed25519 and BLAKE2b come from sodium,
SHA3-256, SHA-512, HMAC and PBKDF2 from `hash`, HTTP from the stream wrapper. No Composer
dependencies. It contains the library (keys, addresses, message signing, the transaction envelope
and chain-bound digest, every transaction body, the node client) and `bin/zbc-cli`.

```
cd php
php tests/run.php                  # every vector in ../spec/vectors through the library and the CLI (no framework needed)
php bin/zbc-cli list
composer install && composer test  # the same, through Composer's autoloader
```

`bin/zbc-cli` runs from a checkout without Composer (it falls back to a PSR-4 autoloader over
`src/`); in a Composer project it is installed as `vendor/bin/zbc-cli`.

## Use the command line

```
php bin/zbc-cli send-zbc <64 hex key> ZBC_... 100000000 --api https://<gateway or node>
php bin/zbc-cli send-zbc - ZBC_... 100000000 --genesis <64 hex> --timestamp 1700000000 --offline    # no node
printf '%s' '{"recipient":"ZBC_...","amount":100000000}' | ZBC_KEY=<64 hex> php bin/zbc-cli send-zbc --json-input
php bin/zbc-cli approve-escrow - 0 <escrowed tx hash>
php bin/zbc-cli sign-message <64 hex key> "text"
php bin/zbc-cli verify-message ZBC_... "text" <signature>       # exit 0 valid, 10 not
php bin/zbc-cli help send-zbc                                    # the fields of one command
php bin/zbc-cli send-zbc --help                                  # options, environment, exit codes
```

The contract every command follows is [`../spec/cli-contract.md`](../spec/cli-contract.md). All
58 transaction types of `../spec/transactions` are subcommands; `php bin/gen-commands.php` embeds
the spec into `src/commands_gen.php`, so a new type in the spec is a regeneration, not new code.
The seven types the spec marks custom are in `src/Custom.php`. Not available yet in this port:
`--encrypt`.

## Use the library

```php
use Zoobc\Zbc\{KeyPair, Wallet, Message, Transaction, SigningContext, Escrow, Address, Client};

$kp = KeyPair::fromHex('<64 hex seed>');                 // $kp->address() ZBC_, $kp->nodeAddress() ZNK_, $kp->accountBytes()
[$acct, $path] = Wallet::account('<12 or 24 words>', 0); // m/44'/883'/0'

$s = Message::sign($kp, 'hello');                        // ZBC-MSG-v1: address, digest, signature
Message::verify($kp->address(), 'hello', hex2bin($s['signature']));   // true

$client = new Client('https://<gateway>', 20);
$ctx = $client->signingRule();                           // SigningContext(2, genesis) from /api/v1/node/info
$tx = Transaction::sign(Transaction::SEND_ZBC, time(), $kp, Address::parse('ZBC_...')->bytes(), 5000000,
    Transaction::sendZbcBody(100000000), $ctx, new Escrow('ZBC_...', 0, 1800000000, 'on delivery'));
bin2hex($tx->hash);                                      // the transaction hash
$client->submitOrThrow($tx->payload);                    // throws ToolError with the contract's exit code
$client->status(bin2hex($tx->hash));                     // staging | mempool | confirmed | not_found
$client->account($kp->address());                        // balances
```

Offline signing takes `SigningContext::of('<genesis hex>')` (or `'v1'`) instead of asking the
node. Every body of `../spec/transactions` is available through `Body::build($def, $params,
$ctx)` with `Spec::command('issue-token')` and friends; `Custom::multisigAddress`,
`Custom::proofOfOwnership` and the custom builders are public.

## Layout

```
src/            one class per file (PSR-4): Encoding, Bip39Words, ExitCode, ToolError, Address, ParsedAddress,
                KeyPair, Wallet, Message, Escrow, SigningContext, SignedTransaction, Transaction, Spec,
                commands_gen.php (generated), Body, BodyContext, Custom, CustomInput, ReferenceBlock, Client, Reply, Cli, Io
bin/zbc-cli     the command line;  bin/gen-commands.php  writes src/commands_gen.php from ../spec/transactions
tests/run.php   the vector suite
```
