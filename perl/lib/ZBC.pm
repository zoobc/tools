# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC;
# ZooBC in Perl: keys, addresses, ZBC-MSG-v1, the transaction envelope with the chain-bound digest,
# every transaction body of spec/transactions, the node client and zbc-cli. Loads every module; see README.md.
use strict; use warnings;
our $VERSION = 'v0.1.1';

use ZBC::SHA3;
use ZBC::Blake2b;
use ZBC::Ed25519;
use ZBC::Encryption;
use ZBC::Encoding;
use ZBC::Error;
use ZBC::ExitCode;
use ZBC::Address;
use ZBC::Keys;
use ZBC::Message;
use ZBC::Transaction;
use ZBC::Commands;
use ZBC::Body;
use ZBC::Custom;
use ZBC::Client;
use ZBC::CLI;

1;
